"""Quota-aware client for the SecureAI Guard API.

Throttles under the per-minute limit, caches deterministic verdicts, honours
Retry-After, and never raises: failures come back as a GuardResult with `error`
set so the policy layer can decide (fail-closed) instead of crashing.
"""
import asyncio
import time
from collections import deque
from dataclasses import dataclass, field

import httpx

from . import config

CHECK_NAMES = ("injection", "harmful_content", "sensitive_data", "unsafe_links", "prohibited_content")


@dataclass
class GuardResult:
    allowed: bool | None = None
    status: str = "error"
    flags: list = field(default_factory=list)
    checks: dict = field(default_factory=dict)
    server_ms: int | None = None
    rtt_ms: int = 0
    cached: bool = False
    error: str | None = None

    @property
    def complete(self) -> bool:
        return self.error is None and self.status == "complete"

    @property
    def blocked(self) -> bool:
        return self.allowed is False

    @property
    def fired(self):
        return [k for k, v in self.checks.items() if isinstance(v, dict) and v.get("flagged")]

    def summary(self) -> str:
        if self.error:
            return f"unavailable ({self.error})"
        verdict = "blocked" if self.blocked else "allowed"
        extra = f" · fired: {', '.join(self.fired)}" if self.fired else ""
        part = "" if self.status == "complete" else f" · status={self.status}"
        return f"{verdict}{extra}{part}"


class GuardClient:
    def __init__(self, url=None, token=None, max_per_min=None, max_wait=25.0):
        self.url = (url or config.GUARD_URL).rstrip("/")
        self.token = token or config.GUARD_TOKEN
        self.max_per_min = max_per_min or config.GUARD_MAX_PER_MIN
        self._http = httpx.AsyncClient(timeout=15)
        self._stamps = deque()
        self._lock = asyncio.Lock()
        self._cache = {}
        self.max_wait = max_wait  # demo: fail fast; benchmark: wait for the window
        self.simulate_outage = False
        self.calls = 0
        self.cache_hits = 0
        self.errors = 0
        self.error_log = []

    async def _throttle(self):
        max_wait = self.max_wait
        async with self._lock:
            now = time.monotonic()
            while self._stamps and now - self._stamps[0] > 60:
                self._stamps.popleft()
            if len(self._stamps) >= self.max_per_min:
                wait = 60 - (now - self._stamps[0]) + 0.05
                if wait > max_wait:
                    return False
                await asyncio.sleep(wait)
            self._stamps.append(time.monotonic())
            return True

    async def _check(self, endpoint: str, text: str) -> GuardResult:
        key = (endpoint, text)
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < config.GUARD_CACHE_TTL:
            self.cache_hits += 1
            r = hit[1]
            return GuardResult(**{**r.__dict__, "cached": True, "rtt_ms": 0})
        if self.simulate_outage:
            self.errors += 1
            return GuardResult(error="503 service_busy (simulated outage)")
        if not await self._throttle():
            return GuardResult(error="client_throttled (30/min budget)")

        for attempt in range(2):
            t0 = time.perf_counter()
            try:
                self.calls += 1
                resp = await self._http.post(
                    f"{self.url}/v1/check/{endpoint}",
                    headers={"Authorization": f"Bearer {self.token}"},
                    json={"text": text},
                )
            except httpx.HTTPError as e:
                self.errors += 1
                self.error_log.append(f"network {type(e).__name__} {e}")
                return GuardResult(error=f"network: {type(e).__name__}")
            rtt = int((time.perf_counter() - t0) * 1000)
            if resp.status_code == 429:
                kind = _err_kind(resp) or "rate_limited"
                retry = float(resp.headers.get("Retry-After", "0") or 0)
                if kind == "rate_limited" and attempt == 0 and 0 < retry <= 10:
                    await asyncio.sleep(retry)
                    continue
                self.errors += 1
                self.error_log.append(f"429 {resp.text[:120]} retry-after={retry}")
                return GuardResult(error=f"429 {kind}", rtt_ms=rtt)
            if resp.status_code >= 400:
                self.errors += 1
                self.error_log.append(f"{resp.status_code} {resp.text[:120]}")
                return GuardResult(error=f"{resp.status_code} {_err_kind(resp) or 'error'}", rtt_ms=rtt)
            d = resp.json()
            res = GuardResult(
                allowed=d.get("allowed"), status=d.get("status", "complete"),
                flags=d.get("flags", []), checks=d.get("checks", {}),
                server_ms=d.get("latency_ms"), rtt_ms=rtt,
            )
            if res.complete:
                self._cache[key] = (time.monotonic(), res)
            return res
        return GuardResult(error="rate_limited")

    async def check_prompt(self, text):
        return await self._check("prompt", text)

    async def check_response(self, text):
        return await self._check("response", text)

    async def usage(self):
        try:
            r = await self._http.get(f"{self.url}/v1/usage",
                                     headers={"Authorization": f"Bearer {self.token}"})
            return r.json() if r.status_code < 400 else {"error": r.status_code}
        except httpx.HTTPError as e:
            return {"error": type(e).__name__}


def _err_kind(resp):
    try:
        return resp.json().get("error")
    except Exception:
        return None
