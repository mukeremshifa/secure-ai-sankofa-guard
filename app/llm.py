"""Minimal OpenAI chat client for SikaBot."""
import hashlib
import json
import time

import httpx

from . import config


class LLMClient:
    def __init__(self, cache: bool = False):
        self._http = httpx.AsyncClient(timeout=60)
        self._cache = {} if cache else None  # benchmark only: identical input -> identical reply

    async def chat(self, system: str, history: list, user: str, model: str):
        """Return (reply_text, elapsed_ms). Raises RuntimeError on API failure."""
        messages = [{"role": "system", "content": system}, *history, {"role": "user", "content": user}]
        key = hashlib.sha256(json.dumps([model, messages]).encode()).hexdigest()
        if self._cache is not None and key in self._cache:
            return self._cache[key], 0
        body = {"model": model, "messages": messages, "max_completion_tokens": 1500}
        if not model.startswith("gpt-5"):
            body["temperature"] = 0
        t0 = time.perf_counter()
        try:
            r = await self._http.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {config.OPENAI_API_KEY}"}, json=body)
        except httpx.HTTPError as e:
            raise RuntimeError(f"LLM network error: {type(e).__name__}") from e
        ms = int((time.perf_counter() - t0) * 1000)
        if r.status_code >= 400:
            raise RuntimeError(f"LLM error {r.status_code}: {r.text[:200]}")
        text = (r.json()["choices"][0]["message"].get("content") or "").strip()
        if self._cache is not None:
            self._cache[key] = text
        return text, ms
