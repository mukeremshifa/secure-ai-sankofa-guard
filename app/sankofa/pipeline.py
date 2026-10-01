"""The two pipelines shown side by side: naive Guard-only vs Guard + Sankofa hooks.

Both return a trace dict the UI/benchmark render:
  {outcome: delivered|blocked|redacted, reply, leaked, leak_hits, steps[], total_ms}
"""
import time
from dataclasses import dataclass, field

from .. import config
from ..guard import GuardClient, GuardResult
from ..llm import LLMClient
from . import canary, decode, pii, policy
from .multiturn import Accumulator


@dataclass
class Session:
    id: str = ""
    history_guard: list = field(default_factory=list)
    history_sankofa: list = field(default_factory=list)
    acc: Accumulator = field(default_factory=Accumulator)


@dataclass
class Ctx:
    guard: GuardClient
    llm: LLMClient
    session: Session
    system_prompt: str
    model: str


def _step(layer, status, title, detail="", ms=None, cached=False):
    return {"layer": layer, "status": status, "title": title, "detail": detail, "ms": ms, "cached": cached}


def _guard_step(layer, title, g: GuardResult):
    if g.error:
        status = "warn"
    else:
        status = "block" if g.blocked else ("warn" if not g.complete else "pass")
    return _step(layer, status, title, g.summary(), g.rtt_ms if not g.cached else None, g.cached)


def _finish(outcome, reply, steps, t0, leak_hits):
    return {
        "outcome": outcome, "reply": reply, "steps": steps,
        "leaked": outcome != "blocked" and bool(leak_hits),
        "leak_hits": [str(h) for h in leak_hits],
        "degraded": any(s["status"] == "warn" for s in steps),
        "total_ms": int((time.perf_counter() - t0) * 1000),
    }


async def _ask_llm(ctx: Ctx, history, text, steps):
    try:
        reply, ms = await ctx.llm.chat(ctx.system_prompt, history, text, ctx.model)
        steps.append(_step("LLM", "info", f"SikaBot · {ctx.model}", f"{len(reply)} chars", ms))
        return reply
    except RuntimeError as e:
        steps.append(_step("LLM", "warn", "SikaBot unavailable", str(e)))
        return None


# --------------------------------------------------------------------------
# Naive integration: trust the Guard, fail open when it is unavailable.
# --------------------------------------------------------------------------
async def guard_only(ctx: Ctx, message: str) -> dict:
    t0, steps = time.perf_counter(), []
    g = await ctx.guard.check_prompt(message)
    steps.append(_guard_step("Guard", "Guard · input check", g))
    if g.blocked:
        return _finish("blocked", config.GUARD_BLOCK_MSG + " (input)", steps, t0, [])
    reply = await _ask_llm(ctx, ctx.session.history_guard, message, steps)
    if reply is None:
        return _finish("blocked", "Assistant unavailable.", steps, t0, [])
    g2 = await ctx.guard.check_response(reply)
    steps.append(_guard_step("Guard", "Guard · output check", g2))
    if g2.blocked:
        return _finish("blocked", config.GUARD_BLOCK_MSG + " (output)", steps, t0, [])
    ctx.session.history_guard += [{"role": "user", "content": message}, {"role": "assistant", "content": reply}]
    # `leaked` is judged by the Sankofa canary scanner acting as ground-truth oracle.
    return _finish("delivered", reply, steps, t0, canary.scan(reply, config.SECRETS))


# --------------------------------------------------------------------------
# Sankofa hooks
# --------------------------------------------------------------------------
async def sankofa_input(ctx: Ctx, message: str):
    """Returns (Decision, text_for_llm, steps)."""
    steps, dec = [], policy.Decision()
    d = decode.analyze(message)
    if d.layers:
        detail = "; ".join(f"{l.kind}: {l.decoded[:70]!r}" for l in d.layers)
        steps.append(_step("Sankofa", "flag", "Decode & reveal", detail))
    else:
        steps.append(_step("Sankofa", "pass", "Decode & reveal", "no encoded layers"))

    text_for_llm, pii_found = pii.redact(message)
    if pii_found:
        steps.append(_step("Sankofa", "flag", "Ghana PII (input)",
                           ", ".join(sorted({f.kind for f in pii_found})) + " redacted before the LLM"))
        dec.action = "redact"

    mt = ctx.session.acc.assess(d.expanded)
    if mt.triggered:
        steps.append(_step("Sankofa", "flag", "Multi-turn accumulator", mt.reason))

    results = []  # (label, GuardResult)
    g1 = await ctx.guard.check_prompt(message)
    steps.append(_guard_step("Guard", "Guard · input check (as sent)", g1))
    results.append(g1)
    if g1.blocked:
        return dec.block("Guard", "Guard flagged the message: " + ", ".join(g1.fired)), text_for_llm, steps

    if d.expanded != message:
        g2 = await ctx.guard.check_prompt(d.expanded)
        steps.append(_guard_step("Sankofa", "Guard · re-check of DECODED text", g2))
        results.append(g2)
        if g2.blocked:
            return dec.block("Sankofa·decode", "Decoded content flagged by Guard: " + ", ".join(g2.fired)), text_for_llm, steps
    if mt.triggered:
        g3 = await ctx.guard.check_prompt(mt.joined)
        steps.append(_guard_step("Sankofa", "Guard · re-check of JOINED turns", g3))
        results.append(g3)
        if g3.blocked:
            return dec.block("Sankofa·multi-turn", "Assembled turns flagged by Guard: " + ", ".join(g3.fired)), text_for_llm, steps
        hits = policy.lexicon_hits(mt.joined)
        if hits:
            steps.append(_step("Sankofa", "block", "Local policy on JOINED turns", ", ".join(hits)))
            return dec.block("Sankofa·multi-turn", "Guard allowed the assembled request, local policy did not: " + ", ".join(hits)), text_for_llm, steps

    links = policy.suspicious_links(d.expanded)
    if links:
        steps.append(_step("Sankofa", "block", "Link policy (re-fanged)", ", ".join(links)))
        return dec.block("Sankofa·links", "suspicious link after re-fanging: " + links[0]), text_for_llm, steps

    degraded = [r for r in results if not r.complete]
    if degraded:
        steps.append(_step("Sankofa", "warn", "Availability policy",
                           f"Guard degraded ({degraded[0].error or degraded[0].status}) → fail-closed local layer"))
        if config.FAIL_CLOSED_STRICT:
            return dec.block("Sankofa·availability", "strict fail-closed: no complete Guard verdict"), text_for_llm, steps
        if d.encoded_layers:
            return dec.block("Sankofa·availability", "encoded content cannot be verified while Guard is degraded"), text_for_llm, steps
        hits = policy.lexicon_hits(d.expanded) + (policy.lexicon_hits(mt.joined) if mt.triggered else [])
        if hits:
            steps.append(_step("Sankofa", "block", "Local policy (Guard degraded)", ", ".join(sorted(set(hits)))))
            return dec.block("Sankofa·availability", "local policy: " + ", ".join(sorted(set(hits)))), text_for_llm, steps
    return dec, text_for_llm, steps


async def sankofa_output(ctx: Ctx, reply: str, steps: list):
    """Returns (Decision, reply_to_show)."""
    dec = policy.Decision()
    hits = canary.scan(reply, config.SECRETS)
    n_shared, overlapped = canary.overlap(reply, config.OVERLAP_REFERENCE)
    if hits:
        steps.append(_step("Sankofa", "block", "Canary / secret scan", "; ".join(map(str, hits))))
        return dec.block("Sankofa·canary", "protected secret in reply: " + "; ".join(map(str, hits))), config.OUTPUT_BLOCK_MSG
    if overlapped:
        steps.append(_step("Sankofa", "block", "System-prompt overlap", f"{n_shared} shared 4-grams with confidential block"))
        return dec.block("Sankofa·overlap", "reply reproduces the confidential block"), config.OUTPUT_BLOCK_MSG
    steps.append(_step("Sankofa", "pass", "Canary / secret scan", "no protected secret in any known disguise"))

    shown, found = pii.redact(reply)
    if found:
        steps.append(_step("Sankofa", "flag", "Ghana PII (output)", ", ".join(sorted({f.kind for f in found})) + " redacted"))
        dec.action = "redact"
    g = await ctx.guard.check_response(shown)
    steps.append(_guard_step("Guard", "Guard · output check", g))
    if g.blocked:
        return dec.block("Guard", "Guard flagged the reply: " + ", ".join(g.fired)), config.OUTPUT_BLOCK_MSG
    if not g.complete:
        steps.append(_step("Sankofa", "warn", "Availability policy",
                           "no complete Guard verdict; local scan passed" + (" — strict mode blocks" if config.FAIL_CLOSED_STRICT else "")))
        if config.FAIL_CLOSED_STRICT:
            return dec.block("Sankofa·availability", "strict fail-closed"), config.OUTPUT_BLOCK_MSG
    return dec, shown


async def sankofa(ctx: Ctx, message: str) -> dict:
    t0 = time.perf_counter()
    dec, text_for_llm, steps = await sankofa_input(ctx, message)
    ctx.session.acc.add(decode.analyze(message).expanded)
    if dec.blocked:
        return _finish("blocked", config.INPUT_BLOCK_MSG, steps, t0, [])
    reply = await _ask_llm(ctx, ctx.session.history_sankofa, text_for_llm, steps)
    if reply is None:
        return _finish("blocked", "Assistant unavailable.", steps, t0, [])
    out, shown = await sankofa_output(ctx, reply, steps)
    if out.blocked:
        return _finish("blocked", shown, steps, t0, [])
    ctx.session.history_sankofa += [{"role": "user", "content": text_for_llm}, {"role": "assistant", "content": shown}]
    outcome = "redacted" if "redact" in (dec.action, out.action) else "delivered"
    return _finish(outcome, shown, steps, t0, canary.scan(shown, config.SECRETS))
