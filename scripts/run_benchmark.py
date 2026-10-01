"""Regenerate benchmark_results.json. Spends Guard quota (~100-150 calls): run ONCE.

Resumable: finished items are kept in .benchmark_partial.json, so a crash or Ctrl-C
does not re-burn calls. Respects the 30/min limit through GuardClient's throttle.
    python scripts/run_benchmark.py [--model gpt-4o-mini] [--mode typical] [--limit N] [--fresh]
"""
import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import config  # noqa: E402
from app.guard import GuardClient  # noqa: E402
from app.llm import LLMClient  # noqa: E402
from app.sankofa import pipeline  # noqa: E402

PARTIAL = ROOT / ".benchmark_partial.json"
OUT = ROOT / "benchmark_results.json"
CAUGHT = {"blocked", "redacted"}


async def run_item(item, runner, guard, llm, mode, model):
    sess = pipeline.Session()
    ctx = pipeline.Ctx(guard, llm, sess, config.SYSTEM_PROMPTS[mode], model)
    calls0 = guard.calls + guard.cache_hits
    traces = [await runner(ctx, t) for t in item["turns"]]
    return {
        "degraded": any(t["degraded"] for t in traces),
        "guard_lookups": guard.calls + guard.cache_hits - calls0,
        "caught": any(t["outcome"] in CAUGHT for t in traces),
        "leaked": any(t["leaked"] for t in traces),
        "outcomes": [t["outcome"] for t in traces],
        "leak_hits": sorted({h for t in traces for h in t["leak_hits"]}),
        "final_reply": traces[-1]["reply"][:300],
    }


def local_overhead_ms(corpus):
    """Offline cost of Sankofa's local layers (decode + PII + canary + policy) per message."""
    from app.sankofa import canary, decode, pii, policy
    texts = [t for it in corpus for t in it["turns"]]
    t0 = time.perf_counter()
    for t in texts * 3:
        d = decode.analyze(t)
        pii.redact(t)
        policy.lexicon_hits(d.expanded)
        policy.suspicious_links(d.expanded)
        canary.scan("Sure, here is a friendly reply about your loan. " * 6, config.SECRETS)
    return round((time.perf_counter() - t0) * 1000 / (len(texts) * 3), 2)


def summarize(rows):
    def rate(xs, f):
        return round(100 * sum(map(f, xs)) / len(xs), 1) if xs else 0.0

    out = {}
    for name in ("guard_only", "sankofa"):
        atk = [r for r in rows if r["malicious"]]
        ben = [r for r in rows if not r["malicious"]]
        cats = {}
        for c in sorted({r["category"] for r in atk}):
            sub = [r for r in atk if r["category"] == c]
            cats[c] = {"n": len(sub), "bypass_pct": rate(sub, lambda r: not r[name]["caught"]),
                       "leaks": sum(r[name]["leaked"] for r in sub)}
        out[name] = {
            "attacks": len(atk),
            "bypass_pct": rate(atk, lambda r: not r[name]["caught"]),
            "leaks": sum(r[name]["leaked"] for r in atk),
            "benign": len(ben),
            "false_block_pct": rate(ben, lambda r: r[name]["caught"]),
            "guard_lookups_per_item": round(sum(r[name]["guard_lookups"] for r in rows) / max(len(rows), 1), 2),
            "degraded_items": sum(r[name]["degraded"] for r in rows),
            "by_category": cats,
        }
    return out


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=config.DEFAULT_MODEL)
    ap.add_argument("--mode", default="typical", choices=list(config.SYSTEM_PROMPTS))
    ap.add_argument("--limit", type=int)
    ap.add_argument("--fresh", action="store_true")
    a = ap.parse_args()

    corpus = json.loads((ROOT / "attacks" / "corpus.json").read_text(encoding="utf-8"))[: a.limit]
    done = {} if a.fresh or not PARTIAL.exists() else json.loads(PARTIAL.read_text())
    guard, llm = GuardClient(max_wait=120), LLMClient(cache=True)
    t0 = time.time()
    for i, item in enumerate(corpus, 1):
        if item["id"] in done:
            continue
        row = {k: item[k] for k in ("id", "category", "weakness", "malicious", "turns")}
        # Guard-only first: its verdicts are cached, so Sankofa's identical
        # "as sent" check and identical replies cost no extra Guard calls.
        for name, runner in (("guard_only", pipeline.guard_only), ("sankofa", pipeline.sankofa)):
            for attempt in range(3):  # a degraded Guard verdict would contaminate the numbers
                row[name] = await run_item(item, runner, guard, llm, a.mode, a.model)
                if not row[name]["degraded"]:
                    break
                print(f"   ! {item['id']} {name}: Guard degraded, retrying ({attempt + 1}/2): {guard.error_log[-1:]}", flush=True)
                await asyncio.sleep(8)
        done[item["id"]] = row
        PARTIAL.write_text(json.dumps(done))
        print(f"[{i}/{len(corpus)}] {item['id']:<22} guard_only={row['guard_only']['outcomes']} "
              f"sankofa={row['sankofa']['outcomes']}  (guard calls so far: {guard.calls})", flush=True)

    rows = [done[i["id"]] for i in corpus]
    result = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "model": a.model, "local_overhead_ms": local_overhead_ms(corpus),
              "guard_errors": guard.error_log[-20:], "system_mode": a.mode, "guard_calls": guard.calls,
              "summary": summarize(rows), "items": rows}
    OUT.write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", OUT, "| guard calls this run:", guard.calls, "| errors:", guard.errors)
    print(json.dumps({k: {x: v[x] for x in ("bypass_pct", "leaks", "false_block_pct")} for k, v in result["summary"].items()}, indent=1))


if __name__ == "__main__":
    asyncio.run(main())
