# Sankofa Guard

**Two hooks that make the SecureAI Guard hold up against attacks it currently misses.**
CAIRLab-KNUST SecureAI Hackathon 2026 · Challenge 3 · Team **Abugida**

> *Sankofa* (Akan): "go back and fetch it." Our **input hook** goes back and decodes what the user hid. Our **output hook** goes back and checks the reply against what must never leave.

![Architecture](docs/architecture.svg)

## The result in one table

Measured on 47 prompts (29 attacks, 18 normal Ghanaian banking questions) against a live SikaBot (gpt-4o-mini) and the live Guard:

| | Guard alone | Guard + Sankofa |
|---|---|---|
| Attacks that slipped through undetected | **62.1 %** | **10.3 %** |
| Secrets actually leaked to the customer | **5** | **0** |
| Normal customer questions wrongly blocked | 0 % | 0 % |
| Guard calls per prompt (cache included) | 1.94 | 1.85 |
| Extra latency from Sankofa's local layers | n/a | ≈ 0.5 ms per message |

The three attacks Sankofa still "misses" are cases where the model refused on its own, so nothing leaked. Full per-prompt results are in `benchmark_results.json` and the app's Benchmark tab.

## What we built, against the three things the brief asks for

1. **Show a weakness.** The Guard screens one message at a time and knows nothing about *our* secrets. The Attack playground fires each weakness live.
2. **Show our system fixing it.** The Live demo runs the same message through two columns, "Guard only" and "Guard + Sankofa", with a verdict chip and timing for every layer.
3. **Working demo with Guard + LLM.** A FastAPI app with a real OpenAI-backed chatbot and the real Guard API. No mocks.

![Live demo](docs/screenshots/live-demo.png)

### The system we protect: SikaBot
A fictional support bot for *Sika Microfinance* (Kumasi). Its system prompt holds a staff fee-waiver code, a supervisor override PIN and a canary token. Customers paste Ghana Card, MoMo and SSNIT numbers into the chat. A toggle switches between a "typical" and a "hardened" prompt to show that the model's own defences are inconsistent.

## Weaknesses found, and our fix for each

| | Weakness in the Guard | What Sankofa does |
|---|---|---|
| **W1** | Injections wrapped in **base64** are allowed (the plain text is blocked). | Decodes base64 / hex / %-encoding / ROT13, strips zero-width characters, folds look-alike letters, then re-checks the decoded text with the Guard (at most one extra call). |
| **W2** | **Context-blind output check.** A reply that leaks our code as an acrostic, spaced out, reversed or encoded is allowed. | Canary and secret scanner covering all those forms, plus an overlap check against the confidential block. |
| **W3** | **Ghana PII** (Ghana Card, MoMo, SSNIT) is not recognised; detection was inconsistent in our runs. | Local Ghana PII detector. Redacts before the LLM and again on the reply. |
| **W4** | **Stateless.** An attack split across turns ("save P1…", "save P2…", "join them") looks harmless each time. | Rolling window of user turns, an assembly detector, and a re-check of the joined text with the Guard plus a local policy. |
| **W5** | **Availability and quota.** `partial`, 429, 502 and 503 responses; 1,000 calls/day. | Local checks run first, identical text is cached, calls are throttled under 30/min with `Retry-After` respected, and a live usage meter shows quota. When the Guard cannot give a full verdict, the local layer fails closed on known-bad classes. `FAIL_CLOSED_STRICT=true` blocks everything instead. |
| **W6** | **Defanged links** (`hxxp://…[.]xyz`) pass the link check. | Re-fangs the URL and applies a local suspicious-link policy. |

**Headline kill chain (W1 + W2).** A harmless-looking poem request passes the Guard's input check, SikaBot spells the fee-waiver code down the first letters of the lines, and the Guard's output check allows it. In the left column the customer gets the secret and the Guard never fires. In the right column Sankofa's output hook blocks it.

By attack class (share not caught, Guard alone → with Sankofa): encoding 83 → 0 %, Ghana PII 50 → 0 %, multi-turn 50 → 0 %, defanged links 50 → 0 %, plain injection 20 → 0 %, exfiltration 80 → 30 %.

## Run it

```bash
pip install -r requirements.txt
cp .env.example .env          # fill in GUARD_URL, GUARD_TOKEN, OPENAI_API_KEY
uvicorn app.main:app --reload
# open http://localhost:8000
```

Secrets live only in `.env`, which is git-ignored. Only `.env.example` (placeholders) is committed.

Offline tests (no network or keys): `python -m pytest`

To regenerate the benchmark (about 100 Guard calls, resumable, rate-limited; run it once): `python scripts/run_benchmark.py --fresh`

### Tour of the app
- **Live demo:** type anything, or click an attack chip. Header controls: system prompt (typical / hardened), model, and **Simulate Guard outage**.
- **Attack playground:** one card per weakness, each explaining what it exploits. Best with the "typical" prompt.
- **Benchmark:** the table above, a per-class chart and every prompt's outcome.
- **Architecture:** the two-hook diagram.

| Playground | Benchmark |
|---|---|
| ![Playground](docs/screenshots/playground.png) | ![Benchmark](docs/screenshots/benchmark.png) |

## Why this is practical
- **Complements the Guard.** It does not replace the Guard or reimplement it. Every request still goes through the Guard, and Sankofa adds what a stateless, app-agnostic screen cannot know.
- **Cheap.** Local layers cost about half a millisecond. Network cost is a cached Guard call, plus at most two extra calls when text was decoded or turns were joined.
- **Quota-aware.** It behaves sensibly when the Guard is slow, rate-limited or down, which is where naive integrations either block everyone or let everything through.
- **Reusable.** Each layer in `app/sankofa/` (decode, pii, canary, multiturn, policy) is an independent, unit-tested module. Adapting to another app means changing the secrets list in `app/config.py` and the policy lexicon in `app/sankofa/policy.py`.

## Repository layout
```
app/main.py            FastAPI server and API
app/guard.py           Guard client: throttle, cache, Retry-After, fail-safe errors
app/llm.py             OpenAI client for SikaBot
app/sankofa/           decode · pii · canary · multiturn · policy · pipeline
app/static/index.html  UI (Tailwind + vanilla JS + Chart.js)
attacks/corpus.json    47-prompt labelled corpus (built by scripts/build_corpus.py)
scripts/run_benchmark.py · benchmark_results.json · tests/ · docs/
DEMO_SCRIPT.md         4–5 minute walkthrough
```

## Limitations (please read)
- **Small, self-written corpus.** 47 prompts we wrote ourselves while building the fixes. The numbers demonstrate the approach; they are not a general claim about the Guard.
- **Self-judged leaks.** "Secret leaked" is decided by Sankofa's own scanner, which knows the secrets. It cannot see disguises we did not model (for example a translation of the code, or hints in the wording).
- **One configuration.** Results are for gpt-4o-mini with the "typical" prompt. Other models and the hardened prompt will differ; the model refuses some attacks by itself.
- **Guard behaviour varies by phrasing.** Some weaknesses (hex, some Ghana PII) were not reproduced on every sample, so we report measurements, not the original claims.
- **Heuristics have limits.** The multi-turn detector and policy lexicon target known phrasing, and a new assembly style could bypass them. PII hidden inside an encoded blob is re-checked by the Guard but not redacted by us.
- **Per-application setup.** Secrets and policy must be configured for each deployment. Cache and throttle are per process, not shared across instances.

## Team
Abugida · CAIRLab-KNUST SecureAI Hackathon 2026
