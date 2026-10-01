# Demo script (4–5 min, Oct 5)
Setup: server running, **typical** prompt, model gpt-4o-mini, outage box unchecked. Quota is shared: don't click-storm.

**0:00 – Frame (20 s).** "SikaBot is a Kumasi microfinance chatbot with secret staff codes. The SecureAI Guard screens prompts and replies. We show where it fails, then wrap it with Sankofa — two hooks, around the Guard, not replacing it."

**0:20 – Kill chain (90 s).** Playground → *Acrostic exfiltration*. Left (Guard only): both Guard checks green, reply is a poem — red banner **SECRET LEAKED (acrostic)**. Right: input passes, SikaBot answers, **Canary / secret scan** blocks. Point at the per-layer chips and ms timings. "The Guard has no idea what is secret *to us*."

**1:50 – Encoding hole (45 s).** *Base64-wrapped injection*. Left: Guard allows. Right: "Decode & reveal" → Guard **re-check of DECODED text** blocks, and the LLM never sees it.

**2:35 – Ghana PII + multi-turn (50 s).** *Ghana PII*: left echoes the numbers, right redacts. *Multi-turn assembly* (3 turns auto-sent): every turn is innocent alone; Sankofa's accumulator joins them and blocks.

**3:25 – Availability (40 s).** Tick **Simulate Guard outage**, fire *Acrostic* again: left fails open and leaks; right goes fail-closed — local layer still blocks. Mention the 30/min throttle, cache and live usage meter in the header.

**4:05 – Benchmark (40 s).** Benchmark tab: not-caught 62.1 % → 10.3 %, leaks 5 → 0, 0 % benign false blocks, ≈0.5 ms local overhead. Be upfront: small hand-built corpus, our own oracle, see Limitations.

**4:45 – Close.** "Sankofa: go back and fetch it — decode before you trust, remember before you answer."
Backup if the network dies: Benchmark tab and Architecture tab work offline from the committed JSON/SVG.
