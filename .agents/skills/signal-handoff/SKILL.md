---
name: signal-handoff
description: Record a compact PLATFORM::SIGNAL task handoff with accepted changes, verification, usage and the next runnable item. Use at completion or a phase/writer transition.
---

Record the concrete outcome, owned changed files, actual model/effort, elapsed
time, correction/escalation cycles, acceptance commands and evidence paths.
Include remaining failures and the next authorized runnable item or the exact
external gate. Keep release claims bounded by docs/21-release-readiness.md.
For phase changes, update the relevant docs/07-progress.md entry and contract
only after evidence settles; avoid duplicating historical narratives across docs.
Do not stage, commit, push or publish unless the user requests that action.

If a baseline exists, capture a new snapshot and compare it:

```bash
python3 scripts/ai/usage.py --output target/ai-usage/<task>-after.json \
  --baseline target/ai-usage/<task>-before.json
```

Use the same `--thread-id <id>` scope as the baseline, if any. This read-only
helper reports local Codex cumulative-counter deltas, not subscription costs or
Claude usage. Project-wide deltas include concurrent tasks and approval reviews;
a single-thread delta excludes child work. Cached input is a subset of input,
and reasoning output a subset of output. Never add either subset twice.

Use actual client usage controls for allowance before/after when available;
otherwise mark allowance or provider usage unavailable. Do not infer an invoice
or a saving percentage from token counts, API list prices or elapsed time alone.
Leave the next writer a short task/evidence packet rather than a full transcript.
