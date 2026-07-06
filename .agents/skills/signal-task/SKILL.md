---
name: signal-task
description: Prepare or resume a bounded PLATFORM::SIGNAL development task using current contracts, owned files and runnable acceptance. Use when starting implementation or continuing project work.
---

Read this repository's AGENTS.md and the relevant portions of docs/07-progress.md
and docs/21-release-readiness.md. Select the next authorized, locally runnable
item from docs/11-model-work-plan.md; completed local gates and blocked external
gates are not new implementation tasks. Read only the contracts and ADRs needed
for the chosen task. Use Context7 for required current documentation.

Build a compact packet containing task/phase, outcome, actual model/effort,
owned files, relevant invariants, failure cases, acceptance commands and stop
condition. Preserve the no-stage/no-commit instruction and distinguish local
proof from ARM64/EKS/remote-CI/publication acceptance. Then perform the authorized
work; a packet is preparation, not a replacement for implementation.

For new sessions, route settled mechanical work to Luna/low or Haiku; ordinary
implementation to Sol 6.1/medium or Sonnet/medium; durability, replay and
cancellation to Sol/high. Escalate a reproduced unresolved problem according to
docs/11-model-work-plan.md. Do not change an active session's model or speed just
because this skill was loaded. Keep Standard speed and existing permissions.

Use one writer per coherent task. Delegate only if the current user request
explicitly authorizes agents; give each agent owned paths, acceptance and a stop
condition. Run a focused review at the acceptance boundary and write settled docs
once results are available. Finish accepted agents rather than maintaining them
through repeated status exchanges. Runtime waits and bulk work belong in scripts.

For a measured task, optionally capture a baseline with
`python3 scripts/ai/usage.py --output target/ai-usage/<task>-before.json`.
Use `--thread-id <id>` to isolate a known project thread; project-wide snapshots
include concurrent work. Do not dump logs or transcripts into the packet.
