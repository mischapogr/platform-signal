# Bounded AI execution and autonomous continuation

Use the compact [progress](07-progress.md), [release boundaries](21-release-readiness.md),
[routing](11-model-work-plan.md) and finite [ledger](31-execution-ledger.json).
Read only the selected contract/ADR sections. Dated history files preserve earlier
reports byte for byte; their older permissions and next-task suggestions are historical.

Use the actual current date and time, with an explicit timezone, for new task
records, handoffs and presentation updates. Preserve original evidence and price
check dates; regeneration does not constitute a new verification. If the owner
authorizes a commit, use its actual creation time for author and committer dates;
do not backdate commits or reuse historical task dates.

## One task at a time

1. Select a locally runnable ledger item whose dependencies permit the next slice.
2. Prepare a packet: outcome, owned individual files, contracts, invariants/failure
   cases, actual model/effort, focused and acceptance commands, stop condition.
3. Implement with focused regressions. Record corrections rather than restarting
   complete qualification after every edit.
4. Conduct the applicable focused review, fix findings, then freeze source.
5. Run final gates sequentially; retain failed attempts. Any source correction
   invalidates the review binding and requires affected checks to run again.
6. Record acceptance, usage, elapsed time, corrections and the exact next slice.

One writer is the default. Independent review is used where the contract requires
it and the current request authorizes agents. Label writer review explicitly;
it does not fulfill an independent-review requirement. If the next task needs
external authority, continue other independent authorized work and retain the gate.

## Packet and serial acceptance helper

Create an owned spec JSON under `target/<work>/spec.json`. The packet schema is:

```json
{
  "task": "bounded slice name",
  "ledger_item": "SHARED-RUNTIME",
  "kind": "rust",
  "route": "critical",
  "outcome": "one verifiable result",
  "actual_model": "record the active model",
  "actual_effort": "record the active effort",
  "owned_paths": ["crates/signal-control/src/lib.rs"],
  "contracts": ["docs/48-shared-control-runtime.md"],
  "failure_cases": ["describe the invariant and its failure regression"],
  "focused_commands": [["cargo", "test", "-p", "signal-control"]],
  "acceptance_commands": [["python3", "scripts/check-workspace.py"]],
  "stop_condition": "accepted slice, explicit interruption, budget or external gate"
}
```

List **every changed file** and the inputs relevant to acceptance, including
configuration/schema/fixtures and their helpers. Directories are refused to keep
the review scope explicit. `ledger_item` is optional for tooling outside the frozen
product ledger. Kinds: `rust`, `tooling`, `docs`; routes: `critical`,
`implementation`, `mechanical`. Recommendations never switch the active model.

```bash
python3 scripts/ai/task.py init --spec target/<work>/spec.json --output target/<work>/packet
python3 scripts/ai/task.py validate --output target/<work>/packet --stage focused
python3 scripts/ai/task.py review --output target/<work>/packet
```

`review.json` is a **pending template**, not approval. After conducting review,
record reviewer, actual model/effort and findings; set status `passed` only with
no blocking findings and the exact source/packet binding. After source corrections,
retain the prior review under another name and create/review a fresh template.

```bash
python3 scripts/ai/task.py validate --output target/<work>/packet --stage final
```

Final validation refuses pending/stale reviews. Rust tasks automatically include
fmt, strict workspace/all-target Clippy, workspace tests and workspace guard.
Declare all-feature and process/container/cluster/security checks when applicable;
the helper does not infer those contract requirements. Tooling/docs use their
declared checks without repeating unchanged Rust campaigns.

Commands are literal argv arrays executed without a shell. Only local Cargo
fmt/clippy/test and repository Python scripts are accepted; declared scripts are
trusted task inputs, not a sandbox. `run-ci-check.py` retains finite logs/reports
and kills/reaps its owned process group on deadline. Per-command deadline is
1–600 seconds; final command count is bounded by the packet plus mandatory gates.
Failed gates stop the campaign. A source/packet change during the campaign fails
acceptance. A nonblocking local lock refuses simultaneous helper campaigns;
direct Cargo/fixture commands bypass this lock, so do not launch them concurrently.
Each attempt gets its own directory. No Git, release or external authority is granted.

## Usage and accepted-task handoff

Use the same known thread scope for both snapshots:

```bash
python3 scripts/ai/usage.py --thread-id <thread> --output target/<work>/usage-before.json
python3 scripts/ai/usage.py --thread-id <thread> --output target/<work>/usage-after.json --baseline target/<work>/usage-before.json
```

Record actual model/effort, elapsed time, correction/escalation cycles, commands,
reports and next runnable task. A single-thread delta excludes children; capture
authorized delegated threads separately. Project-wide counters include concurrent
work. Cached input is a subset of input; reasoning is a subset of output.
Subscription allowance/provider billing remain unavailable unless obtained from
their actual client/account controls. Do not claim a savings percentage from
local tokens alone. Preserve configuration, credentials and global settings.

## Long-running autonomous sessions

Codex Goals attach a durable objective to a thread and permit continuation at
idle boundaries until success, interruption, budget or a blocking condition.
See [official Goals documentation](https://developers.openai.com/cookbook/examples/codex/using_goals_in_codex).
Enter the command in the client's command surface; a code example in chat does
not activate a Goal. Request an explicit budget if one is desired; do not invent
one or equate Goal accounting with included subscription allowance.

Example objective for a separately activated session:

```text
/goal Complete the authorized locally runnable remaining plan items in dependency order, with reviewed source and matching required acceptance reports. Follow docs/49-ai-execution-workflow.md and the finite ledger. Use one writer, preserve dirty work and all evidence; keep staging, commits, pushes, publication and external environments held. After each accepted slice, checkpoint results and the next runnable task. Retain external gates separately; if no authorized runnable work remains, report the exact blockers and evidence rather than declaring the release complete.
```

Use `/goal` to inspect, `/goal pause` to pause, `/goal resume` to resume and
`/goal clear` to remove the objective. Keep the execution host/client available;
a local process cannot do useful work while its host is asleep/offline. Persistent
Goal state and handoffs allow resumption, not a guarantee of uninterrupted hosting.
No background service, scheduled job or always-on cloud runner is configured here.

At every accepted slice, retain a compact `HANDOFF.md` under its owned target
directory with source identities, exact commands/counts, reports, remaining
failures and next task. Update canonical progress only after results settle;
do not copy the complete transcript. Compaction is a context transition, not
completion. After interruption: inspect dirty files, current pages, ledger and
the latest handoff; verify retained evidence inputs; resume the next runnable slice.

Do not spend model turns polling long fixtures or repeatedly retrying unavailable
credentials/hosts. Use finite scripts for waits. Continue independent work when
possible. A recurring external blocker must be reported with the unlock needed;
budget exhaustion and missing release authority cannot turn an unfinished Goal
into a completed release. New agents require current explicit authorization.

## Documentation quota and local navigation tools

Context7 retrieves current external documentation; Serena and CodeGraph retrieve
repository code. They complement each other. When Context7 reports quota failure,
record that boundary and use official version-matching documentation; avoid repeated
failed calls and do not silently replace documentation with model recollection.
The [Context7 usage reference](https://context7.com/docs/api-reference/usage/get-api-usage)
describes per-member free limits and the next-month UTC reset. A free account/key
can authenticate requests but does not remove an exhausted account's quota.
Keep keys out of source, argv and task packets; no paid plan is required here.

The inspected Shop launcher uses Serena's language-server backend and
`@colbymchenry/codegraph@1.4.1`, with lightweight search/callers/callees/impact tools.
Do not copy that launcher: it also sources Shop secrets and configures unrelated
services. Its referenced `docs/ai/mcp.md` is missing in the inspected checkout;
configuration presence establishes neither live connectivity nor useful coverage.

Owner-directed setup on 2026-10-10 enables
[Serena](https://github.com/oraios/serena) 1.5.3 for read-only Rust symbol/reference
navigation, [CodeGraph](https://github.com/colbymchenry/codegraph) 1.6.2 for local
call-path/impact queries, and the official OpenAI Docs MCP. Keep `rg` for simple
text/docs searches and use the navigation tool that fits the question; avoid
duplicate reconnaissance. Both consume local resources and model tokens.
No savings are established until a measured accepted-task comparison.

Pin evaluated inputs, exclude `target/`, vendor/generated files and private paths,
validate index freshness, and cap query output. Tool discovery, live queries and
result accuracy are separate checks. The project launchers now capture local
Codex/Claude usage snapshots and Serena/CodeGraph request timing/byte metadata,
without prompt/tool payloads or external telemetry export. See
[installation and telemetry](08-development-tooling.md#per-task-usage-measurement).
Restart existing sessions to load the new MCP catalog. Global client settings,
credentials, model/effort and speed remain unchanged.
