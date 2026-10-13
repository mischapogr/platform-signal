# Remaining work and model routing

Current routing snapshot: 2026-10-14. New-session defaults already use
Sol6.1/medium/Standard (Codex) and Sonnet/medium (Claude). Loading this plan does
not change the active model, speed, permissions or global settings.
[Historical plan](11-model-work-plan-history-20261010.md) preserves the earlier
phase rows and measurements; completed rows are not new implementation tasks.

## Next task and plan order

Read [current progress](07-progress.md), [release boundaries](21-release-readiness.md)
and the [52-item ledger](31-execution-ledger.json). Local SHARED-RUNTIME is
independently accepted at `b9c58da`; SHARED-METRICS-1 is resolved. Current source-
bound 919 default / 976 all-feature tests, both strict Clippy modes and actual
PostgreSQL/Standard/audit/private/restored5 campaigns pass. Exact review and
limits: `target/shared-runtime-refresh-20261012/INDEPENDENT-LOCAL-ACCEPTANCE.json`.

The actual owned local Kubernetes Standard profile now passes in141.13s,
including regular runtime/TLS Secret files, original WAL/PVC recovery and cleanup:
`target/standard-kubernetes-20261012/ACCEPTANCE.json`. Native CI wiring and checked
compiled-fixture bundle reuse pass locally in181.93s/170.05s:
`target/standard-kind-ci-20261012/ACCEPTANCE.json`. Run38246315239 at`27281e3`
now passes both complete native jobs and Standard cluster profiles107.40s/114.57s
with verified source/bundle/image/WAL/PVC bindings:
`target/standard-kind-ci-20261012/NATIVE-STANDARD-ACCEPTANCE.json`.
OBJECT-CUSTODY is now passed_simulated at its local boundary — 2026-10-14:
932default/993all-feature tests, both strict Clippy modes and12frozen gates.
Actual PostgreSQL TLS/S3/native identity/mTLS API/SDK passes13.56s; actual selected
Standard Main/SDK PUT-only hold, stopped-copy retention and fresh restart/release
passes38.34s with owned cleanup. [Contract51](51-object-custody.md), exact evidence:
`target/object-custody-api-20261012/ACCEPTANCE.json`. Provider retention is simulated.
STANDARD-RECOVERY is in progress. The37.90s actual server-local-loss guard
recovers the exact independent original, while missing enrolled WAL identity
correctly holds replacement startup. Complete stopped-WAL checkpoint recovery
now passes75.16s with17.47s replacement and fresh custody, corrupt backup refusal
and exact original bytes. Evidence:`target/standard-checkpoint-recovery-20261014/ACCEPTANCE.json`.
Next:consistent control-domain backup/restore, stale owners and production restore
authority. This4byte fixture preserves independent PostgreSQL/object domains.
Reuse prior original-WAL/current-authority/restore inputs only while they match.
Observe current native/public CI separately; no release qualification follows
from these local fixtures.
Preserve one replica/Recreate and explicit external configuration;
no runtime bootstrap, inferred custody, private policy or remote DELETE.
Corrected native/current image/CI, actual AWS/EKS, released dependencies and
owner-selected version/publication remain separate gates. Select one reviewable
slice at a time; reuse qualified evidence only while its inputs still match.

Respect ledger dependencies and original phase order. Core phases0–8 and bounded
Phase10 have local evidence. Phase7-B policy lives in the separate private
application. Phase9 AWS collection is post-MVP and needs a separately scoped task.
Do not turn external_pending or passed_simulated rows into local release claims.

## Task routing policy

| Task | Recommended new-session route | Escalation |
| --- | --- | --- |
| Settled mechanical edits, formatting, deterministic inventory | Luna/low or Haiku | Reproduced ambiguity or failed required check |
| Normal bounded implementation | Sol6.1/medium or Sonnet/medium | Reproduced unresolved failure after a focused correction |
| Durability, replay, cancellation, critical review | Sol/high | Stronger model only for concrete unresolved reasoning failure |

Keep Standard speed. Missing credentials, native hosts or release authority are
external boundaries, not reasons to increase reasoning effort. Record actual
model/effort separately from the recommendation. Existing sessions retain their
client-selected model; routing suggestions alone do not switch them.

## Execution discipline

Use one writer, focused review at acceptance, then settled documentation.
Delegate only when the current request explicitly authorizes parallel agents;
historical team authorization is not standing permission. Give each authorized
agent owned files, runnable acceptance and a stop condition. Avoid duplicate
repository reconnaissance and overlapping Cargo/fixture campaigns.

Use [task.py](../scripts/ai/task.py) and the [workflow](49-ai-execution-workflow.md)
for compact packets, source-bound review and serial campaigns. Regressions run
during implementation. Complete review/corrections and freeze source before the
full required acceptance gates. A writer review must be labelled as such and
cannot satisfy a contract requiring independent review.

Load only relevant contracts/ADRs and concise current state; consult the dated
archives for specific historical evidence. Preserve original reports and failed
attempts. Runtime waiting and bulk processing belong in finite scripts.

## Measurement and continuation

Capture per-task scoped usage before/after with [usage.py](../scripts/ai/usage.py),
actual model/effort, elapsed time and correction cycles. Cached input and reasoning
are subsets, not extra totals; local counters are neither invoices nor allowance.
Measure accepted outcomes before claiming cost savings. Context caching does not
justify indefinitely rereading historical logs.

For long runs, use an explicitly requested Codex Goal plus the bounded continuation
loop in [49](49-ai-execution-workflow.md). Checkpoint evidence and the next runnable
slice after each acceptance. A Goal never expands Git, publication, cloud or
private-environment authority. The owner authorized reviewed scoped commits and
pushes on2026-10-11; no version is selected and release publication remains held.

<details>
<summary>Historical heading links (compatibility index)</summary>

- <a id="shared-contract-accepted--2026-10-09"></a>[SHARED-CONTRACT accepted — 2026-10-09](11-model-work-plan-history-20261010.md#shared-contract-accepted--2026-10-09)
- <a id="small-pilot-accepted--2026-10-09"></a>[SMALL-PILOT accepted — 2026-10-09](11-model-work-plan-history-20261010.md#small-pilot-accepted--2026-10-09)
- <a id="security-audit-local-closeout--2026-10-09"></a>[SECURITY-AUDIT local closeout — 2026-10-09](11-model-work-plan-history-20261010.md#security-audit-local-closeout--2026-10-09)
- <a id="current-browser-readiness-and-native-ci--2026-10-09"></a>[Current browser readiness and native CI — 2026-10-09](11-model-work-plan-history-20261010.md#current-browser-readiness-and-native-ci--2026-10-09)
- <a id="current-audit-rotation-and-recovery-seam--2026-10-09"></a>[Current audit rotation and recovery seam — 2026-10-09](11-model-work-plan-history-20261010.md#current-audit-rotation-and-recovery-seam--2026-10-09)
- <a id="current-fixed-pipeline-diagnostics--2026-10-09"></a>[Current fixed pipeline diagnostics — 2026-10-09](11-model-work-plan-history-20261010.md#current-fixed-pipeline-diagnostics--2026-10-09)
- <a id="current-explicit-s3-kms-request-selection--2026-10-09"></a>[Current explicit S3 KMS request selection — 2026-10-09](11-model-work-plan-history-20261010.md#current-explicit-s3-kms-request-selection--2026-10-09)
- <a id="current-verified-identityaudit-composition--2026-10-09"></a>[Current verified identity/audit composition — 2026-10-09](11-model-work-plan-history-20261010.md#current-verified-identityaudit-composition--2026-10-09)
- <a id="current-restricted-receiver-file-access-proof--2026-10-09"></a>[Current restricted receiver file-access proof — 2026-10-09](11-model-work-plan-history-20261010.md#current-restricted-receiver-file-access-proof--2026-10-09)
- <a id="current-reusable-receiver-health-probe--2026-10-09"></a>[Current reusable receiver health probe — 2026-10-09](11-model-work-plan-history-20261010.md#current-reusable-receiver-health-probe--2026-10-09)
- <a id="current-automatic-target-diagnostic--2026-10-09"></a>[Current automatic target diagnostic — 2026-10-09](11-model-work-plan-history-20261010.md#current-automatic-target-diagnostic--2026-10-09)
- <a id="current-independent-receiver-composition--2026-10-09"></a>[Current independent receiver composition — 2026-10-09](11-model-work-plan-history-20261010.md#current-independent-receiver-composition--2026-10-09)
- <a id="current-independent-receiver-host--2026-10-09"></a>[Current independent receiver host — 2026-10-09](11-model-work-plan-history-20261010.md#current-independent-receiver-host--2026-10-09)
- <a id="current-independent-http-transport--2026-10-09"></a>[Current independent HTTP transport — 2026-10-09](11-model-work-plan-history-20261010.md#current-independent-http-transport--2026-10-09)
- <a id="current-independent-receipt-store--2026-10-09"></a>[Current independent receipt store — 2026-10-09](11-model-work-plan-history-20261010.md#current-independent-receipt-store--2026-10-09)
- <a id="current-startup-activation-slice--2026-10-09"></a>[Current startup activation slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-startup-activation-slice--2026-10-09)
- <a id="current-rules-revision-primitive--2026-10-09"></a>[Current rules revision primitive — 2026-10-09](11-model-work-plan-history-20261010.md#current-rules-revision-primitive--2026-10-09)
- <a id="current-native-ingest-audit-slice--2026-10-09"></a>[Current native ingest audit slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-native-ingest-audit-slice--2026-10-09)
- <a id="current-native-ci-diagnostic-slice--2026-10-09"></a>[Current native CI diagnostic slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-native-ci-diagnostic-slice--2026-10-09)
- <a id="current-native-coverage-audit-slice--2026-10-09"></a>[Current native coverage audit slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-native-coverage-audit-slice--2026-10-09)
- <a id="current-native-findings-audit-slice--2026-10-09"></a>[Current native findings audit slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-native-findings-audit-slice--2026-10-09)
- <a id="current-native-audit-query-slice--2026-10-09"></a>[Current native audit query slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-native-audit-query-slice--2026-10-09)
- <a id="ext-ci-reported-idp-failure-stages--2026-10-09"></a>[EXT-CI reported IdP failure stages — 2026-10-09](11-model-work-plan-history-20261010.md#ext-ci-reported-idp-failure-stages--2026-10-09)
- <a id="ext-ci-legacy-candidate-fixture-correction--2026-10-09"></a>[EXT-CI legacy candidate fixture correction — 2026-10-09](11-model-work-plan-history-20261010.md#ext-ci-legacy-candidate-fixture-correction--2026-10-09)
- <a id="current-security-audit-outbox-slice--2026-10-09"></a>[Current SECURITY-AUDIT outbox slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-security-audit-outbox-slice--2026-10-09)
- <a id="current-ext-ci-diagnostic-slice--2026-10-09"></a>[Current EXT-CI diagnostic slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-ext-ci-diagnostic-slice--2026-10-09)
- <a id="current-security-audit-destination-slice--2026-10-09"></a>[Current SECURITY-AUDIT destination slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-security-audit-destination-slice--2026-10-09)
- <a id="current-security-audit-slice--2026-10-09"></a>[Current SECURITY-AUDIT slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-security-audit-slice--2026-10-09)
- <a id="current-security-transport-slice--2026-10-09"></a>[Current SECURITY-TRANSPORT slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-security-transport-slice--2026-10-09)
- <a id="current-security-access-slice--2026-10-09"></a>[Current SECURITY-ACCESS slice — 2026-10-09](11-model-work-plan-history-20261010.md#current-security-access-slice--2026-10-09)
- <a id="persistent-execution-goal--2026-10-07"></a>[Persistent execution Goal — 2026-10-07](11-model-work-plan-history-20261010.md#persistent-execution-goal--2026-10-07)
- <a id="mvp-execution-priority--2026-10-07"></a>[MVP execution priority — 2026-10-07](11-model-work-plan-history-20261010.md#mvp-execution-priority--2026-10-07)
- <a id="security-requirements-tasks--2026-10-07"></a>[Security requirements tasks — 2026-10-07](11-model-work-plan-history-20261010.md#security-requirements-tasks--2026-10-07)
- <a id="objective-and-billing-basis"></a>[Objective and billing basis](11-model-work-plan-history-20261010.md#objective-and-billing-basis)
- <a id="available-model-evidence"></a>[Available model evidence](11-model-work-plan-history-20261010.md#available-model-evidence)
- <a id="api-and-credit-comparisons"></a>[API and credit comparisons](11-model-work-plan-history-20261010.md#api-and-credit-comparisons)
- <a id="remaining-tasks-in-order"></a>[Remaining tasks in order](11-model-work-plan-history-20261010.md#remaining-tasks-in-order)
- <a id="phase-3--parquet-and-durable-consumption"></a>[Phase 3 — Parquet and durable consumption](11-model-work-plan-history-20261010.md#phase-3--parquet-and-durable-consumption)
- <a id="phase-4--url-query-and-datafusion"></a>[Phase 4 — URL query and DataFusion](11-model-work-plan-history-20261010.md#phase-4--url-query-and-datafusion)
- <a id="phase-5--rules-findings-and-the-usable-core-slice"></a>[Phase 5 — Rules, findings and the usable core slice](11-model-work-plan-history-20261010.md#phase-5--rules-findings-and-the-usable-core-slice)
- <a id="phase-6--agent"></a>[Phase 6 — Agent](11-model-work-plan-history-20261010.md#phase-6--agent)
- <a id="phase-7--extension-hooks-and-external-overlay"></a>[Phase 7 — Extension hooks and external overlay](11-model-work-plan-history-20261010.md#phase-7--extension-hooks-and-external-overlay)
- <a id="phase-8--packaging-and-qualification"></a>[Phase 8 — Packaging and qualification](11-model-work-plan-history-20261010.md#phase-8--packaging-and-qualification)
- <a id="phase-10--hardening-and-release-evidence"></a>[Phase 10 — Hardening and release evidence](11-model-work-plan-history-20261010.md#phase-10--hardening-and-release-evidence)
- <a id="invocation-examples-and-execution-discipline"></a>[Invocation examples and execution discipline](11-model-work-plan-history-20261010.md#invocation-examples-and-execution-discipline)

</details>
