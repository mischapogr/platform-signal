# Bounded retention, reachability and query acceleration

Status: RETENTION in_progress, frozen ledger capability. No new service, index
backend, private policy or default retention duration is introduced.

Raw originals, normalized query objects, indexes and materialized copies have
separate lifetimes. Host-supplied version1 policy must validate supported WAL
replay, evidence-reference and reader horizons against configured retention.
Object Lock/holds are independent facts; a shorter requested duration does not
authorize deleting a locked version. Product day ranges remain examples.

The first slice is a finite policy validator and read-only reachability report
from a publisher-authenticated committed snapshot. It reports the exact query
namespace/version identities and conservative blockers. A committed manifest is
still needed to authenticate the chain. Old query data cannot be deleted merely
because its UTC partition expired: the current manifest chain and supported WAL
replay still reference it. Eligible age/checkpoint candidates require a separate
synced retirement transaction before destructive reclamation. Unreferenced data
has no trustworthy creation age in the current reference model; it remains held,
including byte-identical orphans available for unfinished WAL replay.

The read-only report is advisory, never a deletion capability, original-evidence
custody, source ACK, owner epoch or proof that a caller-supplied checkpoint is
current. It keeps exact pinned versions and rejects foreign namespaces, duplicate
references, overflow and report budget exhaustion. Resource/time checks precede
output copies. No automatic retention/sampling is enabled on protected sources.

Remaining slices inside the same item must establish reader quiescence and a
checkpoint-bound synced retirement horizon before any query reclamation; restart,
crash, stale-plan/version and permissions failure must preserve recoverability.
Derived cache pruning must retain active physical readers and permit bounded
rebuild, including quota recovery. Standard distributed retirement is fenced by
the later shared-runtime contract, not by Small's local lock. Private raw evidence
holds/reference policy stays in its overlay and is unaffected by query-cache policy.

Keep partition/projection pruning and finite decoded scan budgets. Measure a
representative selected/unindexed query before deciding on an optional field
index. A measured no-index decision is acceptable; a speculative custom index
is not required. RETENTION passes only after applicable policy, reclamation,
cache/rebuild, simulation and measurement acceptance, with protected originals
untouched and external qualification separate.

## Accepted policy/report slice

Three actual regressions and strict default644/all-feature689 (storage79/88)
pass, with focused source review. Empty/header and prospective dedup budgets are
checked before output/allocation, and temporary dedup state drops before owned
output copies. Evidence is `target/goal-execution-20261007/RETENTION/policy-validation/validation.json`
and `policy-review.json`. This is advisory local mechanism proof, with no
reclamation, custody or real-environment qualification. Parent remains in_progress.
