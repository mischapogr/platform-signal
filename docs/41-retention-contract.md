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

## Stopped derived-cache maintenance

The selected next slice exposes a synchronous maintenance primitive for an
ordinary host worker or stopped operator process. It requires a pre-existing
exact stream/backend binding and exclusive cache Small lock; it never creates a
new cleanup root. Full finite directory validation precedes the first unlink.
Maintenance requires only the existing `.lock` and `binding.json` controls;
temporary/head/genesis/unknown controls are rejected and preserved before general
owner opening could recover them. It never initializes a missing lock.
Only validated SHA-named derived `.parquet`/`.tmp` files in `objects/` are removed.
Each unlink and the final directory sync precede successful completion. Controls,
remote query objects and protected originals remain outside this operation.

Publisher state retains derived ownership for the source lifetime, including
fixed physical query jobs holding that source. Explicit publisher shutdown or
query cancellation cannot free the cache lock while those reads survive. Hosts
must drop stopped query/source handles before pruning or reopening a derived
owner. This is intentionally conservative, with no active eviction or new pool.

Failure/cancellation can leave an uncertain partially pruned derived cache.
Retry only after revalidating the existing binding, complete layout and exclusive
ownership, then rebuild from authenticated source objects. No pruning result
is source ACK, custody, query-retirement permission or distributed fencing.
Actual crash/reopen, quota/rebuild, permission/cancellation, foreign/link rejection
and retained physical-reader tests are required before accepting this slice.

## Accepted stopped-cache slice

Strict default651/all-feature696, focused127, source review, actual SIGKILL/reopen,
non-root permission denial, controls-preservation and surviving physical-reader
regressions pass. Eleven current-binary persistent S3/monolith scenarios also pass.
Evidence: `target/goal-execution-20261007/RETENTION/cache-validation/validation.json`,
`cache-review.json` and `cache-server-simulation-final/report.json`. This does not
retire remote query objects or qualify real cloud/native/HA/custody/release gates.
Parent remains in_progress for retirement/reclamation and measurements.
