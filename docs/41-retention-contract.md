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

## Selected Small query-retirement protocol

The next slice commits a logical horizon before any remote deletion is enabled.
Only a prefix of complete committed batches may retire: every UTC hour must end
before the validated query cutoff, and the last sequence must be at/below a fresh
exclusive WAL checkpoint supplied by the trusted stopped host. A batch with a
retained partition stops prefix retirement; unknown-age orphans remain held.
Retirement uses a fresh publisher that has emitted no materialized query files,
plus exclusive existing cache ownership when a cache exists. Live/physical source
owners block that acquisition independently of a successor’s cache configuration.
Explicit shutdown closes operations but stopped publisher handles retain source
ownership; hosts must drop those handles before opening a successor. The typed
checkpoint carries the WAL stream identity and is a trusted host report, not
proof of exclusivity. A `drop_oldest` WAL checkpoint may exceed store high-water;
only authenticated committed anchors at or below it retire. No HTTP producer can
request this operation.

Version1 control binds stream/backend, exact retired anchor/predecessor, policy,
cutoff and checkpoint. A synced temporary record is atomically published and the
control directory synced. Recovery validates complete controls, monotonic
predecessors and the exact anchor in the authenticated committed chain before
promoting a pending control or omitting retired data from queries. General owner
opening only reads retirement controls; it never promotes/removes a pending record.
Failed authentication preserves both current and candidate bytes. Existing manifests remain authentication
history. Unknown/truncated/mismatched controls fail closed. Supported server
startup rejects a WAL checkpoint below the retired floor. Historical replay at
or below that floor is explicitly rejected, rather than presumed persisted.

This first protocol slice grants no deletion capability. A later exact conditional
removal seam must preserve pinned identities, permissions/locks and uncertain
retry semantics; generic path-only delete cannot substitute for it. Old query
objects and protected originals remain physically held during this slice. A
retirement policy increase does not recover expired bytes; consistent restore and
Standard fencing remain separate ledger contracts. Parent stays in_progress.

## Accepted logical-retirement slice

Strict default658/all-feature703, seven retirement parent regressions, actual
SIGKILL at three control milestones, focused source review and fifteen current-
binary S3/monolith scenarios pass. The real-server retirement control is explicitly
synthetic; genuine synced WAL witnesses isolate the new rollback-floor guard from
older frontier checks. Exact finding maps, source/snapshot/physical reader owners,
current/pending controls and eight remote objects are preserved. Both native CI
runners invoke the extended simulation, without claiming remote execution.
Evidence: `target/goal-execution-20261007/RETENTION/retirement-validation-final/validation.json`,
`retirement-review.json` and `retirement-server-simulation-final/report.json`.
This grants no deletion/custody/fencing capability or external/release acceptance.
The parent remains in_progress for conditional reclamation and measurements.
