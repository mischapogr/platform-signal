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

## Selected conditional reclamation contract

Reclamation is an explicit trusted stopped-host capability. It requires the
actual Small source owner, no emitted query materialization/physical readers,
a fresh stream-bound WAL checkpoint at/above the synced retirement floor, and
fresh chain/inventory recovery under the original operation deadline. Candidate
references are derived from that current committed retired prefix, never from
caller-provided plans. Validate every candidate before the first removal.
Manifest history, live query data, unknown-age orphans and protected originals
stay outside the operation. Query policy never enables raw evidence deletion.

Only explicit immutable version IDs and exact non-wildcard ETags may dispatch.
Null/unversioned references fail closed; there is no path-only delete fallback.
The selected S3 adapter signs an empty `DELETE` with both `versionId` and
`If-Match`, under the existing fixed physical I/O worker and request scope.
Deletion is separately enabled for that adapter; normal ingest/query transports
continue refusing DELETE. The transport rejects namespace/condition/header
substitution, redirects and retention-bypass requests. No automatic retry or
additional connection task/pool is introduced.

AWS documents explicit version removal and conditional ETag matching in
[DeleteObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html).
Version permissions, Object Lock and retention denial are independent runtime
facts; the adapter supplies no governance bypass or MFA-delete override. Actual
AWS behavior remains an external qualification gate. Context7 was over quota;
the pinned object_store0.13.2 source and current primary AWS contract were read.

Every retired pin receives an exact version read, including keys absent from
current inventory (a delete marker can hide older versions). Only exact-version
NotFound counts absence; every other failure stays denied/uncertain. Present bytes
are authenticated before their exact conditional removal.
Timeout/cancellation/lost reply is an uncertain effect, with no successful partial
report or checkpoint change. Retry recomputes authenticated current reachability;
missing retired versions are recoverable, while missing live data remains corrupt.
Success records finite acknowledged/observed-absent counts and byte totals, not
source ACK, raw custody, coverage completeness or a distributed fencing epoch.
Permission/hold denial and stale/replaced versions preserve controls and fail
closed. Local simulation must exercise replacement, duplicates, denial,
crash/replay and lost replies before accepting destructive query reclamation.

## Accepted exact conditional reclamation slice

Strict default659/all-feature710, source review, bounded native wire and actual
child SIGKILL before/after deletion effect qualify the explicit Small mechanism.
Conflicting duplicate integrity headers fail closed. Full-chain tests retain live
files, manifest history, protected originals, unknown-age orphans and control bytes.
Native wire objects are RAM-backed; Small control files are real. Fifteen current-
binary persistent S3/monolith scenarios also pass. Evidence is retained under
`target/goal-execution-20261007/RETENTION/reclamation-validation-final/`,
`reclamation-review.json` and `reclamation-server-simulation/report.json`.
This does not qualify actual AWS conditional/version/Object Lock behavior, raw
custody, Standard fencing, remote CI/native/kind, a fresh image or release.
RETENTION remains in_progress for representative query/cache measurements.

## Parent acceptance and measured query decision

RETENTION is passed_simulated. The complete source-bound workload checks2,048
synthetic events/8hours/16 committed batches,33 query samples and four helper
failure regressions. Exact oracle IDs/messages/nested attributes, stable warm file
identity/mtime/hash, empty-cache rebuild, no-data-read413 preflight and immutable
source/checkpoint preservation pass. Prior strict Rust659/710 inputs are unchanged.

Warm hourly queries select/download2 data objects, versus16 for broad and typed/
JSON predicate queries. Median local debug wall times are501.187ms hourly and
2,937.896ms broad. Every selected query reauthenticates pinned remote bytes; cache
reuse is not a remote-GET saving. Encoded Parquet data totals17,390,662bytes under
this synthetic payload/schema/compression setting; this is no universal ratio.
The5-second normal server deadline is separate from file/decoded/operator budgets.
The workload report records bounds/bytes/identities, not physical I/O or AWS TCO.

Keep whole canonical v1 responses, existing partition/column projections and
predicate pushdown. Defer optional field indexes because the measurement does not
establish benefit. Preserve manifest authentication history within finite caps;
exhaustion holds progress. Independent raw evidence policy and expired storage
class restoration remain distinct. Actual cloud/native/HA/custody/release checks
stay external/later gates. Evidence: `target/goal-execution-20261007/RETENTION/query-measurements-final/report.json`
and `measurements-acceptance.json`.
