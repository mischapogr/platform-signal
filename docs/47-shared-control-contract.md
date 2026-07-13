# Standard shared-control contract, revision 1

This freezes `SHARED-CONTRACT`, the planned Standard control backend. It does not
implement or enable shared runtime, replicas or HA. Small continues using its
existing local state. The [machine-readable contract](../schemas/shared-control/v1.json)
and [administrative schema migration](../schemas/shared-control/001.sql) are the
inputs for the next `SHARED-RUNTIME` task. They introduce no runtime dependency,
service split, company policy, new query language or replica configuration.

Use PostgreSQL17 or newer, one control database per trusted store. Cached local
PostgreSQL17.5 can validate schema syntax; production version/patch selection and
managed-database availability remain external qualification. Context7 was
requested but its monthly quota was exhausted; official version17 documentation
was used for the locking, isolation and constraint semantics below.

## Authority and schema

The host chooses the store ID, tenant, stream, partition, trusted policy and
object backend. Producer fields never grant any of them. Every mutation has a
complete token `(store_id, generation, tenant, stream, partition_id, owner, epoch)`.
Owner is a fresh process-start UUID, not a reusable hostname. Generation changes
only in an explicit coordinated restore; epochs increase on each acquisition,
including reacquisition by the same process. BIGINT exhaustion fails closed;
never cast arbitrary u64 sequence/epoch values into signed database values.

| Table | Bounded authoritative state |
| --- | --- |
| `store` | Singleton identity/generation/revision/checksum/ready flag, global feed position/digest and exact logical capacity counters |
| `partitions` | Trusted tenant/stream/kind, fenced owner/epoch/database-clock expiry, committed sequence and last global finding position |
| `commits` | Immutable request ID/hash, exact sequence range, previous manifest, pinned manifest/rule/normalizer revisions |
| `receipts` | Complete protected receipt/evidence reference and hash, prepared count, verified prefix, explicit source ACK state |
| `state` | Bounded detector/configuration state with exact revision and trusted key |
| `findings` | Immutable exact first-occurrence finding bytes/hash, originating commit and globally unique finding ID/feed position/digest |
| `outbox` | Immutable generic work/plan bytes/hash and delivery ID, durable attempts/status and fencing token |
| `snapshots` | Finite committed manifest pins with fixed database-clock expiry |
| `tombstones` | Irrevocable exact-version retirement intent; initial runtime cannot delete remote objects |

The database contains workflow/catalog metadata, not raw log bodies or every
normalized field. A receipt reference names protected externally retained original
bytes and complete prepared receipt; custody verification is still independent.
Private routes, account mappings, rule content, dispositions and alert destination
policy stay in private adapters. Generic opaque work plans may contain authorized
private references in a private deployment; credentials never enter serialized
plans, SQL, diagnostics or object names. The OSS repository stores no such policy.

The initial feed uses existing version1 `FindingsCursor`: `store_id` is the fixed
feed stream, and `store.feed_position` allocates globally increasing positions in
the commit transaction. Per-partition positions must not impersonate one global
cursor. Existing global-read authority remains mandatory; no new scoped feed
claim is inferred. Findings preserve their existing deterministic identity and
actual evidence references. Persist the exact first-occurrence payload bytes,
`FindingsCursor::advance` digest for each position, and global head digest; never
hash reserialized JSON. Exact duplicate finding IDs with identical content reuse
the original position/obligation; conflicting content fails the entire transaction
before any checkpoint advance. Reads verify the exact historical prefix digest.
Revision1 performs no feed pruning: exhausting its finite history budget fails
closed, preserving the complete cursor chain. Supporting pruning later requires
an explicit retained anchor and consumer recovery contract; it cannot silently
bootstrap `after=begin` at a newer tail. Restart never creates a new stream or
resets position. Restore must preserve the exact chain and reconcile every
supported dependent outbox cursor before readiness; old or ahead-of-backup cursors
cannot be implicitly moved to the restored tail.

## Transactions and fencing

Use a bounded pool (4 connections), bounded admission queue (32 commands) and
original operation deadline. No fallback database or in-memory authority exists.
Ordinary mutations use READ COMMITTED with explicit row locks and fixed lock
order: store identity/capacity row, partition row, then child rows in canonical
key order. This is an engineering choice requiring concurrent runtime tests;
PostgreSQL row locks persist through transaction end and conflicting writers wait.
[PostgreSQL row locks](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS).

Acquisition locks the rows, checks exact store/generation/scope and expiry using
`clock_timestamp()`, increments epoch with checked arithmetic, then records the
new owner/lease. Renew only a matching unexpired token; an expired owner must
acquire a new epoch. A DB restart or lost connection does not renew a lease.
Initial lease15s, maximum60s; no caller-provided wall clock authorizes a mutation.
A worker stalled inside a transaction holds a lock, not everlasting ownership:
lock budget500ms, transaction budget2s, operation budget5s. Configure server-side
statement/lock/idle-transaction limits and caller timeout/cancellation. Cancellation
must retire the connection until rollback is confirmed; do not return it to the
pool while an uncertain transaction can still mutate. Late replies cannot grant
new work after the original deadline.

1. Admit bounded prepared work; retain the complete protected original/receipt
   independently according to source policy. Existing Small HTTP202 still means
   synced local WAL admission. That response alone cannot claim Standard RPO0.
2. Outside a database transaction, upload immutable unique object/version bytes
   and verify exact hashes, sizes, schemas, sequence bounds and source references.
   Never mutate or reuse an existing content identity with different bytes.
3. Begin the bounded transaction, take locks in order and recheck the complete
   token, ready state and unexpired database-clock lease. Recheck eligibility at
   the final publication statement under the same row locks; no takeover can
   linearize before that transaction ends. Validate the previous
   committed head and contiguous sequence range. Reject foreign scopes and
   conflicts before disclosing row content.
4. Resolve existing request ID only if its full request hash and every immutable
   input match. Otherwise reserve exact bounded metadata rows/bytes and commit
   manifest/head, checkpoint, revision-pinned state, findings/feed positions,
   generic notification obligations and receipt verified progress together.
5. A committed transaction is the Standard publication milestone. Object existence
   and a successful upload are insufficient. A lost commit reply remains uncertain:
   reread the exact request under current trusted authority, prove all stored pins
   and resolve once; never skip to a new request or source ACK on an empty result.

A separate bounded `record_receipt` transaction stores retained reference,
original disposition/normalizer/custody pins and capacity under the current fence.
It supports valid all-quarantined receipts with zero prepared events. A retained
receipt may have no event commit yet; after prepared-event admission its commit
must exist. Zero-prepared terminal receipts remain metadata-only: no fake manifest,
event sequence, finding, feed or pipeline checkpoint is created. They require
explicit quarantine/disposition and source-policy authorization plus current
independent custody for any source ACK; an empty prepared prefix alone grants none.
Source record count and prepared count are distinct, bounded0..4096 fields.

Control commit does not prove a fresh protected-custody witness or source
collection coverage. Source ACK follows the existing explicit state machine with
fresh custody, opaque current source handles and an established M2 policy. A
Standard durable-admission response must explicitly represent object-backed
custody and control commit; enabling replicas while reporting local-only WAL
admission as durable is prohibited. Server wiring/qualification remains later.

Notifications initially use the current pipeline owner's complete fence. Claim
and intent commit before network I/O; finish requires the same generation, owner,
epoch and unique attempt ID. A stale completion cannot mutate status. Interrupted
intents become uncertain, and retry preserves the exact original delivery key and
payload. Delivery is at least once: an already in-flight remote effect cannot be
rolled back or reliably revoked by a DB lease. Destination idempotency remains
required; there is no exactly-once or universal no-stale-network-effect promise.

Queries pin committed manifest references using a bounded repeatable-read
transaction, then release the DB transaction before object I/O. A supported pin
expires at a fixed DB-clock deadline; no result may outlive it. Shared reads do
not infer producer-authorized tenant identity. Read either one consistent pinned
snapshot or a clear bounded failure, never partial success or empty success on
missing objects. PostgreSQL repeatable-read keeps the transaction snapshot stable;
serialization/deadlock errors require bounded whole-operation retry, never
extending the original deadline.
[PostgreSQL isolation](https://www.postgresql.org/docs/17/transaction-iso.html).

## Capacity, retirement and permissions

`v1.json` defines finite initial budgets. Maximum request/reply1MiB,128partitions,
65,536logical metadata rows/64MiB; each commit has at most4,096records,
128findings/state changes/deliveries. Manifest256KiB, individual state/finding/
plan/receipt reference64KiB; at most128snapshot objects within5s;10notification
attempts,3transaction retry rounds. These are configurable engineering bounds,
not measured Standard throughput or physical database size guarantees. SQL hard
bounds are ceilings; runtime configuration may be tighter.

Each transaction computes conservative logical byte/row charges, including
indexes/row framing estimates, before mutation and adjusts the store counters
atomically. Release charges only when corresponding supported state is retired.
Bound source inventory, batch buffers, decoding, pool waiters, object I/O and
result serialization independently. Oversize/quota failure rejects the whole
transaction without cursor advancement or partially accepted findings/plans.
Expose queue depth/capacity, rejection, stale fence, transaction timeout, orphan,
lease, snapshot expiry and notification uncertainty metrics without private IDs.

Only committed objects reachable from supported current/reader/restore/replay
snapshots can be served. Retirement uses a current owner transaction, checks pins
and replay/evidence retention, and records a permanent exact-version tombstone.
Tombstone identity is a canonical backend ID, object key and exact version tuple,
with a globally unique digest; partition-local aliases cannot evade retirement.
A tombstoned version may never be republished in any partition. Compaction uploads new immutable
objects and commits a replacement snapshot under the same fence; uncommitted
orphan inventory is bounded. Initial shared runtime performs no remote deletion.
A database lease check cannot fence an S3 request already in flight. Actual
provider deletion requires a separately qualified irreversible-ticket mechanism
and version/retention/Object Lock permissions, not a claim of cross-system atomicity.

The DDL revokes PUBLIC privileges. A dedicated administrative migrator owns
schema/initialization/restore. Runtime credentials receive only reviewed function
execution and bounded authorized read interfaces, with no direct DML, DDL,
TRUNCATE, ownership or schema-creation privilege. The schema file alone does not
install those runtime functions or prove authorization; that is SHARED-RUNTIME.
Plain CHECK constraints do not replace transaction/fence/capacity logic. Composite
foreign keys prevent a receipt/finding from naming another partition's commit;
application predicates still enforce trusted scope and opaque payload semantics.
[PostgreSQL constraints](https://www.postgresql.org/docs/17/ddl-constraints.html).

## Migration and coordinated restore

Initialization is explicit and only into an empty owned schema. Store identity,
generation, revision and exact migration SHA256 must match on every open. Unknown,
newer, corrupt or partially applied schema refuses readiness without reset,
recreation, auto-migration or implicit downgrade. Administrative migration locks
writers, validates checksum/order, runs one bounded transactional migration and
records the revision after complete success. Keep stable receipts, request IDs,
rule/normalizer pins, findings positions and delivery payload/key across upgrades.
No future migration is accepted merely because revision1 syntax loads.

Restore requires stopped writers and current independently delivered authority;
a restored database must not authenticate itself as current because its old data
is internally consistent. Freeze commits/retirement and take a coherent database
checkpoint plus exact reachable object versions/hashes, protected evidence
retention, source cursors, detector/rule revisions and notification states. Copy
only supported stopped backup state, validate every reference and record provenance.
Database backup and object backup alone are each insufficient.

Restore into a fresh controlled environment with readiness false. Independently
approve the restore checkpoint, assign a fresh generation, revoke all leases and
attempt authority through the generation barrier, retain historical attempt IDs,
owner/epoch/generation and outcome evidence, keep previously attempted notifications
uncertain, and verify
current custody/credentials. Reject every old-generation handle even if a restored
epoch value was rolled back. Retain epoch counters; monotonicity is within a
generation, not a claim that a DB backup alone remembers all later epochs. Do not
reconstruct lost security policy or auto-redetect historical events after losing
exact revisions. Missing/corrupt versions, unsupported schema or absent current
authority keep readiness false and source progress unchanged.

## Finite acceptance and next work

The contract's18 failure cases define observable no-mutation/orphan/uncertainty/
readiness outcomes. `check-shared-contract.py` checks schema checksum, field/operation
coverage, bounds and restore/fencing obligations. Its unit regressions reject
invalid contract mutations. These are contract checks, not executable concurrency,
durability, shared custody, availability or Standard runtime qualification.

`SHARED-RUNTIME` must demonstrate real PostgreSQL concurrent acquisitions,
expiry/takeover, stale commit/renew/notification rejection, before/after-commit
crashes and lost replies, atomic publication/checkpoint/state/findings/outbox,
foreign-scope denial, exact quota rollback, pool/transaction cancellation, startup
schema failure, persistent restart and coordinated restore. Object query/reader
retirement and private notification integration must preserve their existing
contracts. A real multi-process/local Kubernetes Standard profile comes after
that runtime evidence. No replica increase follows contract acceptance alone.
