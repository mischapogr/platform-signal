# Shared-control runtime implementation

Status: **in progress** under frozen ledger item SHARED-RUNTIME. The accepted
[transaction contract](47-shared-control-contract.md) remains authoritative.
The `signal-control` library is a generic mechanism. The server-owned publication
component now composes it, with explicit startup authority/WAL binding. Main
startup/global findings/private-consumer integration remains unfinished;
no replicas or shared readiness are enabled. Public/private
policy and monolith deployment boundaries remain unchanged.

## Lease foundation

The compiled client binds every mutation to the exact `001.sql` schema and
`002-functions.sql` routines SHA256. Installation and trusted partition/principal
configuration are explicit administrator operations, never startup migrations.
A dedicated non-login schema owner owns the restricted routines. Runtime roles
receive schema USAGE and only safe operation EXECUTE; table DML and helper
EXECUTE remain denied. `session_user`, trusted scope and current store generation
are checked before disclosing partition authority.

Four owned workers admit at most32 queued commands. Queue depth, active capacity,
rejections and quarantined seats are observable without private identifiers.
Credentials and trust roots are captured explicitly with bounded allocations;
production TLS verifies host identity and CA. Plaintext requires explicit numeric
loopback fixture selection and is never a TLS fallback. Construction starts
bounded workers; it grants no readiness or verified backend authority.

A context has an immutable original deadline of at most5s. Transactions have a
separate2s limit, statements2s, locks500ms and idle transactions2s. Lease acquisition
increments the epoch under fixed store/partition row locks; renewal requires the
current owner, generation, epoch and database-clock expiry at its final UPDATE.
Lease durations are15–60s. Buffered replies are checked at consumption; a late
COMMIT reply cannot extend either deadline.

Cancellation after admission reports uncertainty rather than proving no mutation.
The worker sends ROLLBACK on the same live driver behind any pending query and
retains its seat until acknowledgement. If rollback cannot be confirmed, the
connection retires and its worker stays quarantined without consuming new work.
Shutdown drains queued work, honors cancellation and preserves unfinished join
handles across retries. Unconfirmed retirement stays visible as uncertainty;
a stopped client cannot be reused. COMMIT uncertainty survives a later successful
ROLLBACK because that response cannot undo an earlier committed transaction.

## Atomic publication and receipt primitives — 2026-10-10

`record_receipt` stores bounded exact reference/request bytes and distinct source
and prepared counts under the current partition fence. A zero-prepared receipt
uses metadata only and advances no event checkpoint or findings cursor. This
primitive grants no source ACK or protected-custody authority.

`publish` verifies a contiguous range and previous committed manifest under fixed
store/partition locks, reserves exact logical capacity and atomically writes the
manifest/head/checkpoint, revision-pinned state, exact finding bytes/global cursor,
immutable work obligations and receipt prefixes. Final database-clock eligibility
is checked after the child writes, before publication. Expiry, conflicts and row
or byte exhaustion roll back the entire transaction. Rule-state revision changes
fail closed until an explicit compatible migration exists.

Finding identity is global within the trusted store. Byte-identical duplicates
reuse the original position and obligation; conflicting payloads or work pins
reject the transaction. The SQL cursor matches the existing version1 Rust cursor,
including original payload bytes and byte lengths. History is finite and is not
pruned. Logical byte counters include retained requests, payloads and fixed row
charges; they are not a measurement of physical PostgreSQL storage.

Exact request replay returns the original committed cursor even after later
publications. `resolve_publication` requires current trusted generation, scope,
owner, epoch and lease; it validates retained immutable request/manifest/finding/
work/receipt pins. An absent request remains uncertain and creates no new commit.
A delayed COMMIT reply remains uncertain even after ROLLBACK succeeds; resolving
the same request proves its eventual outcome without publishing another request.

Inputs retain the compiled ceilings: request1MiB, manifest256KiB, individual
state/finding/work/reference64KiB,128child changes and4,096prepared records.
Versioned public types and the restricted SQL boundary reject malformed input.
These APIs reuse the existing four-worker/32-command queue and original timeout,
cancellation, rollback-confirmation and quarantine behavior.

Object uploads and exact object/version/custody verification remain external
preconditions. The fixture uses synthetic manifest references and performs no
object upload. Read and retirement primitives are implemented in the bounded slices below.
Publication and reads reject exact tombstoned versions; unrelated versions remain
usable. Remote DELETE stays disabled.
The publication qualification used a fresh `002-functions.sql` installation.
Earlier lease/publication/snapshot bundle checksums have no implicit upgrade path.
The administrative section below qualifies only the exact later notification
bundle as a populated migration source. Frozen `001.sql` remains byte-identical.

## Bounded committed-manifest snapshots — 2026-10-10

`read_snapshot` requires trusted scope/current generation, without requiring a
pipeline owner's lease. It pins explicit committed IDs in caller order in a
repeatable-read transaction, checks retained manifest/request hashes, returns
original manifest bytes and commits before any object I/O. Missing references,
foreign scope, corrupt state or capacity failures reject the complete operation.
The limit is128manifests and128object references (including predecessor objects),
with a1MiB reply and fixed1–5,000ms database-clock pin. This is a library primitive;
query/server object reading and shared readiness remain unwired.

`SnapshotPin` is not serializable. Its monotonic deadline conservatively anchors
the database's remaining duration before queue/connection admission; callers
check it before object access and before returning query results. Retrying the
same ID requires the exact ordered IDs and lifetime and never updates DB expiry.
Expired IDs remain permanent finite metadata markers, preventing recreation from
renewing a prior request. A new pin compacts at most128expired authorized manifest
lists; only their payload byte charges are released. Marker rows and320-byte
framing remain charged. Row exhaustion fails closed; this slice does not promise
indefinite query admission or prune historical identity.

Serialization/deadlock failures retry the whole operation only after confirmed
rollback, at most three rounds, retaining the original context and one2s budget
including connections. Exhaustion returns a clear retryable failure. Cancellation,
COMMIT uncertainty and unconfirmed rollback never enter that retry loop; their
existing uncertainty/quarantine behavior remains. Metrics count API-observed
snapshot expiry and actual retries without private IDs. Reading bytes from a
previously returned slice does not itself enforce expiry: the eventual query
adapter must perform the documented checks around its object/result transitions.

Snapshot qualification used an explicit fresh-schema installation. The later
administrative slice below defines its sole supported populated source. Restricted
runtime roles receive only the bounded read function;
helpers/table DML remain denied. No remote object DELETE is enabled.

Owned PostgreSQL 17.5/AMD64 qualification proves exact bytes/order/replay, fixed DB
expiry, compacted identity non-renewal, exact counters, scope/generation denial,
reads without a live owner lease, missing/corrupt manifests, row/byte/object/reply
limits, required isolation, actual concurrent-update recovery and exactly three
aborted retry rounds with complete rollback. The reviewed focused fixture passed
in20.06s/33commands with unchanged source and clean owned cleanup. Final matching
workspace and PostgreSQL acceptance, writer review and handoff are retained in
`target/goal-execution-20261007/SHARED-RUNTIME/snapshots-20261010/`. Twenty control unit tests,12fixture guards and28contract guards are applicable.

## Canonical object retirement and retention — 2026-10-10

`CanonicalObjectRef` identifies an administrator-enrolled canonical physical
backend ID plus exact UTF8 key and version. Rust and SQL use the same domain and
length-delimited binary tuple. Backend IDs and permitted key prefixes are enrolled
in `object_backends`/`object_scopes` by the administrator; runtime and producer
fields cannot create aliases. Administrators must use one canonical identity for
one physical namespace. Identical canonical registry names cannot receive another
ID. Key case and Unicode bytes remain significant; ambiguous path/URL spellings,
missing versions and foreign backend/prefix authority fail closed. Standard
publication requires an exact version even when a conditional ETag is present;
the separate Small storage contract is unchanged.

Publication atomically stores canonical object digests with its committed
manifest; snapshots copy the exact digests, including predecessor references,
into finite reader pins. GIN membership supports globally scoped checks. Integrity
seals bind digest arrays to backend/manifest identity and reader scope, ID, expiry
and lifetime. Reader replay/compaction validates existing seals before mutation;
cleanup cannot silently reseal corrupted expiry. Retirement validates retained
metadata before trusting membership. This work is bounded by row/byte ceilings
and existing timeouts; incomplete validation fails rather than granting retirement.

`pin_object` records immutable restore, replay or evidence holds with opaque
external provenance. `release_object_pin` requires an explicit retained release
reason and the current complete owner fence; it preserves original and release
owner/generation/epoch and request bytes. Released IDs cannot become new holds.
Original requests, releases and identity markers remain charged finite history.
These references express an external retention decision; the library does not
infer custody, legal policy, source ACK or independently current restore authority.
Adapters must register applicable holds before permitting lifecycle operations.

`retire_object` checks every committed current/historical replay root across
partitions, every unexpired reader pin and retained restore/replay/evidence hold.
All committed history remains retained in revision1, so its referenced versions
stay protected; no implicit history pruning or compaction is introduced. Eligible
unreachable/orphan versions acquire a permanent globally unique tombstone under
current generation/owner/epoch with a final DB-clock lease check. Exact replay
returns the original result without new charges; conflicts/corruption/quota/expiry
roll back all child and capacity mutations. Tombstones reject serving, republishing
or new holds through any partition alias. Distinct exact versions and enrolled
physical namespaces remain independent. There is no provider DELETE operation,
ticket or network side effect. Future compaction/retention policy must preserve
supported roots, rather than treating this primitive as authority to erase history.

The owned PostgreSQL 17.5/AMD64 fixture proves matching Rust/SQL tuple bytes,
canonical registry uniqueness, global current/predecessor/replay protection,
all three explicit hold kinds and audited release/takeover, independent reader
expiry, corrupted index/expiry/tombstone rejection, cleanup integrity, exact replay,
row/byte and final-expiry rollback, alias republishing/serving denial, permitted
independent versions/backends and both pin/publication versus retirement races.
Malformed restricted-role input, helper/table privilege denial and exact logical
counters are checked. The final focused fixture passed in23.84s/35commands with
stable runtime source and clean owned cleanup. Final source-bound workspace and
fixture reports, writer review, counts and handoff live under
`target/goal-execution-20261007/SHARED-RUNTIME/retirement-20261010/`. Applicable guards:24control unit tests,13fixture and28frozen-contract tests.
This is a library slice; Standard query/server and stopped restore integration,
real provider custody, HA and release qualification remain separate.

## Local qualification

Run `python3 scripts/check-shared-runtime.py --output <fresh-owned-directory>`
with an already available PostgreSQL17+ fixture image. This launcher creates
only its labelled container, a loopback published port and bounded96MiB tmpfs;
it generates synthetic TLS material, explicitly installs routines under the
schema owner, enrolls two independent runtime roles and executes the named
integration test. An overall 180s budget includes cleanup, with at most64 commands.
It retains source hashes and bounded logs and refuses output collisions.

The gate requires PostgreSQL's actual version, the exact named test running once,
one passing test, the completed publication marker, no ignored/filtered tests,
unchanged source and owned cleanup. Thirteen helper regressions reject zero-test success, wrong/ignored/duplicate
names, filtered or failed counts, oversized output and unsupported versions.

The live test exercises verified TLS, wrong host/CA without plaintext fallback,
readiness/checksum/generation/scope/owner/expiry rejection, two concurrent takeover
contenders, four real blocked operations, cancellation without capacity reuse,
a full32-command queue, counted rejection, replay after rollback, restricted
DML/helper denial, actual backend termination, quarantined seats and uncertain
shutdown. Its temporary fixture administrator is not a production credential.

Retained evidence lives under `target/goal-execution-20261007/SHARED-RUNTIME/`.
The initial completed TLS fixture took9.56s/33commands with stable source hashes
and clean cleanup. Reviewed-source rerun and strict workspace qualification are
recorded separately; neither a type test nor this lease primitive closes the
full shared-runtime item. Earlier failed attempts stay retained.

The reviewed publication fixture passed against owned PostgreSQL 17.5/AMD64 in
70.22s/43commands, including Cargo artifact-lock wait, with source hashes stable
and clean cleanup; the executed integration test itself took7.75s. It covers atomic
publication, zero-prepared receipts, global deduplication across independent
partitions, exact prefix hashing, immutable replay/conflicts, both quota failures,
concurrent publication, delayed COMMIT reconciliation, malformed requests through
the restricted SQL role, corrupt retained/predecessor pins and expiry-before-publication
rollback. Evidence:
`target/goal-execution-20261007/SHARED-RUNTIME/publication-20261010/postgres-final/report.json`.
The focused review was performed by the writer; no independent reviewer was
used for this continuation. The complete shared-runtime item stays in progress.

Final source-stable workspace acceptance passes836default tests/11ignored and
891all-feature tests/12ignored, both strict Clippy modes, fmt and14-package
boundaries. Seventeen control unit tests,11 fixture guards and28 frozen-contract
guards pass. The ignored PostgreSQL test is separately executed by the actual
fixture gate above. Logs/source hashes and writer review are retained beside
`publication-20261010/acceptance.json`.

## Notification fencing and retained attempts — 2026-10-10

`ControlClient::notification` is a metadata mechanism only; it performs no network
send and is not wired into the server or private delivery adapter. `WorkInput.id`
is the immutable delivery ID, and the original opaque plan (including any private
idempotency key) remains byte-identical. Credentials and destination policy stay
outside this repository. SQL checks the plan against its original finding commit.

A fresh `Claim` commits intent under the current pipeline generation/owner/epoch
and a globally unique attempt ID. Repeating a claim returns `Conflict`, including
after a lost reply. `Resolve` reads retained evidence under current scope/lease
authority and never authorizes another send. A reply is metadata, not a durable
or replayable dispatch capability. An adapter may send only after a successful
fresh claim, with the same original delivery key and plan. A failed or uncertain
claim must be resolved; absence of a receipt does not imply a safe resend.

`Finish` requires the original claim fence and attempt identity. One completion
with bounded opaque outcome evidence is retained; exact finish replay is free,
conflicting completion fails. `Interrupt` explicitly marks an outstanding intent
uncertain under current authority, including after takeover or generation change;
it records that recovery authority separately and retains the original claim.
A different attempt ID can retry uncertain/retryable work. Old completion cannot
change interrupted or newer attempt state. Delivered/permanent/exhausted work
cannot be claimed again. Ten attempts per obligation is the fixed ceiling;
uncertain/retryable completion of attempt ten marks the obligation exhausted.
No automatic retry, recovery or external dispatch scheduler exists yet.

Every attempt retains immutable original request, generation/owner/epoch, ordinal
and plan hash. Its one completion/interruption and authority remain charged.
Canonical seals do not depend on PostgreSQL bytea output settings. SQL validates
all at-most-ten historical rows and the outbox summary before any operation;
corrupt plan/history/status fails closed. Claim costs one logical row and
512+request bytes; completion adds exact request bytes, without releasing history.
The existing finite queue, connection seats, deadlines, cancellation and uncertain
COMMIT rules apply. A final database-clock fence rolls back expiry after child
writes. `notification_uncertain_results` counts observed uncertain replies/COMMIT
errors, including resolution, rather than distinct obligations or remote effects.

Owned PostgreSQL 17.5/LinuxAMD64 regressions exercise original plans, non-replayable
claims, exact finish replay/conflicts, takeover/generation barriers, lost claim and
completion replies (observe delayed COMMIT before cancellation), one-winner
concurrency, ten-attempt exhaustion, row/byte quota
rollback, expiry after writes, corruption and restricted-role denial. Evidence and
source-bound writer review: `target/goal-execution-20261007/SHARED-RUNTIME/notifications-20261010/`.
This remains at least once. An in-flight remote effect cannot be rolled back by a
lease; destination idempotency and current adapter authority remain prerequisites.
No real notification, operational HA, restore or independent final review claimed.

## Explicit initialization and populated migration — 2026-10-10

`ControlAdministrator` requires captured connection settings and an explicitly
selected schema-owning role (raw PostgreSQL identity, including quoted names).
Runtime never invokes it or obtains migration
privileges. `initialize` creates the absent namespace and installs the frozen
001/002 artifacts plus `003-administration.sql` in one bounded transaction. An
existing namespace is rejected without reset, including an incomplete one. Store
identity/generation and finite budgets are explicit; readiness remains false.
Operator policy, principal/backend enrollment and operational quiescence remain
external responsibilities. Nothing here enables replicas or restores a backup.

`migrate` supports only the exact notification-qualified revision1 source:
002SHA256 `8106d8e021dde8d02d6fc6e4851e56d21ae389094e0541bcee2774b48f92c4cf`,
with the immutable 001 checksum. Earlier development variants, unknown/newer
revisions and partial bundles have no automatic migration or downgrade. Before
DDL, readiness must be false and every owner/lease cleared by the administrator.
Store-first ACCESS EXCLUSIVE NOWAIT locks cover all known metadata tables, so a
remaining reader/writer causes a bounded failure. Locks last through COMMIT.
[PostgreSQL locks](https://www.postgresql.org/docs/17/sql-lock.html).

Eligibility checks a pinned logical catalog fingerprint (columns/defaults,
constraints/indexes/RLS), expected object owners, absence of user triggers, and
exact function bodies, arguments, return types, languages, execution attributes
and search paths. OIDs, storage statistics and configurable ACL/role policy are
excluded from that fingerprint. Retained object/reader/hold/attempt integrity,
receipt requests, rule/normalizer pins, the entire findings cursor chain and exact
logical counters must validate. Current qualification uses PostgreSQL 17.5; another
catalog representation must be separately qualified rather than blindly accepted.
Source reflection bounds table/function replies and validates store field types
before reading stored values. All work shares finite queue/connection seats,
cancellation and the
original operation plus2s transaction budget; incomplete validation fails.

Revision2 changes only administration identity/schema. It preserves request IDs,
receipt bytes/progress, state/revision pins, manifests, finding bytes/positions/
cursors, delivery IDs/plans, and historical attempt claims/outcomes. Store identity,
generation, epochs and budgets are preserved. A fixed administrator-only three-row
catalog records ordered001/002/003 SHA256 identities; it is bounded configuration,
like the existing store/principal/backend catalog, not unbounded runtime history.
Runtime checks revision2 and all three identities on each authorized operation.
Older runtimes fail their routine checksum check. Migration itself leaves readiness
false; the fixture supplies a separate explicit synthetic readiness decision.

DDL error/cancellation rolls back schema, rows and identity together. An uncertain
COMMIT is never retried automatically. `inspect` is read-only resolution of the
current identity and complete ordered chain; it neither repeats DDL nor grants
readiness. Repeating a completed migration conflicts rather than rerunning it.
The migrator has no stopped-restore/current-authority capability in this slice.

Actual owned PostgreSQL regressions prove fresh initialization, populated upgrade
with exact complete before/after retained-record witnesses, source/cursor/catalog/
function corruption rejection, stopped lease/readiness and writer-lock boundaries,
malformed-field/quoted-role handling, DDL failure/cancellation rollback,
observed delayed-COMMIT uncertainty/resolution,
ordered-chain runtime rejection, restricted-role denial and subsequent current
runtime operations. The fixture's failure-injection objects live in its separate
public namespace; production schema guards remain intact. Evidence and writer
review: `target/goal-execution-20261007/SHARED-RUNTIME/migration-20261010/`.
Independent full-item review, full crash/restore
matrix, Standard wiring and release/environment gates remain open.

## Coordinated stopped restore — 2026-10-10

`coordinate_stopped_restore` and `PostgresStoppedRestore` implement a bounded,
explicit restore of the exact revision2/001+003 stopped source. The destination
must be freshly controlled and independently enrolled, with trusted compiled
schema installed and only data imported. Readiness is false, owners/leases are
cleared, and store-first exclusive locks protect the complete source checkpoint
and generation transaction. The fixture independently captures the coherent
source digest before copying; a destination cannot invent its own approval.
Other source revisions, including a previously restored revision3, are refused.
There is no automatic initialization, schema discovery, downgrade or reset.

The bounded inventory binds every retained control row, source cursor, exact
rule/normalizer revision, findings anchor, supported notification consumer,
original notification history and reachable immutable version/hash/size. Current
reader roots and retained evidence/replay/restore holds are protected. Unsupported
or missing revisions are refused rather than reconstructed or redetected. Each
inventory group is limited to128 entries and the encoded inventory to256KiB;
checks fail at capacity instead of truncating. Historical retained manifests are
included conservatively. Exact catalog/functions and the migration chain are
verified before both generation assignment and readiness. Contradictory
checkpoint/head/sequence/epoch/feed/state revision anchors refuse progress.

`RestoreAuthority`, `RestoreCustody` and `RestoreConsumers` are trusted external
adapters with current, independently supplied authority; stored backup approval,
credentials and internally consistent metadata never grant readiness. Decisions
bind destination, independently known checkpoint, inventory, fresh generation,
approval, custody and captured credentials, with an expiry. Custody verifies actual
immutable bytes and current protection, then is checked again before readiness.
All supported consumer cursors must match their exact retained anchors. Operators
must supply complete current consumer/policy state; no cursor is silently reset.

The explicit checksummed004 profile assigns revision3 and a fresh generation,
retains epochs, clears leases and seals restore provenance. Original attempt IDs,
generation/owner/epoch, outcomes/evidence, delivery IDs/plans and committed
manifest generations are preserved. Separate sealed outbox barriers make prior
attempted obligations uncertain, including originally delivered work. At ten
attempts, retry capacity remains exhausted while restore uncertainty is retained;
no retry budget or original evidence is erased. Current readers access original
commits through the sealed restore ancestry. Old handles remain fenced even when
their owner/epoch match a current acquisition. Runtime must explicitly select
`ControlClient::restored`; the normal revision2 client never upgrades itself.

Cancellation/lost mutation replies remain `Uncertain`. The owned worker lifecycle
rolls back or quarantines the connection before releasing its seat.
`resolve` only reads and validates the retained barrier while writers remain
stopped; it does not grant readiness. `resume_stopped_restore` requires the original
inventory and resolved receipt plus independently current authority, actual
custody and complete reconciliation. It never reruns the generation barrier or
trusts its stored approval. After ordinary writers resume, this stopped-resolution
interface is no longer eligible because the captured data checkpoint has changed.

Actual PostgreSQL 17.5 Linux AMD64 and separately copied immutable local files,
with synthetic authority/consumers, qualify the positive flow, missing/corrupt
objects, protection/approval/credential refusal, cursor refusal, original history,
fresh attempt/lease fencing, exact restored catalog tampering, DDL cancellation
rollback and observed COMMIT uncertainty/resolution. The focused fixture reports
54.245 seconds,35 commands and owned-container cleanup. There are36 control unit
tests, including10 coordinator regressions, and16 fixture guards. Writer review
and final source-bound acceptance are recorded under
`target/goal-execution-20261007/SHARED-RUNTIME/restore-20261010/`; only a matching
passed campaign proves final code acceptance. No real notification is sent.

This is an explicit library adapter and owned local fixture. It does not provide
an operational backup service, actual AWS custody/PKI/credentials, HA, native
ARM64/EKS or Standard server/query/private-consumer integration. Those and the
complete crash/restore matrix remain separate acceptance requirements.

## Bounded crash/restore matrix — 2026-10-10

The eighteen IDs/outcomes in `schemas/shared-control/v1.json` remain frozen. Each
has an actual fixture assertion and a unique result marker; `--matrix` refuses
missing, duplicated or unknown cases. Three owned producer processes sync an
immutable local object and are killed/reaped at observed upload, transaction or
COMMIT boundaries. Whole control-table witnesses prove rollback/no mutation;
a fresh client resolves the exact committed request without automatic retry.
Additional producers prove expired-owner and post-upload takeover rejection, and
an observed held-lock statement timeout rolls back before the replacement epoch.

The notification receiver is an owned ephemeral loopback test endpoint, with no
external policy or notification effect. It durably syncs synthetic key/plan bytes,
closes without an acknowledgement, and accepts a second request only with identical
bytes. Control records the first attempt as Uncertain; a fresh attempt reuses the
same work ID and original plan. Original uncertainty/authority/ordinal are retained.
This qualifies accepted-reply-loss handling, not a real provider's idempotency.

The launcher labels and exclusively owns a persistent PostgreSQL volume/container.
It compares ordered complete table hashes in both the control database and restored
destination across an abrupt database SIGKILL/restart, verifies the same container,
image and volume, re-enrolls its inspected loopback port, and runs a separate fresh
client. Exact test counts and both database witnesses are required. Bounded command
capacity reserves cleanup; verified owned container and volume removal is recorded.

Case audit, focused results, writer review and required serial acceptance belong to
`target/goal-execution-20261007/SHARED-RUNTIME/matrix-20261010/`. Acceptance requires
matching current source identities and a passed campaign. Historical reports remain
unchanged. Frozen001/002/003/004, logical catalogs and v1 contract are preserved;
remote object DELETE remains disabled. Standard wiring, operational restore,
independent full-item review and external/release gates remain separate.

## Query selection lifetime adapter — 2026-10-10

`SnapshotPin::bind_query_selection` checks the original pin and restricts the
selection's fixed lifetime. It does not authenticate paths, materialize objects
or grant content/tenant authority. `FileSelection` holds a private optional
deadline; repeated restrictions take the earlier value. Small selectors default
to no pin. An expired pin fails even when the selection is empty.

QueryEngine narrows the physical scan deadline and checks it again when consuming
the final response. Actual Parquet/DataFusion tests observe a paused physical
read, expire its selection without partial success, then release and drain the
original bounded I/O seat. The actual PostgreSQL snapshot fixture verifies that
binding cannot extend its database-derived deadline and fails after expiry.

Review, source identities and final serial gates are retained under
`target/goal-execution-20261007/SHARED-RUNTIME/query-pin-20261010/`; acceptance
requires the matching passed campaign. This is the lifetime seam only. Shared
canonical manifest/object selection, Standard server wiring and complete supported
consumer enrollment remain separate requirements; no replicas are enabled.

## Dynamic committed catalog — 2026-10-10

`ControlClient::catalog` discovers the complete committed chain from the authorized
partition and pins it in the same repeatable-read transaction. Callers supply a
request identity and finite lifetime, never a configured list of manifest IDs.
Replies bind the trusted backend, original head/checkpoint and exact retained
manifest bytes. Replay preserves the original set and database expiry across later
publications; an explicit-ID snapshot cannot impersonate a catalog request.
Empty catalogs receive sealed finite pins. Broken chains, inconsistent heads,
quota exhaustion, more than 128 manifests/objects or a response above 1 MiB fail the
whole operation. The Rust adapter also verifies predecessor bytes/hash and ranges.

The explicit stopped revision 2 to 4 migration preserves existing metadata, refuses
live owners/readiness and atomically rolls back failed DDL. Profile 4 inspection
checks the exact logical catalog, function definitions, migration history and
charged census. Frozen001..004 remain unchanged. Restored revision 3 is rejected;
profile 4 restore requires a separately qualified extension before Standard use.

Evidence: `target/shared-catalog-20261010T201614Z/`. The focused PostgreSQL 17.5
AMD64 fixture passed at 2026-10-10T20:48:10+00:00 (95.763 seconds, 42 commands), including
all 18 existing matrix cases and unchanged metadata across an abrupt restart of
three owned databases. Actual TLS covers discovery/replay, empty pins, corruption,
quota rollback, expiry and both limits. Object references remain synthetic here;
this does not qualify object materialization, Standard server integration or AWS.
Acceptance additionally requires the source-bound final campaign and writer review.

## Shared catalog query materialization — 2026-10-10

`SharedQuerySource` implements the existing `QueryFileSource` seam. It obtains a
fresh dynamic database catalog, checks its scope and trusted backend mapping,
and restricts every object/read/result transition to the original pin deadline.
`select_pin` consumes an existing capability without rediscovery or renewal.
Invalid query bounds and pre-cancellation fail before allocating a database pin.
API outcomes and materializer depth/capacity/rejections expose bounded metrics.

`ObjectSelection` validates the complete manifest chain before object I/O, prunes
UTC partitions and authenticates exact versions/hash/bytes and actual Parquet
schema/rows before exposing paths. One ordinary controller, one I/O worker and
one codec worker retain admission until physical children drain. Returned
selections retain their seat and exclusive derived-cache lease through clones
and shutdown. Cache files/bytes are finite; failure never returns partial files.
Copies remain immutable until stopped maintenance; remote DELETE stays disabled.

Six owned-filesystem/actual-Parquet regressions cover pruning, missing objects,
chain/stream rejection, row mismatch, aggregate/disk quota, empty/populated expiry,
cache ownership and a physically stalled read after caller timeout. The focused
PostgreSQL 17.5 AMD64 matrix passes in90.350s/42commands, including actual
catalog publication, original selection after a changed head, fresh DataFusion
results with nested attributes, backend mismatch denial and expiry. Its object
fixture is write-once with an emulated version; it does not prove AWS versioning.

Recorded at 2026-10-10T21:11:46.521932+00:00. Evidence: `target/shared-query-20261010T205840Z/`.
Acceptance requires matching source-bound writer review and final campaign.
The production control library retains downward dependencies; events/DataFusion
are explicit test-only composition dependencies. This remains a library adapter:
The following slice qualifies profile4 coordinated restore. Standard server/private
consumers, operational retirement and independent full-item review remain required.

## Coordinated catalog restore — 2026-10-10

`PostgresStoppedRestore::catalog` explicitly accepts the exact stopped revision4
profile and installs checksummed006 as revision5. Frozen001..005 remain unchanged;
the complete ordered migration history and logical catalog are verified. Catalog
snapshot rows, seals, charges and original lifetimes participate in the coherent
inventory/checkpoint and retained post-barrier verification. No profile detection,
automatic migration, historical redetection or backup-provided DDL is accepted.

The shared coordinator requires independently current checkpoint approval, exact
rule/normalizer revisions, immutable object custody/protection and captured
credentials. It assigns a fresh generation, retains original commit and delivered
attempt evidence, and marks attempted work uncertain. Only complete current
consumer reconciliation enables readiness. `ControlClient::restored_catalog` is
the explicit runtime identity; older2/3/4 clients and old handles fail closed.
Expired or old-generation catalog identities are never renewed or reinterpreted.

The owned PostgreSQL17.5 AMD64 fixture restores actual authenticated Parquet with
an emulated durable write-once filesystem version. It refuses missing/corrupt
bytes, absent approval/protection, malformed catalog seals and incomplete
consumers; an injected DDL failure rolls back to the exact stopped checkpoint.
The original delivered notification attempt remains byte-identical while its
work becomes uncertain; stale completion is fenced. The eighteen frozen matrix
cases pass, then complete metadata witnesses from five databases survive abrupt
restart and a fresh restored-catalog query returns the retained actual event.
The finite readiness probe permits thirty seconds within its bounded command;
it must observe PostgreSQL readiness and cannot treat recovery as success.

Focused qualification:117.387834seconds/46commands, owned container and volume
removed. Recorded at 2026-10-10T21:46:43.790690+00:00; evidence lives under
`target/catalog-restore-20261010T212803Z/`, including retained failed attempts.
Acceptance requires matching source-bound writer review and passed final gates.
This proves a local library slice, not AWS versioning/custody, operational backup,
Standard server/private consumers, prolonged stability or independent full-item review.

## Standard server publication coordinator — 2026-10-11

`signal-server::shared::SharedPublisher` composes exact object I/O, actual Parquet
encoding and the bounded control client inside the monolith application. Host
scope/backend/rule/normalizer pins and request ID are explicit. Producer fields
supply none of them. There is no Small catalog or automatic schema fallback.
Scope, sequence/count/metadata bounds and pre-cancellation are checked before
database or object I/O. Codec validation rejects invalid event bodies before
publication.

One preparation capability retains the admission seat and original operation
budget through COMMIT. Codec/object workers expose separate finite capacity and
physical-drain metrics. The database snapshot can shorten, never extend, the
original deadline; cancellation propagates to derived object/codec work. Only
already committed predecessor manifest bytes get canonical manifest objects.
Pending current manifests cannot reserve a future head. New data is immutable,
exact-version read back and included in one fenced manifest/findings/state/work/
receipt transaction. Failure leaves no committed partial prefix. No remote DELETE,
source ACK, custody receipt or WAL checkpoint is granted by this component.

Persist the exact versioned request for recovery. Replay retains its original
result; absence stays uncertain. A late or cancelled COMMIT reply is never a
successful acknowledgement or proof of rollback. Explicit resolution requires
current authority and the original request; it does not create another ID.
Shutdown drains physical object/codec workers before the host closes control.

The owned PostgreSQL17.5 AMD64 test uses actual rule evaluation and Parquet/
DataFusion. Preparation exposes neither commit nor finding; two publications and
exact replay retain the first-occurrence finding. Cancellation and stale-owner
publication retain only orphan bytes. A real deferred COMMIT is observed before
caller cancellation, returns uncertainty, then resolves the original request.
Object versions are emulated write-once process-local versions, not AWS proof.
The full fixture passes18 cases/47commands in120.892012seconds, with cleanup.
Recorded at 2026-10-10T22:17:55.787278+00:00. Evidence: `target/shared-server-publication-20261010T215920Z/`.
Final acceptance requires its matching source-bound review and serial campaign.
This is the application coordinator; Standard startup, durable WAL/request-ID
wiring, global findings/private consumers, current custody and operational
restore/retirement remain required. No Standard readiness is inferred.

## Remaining within the existing item

- Standard server and stopped restore integration of the qualified canonical
  query adapter, roots and explicit holds; runtime remote object DELETE remains disabled.
- Operational stopped restore integration with real current authority/custody
  adapters and complete supported consumer enrollment; the local library fixture
  does not grant external restore authority.
- Standard server/query/private-consumer integration and final independent review;
  the bounded library matrix above does not qualify Standard runtime readiness.

No real AWS managed database, operational HA, production secrets/PKI/custody,
current container image, native ARM64 runtime, full matching CI or release claim
is inferred. The existing Small path stays authoritative until the complete
Standard acceptance is demonstrated.

## Explicit server startup authority and existing WAL — 2026-10-11

`SharedStartup` selects only the explicit `Catalog4` or `RestoredCatalog5` client.
The host captures bounded credentials/TLS through `ConnectionSettings`, trusted
scope, canonical backend and the actual open `DurableBuffer`. Construction rejects
foreign stream identity, drop-oldest policy, closed/corrupt WAL and invalid bounds
before starting control workers. The generic WAL policy accessor exposes only its
immutable admission policy. No startup installation, migration, schema detection,
local storage fallback or producer-derived authority exists.

`verify` pins one complete database-owned committed catalog under the original
operation context. Actual restricted SQL checks the chosen compiled schema, ready
state, current generation and authorized partition. Backend must match the host
mapping; committed checkpoint must lie between the existing WAL's acknowledged
prefix and last admitted sequence. A committed-but-unacknowledged local prefix
remains for later exact request replay; verification never advances it.

`VerifiedStartup` is nonserializable and retains the original catalog pin/context
and actual WAL. Every metadata access rechecks original cancellation/deadline,
fixed snapshot expiry, WAL liveness/identity and checkpoint compatibility. It
never renews the pin or discovers later commits. This finite observation grants
no lease, startup READY certificate, durability response, custody or source ACK.
The host retains `SharedStartup` after failed verification so the control client
can physically drain; dependent query/publication users stop before its shutdown,
and the host closes the WAL separately.

The owned server fixture exercises profile4 startup, explicit profile5 mismatch
without fallback, generation/backend/ready denial, real existing WAL admission
and checkpoint mismatches in both directions, compatible unacknowledged commit,
original cancellation/deadline and stable pinned metadata through later commits.
The profile5 constructor uses the independently qualified restored-catalog client;
actual restored-profile server startup remains part of operational restore work.
Default regressions reject foreign streams, lossy policy and closed buffers before
network access. The native report requires both startup and publication markers
exactly once and hashes the consumed WAL/server sources.

Source-bound review/final acceptance and retained diagnostic reports live under
`target/shared-startup-20261010T224833Z/`. The first PostgreSQL run passed all18
cases/47commands in104.73s with cleanup; final acceptance additionally binds the
newly consumed WAL source hashes. This is local AMD64 component qualification with
process-local emulated versions. Main config/runtime wiring, durable original
request-ID/payload recovery before WAL checkpoint, global findings, complete
private consumers and operational restore/retirement still follow. Small remains
the running profile; no replicas or Standard RPO0/readiness claim is enabled.

## Durable original publication recovery and WAL checkpoint — 2026-10-11

`DurableBuffer::open_with_recovery` explicitly enables one recovery slot, at most
4MiB. Ordinary `open` retains Small's existing layout and refuses recovery files.
The slot reuses the existing exclusive WAL directory lock, bounded command queue
and sole disk worker. WAL quota reserves both old and staging slot capacity plus
framing before opening. No second filesystem worker, unbounded queue or ambient
provider is introduced. Metrics expose retained bytes/capacity and distinguish
admission closure from a stopped/failed worker so graceful drain remains possible.

The version1 frame binds stream, exact length and SHA256 over framing/payload.
Replacement is compare-and-swap against the original digest: create-new staging,
write, file sync, atomic rename and directory sync precede the reply. A published
corrupt/foreign/oversized slot fails open without reset. Only bounded regular
owned staging files can be discarded; they never supersede the published slot.
Reclamation requires the exact digest and directory sync. A lost disk reply may
have completed; restart rereads the original slot instead of guessing absence.

`SharedRecovery` binds the actual WAL to its host-owned publisher and admits one
operation/capability at a time. It reads a bounded contiguous prefix, retains a
versioned original draft, revision/finding/state/work/receipt bytes and canonical
row hash before uploads, then replaces that draft with the exact prepared request
before any COMMIT. Prepared capability drop, cancellation and uncertain COMMIT
leave the record and WAL prefix held. Original operation/pin deadlines cannot be
extended through metadata serialization or checkpointing. Draft replay uses the
original plan rather than reevaluating changed policy.

Recovery requires current complete scope/generation/lease authority. It checks
retained range and original WAL row hash before any missing publication retry.
An exact committed request resolves without new findings or work. An absent
request permits only exact byte/version retry while those original WAL rows still
exist: `recommit` rechecks current catalog/backend binding and original exact
object references, then calls the same fenced atomic publication operation. It
never substitutes current versions, new request IDs, metadata or revisions.
A missing/corrupt object, stale owner, foreign scope or conflict leaves the prefix
held. An already acknowledged prefix permits resolution only, never reconstruction
of a missing request from removed WAL bodies.

Only the confirmed exact result precedes synced WAL ACK. The record is reclaimed
after that checkpoint. Crash after COMMIT before ACK resolves and checkpoints
the same request; crash after ACK before reclamation resolves and clears its
retained record without needing removed WAL rows. An uncertain checkpoint/clear
reply remains uncertain. This is local event-consumer checkpointing, not protected
source custody, external source ACK, HTTP durable admission or Standard READY.
The host still must wire authenticated derivation, complete private consumers,
global reads, explicit main runtime selection and operational restore/retirement.

Default regressions prove CAS/restart/reservation, oversized input, corruption
without reset, owned partial staging and actual producer SIGKILL/reaping. The
owned PostgreSQL/server fixture kills four fresh producers at original draft,
prepared-before-COMMIT, committed-before-ACK and ACK-before-reclamation boundaries.
Fresh clients/takeover epochs recover original IDs and one original global finding
cursor. It also observes the driver's deferred COMMIT reply loss, cancellation,
closed-admission drain, full capability rejection and changed-object denial with
unchanged checkpoint/record. Its object provider remains independently in the
parent process and emulates immutable versions; this is not AWS/versioning or
persistent whole-server object-provider evidence.

Evidence, writer review, source-bound final gates and retained first native report:
`target/shared-recovery-20261010T230503Z/`. The first run passed all18 frozen cases
and the server recovery checks in130.30s/47commands with cleanup. A review correction
adds current backend validation to exact retry; matching final acceptance is
required. During acceptance,19 overwritten baseline WAL tests were restored
byte-for-byte from matching retained source; new slot tests are isolated in
`publication-recovery.rs`. The stopped campaign remains recorded as failed.
SQL001–006 and the frozen18-case matrix remain unchanged. Small remains
authoritative; Standard main/global findings/private consumers, operational
restore/retirement, independent review and external/release gates remain open.

## Original global findings page verifier — 2026-10-11

`RetainedFindingsPage` validates a contiguous prefix against the exact retained
anchor and global head from one trusted database snapshot. It preserves original
finding JSON bytes, checks each SHA256, finding schema/ID and cursor digest, and
rejects divergent/foreign/ahead cursors, gaps, duplicate IDs and empty nonterminal
pages. It never resets a consumer to a newer tail. Maximum128 rows,64KiB per
payload and1MiB retained allocation including framing are checked before parsing;
original cancellation/deadline applies at verification and every page borrow.
Errors and record Debug output expose no payload bytes.

This verifier confers no read permission and performs no database query. Current
global-read grants, generation/profile checks, a consistent bounded PostgreSQL
read operation and the server adapter remain required. Caller-supplied anchors
cannot stand in for those database checks. SQL001–006 remain frozen; any new
database read authority needs explicit migration and stopped-restore coverage.
Six focused regressions and matching source-bound workspace gates are retained
under `target/shared-feed-20261011T014738+0200/`; only its passed final campaign
supports acceptance. SHARED-RUNTIME and the full release goal remain open.

## Global findings database reads — 2026-10-11

`ControlClient::read_findings_feed` uses the existing four workers/32 commands
and original operation/transaction budgets. It requires both a current
authenticated all-scope `ReadFindingsFeed` host grant and independently enrolled
PostgreSQL global SELECT authority. Producer partition/function permissions do
not imply that authority. The least-privilege reader needs schema USAGE and
SELECT on `store`, `migrations` and `findings`; no schema-owner credentials,
writer lease, producer principal or DDL privilege is required. Enrollment is an
explicit operator GRANT with currently captured credentials, never startup work.
[PostgreSQL privileges](https://www.postgresql.org/docs/17/ddl-priv.html) and
[privilege checks](https://www.postgresql.org/docs/17/functions-info.html) were
retrieved through Context7 for this decision. Configurable ACLs are already
excluded from the qualified logical catalog, so no schema migration is introduced.

A read-only repeatable-read transaction validates the exact explicitly selected
catalog4/restored5 logical schema and complete migration hashes, store/generation,
READY, fixed global head and retained historical anchor before reading bodies.
The canonical administrative search path is set explicitly. Each row is limited
to64KiB before transfer; bounded128-row/1MiB retained pages preserve original
finding bytes, SHA, IDs and cursor digests without tail reset. A nonempty prefix
may stop at the byte budget. Grant expiry never extends the original monotonic
deadline. Response borrows also recheck the grant, original context and reader
shutdown. The host must still audit/authenticate the HTTP request and bound wire
serialization when wiring the endpoint. [Repeatable-read semantics](https://www.postgresql.org/docs/17/transaction-iso.html)
were retrieved through Context7; objects and the local FindingStore are not queried.

Actual Linux AMD64 PostgreSQL17.5 evidence checks producer-only denial, absent
global enrollment, wrong host operation, stale generation, exact pagination and
empty tail, divergent/foreign cursors, fixed snapshot during retained-row change,
subsequent corruption denial, explicit REVOKE, cancellation and shutdown. Existing
coordinated catalog restore preserves the original feed; fresh destination read
credentials/GRANT and fresh generation succeed, old generation fails, and a new
reader verifies original bytes after actual persistent PostgreSQL restart. No
backup permission or producer grant substitutes for current reader enrollment.

Evidence: `target/shared-global-feed-20261011T015956+0200/`. The reviewed native
run passed18 frozen cases in140.00s/47commands with owned fixture cleanup. Earlier
failed catalog-search-path and overly narrow snapshot-observer runs are retained.
Only matching final source-bound gates qualify acceptance. SQL001–006 remain
byte-identical. Main HTTP/global feed wiring, authenticated scoped derivation,
private consumers, operational restore/retirement, independent full-item review
and external/release gates remain open; no Standard READY or release claim.

## Shared findings wire and HTTP feed route — 2026-10-11

`SharedFindingsFeed` binds an explicitly captured reader/store/generation to
finite caller admission and a bounded JSON response. Caller depth/capacity and
rejections are observable; the existing control workers retain physical database
ownership after caller loss. Wire output preserves original finding JSON bytes.
If only a prefix fits, its cursor names the last included record and `has_more`
remains true. An oversized first record fails without returning a partial page;
an empty tail preserves the input cursor. Grant/context/reader shutdown checks
remain effective through encoding; no raw finding body enters diagnostics.

The existing monolith findings module has an explicit feed-only shared router
constructor. It requires the configured identity backend, rejects bootstrap-token
configuration, and uses the existing authentication/audit decision and completion
flow. The constructor exposes only `/v1/findings/feed`; it has no local finding
store or scoped-listing fallback. Main continues selecting Small until complete
scoped Standard behavior/startup is implemented. The shared request uses the
original deadline/cancellation and concrete all-scope request grant. Responses
retain `no-store` and the existing cursor error classes, including foreign stream,
divergent history and ahead-of-retained positions. A static control error class
now distinguishes an unavailable cursor position from conflicting history.

Focused regressions cover exact wire bytes/prefix cursor/budget, cancellation,
finite caller capacity before network use, missing identity configuration,
unauthenticated and bootstrap-only HTTP rejection, and absent scoped route.
Actual PostgreSQL server-component evidence verifies original retained finding
bytes/cursor, first-row budget failure and foreign cursor classification, alongside
the existing18-case matrix/restart/restore/recovery campaign. A live authorized
shared HTTP/provider round trip is not yet qualified. Source-bound review and
matching final gates are retained under `target/shared-feed-http-20261011T022929+0200/`.
Its first native run passed in155.07s/47commands with owned fixture cleanup.
SQL001–006 remain frozen. Trusted scoped derivation/listing, full main startup,
private consumers, operational restore/retirement, independent review and the
external/release gates remain required; the full release goal stays active.

## Authorized shared feed HTTP qualification — 2026-10-11

The feed-only monolith router is now exercised over an actual loopback HTTP
listener with real TLS token introspection, explicit host policy, the enrolled
PostgreSQL reader and a synced audit destination. The first authorized response
preserves the original retained finding bytes and exactly their derived cursor;
pagination remains authorized. Missing, inactive, expired and unbound identities
are rejected even when provider role/scope strings claim reader/admin authority.
Malformed, foreign-stream and divergent-history cursors retain their HTTP error
classes. The first finding exceeding the response budget returns413. Every feed
response carries `Cache-Control: no-store`.

The destination syncs access decisions and completions. The test verifies a
successful completion and separately loses the acknowledgement after syncing a
completion: HTTP503 withholds the computed finding bytes. The audit outbox and
destination are owned local directories; this is not external destination proof.
Provider requests, socket handshakes, request bodies, calls, subprocess duration,
HTTP client deadlines and server/database/identity shutdown are finite. The
provider reuses the existing finite TLS fixture; no production dependency or
identity transport bypass is introduced. Listener shutdown follows the current
[Axum serve contract](https://github.com/tokio-rs/axum/blob/main/src/serve/mod.rs),
retrieved through Context7.

Evidence: `target/shared-feed-roundtrip-20261011T025437+0200/`. The corrected
native campaign passed18 cases in141.29s/48commands, including persistent database
restart and verified owned container/volume removal. The first diagnostic run
passed the new HTTP test but failed later because a launcher source-loop variable
overwrote its container name; its failed report and separately verified exact
cleanup remain retained. The corrected launcher uses a distinct variable and
binds the provider helper and its imported fixture sources into runtime evidence.
SQL001–006 are unchanged. Matching source-bound final gates qualify acceptance.

This qualifies the explicit feed-only factory. Main still selects Small; trusted
scoped derivation/listing, full Standard startup, private consumers, operational
restore/retirement, independent full-item review and external/release gates remain
required. No replica, Standard READY, alpha or release claim follows from this test.

## Durable shared finding scope schema groundwork — 2026-10-11

`007-finding-scope.sql` adds the separate generic `signal_finding_scope` schema.
The frozen core catalog, finding bytes/IDs/global cursor and SQL001–006 are
unchanged. An explicit schema owner with database CREATE permission installs it
in a stopped transaction; runtime credentials and a live store are rejected.
The migration locks the core store with
[ACCESS EXCLUSIVE NOWAIT](https://www.postgresql.org/docs/17/sql-lock.html),
requires a bounded exact core table inventory, checks its full logical catalog,
and verifies the complete migration checksum history for original profile4 or
restored profile5. Context7 supplied the current PostgreSQL lock documentation.
Complete DDL rolls back without leaving an extension root. Installation neither
creates an activation nor changes READY nor grants runtime access.

Four tables hold the extension profile and finite quota/counter bounds, an
activation's store/generation/original global prefix and separate scope UUID,
per-partition stream/startup/WAL-floor enrollment, and canonical finding facts
bound to the original finding/partition and enrolled scope generation. Selector
facts cap at256 bytes and digest fields at32 bytes. The complete supplemental
logical table catalog is pinned separately in `007-finding-scope-catalog.sha256`.
Future scoped operations must verify this supplemental authority independently;
a valid core catalog or a producer-supplied finding attribute cannot substitute.

Actual PostgreSQL evidence installs on both core profiles, rejects live/runtime
and catalog-drift attempts with the intended error classes, and verifies complete
rollback, original core fingerprint/history, runtime read/write denial and
structural bounds. The fixture owner seeds activation/enrollment records while
leaving facts empty: legacy history gains no provenance. Those exact records and
six complete database witnesses survive an actual persistent PostgreSQL restart,
with a fresh client checking the captured values and supplemental catalog. They
are synthetic owner reports, not authenticated native-host activation or admission
proof. Counter reconciliation/enforcement, immutable host APIs, scoped publication
and reads are not implemented by these schema tests.

Evidence: `target/shared-finding-scope-schema-20261011T031740+0200/`. The reviewed
native diagnostic passed18 cases in144.57s/50commands with verified container and
volume cleanup. Earlier parse/fixture-permission/catalog-discovery reports remain
retained. Matching source-bound final gates qualify acceptance. Next implement
the explicit host activation/enrollment API and current-generation verification,
then deterministic derived publication, original recovery and scoped HTTP reads.
Main stays Small. Operational restore of supplemental authority, private consumers,
independent full-item review and external/release gates remain open.

## Bounded shared scope host activation/enrollment API — 2026-10-11

`FindingScopeAdministrator` captures explicit credentials, schema owner and exact
core profile4 or restored profile5. It uses the existing four physical database
workers/32-entry queue and original request/transaction/rollback/uncertain-COMMIT
semantics. It never installs DDL. Activation and enrollment require the stopped
core; inspection can verify current metadata without toggling READY. Owner-role
selection, complete core function/table inventory and checksum history, complete
supplemental inventory, current store generation and original artifact checksum
are verified. The store lock serializes metadata mutation and prefix validation.

Activation uses an explicitly retained scope UUID and limits, verifies the full
original finding cursor chain/body hashes/contracts, and atomically creates the
profile and original prefix. Exact replay preserves that prefix and limits;
foreign identity, partial roots, incompatible limits, substituted bytes or corrupt
metadata remain held. No reset or reactivation path exists. Current complete feed
integrity and the immutable activation prefix are rechecked before returning a
capability. No historical finding gains facts.

Conservative logical charges are256 profile bytes,144 activation bytes,320 per
producer and512 per fact plus encoded selector bytes. These are bounded logical
accounting, not physical PostgreSQL allocation measurements. Aggregate row,
producer and byte counters reconcile before and after mutation. Facts must retain
current generation, post-prefix identity, original body hash and matching reserved
canonical scope/event metadata; atomic derived fact publication remains unwired.
Enrollment binds the exact partition/stream and explicit startup UUID/WAL floor.
Exact startup replay cannot change its floor; a stopped replacement may only move
the floor forward, and metadata capacity rejects the whole operation. Subsequent
publication/read integration must freshly recheck the captured startup authority.

`FindingScopePin` is nonserializable original-context evidence, not event
credentials, user read authority, READY or source ACK. Context cancellation/expiry
and client shutdown invalidate borrowing. The startup component has a configured
native-identity-only enrollment adapter that captures the actual retained WAL
floor and checks unchanged WAL/checkpoint bounds after completion. This adapter
has component/source review; actual authenticated Standard startup still needs
end-to-end qualification before main can use it.

Actual PostgreSQL library qualification covers activation/enrollment replay,
foreign generation, conflicting or regressing startup floors, quota rollback,
counter corruption, permission/stopped-state denial, original-context and shutdown
invalidation, restored-profile activation and fresh inspection after persistent
restart. Evidence: `target/shared-finding-scope-host-20261011T034549+0200/`;
the first native diagnostic passed18 cases in141.66s/50commands with cleanup.
Only matching reviewed-source final gates qualify acceptance. SQL001–007 and the
supplemental catalog remain unchanged. Deterministic scoped publication/recovery,
scoped reads, complete main/private-consumer startup, supplemental restore,
independent review and external/release gates remain open. Main stays Small.

## Sealed canonical shared finding payload — 2026-10-11

`DerivedFinding::into_scoped` supplies an immutable `ScopedFinding` to the next
atomic publication adapter. Its private fields have no deserialization or mutable
accessor: reserved finding bytes, bounded canonical selectors, complete original
identity digest and explicit activation UUID come from the same deterministic
event/base derivation. Nil activation and unverified replay fail. Overlong
selectors remain unknown without truncation; the full digest still distinguishes
divergent identities with the same deterministic finding ID.

The payload does not authenticate admission or establish current producer/startup
authority. It cannot authorize a commit, upgrade existing unknown history, or
replace the retained original recovery request. Those checks belong to the
remaining atomic database and server recovery integration; main remains Small.
Existing local store activation and duplicate semantics are unchanged.

Evidence: `target/shared-scoped-payload-20261011T042000+0200/`; acceptance requires the source-bound writer review
and matching passed final gates. Scoped atomic publication, recovery, reads and
full startup remain required for SHARED-RUNTIME.

## Atomic shared scoped publication — 2026-10-11

`008-scoped-publication.sql` adds bounded original companion requests and a single
restricted `SECURITY DEFINER` publication wrapper in `signal_finding_scope`.
SQL001–007 and the core catalog remain unchanged. Installation requires the stopped
schema owner, a complete supported core/checksum history and exact007 table
inventory; full DDL rollback leaves neither the new table nor routine. Public
execution is revoked in the same transaction. The owner explicitly grants only
schema USAGE and the wrapper's EXECUTE to an enrolled pipeline role, without
supplemental table access. The fixed trusted search path ends in `pg_temp`, following
[PostgreSQL17 function guidance](https://www.postgresql.org/docs/17/sql-createfunction.html).

`ScopedPublicationInput::from_host` pairs sealed canonical findings and selectors
with the captured scope, startup and WAL floor. The serializable retained input
is evidence, not authority. Before queue admission it verifies bounds, original
finding/event/metadata pairing and sequence above that floor. Normal submit and
resolve share existing physical workers, original clocks, cancellation, rollback,
uncertain COMMIT and quarantine. Complete008 tables and the exact routine definition
are independently pinned. Administrators explicitly select `Catalog4Scoped` or
`RestoredCatalog5Scoped`; older supplemental profiles refuse this extension.

The wrapper holds the original store lock, checks the current token/producer,
activation and counters, then atomically calls frozen core publication and appends
facts, exact companion bytes/hash and quota charges. Fact rows charge512 plus
selector UTF8 bytes; companion requests charge256 plus exact claim bytes. Both
consume the existing root row/byte limits, including empty-claim publications.
A missing operation requires the currently enrolled startup and exact original
floor. Exact committed claims can reconcile after a stopped startup replacement
under independently current lease authority. Divergent claims or bytes conflict.
Existing unknown history is never annotated or promoted; exact duplicates retain
original bytes and global cursor history.

Actual owned PostgreSQL17.5/AMD64 qualifies positive catalog4 facts, exact retained
serialization/replay, divergent binding, whole-request capacity denial, stopped
startup replacement, immutable unknown duplicates and denied runtime table access.
An injected late core rejection rolls back core and supplemental state together;
observed cancellation during deferred COMMIT reconciles only the original claims.
All18 existing crash cases and six exact persistent database witnesses remain
required; the scope witness now includes companion request bytes. Catalog5
qualifies stopped008 installation and owner inspection, not positive scoped
publication or an operational populated008 restore.

Evidence: `target/shared-scoped-publication-20261011T043519+0200/`; acceptance requires
its source-bound writer review and matching final gates. Calibration and failed
fixture runs remain retained. Native event authentication, scoped server/WAL
SIGKILL recovery, scoped listing, full Main startup, private consumers, populated
scope restore/retirement and independent/external release gates remain open.

## Original scoped server publication and WAL recovery — 2026-10-11

The server now prepares a bounded original scoped claim bundle before object
upload and retains the complete original scoped request before COMMIT. The
nonserializable prepared capability keeps the original context and admission
seat. Raw recovery records retain schema1; scoped drafts and requests use
schema2. Downgraded or unsupported phase/version pairs fail before database or
object I/O and keep the original slot and WAL checkpoint.

Recovery verifies canonical findings against the original sequence/event and
the complete saved WAL batch hash. It never regenerates startup, floor,
generation or finding bytes. Committed work resolves using the original exact
claims under a current lease, including after stopped startup replacement.
Missing work can only recommit those original claims with independent current
database checks; an old startup remains fenced without acknowledging the WAL.

Actual owned PostgreSQL/WAL child processes are killed after the scoped draft,
before COMMIT, after COMMIT and after ACK. Reopening preserves the exact saved
record. Committed findings retain their original bytes; resolved work advances
the checkpoint before clearing the slot. The missing old-startup operation
remains held. Ordinary tests reject canonical identity/sequence/observed-time
substitution, divergent attachment and recovery version substitution.

Evidence: `target/shared-scoped-recovery-20261011T052009+0200/`. The corrected
focused fixture passes all18 existing cases and six exact database restart
witnesses, with all owned resources removed. Final acceptance still requires
the matching source-bound writer review and serial gates. Failed diagnostic
runs remain retained. Synthetic host reports and parent-retained emulated
object versions do not prove native authenticated admission, scoped reads,
populated008 restore, full Main startup, private consumers or external gates.

## Scoped server lost-COMMIT qualification — 2026-10-11

The native server fixture observes its own deferred PostgreSQL COMMIT waiting
in `PgSleep` before cancelling the original operation context. An uncertain
return keeps the exact original scoped request slot and pre-operation WAL
checkpoint. After the physical transaction finishes, the stopped owner replaces
the producer startup and captures the next WAL floor. Recovery then reconciles
the original committed request under current authority, retaining byte-exact
finding content and companion claims before confirming WAL ACK and slot removal.
Repeated recovery is empty and no request is duplicated. A subsequent missing
request from the old startup remains fenced with its original slot and checkpoint.

This extends test qualification and its required unique evidence markers;
production Rust, dependency inputs and frozen SQL001–008 remain unchanged.
The expanded fixture has a240-second overall harness budget,150 seconds for
control qualification and30 seconds for the server test, retaining10 seconds
for owned cleanup; GitHub's enclosing command has300 seconds. This follows an
observed118.29-second control test and20.42-second server test whose combined
run exhausted the earlier overall budget. Production request contexts and SQL
statement/lock timeouts remain unchanged.
Evidence: `target/shared-scoped-commit-20261011T055304+0200/`; acceptance requires
the source-bound reviewed fixture campaign. Existing production acceptance is
`target/shared-scoped-recovery-20261011T052009+0200/`. Synthetic host reports do
not establish native HTTP admission, scoped reads, Main wiring or release readiness.


## Grant-only shared WAL admission seam — 2026-10-11

Authenticated ingest forwards its original native RequestGrant and monotonic
request deadline through EventSink::admit_with_grant. The default compatibility
method rechecks live IngestEvents permission and canonical event facts; legacy
requests still use plain admit. The explicit SharedAdmission adapter consumes
an owner-produced FindingScopePin only while its original stream/startup floor
matches the WAL. It rejects plain admission, DropOldest, corruption/drops and
invalid checkpoint/recovery bounds, and exposes a bounded single caller seat
with accepted/rejected/active/capacity counters. No grant is serialized.

Every native call rechecks live canonical scopes, operation and lease bounds,
clamps the original deadline to grant expiry and passes that deadline into the
existing tracked WAL worker. Cancellation releases the caller seat and retains
the worker's existing uncertain-effects semantics. Late replies cannot create a
fresh HTTP receipt. The host must keep this WAL admission path exclusive;
retained producer metadata is configuration, never current credentials or proof
that old rows at/below its captured floor were authenticated.

Evidence: `target/shared-native-admission-20261011T062021+0200/`. Real TLS introspection/Axum
regression verifies original grant/deadline forwarding to a grant-only sink.
Real filesystem tests verify original budget, cancellation and durable replay;
shared adapter grants are synthetic trusted-host reports. Matching source-bound
writer review/final campaign is required. Actual native owner/provider/WAL
composition, scoped derivation/read APIs, Main wiring and release readiness
remain open. HTTP202 continues to mean synced local WAL, not shared publication,
RPO0 or Standard READY.


## Free public CI cache and fixture budget consistency — 2026-10-11

Public CI keeps standard GitHub-hosted AMD64/ARM64 runners. Immutable official
cache-action v6.1.0 restores only Cargo registry index/archive and Git dependency
databases, keyed by OS, architecture and Cargo.lock. A successful develop push
build saves those downloads before later qualification, so a failing runtime
check does not discard reusable dependencies. No target binaries/evidence,
credentials/config, paid settings or validation bypass are included. Artifact
retention is1day, matching the repository limit observed in remote annotations.
Official documentation: [dependency caching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
and [pinned action](https://github.com/actions/cache/tree/55cc8345863c7cc4c66a329aec7e433d2d1c52a9).

The native PostgreSQL harness had an expanded240second execution budget but a
remaining180second final rejection threshold. One FIXTURE_SECONDS constant now
controls both; tests accept complete180.5/240second reports and reject over-budget,
negative/nonfinite or invalid elapsed values. Existing10second cleanup reserve,
150second control/30second server fixture limits and production operation/SQL
deadlines remain intact. All18 frozen cases and owned cleanup are still required.

Evidence: `target/free-ci-cache-20261011T063641+0200/`; matching source-bound writer
review/final native campaign is required. Public run38110565434 on73e0cd5 fails
AMD64 query-retirement and ARM64 PostgreSQL; the budget mismatch is a concrete
local bug, not a confirmed remote root cause. Actual remote acceptance, cache
hits/speed measurements, native ARM64 runtime and release gates remain open.


## Native owner/provider/HTTP/WAL composition — 2026-10-11

The owned native admission fixture creates a real stopped Catalog4Scoped store,
activates scope generation through the owner API and captures a preexisting
legacy WAL row at floor1. SharedAdmission's public constructor consumes the real
owner-produced enrollment pin. Activation-only or canceled pins, foreign streams,
missing recovery capacity and later reuse after the WAL advances beyond the
captured floor fail. Owner inspection verifies the original enrolled startup/floor
and can initialize admission while that floor still matches. No fixture bypass
or synthetic grant constructor is used here.

The existing finite TLS introspection provider supplies native backend-verified
request grants. Actual loopback HTTP rejects absent/inactive/expired/unbound and
query-only actors, spoofed forwarding/role headers and canonical account mismatch.
Plain admission and bootstrap-token routing cannot append to the shared adapter.
An authorized request receives202 only after synced WAL, preserving the captured
floor. An expired original deadline cannot append; a full WAL respects the HTTP
request budget and real short-lived provider grant expiry without renewed worker
deadlines. Counters/caller seats settle, shutdown joins workers and WAL replay
compares complete canonical serialized events and exact original sequences.

Evidence: `target/native-owner-http-wal-20261011T064743+0200/`; matching source-bound writer
review/final native campaign is required. The harness requires both feed/audit
and native admission test identities, unique qualification markers and exact
successful result counts; missing/duplicate markers cannot close acceptance.
CI prebuilds the exact default-feature admission fixture before its finite run.
These are actual local owner SQL/TLS-provider/HTTP/WAL effects with synthetic
laboratory identities. Standard Main/READY, scoped derivation/publication/read
integration, persistent managed-provider behavior and external gates remain open.


## Verified native CI build-order corrections — 2026-10-11

Public run38112482427 archives were downloaded anonymously through
[nightly.link](https://github.com/oprypin/nightly.link) and verified against the
official GitHub artifact SHA256 digests before reading report data; no archive
code, credential or app installation was used. ARM64's control/server cases pass
but the TLS helper spends its25second runtime budget compiling the exact default
server test binary. CI now prebuilds `cargo test -p signal-server --bin signal-server
--no-run --locked --offline` before entering the native fixture. Production and
provider deadlines remain unchanged.

AMD64's process log rejects S3 configuration because its normal server lacks the
s3-query feature. Default-feature integration test builds overwrite the earlier
all-feature normal executable. CI restores `cargo build -p signal-server
--all-features --locked --offline` after all default native fixture operations
and before IdP/S3/query process gates. The local before-restoration simulation
reproduces the exact missing-feature failure; the corrected process simulation
must pass under its matching source-bound campaign.

Evidence: `target/ci-feature-order-20261011T070904+0200/`, with the verified archives
retained under `target/ci-qualification-queue-20261011T070403+0200/public-artifacts/`.
These are verified failed-run causes and local workflow corrections. Fresh remote
AMD64/ARM64/full container/runtime qualification still needs successful observed
jobs and retained matching reports; no current release acceptance is implied.


## Native authenticated mixed-history scoped publication — 2026-10-11

The owned native admission fixture now continues through deterministic rules,
original scoped preparation, Parquet upload and atomic PostgreSQL publication.
The original enrollment floor remains1: the existing WAL row is published with
its exact ordinary finding bytes and no scope claim, while the actually TLS-
authenticated HTTP row at sequence2 receives canonical audit/account/resource
facts. Attempts to claim the old row or substitute another canonical account
fail before publication. Retained attributes and reopened WAL sequences do not
supply authentication; the fixture carries its observed exclusive native admission.

Preparing retains the original request without publishing findings or advancing
the checkpoint. Dropping the prepared capability and reopening the real WAL
preserves the complete saved bytes. Reconciliation uses that original request;
atomic core findings, exact manifest and companion claims precede checkpoint2
and slot clearing. A second resume is empty. Runtime table reads remain denied.

Evidence: `target/native-scoped-publication-20261011T072254+0200/`; acceptance
requires its source-bound writer review and matching passed final campaign.
This is actual owner/SQL/native TLS/HTTP/rules/WAL composition with emulated,
parent-retained object versions. It does not establish scoped shared HTTP reads,
Standard Main/READY, populated scope restore, private consumers or AWS/ARM64/
release acceptance. Existing frozen schemas001–008 and production Rust remain
unchanged. Independent full-item review remains open.
