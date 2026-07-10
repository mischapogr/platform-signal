# Object-backed query publication and committed snapshots

Status: selected frozen S3-QUERY task, passed_simulated (Small local profile). This extends the existing
EventStore/query seam without adding services or private source policy. EVIDENCE
is passed_simulated independently. Query objects are not protected originals,
native source proofs, source ACKs or distributed custody.

## Small publication boundary

Keep one server/storage owner per stream. Encode the existing lossless storage
schema into bounded UTC date/hour Parquet objects. Publish immutable objects with
conditional create, then an immutable manifest under a deterministic first-WAL-
sequence commit slot. Every manifest binds stream UUID, storage/manifest versions,
first/last sequence, event count, predecessor manifest reference and exact object
references (key, version or conditional ETag, byte count, SHA256, rows and decoded
scan budget). Different first-sequence slots may not create overlapping committed
ranges or bypass a predecessor. A bare PUT, listing entry or cache file grants no
commit or source custody. Return storage completion only after required object and
manifest bytes have been read back and validated under the original deadline.

Small retains a synced stream/backend-bound initialization witness after a complete
bounded inventory establishes an empty owned query namespace, before creating its
first query object. An exact local head then selects the committed manifest chain.
This allows a unique fully validated first-manifest write with a lost response to
recover even if subsequent WAL replay uses smaller batches. Missing both controls
with existing commits is unknown authority: queries hold; only complete exact
initial WAL-content reconciliation can adopt that candidate. Unknown branches,
foreign/partial controls and missing predecessors are preserved and hold progress.
The trusted publisher alone initializes/advances these controls; their generic
I/O methods are not authentication, endpoint identity or protected custody.

Publication remains bounded and at least once. Exact already-created content is
idempotent; conflicting content fails closed. Lost responses are uncertain until
explicit bounded discovery/readback reconciles the same slot. Retried WAL batch
boundaries may differ; verify stored sequence/event content before advancing.
Never blindly overwrite or infer success from a matching length/ETag. Conditional
ETags are opaque equality guards, not content hashes. No latest-version fallback
when an exact version is pinned. Missing objects, checksum/schema/sequence
mismatches, unknown commit metadata or exhausted inventory hold progress.

The selected backend must keep bytes immutable under each pinned version/ETag and
provide complete, strongly consistent owned-prefix inventory. Reconciliation checks
every historical manifest/data reference's current ETag and byte length, and any
version the listing supplies, before advancing; drift or absence holds. S3
ListObjectsV2 omits versions: matching nonempty ETag/length permits this drift
check without changing the pinned version or proving that historical version is
available. Actual authenticated reads retain and verify that exact pin. Previously committed history is retained
through these immutable references and authenticated manifest predecessors, without
rereading every cold Parquet object on each WAL batch. This is not continuous
historical data scrubbing: selected query reads, actual replay and uncertain
candidates authenticate bytes, schema and rows. A metadata snapshot exposes only
finite references, never validated event results; same-identity byte corruption
must fail an actual selected read. A backend that mutates pinned bytes is unqualified.

Storage receipts retain exactly the submitted first/last sequence, independently
of a recovered store high-water mark. Whole or partial replay compares actual
sequence/event content, including gaps and changed batch boundaries. Counted
unreferenced query objects can be reused only after exact content/identity
reconciliation; quota reservation charges new objects and bytes once. No object
is deleted by publication or recovery. Recovery catalogs and returned snapshots
have finite metadata bounds and retained admission leases.

The Small exclusive owner and immutable slots are not Standard distributed
fencing. SHARED-CONTRACT/SHARED-RUNTIME later publish references/progress with
transactional owner epochs; OBJECT-CUSTODY qualifies the stronger receipt. This
item must neither invent consensus nor close those gates.

## Query and cache boundary

The next Small slice adds a generic committed-file source for the existing query
engine. It selects bounded references and sums selected decoded bytes before any
data-object GET. Each selected pinned object is authenticated and its actual
Parquet schema/rows/partition inspected before materialization or DataFusion.
The exclusive derived root has finite file/disk quotas, immutable SHA-named
copies, and a stream/backend binding. Copies survive restart and can be rebuilt
after an operator deletes the derived root while the server is stopped. There is
no eviction while readers exist in this slice; quota exhaustion rejects the whole
query. RETENTION owns later eviction/deletion and reader horizons. Every selected
object is still read/authenticated remotely: this first materialization mechanism
makes no cache-hit/network-cost optimization claim. Shutdown drains query physical
I/O before releasing the derived root. A failed query never changes source ACK,
protected originals or committed object references.

Readers discover bounded committed manifests and authenticate exact referenced
bytes, not every object matching a bucket prefix. Time ranges prune UTC hour
partitions before object reads; query snapshots retain referenced versions.
Reuse the existing lossless Parquet schema, DataFusion URL filters, projections,
result/time/memory limits and bounded physical I/O. Object copies/cache entries
are derived: deletion or restart rebuilds them from committed references under
bounded quotas, while cache corruption/missing objects yields an explicit error.
Do not silently return empty success or mix partially restored snapshots.

Original/native evidence has a separate private authority, namespace and retention.
Neither query cache policy nor orphan cleanup may delete protected originals.
Unreferenced query objects remain invisible and count against storage limits.
Recovery classifies them without treating object existence as commitment. A
bounded inventory/reachability report precedes reclamation; age-based policy,
supported reader horizons and safe deletion remain the RETENTION task.

## Finite implementation and acceptance

Within this existing item, finish: strict versioned manifests/references; bounded
idempotent conditional publication and readback; committed snapshot discovery and
restart/orphan classification; actual query/cache rebuild and monolithic server
wiring; reproducible local object/queue outage, duplicate, malformed/permission,
uncertain-write, replay/crash and pruning checks. Each slice receives focused
regressions and review; the parent passes only after applicable full gates and
actual local storage/server simulation. Native AWS/IAM/KMS/Object Lock and AZ-loss
behavior remain external; an in-memory object store alone is not process-restart
or AWS proof. Evidence stays under `target/goal-execution-20261007/S3-QUERY/`.

The selected object_store version is0.13.2. Context7 resolve is quota unavailable;
use its exact locked source and official docs for
[conditional PUT](https://docs.rs/object_store/0.13.2/object_store/enum.PutMode.html),
[version/conditional GET](https://docs.rs/object_store/0.13.2/object_store/struct.GetOptions.html)
and the [backend contract](https://docs.rs/object_store/0.13.2/object_store/trait.ObjectStore.html).
Do not add AWS SDK features or dependencies without a bounded concrete use.

## First accepted slice

Strict manifest/reference content binding and UTC partition pruning pass four
regressions, default592/all-feature626 strict workspace checks and focused source
review. Validation does not grant commitment or prove actual predecessor/Parquet
rows/sequence/partitions/decoded sizes; those remain publication/recovery inputs
and must be checked before a query snapshot is exposed. The parent S3-QUERY item
remains in_progress. Context7 quota and real-environment exceptions remain visible.

## Bounded Parquet preparation and inspection

The accepted codec seam uses one ordinary CPU thread and one admission lease;
borrowed typed intake validates finite nesting/nodes/scalars before canonical wire
copies. Prepared and inspected result ownership retains that lease. Physical work
keeps it after caller timeout/drop. Before inspecting untrusted Parquet, bounded
footer/page metadata, actual decoded byte budget and raw canonical JSON byte/node/
depth preflight prevent unchecked page/Value allocations. Exact schema, row count,
partition/sequence range and SHA references are checked against actual bytes.
This produces sealed prepared/inspected data only. It performs no disk/network
operations and cannot establish a manifest commit, source ACK or custody.
Seven regressions, storage45/default599/all-feature633 strict acceptance and focused
review pass; publication/recovery/query/server remain pending in the parent task.

## Bounded object I/O extension contract

The next publication slice uses conditional Create only, explicit current-state
discovery for reconciliation, and pinned version/ETag reads. Reads verify returned
metadata/identity/range and exact SHA/length; no latest fallback is allowed. A
listing is finite discovery metadata with unknown content hash, never commitment
or coverage. It must be followed by authenticated exact discovery/readback before
becoming a selected reference. No delete/overwrite/multipart operation is exposed.

One physical ordinary worker serializes admission, backend work and retained
read/inventory replies. Local filesystem work executes outside Tokio's blocking
pool. Audited remote backend futures execute through the selected runtime under
the original cancellation/deadline; cancelled/lost writes remain uncertain. The
backend extension is trusted to bound its own HTTP headers/metadata/body decoding
and any internal tasks. Generic object_store injection alone does not qualify a
remote adapter; the selected S3 HTTP connector and local server must enforce and
exercise those backend bounds separately. File payloads from remote backends fail
closed. LocalFileSystem is a filesystem simulation, not S3 durability or a
synced-write guarantee; production storage completion still requires the selected
backend's qualified durability and publication readback.

Backend cancellation must either stop its work or retain independently bounded
resources until any detached work exits; this generic trait port cannot enforce
that property inside an injected implementation. The selected S3 adapter requires
its own audit and acceptance.

Small startup binds stream/backend UUIDs in a bounded synced control record and
locks the same local/RWO control root on the physical I/O worker. That worker
retains ownership through non-cancellable disk work after caller timeout/drop.
Unknown, oversized, partial or mismatching controls fail closed and are preserved.
All owners of the same stream must use that same control root; different roots
or independent hosts are not fenced by this mechanism. The binding records
configured identity, not proof of endpoint authority or evidence custody.

## Accepted object I/O and Small owner slice — 2026-10-08

Nine I/O/owner regressions and eight codec regressions pass. The complete storage
suite has55 passing tests; strict default609/all-feature643 workspace gates and
focused reviews pass (six parent-invoked subprocess helpers remain ignored).
Evidence: `target/goal-execution-20261007/S3-QUERY/io-validation-late-final/validation.json`.
Two actual failed async reproductions exposed completed replies bypassing their
deadline; final context checks now reject those replies, release physical leases
and count rejection exactly once. Original failed logs and the earlier607/641
boundary are retained. Recovered control descriptors sync before readiness and
explicit unlock covers cloned/inherited descriptions and every failure path.

This acceptance is a generic audited backend port and Small local ownership,
not S3 durability, committed publication, source ACK, query/cache/server integration
or distributed fencing. Conditional publication/recovery and the selected bounded
S3 adapter/local server simulation continue within the same parent item.

## Accepted Small publication/recovery slice — 2026-10-08

Thirteen publication and four new head/genesis regressions pass; storage72,
default626/all-feature660 strict workspace checks and focused review pass. See
`target/goal-execution-20261007/S3-QUERY/publication-validation-accepted/validation.json`. Retained failed initial logs record the local-socket sandbox boundary.
In-process lost-response, cancellation and explicit owned-control reopen tests
are not process-crash or S3 durability proof. The head/genesis witness, exact
submitted receipt range, identity-drift guard and byte-validated orphan reuse
resolve review findings. Selected adapter, cache/query/server and actual local
process simulation continue; S3-QUERY and every real-environment gate remain open.

## Accepted selected S3 adapter slice — 2026-10-08

Optional `s3` selects object_store0.13.2 AWS signing with a bounded custom HTTP/1
connector. Explicit endpoint/region/bucket and static host credentials avoid
ambient metadata/STS/refresh probes. Default HTTPS validates TLS server identity
using WebPKI roots; explicit local HTTP opt-in accepts only literal loopback IPs.
There is no insecure-TLS switch. This acceptance implies no actual TLS runtime
qualification or independent signing certification.

The bounded I/O port exposes GET/HEAD/conditional PUT; scope-less direct HTTP
calls are rejected and counted. URI4KiB, headers64/32KiB, control/XML/error256KiB
and configured data-object limits precede backend decoding. Connections retain
the original deadline/cancellation and physical admission, with no driver task,
pool, proxy, redirect or implicit retry. Native DNS runs on the retained ordinary
worker; cancellation cannot release that lease before an OS resolver exits.
Origin-form preserves signed Host/path/query. Host credential and provider/store
Debug redact the access-key ID, secret and session token.

Nine owned native-wire tests and one versionless-inventory guard pass; storage73/
default and82/S3, default627/all-feature670 strict gates and focused review pass.
Tests cover conditional Create/pinned reads, two commits/reopen/exact prefix replay,
versionless listing/pagination, IPv6, malformed/oversized responses, denial/
throttling/redirect, wrong returned version, missing scope and cancelled socket
closure. These finite in-process fixtures do not qualify disk/process durability,
AWS/IAM/KMS/Object Lock/TLS runtime, source custody or throughput. Query/cache,
monolithic server and persistent process simulation continue; S3-QUERY stays open.
Evidence: `target/goal-execution-20261007/S3-QUERY/s3-adapter-validation-accepted/validation.json`
and `s3-adapter-review.json` in its task directory. Earlier failed logs are retained.

## Accepted committed query/materialization slice — 2026-10-08

Eight actual Parquet/DataFusion object-query regressions and three cache tests pass;
storage76/default and85/S3, default638/all-feature681 strict workspace gates and
focused source review pass. The generic `QueryFileSource` retains the existing
local constructor and URL filters. Committed UTC selection checks file/decoded
budgets before data GET, authenticates pinned bytes/schema, and materializes
immutable derived copies in a bounded, exclusively owned Small cache. Nested
attributes, account/source filters, pruning, cache deletion/rebuild, quota,
denial/corruption, cancellation and retained physical ownership are exercised.
No eviction or source-original deletion is authorized by the query cache.

A reproduced high review finding showed shutdown returning while remote selection
remained admitted. Shutdown now drains all admitted query lifetimes before local
I/O; the original deadline and cancellation remain binding. Cancelled publisher
commands retain admission until physical child workers actually drain. Red/green
logs and source hashes are retained. Final evidence:
`target/goal-execution-20261007/S3-QUERY/query-materialization-validation-resumed/validation.json`
and `query-materialization-review.json`. Completed unchanged-source formatting,
Clippy and build checks were reused after a session interruption; only unfinished
workspace tests and the workspace check were resumed, with interrupted logs kept.

S3-QUERY remains in_progress. Next: monolithic server backend/configuration,
query-before-source shutdown and bounded append/query contention, then persistent
source/server outage, SIGKILL and replay simulation. This slice provides no server
process, AWS/TLS/runtime/custody/HA/native ARM64 or release qualification.

## Monolithic selected backend contract — implementation in progress

`signal-server` keeps a local filesystem backend by default. Explicit
`storage.type: s3` requires the `s3-query` build feature; missing features,
unknown types or unused S3 settings fail startup without local fallback. The
same WAL stream binds the Small query owner. Startup authenticates its committed
chain before the existing storage/WAL frontier compatibility check and readiness.
Production Docker builds explicitly include `s3-query`; changed images still need
fresh qualification. No version or publication is selected here.

S3 settings are endpoint, region, bucket, stable non-nil canonical backend UUID,
owner directory (`storage.directory`), derived cache directory and finite cache,
object, inventory and catalog limits. YAML uses `s3_endpoint`, `s3_region`,
`s3_bucket`, `s3_backend_id`, `s3_cache_directory`, `s3_cache_files`, `s3_cache_bytes`,
`s3_object_bytes`, `s3_inventory_objects`, `s3_catalog_bytes` and string
`s3_allow_loopback_http: 'true'|'false'`. Corresponding environment overrides use
`SIGNAL_S3_*` (cache directory is `SIGNAL_S3_CACHE_DIR`), and backend selection
uses `SIGNAL_STORAGE_TYPE`. Credentials come only from host environment
`SIGNAL_S3_ACCESS_KEY`, `SIGNAL_S3_SECRET_KEY` and optional `SIGNAL_S3_SESSION_TOKEN`.
There is no ambient credential provider or credential value in YAML. Explicit
loopback HTTP is only for local fixtures; ordinary endpoints require HTTPS.

Publisher admission contention is typed `Busy`, distinct from durable quota
`Full`. The single consumer retries only `Busy`, retaining its bounded batch and
original deadline/cancellation. Quota, corruption, timeout and uncertain effects
leave the checkpoint unchanged. Query contention uses existing Busy/429 rather
than resource-limit/413. Publication completes before rule/findings completion
and the shared WAL checkpoint, as on the local backend.

Reported storage bytes/files count the last fully validated remote query inventory
or completed commit, including manifests and orphans; they exclude derived cache
and protected originals. Actual committed/replayed rows and rejected quota,
timeout and failed operations are counted separately. Inventory freshness is not
continuous historical scrubbing or external storage custody.

Shutdown closes ingress, cancels/drains queries before source release, then drains
the consumer and storage/WAL under one original shutdown deadline. A failed query
drain cannot explicitly release the source owner. Physical query jobs retain the
source owner through actual kernel work, including caller/engine drop; no new
worker is started to wait for a stalled read. Persistent simulator/server acceptance
and the parent S3-QUERY status remain pending until executable evidence passes.

## Accepted monolith/persistent simulation — 2026-10-08

S3-QUERY is passed_simulated. Optional `s3-query` backend selection stays inside
`signal-server`; default local storage and unsupported/configuration failure
behavior are preserved. Startup authenticates committed object state before the
existing WAL frontier check. Busy query/append contention is distinct from durable
quota: only Busy retries under the original batch deadline, and no unfinished
batch checkpoints. Queries drain before source release; failed drain/drop retains
the source through physical query jobs. The actual stalled-read red/green regression
and source review are retained.

Strict workspace acceptance passes default641/all-feature686 (storage76/default,
85/S3; six parent-invoked helpers ignored standalone). Final evidence:
`target/goal-execution-20261007/S3-QUERY/server-backend-validation-corrected/validation.json`
and `server-backend-review.json`. Earlier quota-fixture failures used an undersized
50ms physical-inventory deadline; corrected quota checks allow5s while contention
keeps its50ms original deadline. Superseded logs are preserved.

The real monolith and disk-backed bounded loopback S3 simulator pass11 scenarios:
committed search/findings/pruning, denied/corrupt/malformed/oversized/throttled/
unavailable reads, stopped cache deletion/rebuild, actual source/server SIGKILL
after unreferenced data publication, and a second crash after synced manifest but
before reply/local head. WAL checkpoints stay behind unfinished effects; recovery
preserves four exact canonical events/findings with four manifests/eight objects,
no duplicate query rows or altered prior events. Six helper regressions verify
hard output caps, creation interruption/evidence failure, SIGTERM, both-child
cleanup and failed-report nonzero. Evidence:
`target/goal-execution-20261007/S3-QUERY/server-simulation-final-reviewed/report.json`,
`server-simulation-checks/` and `server-simulation-review.json`.

CI runs these helper/process gates through its existing bounded wrapper on both
native architectures. Docker builds explicitly include `s3-query`; this source
change requires a fresh image/campaign. Actionlint passes locally. No remote CI
execution, fresh image, actual TLS/AWS/IAM/KMS/Object Lock, native ARM64/EKS,
shared HA, custody/completeness or release qualification is implied. Standard
shared fencing remains a later item. Next: RETENTION in the frozen ledger.
