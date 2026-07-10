# Object-backed query publication and committed snapshots

Status: selected frozen S3-QUERY task, in_progress. This extends the existing
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

Publication remains bounded and at least once. Exact already-created content is
idempotent; conflicting content fails closed. Lost responses are uncertain until
explicit bounded discovery/readback reconciles the same slot. Retried WAL batch
boundaries may differ; verify stored sequence/event content before advancing.
Never blindly overwrite or infer success from a matching length/ETag. Conditional
ETags are opaque equality guards, not content hashes. No latest-version fallback
when an exact version is pinned. Missing objects, checksum/schema/sequence
mismatches, unknown commit metadata or exhausted inventory hold progress.

The Small exclusive owner and immutable slots are not Standard distributed
fencing. SHARED-CONTRACT/SHARED-RUNTIME later publish references/progress with
transactional owner epochs; OBJECT-CUSTODY qualifies the stronger receipt. This
item must neither invent consensus nor close those gates.

## Query and cache boundary

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
