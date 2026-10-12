# Generic object-backed custody v1

Status: implementation slice; OBJECT-CUSTODY remains incomplete until trusted
object-adapter, actual PostgreSQL, server/API and producer-retention acceptance.
This follows [the reliability contract](27-product-architecture.md#5-reliability-objectives-and-custody).
HTTP202 remains synced local WAL admission. Query publication, completed
detection and M3 protected-original validation remain separate.

## Immutable description and trust

The v1 description binds a non-nil receipt ID, complete configured control scope,
canonical enrolled backend/key/non-null version, exact byte length and SHA256,
and a caller-pinned UTC retention deadline. One object is at most64MiB and the
complete reference is at most64KiB. Unknown fields reject. The description is
persisted under the `object_custody_v1` domain in the existing bounded receipt
record, with prepared/source counts0; it does not represent detection progress.
Its exact serialized bytes and digest stay unchanged on retry/takeover.

Scope and required retention come from the trusted embedding application,
never producer-selected policy. A separately configured verifier must perform
bounded exact-version readback and verify the complete digest/length, current
credentials, retention horizon and configured authority revision. A successful
PUT, HEAD, version ID, query manifest or producer assertion cannot implement
this verification. Archive isolation and actual provider retention require their
own environment evidence; no trait invocation alone proves them.

## Coordination and original-copy retention

Use one cancellation/deadline context for the entire operation:

1. Validate scope/lease/description before I/O; verify retained accessibility.
2. Commit the exact idempotent receipt with current owner/generation checks.
3. Verify retained accessibility again, then resolve that same record under
   current owner/generation checks before returning a permit.

The final resolve uses the same bytes and ID and does not charge another record.
Any cancellation or timeout after a control submission can have committed and
is reported as uncertain. Never invent another ID or release the producer's
last recoverable copy on uncertainty. Conflicting bytes, stale ownership,
expired retention, failed integrity or substituted authority grant no permit.
Retry uses the original immutable description and fresh verification.

The in-process permit is opaque, non-cloneable and non-deserializable; it expires
with the operation/cancellation context and retention deadline. Serialized receipt
metadata is not a persistent authorization or source ACK. A restarted producer
must obtain fresh authenticated confirmation. No automatic producer deletion,
HTTP endpoint, schema bootstrap, replica increase or provider DELETE is added by
this library slice. Adapters retain physical I/O ownership on dropped futures.

## Required completion evidence

Retain the original copy through PUT-only crash, lost commit reply, inaccessible
or substituted version, shortened retention, revoked authority, stale/competing
owner, conflicting duplicate, cancelled/late control completion and producer
restart. Qualify real PostgreSQL record replay/quota/fencing and independently
retained pinned objects, then actual authenticated server/API and producer
relinquishment. Measure only the stated failure model; local simulation does not
prove AWS/AZ/account-loss custody.
