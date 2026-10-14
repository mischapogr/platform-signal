# Generic object-backed custody v1

Status: local simulated acceptance, 2026-10-14. Trusted object verification,
actual PostgreSQL coordination, authenticated API and producer retention pass.
Actual AWS retention and account/AZ isolation remain external gates.
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
must obtain fresh authenticated confirmation. The SDK never automatically deletes the original or acknowledges a source.
Adapters retain physical I/O ownership on dropped futures. There is no provider
DELETE, schema bootstrap or replica increase.

## Required completion evidence

Retain the original copy through PUT-only crash, lost commit reply, inaccessible
or substituted version, shortened retention, revoked authority, stale/competing
owner, conflicting duplicate, cancelled/late control completion and producer
restart. Qualify real PostgreSQL record replay/quota/fencing and independently
retained pinned objects, then actual authenticated server/API and producer
relinquishment. Measure only the stated failure model; local simulation does not
prove AWS/AZ/account-loss custody.

## Authenticated Standard API and producer SDK

The optional Standard `custody` configuration supplies `schema_version: 1`,
`key_prefix`, `expected_bucket_owner` (12 digits), `authority_revision` (32 bytes, not all zero) and a future UTC `required_until`. The key prefix must
lie beneath `query/<configured-stream>/`. Configuration is private deployment
policy. Startup requires the selected producer role's explicit `record_receipt`
RPC capability before opening the WAL or becoming ready. Default producer and
lifecycle profiles retain their narrower privileges.

With this configuration, native mandatory-mTLS Standard mounts
`POST /v1/custody/confirm`. Authentication requires the distinct
`confirm_object_custody` permission with explicit `all` dimensions; ingest does
not imply it. A strict JSON request contains `schema_version: 1`, a fresh
`request_nonce` and the immutable `description`. The body caps at64KiB and
concurrent requests at4. The entire operation shares a five-second cancellation
and deadline context, including authentication, both retained reads, receipt
coordination and final permission checks. Success returns200 with no-store
confirmation metadata; HTTP202 remains synced WAL admission.

`signal_collector_sdk::object_custody::ObjectCustodyClient` uses a separately
configured HTTPS endpoint, bearer credential and trusted TLS configuration. It
generates a new nonce for every attempt, validates the exact description/digest
and returns an opaque `FreshCustodyPermit`. Its single physical HTTP worker
retains ownership through cancellation. Permission expires against the original
request's monotonic deadline, server elapsed-plus-remaining budget, identity
lease and UTC retention horizon. A saved response cannot authorize a restart.
The application must call `checked_confirmation` immediately before any
explicit original-copy release; failed or uncertain confirmation keeps the copy.

## Local acceptance — 2026-10-14

`target/object-custody-api-20261012/ACCEPTANCE.json` records12 frozen gates:
932 default and993 all-feature tests, both strict Clippy modes,14 workspace
boundaries and36 launcher guards. Actual PostgreSQL TLS, signed S3 protocol,
native identity/mTLS API and SDK pass in13.56s. The actual Standard executable
and SDK pass in38.34s, retaining originals after PUT-only or stopped-server
attempts, denying ingest-only permission, and obtaining fresh confirmation of
the same description after restart before explicit test-only release.
Owned resources are removed. Provider retention is simulated; this does not
qualify AWS/AZ/account loss, native ARM64, current images or a release.

## Consistent stopped restore — 2026-10-14

Custody-only originals are protected restore roots even when absent from query
manifests and explicit object pins. The stopped PostgreSQL adapter bounds receipt
inspection to128records and256KiB of reference bytes; larger inventories fail
explicitly. Reserved custody references must retain canonical bytes, original
receipt ID/scope and zero progress. Every exact backend/key/version/length/hash
must match the independently retained inventory. Missing inventory or inaccessible
originals refuse restore before readiness. Historical receipt metadata never
recreates current identity or retention authority.

`target/restore-custody-roots-20261014/ACCEPTANCE.json` binds933default and994
all-feature tests, both strict Clippy modes and the18-case actual PostgreSQL
matrix121.29s. The custody-only object, omission/missing-object refusal and exact
source-to-destination receipt bytes are exercised. Provider authority/retention
remain synthetic; native restored-generation fresh custody is still a separate
integration gate.
