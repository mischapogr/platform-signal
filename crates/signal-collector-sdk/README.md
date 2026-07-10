# Collector and enrichment hooks

This SDK provides generic `Collector` and `Enricher` traits. Implementations use
`#[signal_collector_sdk::extension]` (the re-exported `async_trait` macro) and may
be stored as `Box<dyn Collector>` or `Box<dyn Enricher>`. Collectors receive an
`Arc<dyn signal_protocol::EventSink>`; successful admission transfers ownership
according to that sink's documented durability boundary. The SDK adds no queue.

Use `run_collector` and `apply_enricher` to invoke extensions with a validated
`ExtensionContext`, containing a cancellation token and an absolute deadline.
Timeouts must be positive and at most 24 hours. Helpers drop unfinished futures
on timeout or cancellation and spawn no workers. Extensions must yield, bound
all input and buffers, apply remaining deadlines to network/disk operations,
and ensure future cancellation stops their work. Synchronous blocking or tasks
spawned inside an extension cannot be forcibly cancelled by these helpers.
Admission cancelled after a sink's commit may be uncertain; duplicate-tolerant
replay remains the sink's responsibility.

`apply_enricher` validates the canonical event before cloning it, enriches a
staged copy, validates the result, and commits only on success. Failures,
cancellation and timeout preserve the caller's event. Schema version, event ID,
event timestamp and observed timestamp are immutable. Other fields can be
annotated subject to canonical semantic validation. The enrichment hooks inject
no attribute namespace or company metadata. Optional public source profiles define
their own diagnostic paths. Arbitrary nested JSON and precise JSON
numbers remain unchanged unless the extension edits them.

`EventLimits` defaults to 64 KiB serialized JSON, attribute depth 32 and 16,384
attribute nodes. Positive configurable ceilings are 2 MiB, depth 64 and 65,536
nodes. Borrowed string, key and numeric digit lengths are charged before serialization,
with a minimum charge per attribute node and tag. Iterative attribute traversal
checks cancellation and deadlines and precedes capped serialization and cloning.
Programmatic timestamps must use wire years 0000 through 9999. Limits and context
are runtime options, not serialized contracts; `SignalEvent` remains the
versioned serialization contract.

Extensions are trusted in-process code. Their own allocations and external side
effects cannot be rolled back; limits bound accepted input/output and SDK work.
Extension errors contain static classifications rather than plugin diagnostics
or credentials. Implementers should return `Failed` for private error details.

`OverlayPath::resolve(Some(path))` selects an explicit external directory;
`resolve(None)` reads `SIGNAL_OVERLAY_PATH`. Missing or empty paths return
`MissingOverlayPath`. Selection does not access the filesystem, and there is no
compiled default. Providers own that path and implement their own bounded,
cancellable reads. Private configuration and policy remain in the external repo.

`EnrichmentProvider::load(context)` returns `Arc<dyn Enricher>` after validating
the provider's metadata schema. `RuleProvider::load(context)` returns
`Vec<RuleDocument>`, each with `schema_version: 1` and a nonempty `yaml` string.
Both traits are object safe. Invoke them using `load_enricher` and `load_rules`
to enforce deadlines and cancellation without worker tasks. Returned rules are
transport documents: the consumer must compile their YAML using its rule engine,
including predicate and duplicate-ID validation, before readiness or processing.
The SDK does not depend on the rule engine or accept private policy itself.

`RuleDocumentLimits` defaults to 64 documents, 64 KiB per document and 1 MiB total
YAML bytes. Positive configurable ceilings are 1,024 documents, 2 MiB per
document and 16 MiB total. An empty document list is allowed. Helpers enforce
these bounds on returned output; trusted providers must bound their own reads
and allocations before returning. `RuleDocument` serialization rejects unknown
envelope fields, and the loader rejects unsupported schema versions.

Use `validate_event(&fixture, limits, &context)` to validate canonical fixtures
or collected events without mutation or cloning. It uses the same bounded
canonical validation as enrichment; `apply_enricher` adds transactional mutation
and immutable identity checks.

## CloudTrail management-record profile

`cloudtrail::normalize_record(raw, &profile, preparation_identity)` is a pure
decoded-record helper. `CloudTrailProfile::new` takes a trusted source name and
bounded recipient-account/region lists; it does not authenticate native claims.
`PreparationIdentity::new` takes caller-pinned non-nil event/receipt UUIDs,
observation time and ordinal. The helper generates no IDs or clock values.

Input is capped at 256 KiB, 16 container levels and 16,384 nodes, counting object
keys as nodes. The decoder charges before child allocation and rejects duplicate
decoded keys, invalid UTF-8/JSON, nonfinite floating exponents and trailing input.
Unknown JSON objects cannot trigger Serde's internal number-map convention.
Profile lists allow at most 128 accounts/64 regions; source names are 128 bytes
and region strings 64 bytes. Prepared event JSON is capped at 64 KiB.

The result borrows exact original bytes and exposes SHA-256, immutable canonical
event/bytes, disposition and bounded reason codes. Field/scope rejection returns
`quarantine_record` without an event. Unsupported/missing detection semantics
may return `emit_indeterminate` with unknown fields omitted. This is a preparation
disposition, not an implemented coverage or detection assessment. Caller copies
and multiple results require a separate bounded owner. Historical prepared pins
qualify canonical content; new encoding is deterministic, and pending receipts
must replay stored bytes rather than re-encode under a changed implementation.

This API parses one record, not gzip objects or notification envelopes. Original
retention, source authorization, custody, proof validation, checkpoints and ACKs
remain the application's responsibility. Nothing is sent or durably retained by
the helper. See [the profile and custody contract](../../docs/29-cloudtrail-source-receipt.md)
and the actual native-to-finding tests in `apps/signal-server/tests/cloudtrail-profile.rs`.

## SourceCoverage validation and assessment

`signal_collector_sdk::coverage` provides a pure SourceCoverage v1 mechanism.
`CoverageProfile::parse` and `CoverageContext::parse` validate trusted local
configuration; `ValidatedCoverage::parse(record_bytes, Some(&profile))` admits
one bounded immutable assertion and returns static typed errors. Resolve the
exact profile ID/revision in the consuming application. Parse success does not
authenticate an observer or check the contents of a proof reference.

`validated.assess(&context)` evaluates current or historical coverage without
changing verification/expiry times. `assess_coverage(record_bytes, profile, &context)`
maps missing profiles and invalid candidates to unknown coverage. Assessment
serialization carries `schema_version: 1`, `status` and zero/one `reason_codes`.
An absent match is still a separate detection decision, not a coverage result.

Record, profile and context inputs are limited to 65,536 raw UTF-8 bytes before
parsing. Records have 1,024-byte text limits, 128 gaps, 32 proof references and
16 attributes per scope. Duplicate/unknown keys, missing required nullable fields,
invalid UTC/calendar timestamps and inconsistent profile/status claims fail
closed. Time budgets and clock skew compare full fractional seconds; immutable
historical assertions survive current expiry/observer-health changes.

The [contract and acceptance](../../docs/source-coverage-contract.md) describe
the exact wire/summary/binding rules. The module adds no I/O, queue, observer,
coverage store, server wiring or private policy. Run its focused requirements with
`cargo test -p signal-collector-sdk --test coverage`.

The separate [`signal-coverage`](../signal-coverage/README.md) library depends on
this validator for bounded local persistence. The SDK has no database dependency;
trusted intake/retry policy and observers remain separate tasks.

The public integration tests establish local compatibility of generic hooks.
They do not provide proof of an external overlay integration, private detection,
released dependency, or deployment.

## Local source-receipt store and progress

`receipt::ReceiptStore` implements one private local root, one retained immutable
receipt and one physical blocking disk worker with a queue capacity of one.
`ReceiptBinding::from_json` accepts the complete bounded canonical v1 binding
from trusted application configuration; it is not authentication inferred from
native metadata. Every `publish`/`inspect`/`replay`/`advance` takes that current full binding and an
`ExtensionContext` deadline/cancellation budget. The root must already exist with
Unix mode 0700; quota is at least 64 MiB. Call `close` to stop admission and await
physical worker exit. A timeout/caller drop may race publication; it neither
proves rejection nor releases a lock while the worker is doing disk I/O.

The frozen [wire contract](../../docs/30-source-receipt-contract.md) is checked in
Rust, including all three immutable and initial-control golden pairs, SHA256,
canonical metadata, record/prepared mapping, event-v1 context and recipient scope.
Original and prepared payloads stay byte-for-byte unchanged. Publication creates
the immutable and initial-control names without overwriting an existing target;
a temporary hard link shares one inode and is removed before directory sync.
Only the final control-directory sync exposes local publication. Orphaned,
corrupt, missing or unsupported custody/ACK/retirement controls fail closed and
are retained. Full-scope,
owner/generation and OS lock checks apply to reopen; consistent older backups
still need independent history reconciliation. Identical retained receipt bytes
replay; a different receipt holds the occupied slot, including after retention
expiry. This slice has no eviction/reclaim API.

Metrics expose queue depth/capacity, active/stopped worker, admitted receipts,
replays, committed progress updates, rejected work, caller uncertainty and
unobserved replies. These are
separate counters, not a sum proving delivery. Caller-retained buffers/results
need an aggregate application budget. Kernel I/O cannot be forcibly cancelled;
a blocked worker retains its lock, and process supervision/runtime shutdown
must account for that physical boundary.

`replay` returns an exact current progress token plus immutable suffix bytes.
`advance` compares the complete binding and prior control, verifies a bounded
actual response body/status using the agent’s shared protocol verifier, then
atomically writes/syncs progress. Partial admission advances only the verified
leading prefix; uncertain/permanent attempts advance zero. Reopen validates
immutable pins, prefix witness and the initial predecessor at revision one.
A mutation error stops dispatch until reopen/reconciliation. The library does
not authenticate a transport endpoint or obtain grants itself.

`transfer_owner` consumes the old store and awaits physical exit after a checked
owner/generation transition. It requires an independently current application
checkpoint and full scope. `open_reconciled` checks that checkpoint before
exposing state; ordinary `open` remains process-local only. The library checks
bounds and equality, not checkpoint authenticity.

The receipt store alone does not authenticate source proofs or establish
provider continuity. Delivery helpers and the optional signed adapter below
compose the bounded reader/retirement/ACK mechanisms. This is surviving
local-filesystem process recovery evidence, not host/AZ/account-loss custody or
source continuity. The caller must qualify original-to-record spans and native
normalization before operating a real collector. Security policy, credentials,
retention horizons and deployment remain in the private application.

## Bounded CloudTrail delivery

`receipt::collect_delivery` composes a one-message `SourceQueue`, exact-version
`CaptureTransport`, retained HTTP publisher and application-owned `DeliveryPolicy`.
It physically retains preparation, sends one batch, and attempts process-local
ACK only after full verified admission. Fresh binding/history checks, durable
intent and exact receipt identity guard side effects. Caller owns credentials,
aggregate work/retry policy and independently authenticated reconciliation.
See [delivery contract and simulations](../../docs/35-cloudtrail-delivery.md).
No AWS credentials, deployment policy or company topology are built into the SDK.


The optional `aws-source` feature provides an official SigV4-signed SQS/S3 HTTP
adapter with application-supplied rotating credentials, trusted endpoint/queue
scope, actual response bounds and finite cancellation. It retains exact key,
version and expected-owner checks and accepts ACK tickets only for the same
full binding. Default dependencies require no AWS SDK. See the delivery contract
for supported source capacity and local signed-wire/runtime evidence; real AWS
and independent protected custody remain separate qualification gates.

## Native CloudTrail byte proofs

`cloudtrail::proof` verifies bounded native RSA digests over exact uncompressed
bytes, then independently checks every referenced log before producing delivery
evidence. Ordered chains distinguish bootstrap, unanchored, temporal gaps,
anchored continuity and backfill-only evidence. Source configuration/category
coverage stays separate. A restored checkpoint requires independently trusted
retention/history; parsing does not grant authority or prevent rollback.

Optional `cloudtrail::proof::aws` adapters use the existing SigV4 transport for
regional keys and exact-version native S3 body/metadata capture, with finite
responses, one active request, cancellation and no retries/latest fallback.
Trusted endpoints, scope and credentials come from the application. The validator
runs on its caller's bounded blocking worker; retained copies need aggregate
budgets. See [protected evidence contract](../../docs/38-protected-evidence-contract.md).
Independent receipt custody, required ACK and actual AWS qualification remain
separate from these read-only byte-proof mechanisms.

## Independent complete-receipt custody

`prepare_custody_manifest` and `verify_custody_witness` bind all framed receipt
bytes, exact pins, stable archive version/commit time and retention. An independently
configured Ed25519 authority verifies a fresh bounded challenge; the resulting
nonserialized token expires at the earliest key/retention/challenge/context limit.
These pure helpers do not publish archives, enforce storage permissions or prove
native source completeness. Crypto work belongs on a caller-owned bounded worker.

`ReceiptStore::verify_custody` commits on the existing physical worker with full
CAS/current-history authority. Explicit independent begin/finish/recovery ACK
updates each consume fresh verification of the exact saved manifest. Quarantine
needs trusted purpose selection; pinned M2 and process-local denials remain.
Tickets narrow source I/O budgets and expose an owner-fence future that adapters
must select during authenticated work. The optional AWS adapter enforces it;
handover/poison/worker exit cannot authorize new deletion using retained tickets.
Already dispatched remote effects remain uncertain. Local retirement preserves
custody controls and never deletes archive originals. The ordinary collector
driver remains process-local. Independent enforced archive/checkpoint/coverage
integration and actual AWS isolation require separate acceptance within EVIDENCE.

Independent archive implementations can inspect exact received frames through
`StoredReceipt::from_framed_bytes` on their bounded worker. It rejects oversized
retained allocations and reuses the frozen content/checksum validator without
disk writes or mutable progress. It supplies no source authentication or custody;
archive permission, full trusted scope comparison and native proof validation
remain separate before retention or signing.
