# CloudTrail source receipt and normalization profile

Status: PS-02 source custody remains a **design contract**, 2026-10-07. The pure
[Rust management-record normalizer](../crates/signal-collector-sdk/src/cloudtrail.rs)
and generic D01 predicate correction now have local fixture/test evidence.
Source-receipt custody and adapter implementation remain separate work. No
CloudTrail reader, source acknowledgement, durable SourceReceipt, cloud
configuration or AWS qualification is implemented by the helper or offline fixtures.

This addresses [A1–A4](26-ingestion-architecture-audit.md#findings-ordered-by-implementation-risk)
using the existing [M0–M7 milestones](failure-domains.md#acknowledgement-milestones),
the unchanged [v1 event envelope](../crates/signal-event/src/lib.rs), and the
[detection catalog](source-detection-catalog.md). A SourceReceipt owns captured
telemetry work; a [SourceCoverage history receipt](source-coverage-history-contract.md)
owns a coverage assertion. They are separate identities and contracts.

## First slice and trusted scope

The proposed profile is `cloudtrail-management`, revision `v1`. One operation
prepares one bounded gzip CloudTrail object containing a `Records` array. Direct
S3 notification JSON is discovery input, not the CloudTrail record format. SNS
wrappers, EventBridge envelopes, S3 test notifications, digest files, data events
and network-activity events require explicit separate dispositions or profiles.
They must never be passed to the management-record parser as empty success.
The proposed discovery boundary is at most 256 KiB of notification JSON and 16
object references; validate both before dispatch. Only direct S3 `Records`
notifications are supported by this first adapter design. Oversized messages,
`s3:TestEvent` and wrappers take explicit poison/quarantine responsibility rather
than becoming an empty completed message.

The authenticated application supplies a fresh exact scope grant: collector and
source IDs, configuration/authority revisions, approved queue and bucket owner,
bucket/key namespace, trail scope, allowed **recipient accounts and event regions
for this object**, stream, profile revision and custody requirement. Actual
accounts, permissions, retention and detection policy stay in the private
application. Bearer authentication, a key prefix and native account fields are
not this grant. Recheck it for capture, replay, original access and source ACK.

Each record's `recipientAccountId` and `awsRegion` must be in that object grant.
Do not compare recipient account to `userIdentity.accountId` as an authorization
test: cross-account actors are legitimate. Unknown recipient scope quarantines
the record rather than assigning authority from the actor. The recipient field
is natively optional; requiring it is this conservative profile's decision.
[AWS record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
distinguishes these account identities.

## Original, identities and immutable preparation

The first receipt keeps the **exact fetched compressed bytes inline**, their
length and SHA-256. Decoded JSON is a bounded transient view, not a substitute
original. A captured object reference also records bucket, exact key, version ID
when supplied, capture time, compression and delivery metadata. It confers no
access permission. A mutable pointer alone cannot discharge the receipt's work.

For the first eventual S3 discovery adapter, require a retrievable non-null
version ID. Versionless discovery is unsupported until a separate qualified
conditional-capture contract binds the intended notification to captured bytes.
An expired version, pending archive restore or access denial is not an empty
object; keep source replay responsibility and report bounded unavailable/restore
pending state. ETag remains an opaque source condition/diagnostic, not SHA-256;
[S3 ETag semantics](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Object.html)
vary with encryption and multipart upload.

Persist a non-nil receipt UUID and, for every native record, its ordinal, exact
decoded byte span/length/hash, native event ID where valid, and disposition.
Prepare non-nil normalized UUIDs, `observed_at`, normalizer/profile revision,
trusted scope/configuration revisions and **exact serialized event bytes once**.
Count and validate all records before any prepared event is published. A late
malformed record cannot leave an earlier unsafe published preparation prefix.
Commit all preparation and dispositions atomically as M1 before the first send.

Object replay identity is the exact trusted scope plus bucket/key/version and
retained original bytes. Compare the retained bytes on a known replay; a digest
is an integrity witness, not an exact-byte deduplication decision. Reuse all
prepared IDs/bytes, times and dispositions after restart or parser upgrade.
Changed bytes under that retained identity fail closed. Distinct object versions
and distinct native event IDs are not collapsed merely because content looks
identical. SQS MessageId/ReceiptHandle are delivery metadata, not native event IDs.

This first bounded design promises identity reuse only for a retained receipt.
It does not introduce global native-event deduplication across different objects
or after receipt reclamation. Repeated native events may therefore produce
at-least-once derived events/findings. A broader finite dedupe ledger needs its
own exact-byte collision, scope and retention contract.

## Bounded local receipt representation

Proposed immutable local encoding, independent of a future storage backend:

```text
"SIGSRC01" || u32be(metadata_length) || u64be(original_length)
           || u64be(prepared_count) || u64be(prepared_total_bytes)
           || metadata_json || exact_original_bytes
           || [u32be(event_length) || event_uuid16 || SHA256(event_bytes) || event_bytes]
           || SHA256(all preceding bytes)
```

Metadata is version-1 UTF-8 JSON with sorted keys, compact encoding, no duplicate
keys/non-finite numbers, checked unsigned integers and bounded UTC times. It
contains receipt UUID, complete trusted scope/revisions, original reference and
hash, capture/preparation time, pinned normalizer definition fingerprint, ordered
record spans/dispositions and prepared-event mapping. Do not put the final
receipt digest inside prepared events: that would create a circular encoding.
An event's scoped `attributes.evidence_ref` instead identifies
`receipt://<receipt_uuid>/record/<ordinal>`; resolving it requires current grant
and retained custody. Access tokens and queue handles never enter event payloads.

The immutable receipt checksum and hashes detect inconsistency; they are not
signatures or administrator-resistant proof. Backend framing, exclusive owner,
atomic publication, recovery, fault injection and golden binary vectors remain
implementation gates. Only a completed sync/atomic publication exposes M1.

Progress is a separate atomic control record bound to receipt UUID/checksum,
owner generation, ordered prepared IDs/content witnesses and verified M2 prefix
`0..prepared_count`. It also records quarantine responsibility and source-ACK
intent/result. Never rewrite prepared bytes to reduce a retry batch. Reserve
space for both control state and its replacement before progress mutation.

## Publish progress and source acknowledgement

Use the existing [agent transport verifier](../apps/signal-agent/src/http.rs)
semantics as the M2 witness, not a status code alone:

- Schema, counts and the exact ordered IDs must agree with the submitted batch.
  HTTP 202 must accept the complete batch with no rejection/error.
- A recognized retry response can acknowledge only its verified leading prefix;
  the error index must identify that prefix boundary. Permanent/reduce-batch
  responses do not acknowledge a partial prefix.
- A lost, malformed, oversized, cancelled or timed-out response advances **zero**
  local progress for that attempt, even if the server admitted records. Retry
  the original prepared suffix and persist verified prefix progress atomically.

M2 proves synced local server WAL admission. It does not prove M3 protected
originals, M4 processing or source completeness. There is no current remote M4
query receipt for a collector to demand. Do not invent one for source deletion.

The application must select an ACK custody contract before collection:

| Custody choice | Source delivery ACK condition |
| --- | --- |
| Process-recovery local M1 only | May transfer responsibility only when the owner explicitly accepts that limited failure domain; it cannot promise host/AZ/account-loss recovery |
| Required host-loss/object-backed custody | A qualified independent durable owner must receipt the exact original **and all prepared pending work/revisions**, or retain a proven recovery route; local sync or M2 alone is insufficient |
| Protected-original replay responsibility | Retain source delivery/replay responsibility until the selected original-retention and pinned-preparation recovery conditions are verified |

No row in this table is a current guarantee. Selecting a stronger requirement
without a qualified custody witness leaves ACK blocked. Original deletion itself
requires separate retention/legal authority; deleting an SQS delivery does not
authorize deleting its S3 object. A later M3 source-validation result is tracked
separately from custody acceptance.

The first local single-receipt adapter supports **one reference per message**.
The 16-reference limit is a parser/work bound, not successful processing capacity.
Hold a multi-reference message with an explicit unsupported disposition and keep
its source ACK blocked until a qualified handoff accepts all references and their
replay/custody obligations. Merely retaining notification JSON does not own the
referenced originals or pending prepared work. Do not evict an unexpired receipt
to process its next reference. A later multi-reference implementation may process
objects under the single-object work budget in bounded sequence only when its
independent custody and bounded message-control contract permits authorized slot
reclamation. Delete the message only after **every reference** has settled its
selected custody or durable quarantine obligation and the completion mapping is
persisted. That protocol is a separate acceptance gate.
Accept numeric notification major 2/minor at least 1 with additive minor fields,
`eventSource=aws:s3`, and the `ObjectCreated:Put`, `ObjectCreated:Post`,
`ObjectCreated:Copy` or `ObjectCreated:CompleteMultipartUpload` event names.
Other notification kinds take explicit unsupported disposition. Require typed
bucket/key/non-null version fields and trusted namespace agreement before fetch.
Decode URL-encoded object keys once (including form-encoded `+` spaces) and
validate notification version/shape;
[S3 notification content](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html)
defines this distinct discovery envelope. Notifications can duplicate or arrive
out of order; they are not a global checkpoint or continuity proof.
[S3 delivery semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventNotifications.html)

Delete using only the freshest received handle for the authorized queue after
durable ACK intent. Ambiguous deletion remains uncertain, tolerates redelivery
and must not erase the receipt. A successful deletion can still be followed by
duplicate delivery; replay retained preparation rather than allocating new IDs.
[DeleteMessage](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_DeleteMessage.html)
and [standard-queue delivery](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/standard-queues-at-least-once-delivery.html)
do not make an old handle a stable event identity.

## Native profile and predicate boundary

Require well-typed `eventVersion`, non-nil UUID `eventID`, UTC `eventTime`,
`eventSource`, `eventName`, `awsRegion`, `eventType`, `recipientAccountId` and
`managementEvent=true`. Accept numeric major 1/minor at least 6, including
additive later minor versions; unsupported major/older version is explicit.
If present, `eventCategory` must be `Management`. This deliberate narrow scope
does not promise normalization of every historic CloudTrail record. Native
`eventType` is restricted to `AwsApiCall` or `AwsConsoleSignIn`; API mappings
require the former and ConsoleLogin requires the latter. A supported name in
the wrong accepted event type remains forensic unknown, without action/outcome.
Other event types are outside this profile and quarantine explicitly. Native
source IP is preserved as text: service DNS/`AWS Internal` is not forcibly
parsed as an IP or assigned geography.

Use existing `source.type=cloudtrail`, a name pinned from trusted source config,
`timestamp=eventTime`, pinned `observed_at`, severity `info`, and generic
resource `{kind: "aws_account", id: recipientAccountId,
account_id: recipientAccountId, region: awsRegion}` only from validated recipient
scope. The v1 message is `CloudTrail <eventSource>/<eventName>` and tags are empty;
this describes the native request without inventing a completed effect. Source-native
diagnostics stay under bounded `attributes.aws.cloudtrail`; normalized predicate
fields are the existing `attributes.security.*`. Preserve event ID, service/name,
version/type, recipient and actor accounts, region, normalized actor kind,
native source-IP text and record ordinal/hash when present and within bounds.
Do not copy arbitrary request/response credentials or the whole native record
into attributes. Authorized receipt originals retain unknown extension bytes.
The fixed diagnostic paths are `event_id`, `event_source`, `event_name`,
`event_version`, `event_type`, `recipient_account_id`, `region`, `record_ordinal`,
`record_sha256`, and optional `actor_account_id` / `source_ip_address` under
`attributes.aws.cloudtrail`. Add only explicitly bounded actor/target context
in the reviewed Rust profile; the fixture does not claim these extra projections.
`attributes.normalizer.id/revision` pins this profile. UUIDs must be canonical
non-nil lowercase text; times are valid UTC calendar values with `Z` and at most
nine fractional digits. Required strings are nonempty; recipient account is
exactly 12 decimal digits. Attribute-size excess quarantines rather than truncates.

| Service-qualified native action | `security.action` | Additional condition/context |
| --- | --- | --- |
| `ec2.amazonaws.com` / `DescribeInstances` | `resource.activity` | First bounded general activity example |
| `cloudtrail.amazonaws.com` / `StopLogging`, `DeleteTrail` | `audit.stop`, `audit.delete` | Preserve target trail name/ARN; API acceptance is distinct from independently observed collection state |
| `signin.amazonaws.com` / `ConsoleLogin` | `identity.console_login` | Explicit login result; native MFA has narrower applicability |
| `guardduty.amazonaws.com` / `UpdateDetector` | `control.disable` | Only literal boolean `requestParameters.enable=false`; preserve detector ID, control `guardduty` |
| `guardduty.amazonaws.com` / `DeleteDetector` | `control.disable` | Preserve detector ID, control `guardduty` |
| `securityhub.amazonaws.com` / `DisableSecurityHub` | `control.disable` | Control `securityhub`, recipient/region context |
| `config.amazonaws.com` / `StopConfigurationRecorder` | `control.disable` | Preserve recorder name, control `config` |

Target trail/detector/recorder identifiers and richer actor/session identity are
retained in the original; this first projection does not claim extra attribute
paths for them. Any later projected context needs explicit path/type/size tests.

`UpdateDetector` with true, absent or malformed `enable` is not mapped to disable.
Its [API definition](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_UpdateDetector.html)
documents that switch. Event name alone, without service qualification, is never
enough to map a supported action. Other operations preserve native names with
action/outcome unknown rather than receiving a global success default.

For supported API actions, record `security.outcome=success` only when
`responseElements` is present as object/null and recognized error evidence is
absent. A nonempty top-level or `responseElements.errorCode` means failure.
`errorMessage` without a code, empty/malformed error fields or contradictory
signals keep outcome absent/unknown. This classifies the audited API request's
acceptance, not verified resulting control/resource state. The selected API
response contracts are [StopLogging](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StopLogging.html),
[DeleteTrail](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DeleteTrail.html),
[DeleteDetector](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html),
[DisableSecurityHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DisableSecurityHub.html)
and [StopConfigurationRecorder](https://docs.aws.amazon.com/config/latest/APIReference/API_StopConfigurationRecorder.html).
Missing errorCode alone is never a service-independent success classifier.

ConsoleLogin instead requires explicit `responseElements.ConsoleLogin` equal to
`Success` or `Failure`; conflicting success/error evidence stays unknown. Set
`security.actor_kind` only from a valid `userIdentity.type`. Map
`additionalEventData.MFAUsed` exact `Yes`/`No` to boolean `security.mfa_used` only
for Root/IAMUser. Missing/unsupported values are omitted. Federated/AssumedRole
`No` and session `mfaAuthenticated=false` do not establish absence of IdP MFA.
[AWS sign-in records](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html)
support this separate classifier.

The design snapshot's D01 rule required `security.action=resource.activity`,
missing a root `audit.stop` operation while D02 matched. The selected generic
catalog rule now uses cloudtrail + successful supported outcome + Root without
that action constraint. Actual Rust native-to-finding tests verify root StopLogging
produces D01 and D02. The independent design review approved this exact correction;
the implementation removes only that action term. Offline fixture keys retain
their historical meaning: `catalog_matches` is the legacy action-filter view,
and `proposed_matches` is the now-selected profile. Unknown outcomes still cannot
satisfy a success predicate. D02/D03/D05 use existing field
paths. The older `examples/logs/aws-cloudtrail.json` illustrative profile is not
a production normalizer or a replacement contract.

## Missing, unsupported and poisoned input

Every native ordinal has an explicit bounded disposition: `emit`,
`emit_indeterminate` or `quarantine_record`. Valid supported input is prepared;
missing detection semantics or unsupported operations may prepare forensic events
with omitted unknown fields and bounded ordered reason codes. This does not
upgrade current predicates' no-finding result into an implemented indeterminate
assessment. Missing base identity/scope, malformed types, unapproved recipient,
oversized prepared attributes or contradictory routing quarantines the record.
Unknown native fields remain in the retained original, without widening scope.

Invalid compression/CRC/trailing data, invalid UTF-8/JSON, duplicate keys,
non-finite numbers, excessive nesting/count/bytes or a non-array Records value
quarantines the entire object before publish. A partially decoded unsafe object
does not become an M1 success. The quarantine owner must durably retain available
originals and a bounded reason/disposition with the selected custody assurance;
quota rejection or unavailable custody leaves source ACK blocked. If an original
cannot be captured within the bound, source replay remains the owner and an
independent gap/escalation is required. DLQ routing alone is not fulfilled
quarantine custody, and unsupported discovery input is not endlessly retried as
an unexplained parser error or silently deleted.

## Finite laboratory limits and reservation

These are fixture/design limits, not production defaults, source-size guarantees
or physical RSS measurements. All integers and sums are checked before allocation,
hashing, fetch, decompression, serialization or durable mutation as applicable.

| Item | Selected bound |
| --- | ---: |
| Exact compressed original | 8 MiB |
| Discovery JSON / object references per message | 256 KiB / 16 |
| Total decoded object | 32 MiB |
| Records per object / metadata dispositions | 1,024 |
| One decoded native record | 256 KiB |
| JSON depth | 16 |
| One prepared canonical event | 64 KiB |
| All prepared event bytes | 16 MiB |
| Immutable metadata | 1 MiB |
| Binary framing/index allowance | 64 KiB |
| Immutable receipt, including all sections | 32 MiB |
| Active object operations / locally retained receipts | 1 / 1 |
| Transient application reserve | 128 MiB |
| Working-directory quota minimum | 64 MiB |
| Progress/control plus replacement | 8 MiB + 8 MiB |
| Fixed HTTP response cap | 64 KiB, as current agent transport |

The receipt's maximum section sum is `8 + 16 + 1 + 1/16 = 25.0625 MiB`, below
32 MiB. Original/event sections are binary bytes, not base64-expanded JSON.
Decoded 32 MiB is not also retained in the receipt. Count metadata, index and
framing, including per-record dispositions/IDs; reject before any section exceeds
its allowance. A 256 KiB native record can fit by retaining its original in the
receipt and projecting bounded fields; oversized normalized fields are explicit
quarantine, never silently truncated or changed across retries.

The conservative transient sum is `8 original + 32 decoded + 16 prepared +
32 receipt encoding + 16 parser/HTTP scratch + 1 metadata + 1 index +
1/16 ACK + 16 allocation allowance = 122.0625 MiB`, below 128 MiB. Stream
records with a bounded parser; do not materialize an unbounded whole-object DOM.
HTTP request/batch encoding, response, cancellation and decompressor buffers
must fit their scratch reserves or fail before dispatch.

The working sum is `32 receipt OR preparation temp + 8 capture temp +
8 control + 8 control replacement + 4 root/index allowance = 60 MiB`, leaving
4 MiB in the minimum 64 MiB quota. Publication renames the preparation temp;
it must not require a second simultaneous full receipt copy. Count interrupted
files and quarantine material against the same root quota. Bounded discovery
completion mappings fit the root/control allowance; there is no unbounded
notification-reference queue. A live/unexpired
receipt, including a completed one awaiting its private retention/custody horizon,
holds the sole slot: block new capture rather than evict it. Scaling receipt
count or adding archive handoff requires recalculated quotas and authority.
The single-slot laboratory design is not a throughput or production default.
It cannot promise successful handling of a 16-reference message; the parsing
bound does not relax single-reference support or message-level ACK requirements.
Filesystem allocation/journals and actual memory use need backend qualification;
these sums do not promise a physical filesystem or whole-process bound.

Require finite configured network/decompression/prepare/publish deadlines,
cancellation, visibility renewals, retry attempts and delay ceilings. Retention,
recovery horizons, required original retrievability and source-message lifetime
are mandatory private inputs, validated against the intended outage/custody
budget. The fixture's byte limits do not establish those production SLOs. Quota,
deadline or retry exhaustion degrades intake and preserves already owned work.

## Ownership, crash and divergent restore

One exclusive writer owns preparation, progress and source ACK intent. A local
lock covers process recovery only. A distributed generation must be enforced by
the durable backend and every side-effect path before claiming stale-owner
fencing; a lease number in metadata alone cannot fence S3/SQS/API calls.
The first adapter must remain a single supported owner until such a protocol is
qualified. Never resume a restored clone concurrently with the old owner.

Crash before M1 commits publishes nothing and leaves replay responsibility at
source. Crash after M1 reuses the complete retained preparation. Crash after a
verified HTTP response but before progress sync retries the original suffix;
duplicates are acceptable, guessed progress is not. Commit/ACK ambiguity retains
ownership and buffers until settlement or closed recovery. A changed receipt,
missing original/prepared bytes, unsupported pinned revision or mismatched progress
prefix fails closed rather than rebuilding under a current parser.

A same-UUID restore must verify original hash/bytes, prepared IDs/content,
normalizer fingerprint and progress witnesses. A lost or divergent progress
history cannot prove source deletion is safe. Reconcile against retained custody
and selected source replay under a fresh exclusive owner; do not manufacture a
fresh receipt for an old source ACK. Protected recovery horizons and bounded
receipt reclamation require acceptance before any disaster-recovery claim.
Checksums can reject inconsistent restoration, but a self-consistent older backup
cannot by itself reveal later lost progress or an unseen divergent owner. Treat
that history as uncertain, establish fresh fencing and reconcile independent
custody/replay responsibility before any new source ACK. Do not advertise rollback
or competing-owner detection from local hashes alone.

## Independent coverage, proof and acceptance

Receipt M1/M2 says nothing about whether required accounts/regions/selectors
were enabled, an interval was continuous, an observer was healthy or originals
were authentic. Keep SourceCoverage configuration/scope/continuity/source-integrity
components and independently reachable observer health separate. M3 separately
records original custody, retention controls and source-proof validation status.
SHA-256 of fetched bytes is not CloudTrail digest/signature validation, and
enabling digest delivery is not running validation.
[CloudTrail integrity validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
requires the relevant files, digest chain and validation process.

[Offline fixture inventory](../tests/fixtures/cloudtrail-source/contract.json),
[contract checker](../scripts/check-cloudtrail-source-contract.py) and independent
[mutation regressions](../scripts/test-cloudtrail-source-contract.py) are design
evidence only. They exercise synthetic native
projection, exact hashes/identities, legacy-vs-selected predicate expectations,
verified-prefix witness rules and explicit custody failure expectations. They
do not execute a Rust normalizer, source receipt store, S3/SQS delivery, protected
archive, fencing, decompression implementation or AWS source coverage.

The pure Rust helper now executes all 41 native record cases with fixed caller
identity/time and the selected generic predicates. It additionally bounds decoded
record nodes at 16,384 (keys included) before child allocation, preserving the
16-level/256 KiB limits. Two historical prepared pins are canonical-content
witnesses; newly prepared bytes are deterministic, but their field ordering is
not a license to rewrite existing pending receipt bytes. Source names are supplied
by trusted configuration, bounded to 128 bytes, with 128 recipient accounts and
64 regions (64 bytes each) at most. Result memory is per record; retaining multiple
results requires aggregate capacity/ownership outside this helper.

Actual Rust tests qualify this decoded-record mechanism; the offline checker
still does not execute it or the custody scenarios. Receipt storage/adapter custody
is the next bounded task, with backend/crash/fault-injection, quota, replay, ACK and authorized
environment gates; no cloud resources or current production protection follows
from accepting this design.
