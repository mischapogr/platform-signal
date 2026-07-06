# Failure domains, acknowledgement and coverage

Status: requirements and recovery contracts, 2026-10-07. The
[detection catalog](source-detection-catalog.md) supplies the motivating cases;
the [logical diagram](logical-architecture.md) overlays F1–F7 on responsibilities.
Only milestones explicitly marked current are implemented. None of the target
coverage, independent evidence, critical-reserve or HA contracts is qualified by
the existing normalized predicate fixtures.

## Acknowledgement milestones

| Milestone | Meaning and retained identity | Current status / recovery boundary |
| --- | --- | --- |
| M0 source capture | Provider/source created evidence under known collection configuration | Outside server; configuration and continuity require SourceCoverage; an API enable response alone is insufficient |
| M1 durable source receipt | Original pointer/payload and prepared normalized bytes/checkpoint committed by collector or private intake | Proposed intake contract in [24](24-company-integration-proposal.md); current agent has a bounded local spool but no source-wide proof |
| M2 WAL admission | Complete record synced into server WAL; HTTP 202 acknowledges the accepted prefix and event IDs | **Current**; does not acknowledge Parquet, a finding, S3 evidence or SecOps delivery |
| M3 protected evidence | Original object version exists with required retention controls; checksum/signature and provenance validation have separately recorded results | Proposed, independently obtained; `written`, `locked` and `source_validated` are separate states |
| M4 processing checkpoint | Event persisted to Parquet, rules evaluated, required findings synced, then WAL checkpoint advanced | **Current** coordinated consumer; processing success is not complete source coverage |
| M5 delivery plan committed | Findings page/cursor and destination plan atomically durable in private consumer | Proposed [cursor seam](25-findings-cursor-proposal.md); current listing has no durable cursor |
| M6 destination receipt | Downstream accepts a stable notification identity or reports delivery uncertainty | Private integration, proposed; receipt is not analyst acknowledgement |
| M7 SecOps outcome | Analyst/incident disposition recorded with time, reason and revision | Proposed private workflow with generic feedback mechanism |

M2/M3/M4 need not occur in numerical order. Native AWS originals may reach M3
before SIGNAL reads them. Live host detection may reach M4 while M3 validation
is pending. Consumers must report the actual attained milestones rather than
implying that one HTTP success proves all of them.

At M2, a timed-out/lost response can mean admission happened. Retry the exact
prepared event identity/content; at-least-once replay is expected. A batch caller
uses the acknowledged prefix; it cannot assume an all-or-nothing admission.
Current persistence is tied to the WAL stream/sequence and findings use stable
rule/event identity. Arbitrary resubmission under a new WAL sequence is not a
claim of globally deduplicated events. Stable IDs and collector receipt/checkpoint
rules must account for both source duplicates and consumer replay.

M4 failures stop checkpoint advancement. The current consumer can expose Parquet
before a finding fails to append, leaving query-visible events with detection
lag. Replay must reproduce the same prepared content/rule revision. Rule upgrades
need a settled backlog or a separately specified revision migration; do not
change historical semantics while replaying an old checkpoint.

## Failure and recovery map

| Domain | Failure / visible degradation | Acknowledgement and recovery expectation |
| --- | --- | --- |
| F1 source/collector | Logging disabled, inaccessible scope, stale config, collector crash, provider throttling or expired source retention | SourceCoverage becomes partial/failed/unknown with interval and reason. Resume from durable source receipt/checkpoint; loss beyond source/spool retention is an explicit gap. Independent native archive may remain healthy |
| F2 gateway/WAL | Authentication/admission rejected, WAL capacity/I/O exhausted, response lost, process crash | No new M2 beyond synced records. Retry accepted/uncertain prefixes safely. Replay incomplete final record under current WAL contract; complete corruption fails closed. Host/disk loss exceeds local-only recovery scope |
| F3 observability account | Account-wide IAM/network/storage/service outage or compromise | Ingest/query/detection can fail together. Security-native original delivery must have independent credentials/route. Restore processing from retained WAL or validated original evidence within stated budget; local WAL is not account-disaster backup |
| F4 query plane | Query saturation, memory/scan limits, timeout or query host failure | Queries return bounded errors, not empty success. No requirement to block source evidence capture or live detection; shared-process resource contention currently remains a risk |
| F5 detection/findings | Invalid rule, stale state, excessive lag, finding quota or engine failure | Invalid startup rules keep readiness false; consumer failure does not advance M4. Expose lag and state/coverage degradation. Recover with pinned revisions and durable checkpoint; query visibility does not imply detection completion |
| F6 security evidence | Native delivery denied, archive unavailable, validation failure, retention/KMS access issue | M3 remains pending/failed; do not imply archival proof from M2. Independently alert/report gaps and retry within source/receipt retention. Validation failure quarantines proof status while retaining authorized original bytes |
| F7 notification/feedback | Destination timeout, duplicate delivery, route error, private outbox full, analyst/disposition store failure | Preserve M5 plan and retry stable destination identity; uncertain receipt stays uncertain. Do not roll back M4 or discard findings. Escalate backlog/failed routing via an independent health channel |

Each recovery claim requires a measured detection deadline, allowable outage,
retention/capacity budget, recovery point and recovery time. This document does
not invent numerical production SLOs. The owner supplies them per source and
security policy before cloud qualification; synthetic fixture windows are not SLOs.

## Source Coverage Record

SourceCoverage has a versioned, bounded pure SDK validator/assessment. It records
what was verified for a declared scope/stream and interval, including gaps. It
does not assert universal source completeness or hostile-producer correctness.
Store records and observer self-health where loss of the observability account
does not also erase the only failure evidence.

The [formal v1 contract](source-coverage-contract.md) now defines standalone
record/profile schemas, structural/semantic/transition fixtures and accepted pure
evaluation. The [intake/history contract](source-coverage-history-contract.md)
defines durable receipts, finite retry/identity horizons, bounded prefix pruning,
corrections, uncertain commits and ownership requirements; its fixtures are offline
expectations. [ADR-015](adr/015-source-coverage-store.md) records implemented
prepared append/recovery, application-authorized intake, exact-byte receipt replay
and immutable correction admission, with process-crash and cancellation evidence.
Payload/identity pruning, scans, source observers and server integration remain
unimplemented; the complete history state machine is not accepted. The
[ingestion audit](26-ingestion-architecture-audit.md) separately specifies the
missing telemetry source-receipt/checkpoint boundary. This YAML
example is an illustration of the JSON contract; it does not enable an observer.

```yaml
schema_version: 1
record_id: 00000000-0000-4000-8000-000000000001
source_id: fixture-source
collector_id: fixture-collector
resource_scope:
  kind: fixture-scope
  id: fixture-resource
expected_stream: fixture-audit-stream
coverage_profile:
  id: fixture-basic
  revision: v1
coverage_start: 2026-10-07T00:00:00Z
coverage_end: 2026-10-07T00:05:00Z
last_observed_at: null
last_verified_at: 2026-10-07T00:05:00Z
valid_until: 2026-10-07T00:06:00Z
checkpoint:
  schema_version: 1
  kind: fixture-provider-position
  milestone: durable_receipt
  value: fixture-checkpoint
collection_config_revision: fixture-revision
validation_status: verified
validation:
  configuration: verified
  scope: verified
  continuity: verified
  source_integrity: unsupported
gaps: []
gap_summary:
  total: 0
  truncated: false
provenance:
  observer_id: fixture-observer
  method: fixture-independent-probe
  proof_refs: [fixture://coverage/probe]
  observed_at: 2026-10-07T00:05:00Z
```

This example is a quiet interval verified for the fixture's declared capture
preconditions. It does not claim source-integrity verification: an assertion
requiring signed source proofs would remain unsupported. No production provider
or running SourceCoverage observer is implied by the example.

### Interval, freshness and validation semantics

- Coverage interval is half-open `[coverage_start, coverage_end)` in UTC, with
  end strictly later than start and immutable evidence/configuration identity.
  `last_observed_at` is nullable: a quiet stream may have no event.
- `last_verified_at` describes the observer's actual verification, not the newest
  replayed event timestamp. `valid_until` expires the current-health assertion;
  historical records remain evidence for their original interval. Clock skew and
  observation delay must be bounded; expiry changes current assessment to unknown.
- `verified` means all preconditions required by a named source/detection profile
  were checked for this interval. `partial` means only part of the declared scope
  or interval is supported. `failed` means positive evidence of a required capture
  or validation failure. `unknown` means insufficient/freshness-expired evidence.
  `unsupported` means the profile requires a capability this source cannot verify.
- Configuration, scope, continuity and source integrity are distinct component
  results. Consumers evaluate the components their detection requires; the summary
  may never upgrade a failed/unknown required component to verified. An unsupported
  optional source proof must be explicit rather than silently called validated.
- `gaps[]` records start/end, affected scope, reason, recoverability and proof
  reference. An unresolved gap remains visible after new data arrives. Recovery
  closes an interval or adds a new verified interval; it does not erase past gaps.
- `checkpoint` is source-specific, versioned and opaque; it is not interchangeable
  with WAL sequence, S3 object key, auditID or event time. Define whether it records
  capture, receipt or processing and only advance it after that milestone.
- Provenance identifies the observer, method, time and bounded proof references.
  Observers have their own heartbeat. If the observer is unhealthy, stale records
  cannot establish that the collector failed or that the stream was clean.

A profile/revision reference defines required validation components so `verified`
has a checkable meaning. The fixture profile above requires configuration, scope
and continuity, while recording source integrity as unsupported. Configuration
probes establish enabled settings and access; they do not prove no upstream
events were lost. Native provider proofs, controlled source fixtures, producer
drop counters and delivery checkpoints support different claims. A quiet stream
with a fresh verified probe is distinguishable from a silent unobserved stream.

Proposed initial structural limits: 64 KiB serialized record, 128 gap entries,
32 proof references, 1 KiB per identifier/checkpoint string and 16 scope attributes.
The retained record count/bytes and source-key cardinality also need configured
finite limits and retention before runtime implementation. Truncated gaps have
`gap_summary.truncated=true` and exact total when known; truncation cannot produce
a verified summary for the omitted interval. Limit rejection/eviction is counted
and degrades coverage; no unbounded list of account/resources/processes is allowed.

### Detection integration

Coverage is evaluated for the required stream, resource and event/window time.
Account discovery alone does not establish logging coverage. AWS management
events do not cover S3 data reads unless the corresponding selectors and delivery
are verified. Kubernetes Metadata records do not provide workload body evidence.
Host heartbeats do not prove every runtime hook was active or free of drops.

Positive evidence may still yield a finding during partial coverage. Include
the gap and bounded confidence in the proposed assessment. A negative assessment,
"no suspicious activity" report or detection-coverage metric requires all of its
declared preconditions. A missing source remains indeterminate, never a clean
result. The current stateless engine has no coverage-aware negative assessment.

## Capacity and critical-stream reserves

Every queue has finite record/byte bounds and reports depth, capacity, age,
rejections/drops and persistence lag. Model reserves from measured ingress:

```text
required durable bytes >= peak protected bytes/second × outage seconds
                         + replay/publication/headroom budget
```

Include shared filesystem usage, pending publications, finding/state/outbox
storage, producer bursts and provider retention. Once finite capacity is exhausted,
protected capture must reject/backpressure or stop advancing its source checkpoint;
it cannot promise indefinite losslessness. Sources that cannot pause need
independent upstream durable retention, or an explicitly recorded irrecoverable gap.

Classify protected sources using trusted configuration, not caller-supplied
severity. Proposed critical reserves cover WAL/spool bytes, admission concurrency,
processing capacity and outbox/evidence backlog; optional traffic is throttled first.
Their priority queues and separate budgets are not implemented today. Shared
CPU/disk/KMS dependencies can defeat a memory-only reserve.

Current server defaults to `reject_new`; configurable `drop_oldest` intentionally
loses queued records and must not be selected for a protected stream.
`block_with_timeout` is a finite wait, not a lossless guarantee. The current
single WAL has no protected/observability per-stream reserve, and a current HTTP
202 does not guarantee protection against subsequent physical disk loss.
Add an enforceable trusted classification/reserve policy and pressure/recovery
tests before claiming separate protected guarantees.

## HA, ownership and fencing assumptions

Current deployment is one writer with local durable directories and one server
replica. Local locks and Kubernetes volume access modes are not a distributed
fencing protocol. Do not enable two writers over the same WAL/findings/storage
directories or call a second replica HA.

Future collection partitions need one active owner per source/checkpoint scope;
window/correlation partitions need one authority per key/state/checkpoint epoch.
A lease alone cannot stop a paused former owner. Require a monotonic fencing
token enforced at commit, bounded lease expiry/takeover and rejection of stale
owners. Specify checkpoint/state/finding atomicity and reader publication before
choosing shared storage or independent writer replicas.

HA acceptance must reproduce stale-owner resume, network partition, lease loss,
crash between publication and checkpoint, object-store unavailable, replay and
downstream uncertainty. Recovery cannot silently reset a findings cursor or
overwrite a divergent evidence revision. Query replication can be considered
separately after snapshot semantics exist; it does not confer ingest/detection HA.

## Required recovery acceptance by capability

| Capability | Required failure cases before acceptance |
| --- | --- |
| Coverage/normalization | Quiet healthy stream, missing config/field, observer outage, stale probe, changed scope, gap recovery, bounded overflow and unsupported source proof |
| Original-evidence path | Observability outage with source-native evidence delivery continuing; rejected write; validation/signature failure; retention/KMS permission failure; expired source retention |
| Stateful detection | Duplicate/out-of-order/late events, key/byte limit, TTL expiry, stale state, unsupported policy semantics, crash/replay with pinned revision and stable findings |
| Findings delivery | Page replay, durable cursor+plan commit, destination timeout/duplicate, outbox pressure, history invalidation and disposition failure |
| Scale/HA | Measured contention, partition ownership, fenced stale writer, takeover/recovery, shared dependency failure and defined outage budget |

The proposed tests extend the roadmap. Existing WAL/process/native checks remain
their original evidence, and [release gates](21-release-readiness.md) remain open.
