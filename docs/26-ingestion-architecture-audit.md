# Ingestion architecture audit — 2026-10-07

**Decision:** adopt multiple collection patterns and shared mechanisms, retaining
one server. The immediate gap is durable source intake and source-specific
coverage, not additional service names. This is a source/documentation audit of
`dd4a1cde287db7b56a4a5c56f60c00cdef9ea255`, not a cloud qualification or a new
implementation authorization. Recommendations below are proposed post-MVP work.

## Current implementation and evidence

| Area | Present | Missing for the proposed architecture |
| --- | --- | --- |
| Collection | File/stdin agent with bounded spool and retry; generic `Collector`/`Enricher` SDK | Kubernetes discovery/CRI semantics, AWS/SaaS adapters, syslog receiver, OTLP adapter |
| Admission | Canonical JSON single/batch HTTP; limits, optional shared Bearer token; synced WAL admission | Vendor transport protocols, scoped publisher authorization, generic durable raw-source receipts |
| Processing | Single server publishes Parquet, evaluates stateless predicates, persists findings, then checkpoints | Production vendor normalization pipeline, windows/state/correlation, independent protected-stream routing |
| Storage/query | Local filesystem Parquet and bounded DataFusion queries | S3 `EventStore`, object publication/manifests, independent security archive; no hot tier is required yet |
| Coverage | Pure SDK validation/assessment; standalone bounded SQLite history, authorized intake/retry, immutable corrections, payload/identity-prefix pruning and fixed-frontier scans | Source observers, server wiring and independent observer health |
| SecOps | Durable findings and listing | Durable consumption cursor, notification outbox, dispositions and incident workflow |
| Samples | 55 synthetic cases across 11 source families | Qualified live collection and arbitrary-input production normalizers |

Code anchors: [agent inputs](../apps/signal-agent/src/input.rs),
[SDK](../crates/signal-collector-sdk/src/lib.rs),
[ingest](../crates/signal-ingest/src/lib.rs),
[consumer ordering](../apps/signal-server/src/pipeline.rs),
[storage](../crates/signal-storage/src/lib.rs),
[coverage implementation](../crates/signal-coverage/README.md),
[sample limitations](../examples/logs/README.md).

Retained acceptance records 300 workspace tests, including 45 coverage-library
tests, on local Linux AMD64. This audit does not rerun Rust acceptance or extend
its scope. Native ARM64, current-image kind, actual EKS, remote CI, released
external dependencies and publication remain open as recorded in the
[release audit](21-release-readiness.md). Older images/candidates do not qualify
subsequent source changes. Versions remain `0.1.0-dev.0`.

## Findings, ordered by implementation risk

### A1 — Source acknowledgement is not yet a shared durable contract

**High, before implementing adapters.** The SDK invokes a collector; it does not
own a durable provider cursor. HTTP 202 is M2 synced server WAL admission, not M3
protected evidence or M4 completed processing. Independent resubmission can
duplicate IDs, and batch admission can accept only a prefix. Advancing a page,
SQS message or file checkpoint merely because a request was sent can lose data.

Specify one bounded source receipt containing source scope, source delivery/event
identity, original bytes or a retained versioned object reference, prepared event
IDs/bytes, normalizer revision and progress. Commit the receipt before advancing
the fetch cursor; track downstream completion separately. A pointer is sufficient
only while its object is guaranteed retrievable for the recovery horizon.
Replayed receipts reuse prepared bytes and IDs, not current enrichment results.
The adapter must define source-event versus delivery identity and finite dedupe
horizons. Content hashes alone must not collapse legitimate identical events.

Source acknowledgement may follow M1 if its durable receipt owns all remaining
work and has the required failure-domain protection. Local disk sync alone does
not cover host/account loss. Otherwise retain source replay responsibility until
the required milestone is met. Do not make every source wait for M4 or pretend
every M2 success permits permanent deletion of original evidence.

Acceptance must cover crash before/after receipt commit, lost response, partial
batch acceptance, duplicate/out-of-order delivery, expired cursor/object,
quota exhaustion and replay after parser upgrade. Reuse the
[M0–M7 milestones](failure-domains.md#acknowledgement-milestones); SourceCoverage
history receipts are not interchangeable with telemetry source receipts. The
[CloudTrail receipt/profile design](29-cloudtrail-source-receipt.md) now selects
this boundary for the first source; its offline witnesses do not implement M1.

### A2 — Shared authentication does not establish account or tenant authority

**High, before multi-account or SaaS exposure.** Current optional shared-token
authentication is appropriate only within its documented trust boundary. A
producer can supply event resource/account attributes; those values are not
authorization. Adding a `tenant.id` field would not isolate ingestion or queries.

Derive allowed source scope from authenticated workload/connection and trusted
configuration. Keep actor, affected resource, collector and storage owner
distinct. Reject conflicting authoritative identity claims or retain them as
unverified assertions. Enforce access on query and evidence retrieval as well as
ingest; prevent bypass of the trusted adapter. Generic authorization hooks can be
public, while actual tenant/account mappings and policies remain private. Do not
advertise multi-tenancy until cross-scope denial tests pass.

### A3 — Protect originals before lossy transformations

**High, before security collection claims.** Keep the independent security-owned
evidence route from the existing architecture. A central observability gateway
must not become the only route for protected originals. Original parsed JSON is
not necessarily the original byte sequence or compressed source object.

Retain an authorized original object/version, digest, capture context and separate
source-proof validation result. Restrict raw access independently of searchable
copies; an evidence reference grants no permission. Normalization, redaction and
sampling produce derived copies. Required security detection input must not pass
through observability sampling. Current shared WAL policies do not implement
protected-stream reserves or independent archival durability. Capacity exhaustion
needs an explicit bounded recovery/gap policy; finite storage cannot promise
unlimited lossless collection. See [protected evidence](logical-architecture.md#protected-evidence-and-query-copies).

### A4 — Preserve the existing v1 envelope

**Medium, compatibility constraint.** `source` already is an object with `type`
and optional `name`; it is not an arbitrary vendor map. The v1 envelope rejects
unknown top-level fields and unknown source/resource fields. The proposed
`source.vendor`, top-level `tenant`, `cloud`, `raw`, etc. cannot be sent unchanged.
Use existing `resource` fields and bounded nested `attributes` for extensions;
document a versioned normalization profile before adopting new semantic names.
See [event contract](../crates/signal-event/src/lib.rs).

The current fixture convention stores original text in `attributes.log.original`.
Large/binary originals should use an authorized external evidence reference;
define that profile rather than forcing them through the event size limit.
Log severity (`trace/debug/info/warn/error/critical`) remains separate from
finding severity (`low/medium/high/critical`). Missing outcome or identity is
unknown, not success. Preserve provider extensions without granting them authority.

A shared context model is useful across logs, events, findings, metrics and spans.
It does not imply one interchangeable payload. Metrics need units, temporality,
aggregation and histogram semantics; spans need their own lifecycle. Defer native
metrics/traces until a typed contract and concrete detection/query requirement
justify them. Do not silently encode metric samples as ordinary log messages.

### A5 — Bound decoding and isolate failing sources

**High for untrusted intake.** Existing canonical-event limits do not bound a
future gzip expansion, S3 object, API page, syslog frame or vendor parser. Specify
compressed and expanded byte limits, record/depth limits, deadlines, concurrency,
per-source fairness and bounded quarantine. One malformed record must not cause
an infinite page retry or silent checkpoint advance. Quarantining preserves the
original and a visible failure; it is not successful normalization or detection.

Keep revisioned normalization policy centrally managed while allowing the same
generic parser library at the edge when required by transport or data residency.
Local identity capture and required pre-egress redaction cannot always wait for a
central processor. Avoid duplicate parser implementations across roles.

### A6 — Fixture and documentation coverage exceeds runtime coverage

**Medium, corrected documentation drift.** The sample corpus proves fixture
contracts, not operational collectors. Some overview documents still described
trusted coverage intake and corrections as entirely planned. They are now local
library capabilities, including accepted prefix pruning and fixed-frontier scans;
source observers and runtime integration remain open.
The detection catalog contains 15 requirements; only its first five predicate
cases fit the present engine after normalization. Correlation and absence-based
detection require additional state and coverage evidence.

## Source-by-source disposition

Official documentation was consulted on 2026-10-07. Context7 supplied useful Cato
documentation but insufficient S3 delivery detail and no suitable Management
Activity API match; primary vendor documentation supplies those details below.
These are source profiles to qualify, not enabled integrations.

| Source | Recommended path | Required qualification / correction |
| --- | --- | --- |
| CloudTrail | Native protected S3 originals → regional SQS discovery → bounded reader/normalizer | Trail scope/selectors, delivery lag, original object/version and digest validation; management events do not imply data-event coverage |
| CloudWatch Logs | Subscription → selected Kinesis or Firehose path → transport adapter | Decode the actual delivery envelope; choose one path initially; measure buffering/recovery latency, not just nominal near-real-time delivery |
| EKS workloads | Node-local file/CRI collector with metadata cache | Container log rotation/restarts, CRI partial records, pod UID/container ID, cluster scope; a DaemonSet alone does not supply these semantics |
| EKS control plane | Enabled audit/control-plane categories → CloudWatch adapter | Separate from node logs and cluster object watches; logging categories are configurable and disabled by default |
| ECS EC2/Fargate | Existing supported log router where practical; FireLens on supported Linux tasks | Explicit router output protocol/ACK behavior, task identity and bounded buffering; FireLens is not automatically compatible with `/v1/events` |
| ALB/NLB | S3 object adapter; consider supported NLB CloudWatch delivery separately | ALB logs are best-effort; NLB access logs cover TLS and are best-effort, including its newer CloudWatch delivery options |
| RDS | Engine-specific exported logs → CloudWatch/object adapter | Enumerate engine/version, log types and audit prerequisites; exports do not establish coverage of every query or privileged action |
| VPC Flow / WAF | Reuse a selected supported object/stream transport | Separate source profiles, enabled scope, delivery status and volume budgets; do not infer application identity solely from network tuples |
| Route 53 | Separate public DNS and VPC Resolver profiles | Public DNS logs use CloudWatch in us-east-1; Resolver supports CloudWatch/S3/Firehose and has caching-related coverage limits |
| GuardDuty / Security Hub | Provider finding feed via EventBridge/appropriate API | Preserve provider finding identity/revision/status and distinguish updates from new findings; do not treat findings as raw complete evidence |
| Microsoft 365 | Management Activity subscriptions for supported audit content; Graph adapter for selected Entra/security data | Separate permission/retention profiles, tenant boundaries, content IDs, pagination and overlapping reconciliation windows |
| Cato | `eventsFeed` API | Persist opaque markers with retained pages; explicit initialization/expired-marker behavior and finite catch-up horizon |
| FortiGate / appliances | Site/regional receiver → bounded durable spool → authenticated central delivery | Qualify device firmware, message format, TCP framing and TLS separately; UDP is explicitly lossy |
| Cloudflare | Logpush to supported object destination, initially reusing S3 | Keep this previously requested source in scope; dataset/plan/field selection and destination ownership need qualification |

AWS delivery details change implementation choices:

- S3 notifications are at least once and unordered; direct SQS destinations must
  be in the bucket's Region. Use regional discovery plus bounded reconciliation
  of retained objects to recover configuration/outage gaps. A central account can
  own regional collectors; do not equate central ownership with one Region.
  [S3 notifications](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html).
- CloudWatch subscriptions use supported AWS destinations and gzip/base64 delivery,
  with finite retry behavior. Firehose HTTP requires its own envelope and a 200
  response carrying the request identity; current SIGNAL 202/prefix semantics are
  a different protocol. A receiver must durably own the complete Firehose request
  before declaring success, even if later SIGNAL admission is partial.
  [Subscriptions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Subscriptions.html),
  [Firehose protocol](https://docs.aws.amazon.com/firehose/latest/dev/httpdeliveryrequestresponse.html).
- [EKS control-plane logs](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html),
  [FireLens platform support](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_firelens.html)
  and [RDS export types](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.Procedural.UploadtoCloudWatch.html)
  require separate source preconditions. Kubernetes object discovery can enrich
  workload identity but cannot replace audit records of API actions.
- [ALB access logs](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html),
  [NLB legacy access logs](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-access-logs.html)
  and [NLB CloudWatch delivery](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-cloudwatch-logs.html)
  do not provide complete accounting of all network traffic.
- [Public DNS logging](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html)
  and [Resolver logging](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html)
  are distinct products. [GuardDuty findings](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html)
  similarly need a finding-oriented adapter, not a log parser.
- [VPC flow-log destinations](https://docs.aws.amazon.com/vpc/latest/userguide/working-with-flow-logs.html)
  and [WAF logging](https://docs.aws.amazon.com/waf/latest/developerguide/logging.html)
  support choosing an object or stream path. [Security Hub CSPM events](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html)
  include both newly imported findings and updates, so pin the selected product
  and event schema before writing its adapter.

For Microsoft 365, the Management Activity API exposes tenant/content-type
subscriptions and content blobs. Listing windows are at most 24 hours with a
start no more than seven days back; event order can differ from content arrival.
Persist discovered content IDs and unfinished blobs alongside the discovery
cursor. Graph Entra sign-ins are a different endpoint with its own permissions and
retention. Choose the API by evidence requirement rather than labeling all M365
collection “Graph.” [Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference),
[Graph sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0).

Cato documents a three-day marker horizon and a 2025 marker-behavior change. Old
examples of empty-marker initialization conflict with newer guidance; never
silently reset a rejected marker and declare continuity. Pin behavior to the
supported API and tenant test, retain the returned page before advancing, and
record an explicit coverage gap when replay is no longer possible.
[EventsFeed](https://support.catonetworks.com/hc/en-us/articles/360019839477),
[marker update](https://knowledge.catonetworks.com/docs/en/product-update-april-28-2025).

FortiOS 7.6.4 distinguishes RFC6587 reliable TCP mode from TLS encryption settings.
Test framing and encryption against the deployed firmware. TCP/TLS transport
success does not acknowledge a synced receiver spool; account for device buffers
and site-gateway loss separately. [Fortinet settings](https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/141516630/config-log-syslogd-setting).
Cloudflare can reuse object intake rather than requiring another generic polling
framework. [Logpush S3 destination](https://developers.cloudflare.com/logs/logpush/logpush-job/enable-destinations/aws-s3/).

## Role and failure-domain map

```text
Source / native delivery [F1]
  |-------------------------> independent protected originals [F6, M3]
  |
  +--> host/node collector --+
  +--> regional AWS adapter -+--> authenticated source receipt [M1]
  +--> SaaS API adapter -----+       + bounded prepared-event spool
  +--> site syslog gateway --+                   |
                                    normalize + verified identity
                                                |
                                  canonical HTTP / EventSink [M2, F2]
                                                |
                         signal-server: Parquet + predicates + findings [M4]
                              |          F3 shared account/process
                              +--> query [F4] / detection lag [F5]
                              +--> proposed private outbox / SecOps [F7]
```

This is a responsibility map, not mandatory extra hops. An adapter can run beside
the server where permissions and failure budgets permit. Native original delivery
may precede collection. Where a source has no independent native archive route,
the site/source receipt must bridge outages within a measured budget; do not claim
account-independent protection before that route exists.

Keep agent, AWS collector, SaaS collector and gateway as four operational roles.
Retain cluster metadata coordination as a bounded sub-role, not a reason for a
fifth service today. Separate processes when credential privilege, site placement,
memory isolation or measured scaling requires it. Share libraries, not one
universal credential set. Polling remains necessary for API-only sources,
configuration discovery and reconciliation even with event-driven bulk delivery.

Before parallel collectors, define partition ownership and fencing for cursor
commits; local advisory locks are not distributed HA. Isolate fairness/quotas by
source so one account or poisoned page cannot starve protected streams. Track
source freshness/coverage, spool bytes/age, checkpoint lag, oldest unfinished
receipt, retries, quarantine and exhausted recovery horizon. Observer self-health
must survive the failures it is intended to report.

## Proposed sequence and next task

The file/stdin agent and generic canonical HTTP path already exist. EKS is new
work, and broad source collection remains Phase 9/post-MVP. Do not restart the
MVP or make all integrations prerequisites for the current release.

1. The selected bounded coverage-history slices (payload/identity-prefix pruning
   and fixed-frontier scans) now pass locally with 96 coverage/358 workspace tests.
   Keep observer integration separate; no live source health follows.
2. [The bounded CloudTrail receipt/profile design](29-cloudtrail-source-receipt.md)
   supplies original synthetic fixtures and custody/replay requirements. The pure
   Rust record normalizer/profile and exact D01 correction now have 377-test
   workspace evidence; custody, native delivery and source coverage remain open.
   Freeze source-receipt metadata/progress schemas and binary golden vectors next.
   Offline projections do not qualify the receipt store.
3. Implement bounded source-receipt custody before retained CloudTrail S3 objects
   and SQS discovery, with replay/coverage fixtures and D01/D02/D03/D05 predicates.
   Reuse existing SDK/spool/WAL seams where they fit; do not build a universal
   provider workflow before proving one adapter. Native
   evidence permissions, proof validation and outage qualification are explicit
   PS-04 gates before security-control claims.
4. Add a selected CloudWatch delivery adapter and EKS audit profile. Add EKS
   workload/CRI collection and bounded metadata independently; node agents do not
   replace control-plane audit. Other AWS object formats reuse the transport only
   after their own normalization/coverage tests.
5. Qualify site syslog/FortiGate; then selected Microsoft 365 feeds; then Cato.
   Cloudflare S3 Logpush can reuse the object path when prioritized. Advance a
   source earlier if an initial detection demonstrably requires it.

Each source slice must pass raw→canonical→finding fixtures, negative/missing-field
cases, source identity rejection, bounded malformed-input handling and the A1
crash/replay matrix. Synthetic transport tests precede authorized live source
qualification. PS-03 finding delivery can progress independently; it need not wait
for every collector or a correlation engine.

No credible AWS cost estimate follows from “100 accounts” alone. Measure daily
compressed/uncompressed bytes by source, burst rate, source delivery latency,
retention, query scan volume/concurrency, object size/count and catch-up throughput.
Model CloudWatch/stream delivery, object requests/storage, KMS, cross-region/NAT
traffic and query compute separately. Benchmark before adding a hot store or
splitting the server. Select EC2/EKS deployment from permissions, placement and
operating constraints once a concrete source slice is scoped.

Bounded coverage-history implementation is accepted locally. The next new
ingestion task is the CloudTrail source-receipt/profile design,
not four new binaries. No release gates, public/private ownership rules or
publication authority change in this audit.
