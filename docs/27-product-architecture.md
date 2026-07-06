# Product architecture and design envelope

Status: target architecture baseline for the owner-requested product positioning,
2026-10-07. This settles product boundaries and engineering direction. It does not
declare the target implemented, qualified or released. Changes to these decisions
need a documented requirement or measured result. The
[release audit](21-release-readiness.md) remains authoritative for current proof.

## 1. Product and customer

PLATFORM::SIGNAL is a self-hosted log and security telemetry platform for small
and mid-sized cloud-native organizations. Its target workflow combines AWS,
Kubernetes, selected SaaS and network evidence with infrastructure context,
search, actionable detections and alert delivery. The design prioritizes
recoverability, security and low operating effort for a shared DevOps/SecOps team.

| Design dimension | Primary target, not a supported-capacity claim |
| --- | --- |
| Organization | Approximately 100–1,000 employees; 3–30 platform/DevOps/SecOps engineers; no dedicated observability team required |
| AWS footprint | 5–100 accounts, normally 1–5 Regions, 1–20 EKS clusters |
| Workloads | Tens to low thousands; explore up to 5,000 monitored workloads, recording hosts, nodes, pods and containers separately |
| Main volume | GB/day through 2 TB/day; 2–5 TB/day is the upper design profile |
| Operating model | AWS-first, self-hosted, automated installation/upgrades, simple recovery and explicit cost controls |
| Initial product | Logs, security events, infrastructure identity/context, search, detections and alerts |

Employee/account/cluster counts guide discovery, permissions and cardinality tests;
they do not determine throughput. No claim of comparative vendor cost, market
coverage or achieved scale follows from this positioning.

## 2. Settled architecture decisions

| Decision | Consequence |
| --- | --- |
| Modular Rust monolith remains the default | Keep existing crates and `signal-server`; retain DataFusion/Parquet. No language rewrite for cross-compilation convenience |
| Four role families: agent, collector, gateway, server | Roles describe placement and permissions, not four mandatory deployments or new binaries today |
| AWS-native bulk delivery, API polling where necessary | Collector modes cover AWS, SaaS and cluster metadata with independently scoped credentials and queues |
| S3 is the durable telemetry/evidence plane | Local disks spool and cache; independent protected originals remain security-owned |
| Small uses local control state; Standard uses PostgreSQL for shared control state | No mandatory separate database service for Small; choose one shared relational control backend for Standard, not a separate catalog, coordination and outbox service each |
| Selective query acceleration | Parquet projection/partition pruning first, optional measured field indexes and local caches later; no mandatory ClickHouse/Elasticsearch tier |
| Bounded spool plus explicit custody receipts | No required Kafka/NATS cluster or custom distributed queue; SQS/Kinesis remain optional source transports |
| Security controls apply across deployment sizes | Profiles change capacity/availability, not access-control strength or feature licensing |
| Native AMD64 and ARM64 qualification | Every deployable and native dependency must build and run on both; cross-compilation alone is insufficient |

The PostgreSQL choice is a target backend decision, not a new dependency or a
claim that the present SQLite coverage store is remotely shareable. Its schema,
transaction/fencing contract and migration require a bounded design task before
implementation. Use a managed HA deployment for the AWS Standard reference
profile to reduce database operations. Do not turn it into a bulk telemetry
broker. Public engine state and private integration/outbox state need separate
schema/role permissions even when they use the same database service.

## 3. Roles, placement and deployment profiles

| Role | Responsibilities | When separately deployed |
| --- | --- | --- |
| `signal-agent` | Host/node capture, local identity, bounded disk spool and outbound delivery | Where local logs are required; not on every account or managed AWS service |
| `signal-collector` | AWS object/stream and SaaS adapters; Kubernetes metadata coordination; receipts/checkpoints | Where credentials, Region/site placement or source rate limits require separation; AWS/SaaS/cluster modes share code, not credentials |
| `signal-gateway` | Transport termination, source authentication, admission bounds and durable forwarding | Site syslog, transport translation or network isolation; optional when an adapter can reach server admission directly |
| `signal-server` | Ingest, object publication, query, detection, findings, API and control coordination | One process by default; identical binaries with partition ownership for Standard, then separate role workers only after evidence |

`signalctl` remains an operator tool. Cluster metadata coordination is a collector
mode; it is distinct from node log capture and EKS control-plane audit delivery.
FortiGate normally uses site syslog intake, not the SaaS polling mode. A product
role does not require an extra network hop or a universal privileged binary.

| Profile | Planning envelope | Target topology | Availability boundary |
| --- | --- | --- | --- |
| Small | Up to about 20 accounts, 1–3 clusters, under 100 GB/day | One server, optional gateway, only needed agents/collectors; S3 plus local control database/journals and tested backups | Single writer; maintenance/host outages allowed within the selected spool/recovery budget |
| Standard — primary product | About 20–100 accounts, 3–20 clusters, 100 GB–2 TB/day | Three servers across failure domains; zero or 2–3 gateways where required; S3 and one HA PostgreSQL control store; scoped collectors | Target survives one server/AZ failure after distributed custody, ownership and restore gates pass |
| Scale — upper design range | Approximately 2–5 TB/day; near or beyond 100 accounts/20 clusters | Same software, independently sized ingest/query/detection workers and gateway pools, S3 and shared control store | Requires measured contention/capacity reason for each split; no global active/active promise |

These ranges overlap and are planning categories, not license tiers or automatic
node-count calculators. Size by bytes, bursts, query concurrency and rule state.
Deploy on EC2/container hosts when no cluster already exists; use EKS when the
operator already runs it. Kubernetes is not a product prerequisite. Helm packages
SIGNAL workloads; it does not by itself provision or authorize AWS/IdP resources.

**Today:** the chart enforces one replica and one filesystem writer. Never turn
the Standard profile into a `replicaCount: 3` change on the present chart. See
[chart constraints](../deploy/helm/signal/README.md).

```text
AWS native evidence ───────────────────────────> security-owned S3 originals
     │                                                    │
     └─> scoped collector ─┐                              │ references/proofs
host/node agent ──────────┼─> optional gateway ─> signal-server
SaaS API collector ───────┤                       ingest/query/detect/API
site syslog receiver ────┘                           │           │
                                         S3 Parquet/manifests   control state
                                           + local cache       SQLite/local: Small
                                                               PostgreSQL: Standard
                                                                    │
                                                         findings/outbox/disposition
```

Keep observability processing and independent security evidence in separate trust
domains. A combined “observability/security account” is not the reference for
account-compromise resilience. Account inventory, deployment values, actual
retention, permissions and routing remain in the private application.

## 4. Storage, indexing and authoritative state

“S3 is durable truth” applies to retained telemetry and evidence. It does not mean
all platform state is an object, all objects are trusted, or local admission has
already reached S3.

| State | Authority and recovery |
| --- | --- |
| Authorized original evidence | Retained object/version plus digest and capture provenance; source validation and Object Lock status recorded separately |
| Queryable telemetry | Immutable normalized Parquet objects and versioned committed manifests; retain schema/normalizer revisions and source references |
| Accelerators | Derived partition statistics, selected field indexes and local caches; rebuildable within a measured time/cost budget |
| Live workflow/control state | Durable receipts, source cursors, ownership epochs, configuration/rule pins, findings, outbox and dispositions; backup/restore and transaction semantics required |
| Identity/access policy | Trusted configuration/IdP and server-enforced authorization; never reconstructed from producer attributes or query indexes |

The control database contains bounded workflow/catalog metadata, not every log
field or raw payload. A database backup alone does not recover object versions;
an object bucket alone does not recover every cursor, permission or disposition.
Define a consistent restore checkpoint spanning retained objects and control state.
Do not claim all state is reconstructible from raw events or enable automatic
historical redetection after losing rule/receipt revisions.

For Standard, assign one active owner per ingest/detection partition with a
monotonically fenced epoch. Upload immutable uniquely named objects, then publish
their manifest references and progress in a transaction that verifies ownership.
Stale owners may leave unreferenced objects; they must not publish a committed
manifest, checkpoint or notification. Fence compaction and retention too. An
expired lease alone is insufficient. Bound orphan cleanup and retain objects
reachable from supported reader snapshots. S3 does not atomically transact across
multiple keys, so object existence cannot replace this commit protocol.
[S3 consistency](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel).

A shared load balancer is not shared durable state. Stateful detection and
findings must follow partition ownership; query workers use committed snapshots.
If control ownership cannot be verified, fail closed on commits and apply bounded
backpressure. Do not invent a new consensus system to eliminate one database.

Selective indexing is a cost-control feature, not a promise that arbitrary scans
are fast. Partition by bounded time/source-scope dimensions, prune files, project
selected fields, then benchmark whether optional indexes help. Unindexed fields
remain queryable while retained, subject to explicit scan/time/memory budgets;
report limits and incomplete results rather than silently returning empty success.
Per-pod/user IDs are not default object partitions. Batch and compact to limit
small-object requests, with measured publication latency and memory limits.

Retain what the approved source policy requires; avoid “store everything forever.”
Sampling/rejection of observability input must be declared and counted. Protected
input is unsampled and never intentionally evicted to favor debug traffic, within
its documented source coverage and outage budget. Raw, searchable and index
retention are separate. The owner's 7–30/30–90/90–365+ day ranges are examples,
not fixed product defaults or company policy. Retention validation must detect
conflicts between replay horizons, evidence references, index expiry and locks.

Use immediately readable S3 classes for online historical queries. Optional deep
archive explicitly means asynchronous restoration and different query SLOs;
Glacier Flexible Retrieval/Deep Archive cannot meet an unconditional “no
rehydration” promise. [AWS retrieval semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/archived-objects.html).
Object Lock protects retained versions, not source completeness or authenticity.
[Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).

## 5. Reliability objectives and custody

The Standard design objective is **99.9% monthly control/API availability**, not
five nines. Measure eligible authenticated requests within published operation
budgets; include service failures/timeouts and platform-caused throttling within
the contracted load, exclude invalid/unauthorized requests. Report planned and
unplanned disruption; 99.9% allows 43.2 minutes in a 30-day period. Small reports
actual availability without inheriting the HA objective.

Availability, evidence preservation, detection freshness and notification delay
are separate measures. Source-created→observed delay must be separated from
SIGNAL-admitted→finding delay. Require numerical per-source/profile lag and
catch-up budgets before qualification; provider delivery delay prevents a single
honest end-to-end detection deadline for all sources.

| Condition | Target contract and acceptance |
| --- | --- |
| Process restart | Replay exact admitted/prepared identity; tolerate duplicates; no acknowledged record silently disappears |
| Standard server/AZ loss | RPO 0 for acknowledged object-backed custody within the tested failure model; replacement owner resumes within a provisional 15-minute failover objective |
| Source-to-server outage | Qualify 15-minute, one-hour and four-hour outage/replay scenarios at selected input rates; no loss only while source/spool capacity and retention suffice |
| Account/Region loss | Independent protected originals survive only under the separately tested security-account/replication policy; reconstruction RTO/RPO are measured per deployment, not implied by three nodes |
| Exhausted recovery horizon | Explicit gap, degraded coverage and independent health notification; never claim losslessness or healthy silence |

M2 still means synced local WAL. Local custody protects against a different set
of failures than committed object custody. The Standard target must provide an
explicit, versioned **object-backed custody receipt** before a producer relinquishes
its last independently recoverable copy. That receipt requires an accessible
retained object and a committed idempotent control record, not a successful PUT
alone. It is distinct from completed detection and from M3 protected-evidence
validation. The current API does not supply it; do not silently reinterpret 202.
Native sources may already supply independently durable originals.

No design promises recovery of events never emitted, never captured, expired at
the provider, or dropped before durable intake. SourceCoverage and observer health
remain necessary. TCP acknowledgements and encryption do not acknowledge disk
custody. See the existing [failure contract](failure-domains.md).

Size spools by the longest supported outage plus catch-up and reserve:

```text
usable_spool_bytes >= persisted_bytes_per_second × outage_seconds × headroom
catch_up_seconds  = backlog_bytes / (replay_bytes_per_second - new_bytes_per_second)
```

The second equation requires replay throughput greater than new arrival rate.
Use measured persisted compression/framing, not assumed ratios. At 1 TB/day of
uncompressed bytes, four hours is 166.7 GB; at 2× headroom it is 333.3 GB before
filesystem overhead. At 5 TB/day the same reserve is about 1.67 TB. Capacity must
cover the actual ownership/failover distribution; summing all disks is not a
guarantee that one hot shard can use them. Reserve control/receipt capacity so data
pressure cannot erase recovery state. Native retained S3 sources may need less
local payload spooling than non-replayable sources.

## 6. Resource and scale budgets

All numbers below are **initial engineering targets**, not benchmark results or
deployment guarantees. Memory means process RSS in MiB/GiB; CPU means cores;
daily traffic means decimal GB/TB of canonical uncompressed admitted payload.
Report original-wire and stored-compressed bytes separately.

| Component | Initial budget | Qualification workload |
| --- | --- | --- |
| Agent | Idle RSS <50 MiB; typical <100 MiB; idle mean CPU <0.01 core; normal mean CPU <0.1 core | Idle after warm-up; typical 100 events/s at 1 KiB, ten tailed files, batching/transport and bounded metadata enabled; measure 30 minutes, plus separate outage/rotation stress |
| Gateway | Start at 2–4 vCPU / 2–8 GiB RAM | Selected protocol, TLS, decompression, spool writes and replay under per-source fairness; publish achieved bytes/s and limits |
| Small server | Start at 2–4 vCPU / 4–8 GiB RAM | Full ingest→object→query→detection workload at the selected Small volume and concurrency |
| Standard server | Start at 4–8 vCPU / 8–16 GiB RAM per node | Shared-state commits, query contention, rule set, compaction, one-node failure and catch-up; no assumption three nodes meet 2 TB/day |

Budget collectors separately for API concurrency, object expansion and Kubernetes
cache cardinality. Include database, gateways, agents, S3 requests/KMS, network,
query scans, backup and operator time in total cost; raw storage alone is not TCO.
Existing finite AMD64 measurements do not qualify these profiles.

The upper design envelope is 5 TB/day, roughly 100 accounts and 20 clusters, with
50k–200k events/s as **aggregate burst experiments**. Start burst qualification at
60 seconds and state recovery time and sustained background traffic. At 1 KiB per
event, 1–5 TB/day averages about 11.3k–56.5k events/s; 200k sustained would be
17.7 TB/day. Repeat with 4 KiB and larger bounded records; event count without
size/duration is not a capacity specification. Traffic beyond this envelope is
outside primary optimization, not forcibly rejected by license.

Each published profile needs a workload manifest: event-size distribution,
source mix/cardinality, raw-retention/index choices, rule/window counts,
query selectivity/concurrency, compression, hardware/storage, architecture,
steady/burst durations, loss/duplicates, p95/p99 latencies, peak RSS and catch-up.
Run both native architectures, a 24-hour steady campaign and controlled failure
tests before a supported-capacity claim; longer stability evidence remains a
separate operational qualification. Tune budgets from evidence, recording changes.

## 7. Security and useful defaults

Production profiles require the following acceptance; these controls are target
requirements, not claims about the current optional-Bearer development server.

| Control | Required evidence |
| --- | --- |
| Authenticated transport | mTLS between deployed SIGNAL components; approved provider authentication at adapters; certificate rotation/revocation and failed-chain tests; outbound-only agent connections |
| User and source access | OIDC user sign-in, scoped API credentials/RBAC, account/resource scope checks on ingest/query/raw evidence/findings, separate admin roles; cross-scope denial tests |
| Encryption and secrets | TLS; encrypted local volumes, objects, control database and backups; AWS KMS and Secrets Manager integration, workload identity/least-privilege IAM and rotation/recovery tests |
| Audit and evidence | Audit config/rule/access/admin actions to a restricted independent destination; protected original retention/validation; failure health outside the failing observability plane |
| Release/update trust | Signed artifacts and rule bundles, SBOM/provenance verification, supported upgrade/rollback and restore procedures; no unsigned auto-update fallback |
| Resource abuse | Bounded parsers/queues/state, scoped quotas, safe diagnostics and protected-stream admission; poisoning, isolation and saturation tests |

Use established identity and cryptographic mechanisms. Trusted TLS/OIDC ingress
may supply termination, but SIGNAL must verify trusted identity propagation and
enforce authorization with no bypass. Reuse the organization's IdP; do not build
an identity server. “Enterprise-grade” describes the ambition, not a certification.

Ship opt-in, versioned **generic baseline detection packs** with source
preconditions, fixtures, evidence explanations, severity/confidence guidance and
investigation steps. This generic reusable content may be public. Actual enabled
rules, thresholds, exceptions, sensitive detections and response routing stay
private. Baselines do not authorize automatic remediation.

Onboarding should show connected → coverage verified → supported detections active,
with missing permissions/log categories/state visibly blocking relevant rules.
“Useful immediately” means after required data/preconditions exist, not after a
successful OAuth or AssumeRole handshake. Root activity/control tampering can
start with predicates; unusual role use, effective privilege escalation,
impossible travel and multi-source compromise need additional state/context.
Keep current [15 detection requirements](source-detection-catalog.md) as the
executable starting point, then add one evidenced pack capability at a time.
Record analyst disposition and tuning; share one resource/time/evidence workflow
between DevOps and SecOps while preserving their permissions.

## 8. Product milestones and explicit exclusions

The current `0.1.0-dev.0` core and its release checklist remain separate from
the first operational product scenario. Do not advertise a completed AWS/SaaS
platform when releasing only a qualified core library/server milestone.

1. **Core qualification:** finish selected bounded coverage-history work and
   existing ARM64/EKS/CI/released-dependency gates. Keep local design work runnable
   while external gates are unavailable.
2. **AWS operational foundation:** CloudTrail source receipts/coverage, S3 original
   and query publication, baseline predicates, scoped security controls and
   durable finding delivery; prove the full source→evidence→finding→notification
   path before expanding the adapter count. Choose a bounded Small pilot first.
3. **Primary Standard profile:** shared control state, object custody, fenced
   ownership, secure onboarding, restore/failover and supported workload evidence.
   Add EKS audit/workload context and the first bounded detection windows.
4. **Selected external evidence:** FortiGate/site syslog, chosen M365 feeds and
   Cato, with Cloudflare reusing object intake; source priority follows customer
   evidence requirements. Add bounded correlation and dispositions only with the
   necessary inputs. This completes the intended multi-source product scenario.
5. **Scale profile:** separate workers only when measured Standard contention,
   privilege isolation or recovery budgets justify the operational cost.

These are product milestones over PS-01–PS-06, not new version assignments or
permission to provision accounts. [The implementation plan](04-implementation-plan.md)
still selects one bounded change set at a time. The next existing implementation
task remains payload-prefix pruning; the first new ingestion design is the
CloudTrail durable source-receipt/normalization contract.

Initial non-goals: full APM, continuous profiling, RUM, synthetic browser testing,
a tracing or custom time-series backend, broad SaaS/plugin catalogs, ML/AI causal
RCA, multi-cloud parity, universal on-prem support, petabyte query scale, global
active/active federation, a custom Kafka replacement and license-gated deployment
features. Metrics can supply selected context later without becoming a parallel
time-series product. Retain the current v1 event envelope and explicit typed
extensions; shared context does not erase the semantic differences among signal
types.

## 9. Change and evidence boundary

This baseline finalizes the target customer's constraints, role families, storage
and control responsibilities, profile structure, security requirements and
qualification budgets. Implementation contracts still need executable acceptance
for S3 publication/custody, distributed fencing, authorization, stateful detection
and migration. A final architecture direction is not a claim of solved distributed
correctness. No replica setting, dependency, wire schema or release gate changes
as a side effect of this document.

S3 behavior was checked against primary AWS documentation on 2026-10-07 after
Context7 returned only general S3 material. Source-specific delivery details
remain in the [ingestion audit](26-ingestion-architecture-audit.md). Deployment
policy and private operational data remain outside OSS.
