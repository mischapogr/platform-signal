# Finite execution ledger

Owner-authorized persistent Goal, frozen 2026-10-07. The machine-readable
[ledger](31-execution-ledger.json) is the item inventory; each item records
dependencies, executable acceptance and evidence paths. Pending evidence paths
are destinations, not proof that reports exist. Existing progress/release
reports remain authoritative for accepted results.

This reconciles [product scope](27-product-architecture.md),
[implementation order](04-implementation-plan.md), [routing](11-model-work-plan.md),
[current progress](07-progress.md) and [release gates](21-release-readiness.md).
The newer progress/routing acceptance supersedes old “UI then pruning” next-step
text: UI-01/UI-02, coverage pruning/scans and initial source receipts are done.
OBJECT-READER is accepted locally; AWS-DELIVERY now has local signed-transport/delivery simulation acceptance; COVERAGE-OBSERVERS is in progress with bounded state and regional configuration observation accepted; independent checkpoint/gap simulation and server integration remain.

## Execution and evidence

One coherent writer change set at a time. Verify, resolve focused review, record
evidence and continue the next dependency-ready item without a routine approval
stop. This Goal authorizes post-MVP implementation and bounded independent
review/testing; it does not authorize external provisioning or publication.
Use statuses `pending`, `in_progress`, `passed_local`, `passed_simulated`,
`external_pending`. A dependency with both local and external aspects must be
split: local simulation acceptance never satisfies the real environment gate.
Do not convert complexity or ordinary test failure into an external exception.

The ledger fixes capabilities, not hypothetical scale promises. Contracts for
unimplemented capabilities must be made executable within their existing item
before code. Profile claims require actual measurements. Scale worker separation
is conditional on evidence; a justified no-split decision satisfies that item.
Advanced SOC UX remains post-MVP; universal SOAR/AI RCA/APM and other explicit
product non-goals are excluded. Actual enabled policy/configuration/routing and
private fixtures stay in the private repository. Its writes require the correct
writable scope, not a reverse dependency or copied private data in public core.

Simulations use isolated local endpoints and synthetic identities. Test relevant
rate limits, paging, duplicates, malformed data, scope denial, crashes, replay,
uncertain effects and retention exhaustion. Local evidence is never native
ARM64, actual AWS/EKS, live vendor or remote CI evidence. No full release claim
while these gates remain open. Retain final candidate bindings and documented
external exceptions even after the local Goal is complete.

The frozen retirement contract requires a confirmed source ACK. Therefore ACK
control follows the qualified owner-handover/reconciled-open substeps, then
retirement completes RECEIPT-RECOVERY. This corrects the initial dependency order
without adding capabilities or claiming general recovery from copied bits.

## Frozen inventory

| Item | Status | Depends on | Outcome |
| --- | --- | --- | --- |
| CORE | passed_local | — | Core phases 0–8, bounded phase 10 and minimal SecOps UI |
| COVERAGE | passed_local | CORE | Bounded SourceCoverage history/intake/corrections/pruning/scans |
| RECEIPT-BASE | passed_local | CORE | CloudTrail normalization/profile and initial receipt store |
| RECEIPT-PROGRESS | passed_local | RECEIPT-BASE | Atomic verified-prefix progress and immutable suffix replay |
| RECEIPT-RECOVERY | passed_local | RECEIPT-PROGRESS, SOURCE-ACK | Retirement, owner takeover and restore reconciliation |
| SOURCE-ACK | passed_local | RECEIPT-PROGRESS | Source acknowledgement and selected custody seam |
| OBJECT-READER | passed_local | RECEIPT-RECOVERY | Bounded CloudTrail gzip object reader/preparation |
| AWS-DELIVERY | passed_simulated | SOURCE-ACK, OBJECT-READER | CloudTrail S3/SQS collector and local delivery simulation |
| COVERAGE-OBSERVERS | in_progress | COVERAGE, AWS-DELIVERY | Source observers, health and SDK/server integration |
| FINDINGS-CURSOR | pending | CORE | Durable public findings cursor runtime |
| OUTBOX | pending | FINDINGS-CURSOR | Private transactional finding cursor/outbox and notification simulation |
| DISPOSITIONS | pending | OUTBOX | Disposition/outcome backend seam |
| EVIDENCE | pending | AWS-DELIVERY | Independent protected original route and validation simulation |
| S3-QUERY | pending | CORE | Object-backed Parquet and committed query manifests |
| RETENTION | pending | S3-QUERY, EVIDENCE | Selective query acceleration, retention and cost controls |
| SECURITY-ACCESS | pending | CORE | OIDC/trusted identity, scoped credentials and RBAC |
| SECURITY-TRANSPORT | pending | SECURITY-ACCESS | mTLS and credential/certificate rotation |
| SECURITY-AUDIT | pending | SECURITY-ACCESS, EVIDENCE | Restricted independent audit and secrets/encryption integration seams |
| SMALL-PILOT | pending | AWS-DELIVERY, COVERAGE-OBSERVERS, OUTBOX, EVIDENCE, S3-QUERY, SECURITY-TRANSPORT | Small source→evidence→finding→notification simulation |
| SHARED-CONTRACT | pending | SMALL-PILOT | PostgreSQL shared-control schema, transactions, fencing and migration contract |
| SHARED-RUNTIME | pending | SHARED-CONTRACT | Shared-control implementation and local PostgreSQL qualification |
| OBJECT-CUSTODY | pending | SHARED-RUNTIME, S3-QUERY | Versioned object-backed custody receipt |
| STANDARD-RECOVERY | pending | OBJECT-CUSTODY, SECURITY-AUDIT | Standard ownership, failover and consistent restore simulation |
| ONBOARDING | pending | COVERAGE-OBSERVERS, SECURITY-ACCESS, SHARED-RUNTIME | Secure scoped onboarding and coverage/detection activation |
| CLOUDWATCH | pending | SMALL-PILOT | Bounded CloudWatch managed-log intake |
| AWS-PROFILES | pending | CLOUDWATCH, OBJECT-READER | AWS RDS/ALB/NLB/ECS/VPC/DNS/WAF/security-event profiles |
| EKS-AUDIT | pending | CLOUDWATCH | EKS/Kubernetes audit adapter |
| K8S-CONTEXT | pending | EKS-AUDIT | Node/workload context and cluster collector mode |
| HOST-AUTH | pending | SMALL-PILOT | Selected host/runtime and authentication source profiles |
| SYSLOG | pending | SECURITY-TRANSPORT, SOURCE-ACK | Site TCP/TLS syslog and FortiGate normalization |
| M365 | pending | SMALL-PILOT | Selected Microsoft 365 audit/authentication API feeds |
| CATO | pending | M365 | Cato API event collection |
| CLOUDFLARE | pending | OBJECT-READER, SMALL-PILOT | Cloudflare object-delivery normalization |
| BASELINES | pending | EKS-AUDIT, AWS-PROFILES | Versioned generic baseline predicate packs |
| WINDOW | pending | FINDINGS-CURSOR, HOST-AUTH, COVERAGE-OBSERVERS | First bounded window detector D10 |
| STATE | pending | WINDOW, BASELINES | Scoped state lookup detectors D04/D06/D08/D09/D12/D13 |
| SENSOR-HEALTH | pending | COVERAGE-OBSERVERS, WINDOW | Independent missing-telemetry detector D15 |
| CORRELATION | pending | STATE, DISPOSITIONS, CATO, M365, SYSLOG | Bounded multi-stream episodes D11/D14 |
| SOC-UX | pending | CORRELATION, DISPOSITIONS, SECURITY-ACCESS | Planned advanced SOC case/disposition/workbench workflows |
| PROFILE-LOAD | pending | STANDARD-RECOVERY, CORRELATION | Resource/profile and controlled-outage qualification |
| SCALE-DECISION | pending | PROFILE-LOAD | Measured Scale profile worker-separation decision |
| KIND | pending | CORE | Current-revision local Kubernetes persistence/restart gate |
| RELEASE-REVIEW | pending | RECEIPT-PROGRESS | Independent source review and resolve findings |
| RELEASE-TRUST | pending | BASELINES, SECURITY-TRANSPORT | SBOM, provenance and signed release/rule verification |
| UPGRADE | pending | SHARED-RUNTIME, STANDARD-RECOVERY | Supported migration/rollback/restore local rehearsals |
| LOCAL-CANDIDATE | pending | SOC-UX, SCALE-DECISION, KIND, RELEASE-REVIEW, RELEASE-TRUST, UPGRADE | Final current-revision local release candidate |
| EXT-ARM64 | external_pending | — | Native ARM64 qualification |
| EXT-AWS | external_pending | — | Actual AWS/EKS/storage/IAM/KMS/Object Lock qualification |
| EXT-VENDORS | external_pending | — | Live SaaS/network-provider qualification |
| EXT-CI | external_pending | — | Remote CI for reviewed revision |
| EXT-DEPENDENCY | external_pending | — | Private overlay against actual released public dependency |
| EXT-PUBLICATION | external_pending | — | Owner-directed version, publication and main merge |
