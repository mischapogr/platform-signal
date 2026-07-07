# PLATFORM::SIGNAL — AWS adoption
Source snapshot: 2026-07-07. Estimated delivery: 40–45 minutes plus discussion; use Contents to select chapters.

## 01. Your telemetry. Your context. Your control.

PLATFORM::SIGNAL: an AWS-first log and security telemetry platform built around an OSS core and private company policy.

Decision today: evaluate a bounded pilot. Production adoption depends on qualification.

**Speaker notes**

Allow 40–45 minutes plus discussion. This is an architecture and adoption presentation, not a released-product sales pitch. The core exists and has local AMD64 evidence. S3, Standard HA, production access controls and end-to-end AWS collection remain target capabilities. The deck uses an invented company scenario and no private account, policy or customer data.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 02. Control is the reason to evaluate

A good fit when a shared platform/security team needs a focused evidence workflow and can own its operation.

**DevOps**

- Search operational events with account and resource context.
- Recover admitted events after process restarts.
- Make pressure, rejection and capacity visible.

**SecOps**

- Inspect a finding and its retained source events.
- Keep sensitive detections and routing private.
- Target: verify source coverage and preserve independent originals.

**Architects**

- Stable event contracts and replaceable storage seams.
- Start with one process; split after measured need.
- Target: separate telemetry, control state and security trust.

A pilot must prove value, operating effort and total cost; savings are a hypothesis.

**Speaker notes**

The shared benefit is one vocabulary for resource, time and evidence. Each team still has different permissions and duties. Search does not replace incident ownership. Self-hosting transfers platform availability, dependency updates and detection maintenance to the adopter. Do not infer lower cost from Rust or object storage alone.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Architecture / canonical event / OSS boundary](../../01-architecture.md)
- [Read-only SecOps UI contract](../../28-secops-ui.md)

## 03. A working core; an unfinished product



**Implemented locally**

- Authenticated HTTP → synced WAL → Parquet → findings.
- Bounded file/stdin agent and at-least-once replay.
- Read-only UI: findings, search and exact event-ID navigation.
- Local source-coverage library and CloudTrail record normalizer.

**Target / follow-on work**

- S3 publication and object-backed custody receipts.
- Live AWS adapters and independent coverage observers.
- OIDC/RBAC, mTLS and durable notification delivery.
- Shared control state, fenced ownership and stateful detections.

**Qualification still open**

- Native ARM64 and actual EKS runtime.
- Remote CI and released overlay dependencies.
- Current-image kind gate blocked by host resources.
- Unpublished dev candidate; no production scale guarantee.

Local Linux AMD64 proof does not establish AWS production readiness.

**Speaker notes**

The current progress record reports 377 passing Rust workspace tests, but test count is not a capacity or release claim. The CloudTrail normalizer is a bounded pure helper, not a deployed collector. Coverage storage has isolated local evidence, not live source-health inference. Historical container and benchmark results remain bound to their own inputs; do not claim all later source changes ran in those images.

**Sources**

- [Current implementation and local evidence](../../07-progress.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 04. A 450-person company running on AWS



**Environment**

- 12 AWS accounts across two Regions.
- Two EKS clusters plus EC2 and managed services.
- Eight platform engineers and three security engineers.
- Assume 50 GB/day of selected canonical telemetry.

**Problem to investigate**

- Operational logs and audit evidence have different owners.
- Company resource context is repeated across tools.
- Retention and query cost need clearer budgets.
- Teams need a common path from alert to evidence.

**Pilot scope**

- One nonproduction account and one application.
- Use existing HTTP/file paths for the first core exercise.
- Add native CloudTrail delivery only after its adapter is qualified.
- Keep existing detections and archives authoritative.

Company size is context. Size the system by bytes, bursts, queries and rule state.

**Speaker notes**

These assumptions are hypothetical and deliberately within the Small planning category. They do not imply that today's binary supports 50 GB/day. Initial tests use a measured selected rate, not the whole company volume. The two Regions require distinct source and recovery decisions; a single regional pilot does not demonstrate regional disaster recovery.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 05. One evidence workflow, four optional roles



Target: normalize once, keep telemetry and control authority separate, and preserve protected originals through independent delivery. Today: one local-filesystem server; target adapters and stores remain pending.

Roles describe placement and permissions. They do not require four new services today.

**Speaker notes**

The implementation remains a modular Rust monolith. The server owns ingest, storage, query, rules and findings. Agent and signalctl exist; collector and gateway are target role families. Native audit originals can bypass observability and enter a security-owned archive directly. The boxes do not imply fault isolation or implemented adapters.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Logical architecture and trust boundaries](../../logical-architecture.md)

## 06. HTTP 202 is admission, not completion



**What replay protects**

- Admitted records survive qualified process-restart scenarios; checkpoints follow required persistence.

**What retries mean**

- Lost responses can hide successful admission. Independent resubmission can create duplicate records.

**What is still missing**

- 202 provides neither S3 custody nor protected originals, complete coverage or analyst acknowledgement.

Bounded agent → 202 / M2 → Processing / M4 → Read-only UI



**Speaker notes**

M2 is synced WAL, M3 is protected evidence and validation, M4 is processing completion, M5/M6 are delivery plan and destination receipt, M7 is analyst outcome. These milestones need not occur in numerical order. Parquet can be query-visible before finding persistence succeeds; checkpoint advancement then stops. At-least-once processing is not globally exactly-once ingest.

**Sources**

- [Failure domains and M0–M7 custody semantics](../../failure-domains.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 07. A company application depends on OSS



**Public PLATFORM::SIGNAL**

- Canonical event, transport and findings contracts.
- WAL, storage, query and rule mechanisms.
- Collector/enricher SDK and generic adapters as added.
- Target: generic opt-in detection packs with fixtures and preconditions.

**Private company application**

- Account topology, IAM, environments and ownership.
- Enabled rules, thresholds, exceptions and sensitive detections.
- Alert routing, incident integration and deployment values.
- Retention policy, evidence access and private fixtures.

Dependency direction: company → versioned public contracts. OSS never imports company policy.

**Speaker notes**

This is a code and trust boundary, not a claim of a commercial premium edition. The public workspace is Apache-2.0. The target profiles do not license-gate security. A company can contribute a generic hook while keeping its policy private. Today integration uses separate source checkouts and trusted in-process extensions; it is not a dynamic plugin marketplace or sandbox. Qualification against released dependencies is still open.

**Sources**

- [Architecture / canonical event / OSS boundary](../../01-architecture.md)
- [External company overlay integration](../../17-external-overlay.md)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)

## 08. Share context without making it authority



**Canonical event**

- Version, ID, event/observation times, source and severity.
- Message plus nested attributes; optional resource and trace IDs.
- Private metadata enriches the event through public seams.

**Company context**

- Resolve resource → service → owner → environment.
- Pin schema, normalizer and rule revisions for replay.
- Validate private metadata in the company application.

**Access and change**

- Producer attributes never grant authorization.
- Target RBAC must verify trusted account/resource scope.
- Test upgrades in both repositories and rehearse restore.

Stable public mechanisms reduce forks; the adopter still owns private policy correctness.

**Speaker notes**

A service tag supplied by a producer is useful context, not proof of who is allowed to read an account. Do not add company-specific fields to the OSS envelope. The current extension model trusts cooperative application code. The owner must qualify version compatibility and restore before an operational upgrade. Current same-binary restore proof does not establish cross-version migration.

**Sources**

- [Architecture / canonical event / OSS boundary](../../01-architecture.md)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [External company overlay integration](../../17-external-overlay.md)

## 09. Keep evidence outside the processing account



Standard target: workers across three AZs, object publication plus fenced control commits. One-account scenario cannot provide a separate security-account failure boundary.

Native original delivery and security administration stay independent of processing. AWS qualification remains pending.

**Speaker notes**

Separate AWS accounts help only when administration, delivery, credentials and recovery are also independent. Object Lock protects retained object versions; it does not establish source completeness or authenticity. The topology is proposed, not deployed. Choose EC2/container hosts if the company has no Kubernetes operations; use EKS when it already operates clusters. Never create a cluster simply to satisfy this drawing.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Logical architecture and trust boundaries](../../logical-architecture.md)
- [S3 Object Lock retained-version protection](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)

## 10. Begin Small. Earn Standard with evidence.



| Profile | Planning envelope | Target topology | Availability boundary |
| --- | --- | --- | --- |
| Small | <100 GB/day; ~≤20 accounts | One server; S3 + local control; only needed collectors | Single writer; host/maintenance outages accepted |
| Standard | 100 GB–2 TB/day; ~20–100 accounts | Three servers; S3 + HA PostgreSQL; fenced ownership | Target one server/AZ failure survival |
| Scale | ~2–5 TB/day upper design range | Independently sized workers after measured contention | Qualification specific to each workload |

Today's chart enforces one replica. Setting replicas to three does not implement Standard.

**Speaker notes**

These are planning envelopes, not achieved capacity, license tiers or sizing guarantees. Standard requires immutable objects, committed manifests and monotonically fenced ownership; a lease or load balancer is insufficient. Initial target server budgets are 2–4 vCPU/4–8 GiB Small and 4–8 vCPU/8–16 GiB per Standard node, to be validated. Existing finite local campaigns do not qualify them.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 11. From control tampering to useful evidence



**DevOps**

- Identify the affected account/service; check intended changes and restore collection.

**SecOps**

- Inspect native context and archive evidence; determine intent and incident response.

**Coverage**

- Target: show missing audit intervals explicitly. Zero findings alone does not prove safety.

Native record → Normalize + detect → Investigate → Company action

Native normalizer/predicate tests exist. Live delivery, coverage and notification remain pending.

**Speaker notes**

The local normalizer and rule-profile tests include root activity and logging tampering. Do not represent them as a live AWS detector. Current UI can navigate a finding to exact retained canonical rows; those rows are not proof of original vendor bytes. A future workflow needs original-byte custody and validation. Notification and analyst outcome are separate, proposed steps.

**Sources**

- [Current implementation and local evidence](../../07-progress.md)
- [Failure domains and M0–M7 custody semantics](../../failure-domains.md)
- [Read-only SecOps UI contract](../../28-secops-ui.md)
- [Source/detection requirements catalog](../../source-detection-catalog.md)

## 12. Workflow: verify coverage before enabling rules



Inventory → permission checks → positive collection/continuity proof → supported detections. Unknown coverage blocks a clean-security claim.

Automation reduces routine effort only when permissions, source adapters, upgrades and recovery paths are qualified.

**Speaker notes**

Inventory → permission checks → positive collection/continuity proof → supported detections. Unknown coverage blocks a clean-security claim. This is an operational workflow design, not evidence of a deployed observer, distributed control store or automated upgrade system. A published core alone does not fulfill these prerequisites.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Failure domains and M0–M7 custody semantics](../../failure-domains.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 13. Workflow: restore data and control together



A restore must preserve object versions and workflow state. Local same-binary rehearsal exists; this full AWS workflow requires separate qualification.

Automation reduces routine effort only when permissions, source adapters, upgrades and recovery paths are qualified.

**Speaker notes**

A restore must preserve object versions and workflow state. Local same-binary rehearsal exists; this full AWS workflow requires separate qualification. This is an operational workflow design, not evidence of a deployed observer, distributed control store or automated upgrade system. A published core alone does not fulfill these prerequisites.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Failure domains and M0–M7 custody semantics](../../failure-domains.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 14. Workflow: qualify changes before rollout



Target operational workflow after a stable release. Rollback depends on a supported state/schema path; irreversible migrations require restore, not blind binary reversal.

Automation reduces routine effort only when permissions, source adapters, upgrades and recovery paths are qualified.

**Speaker notes**

Target operational workflow after a stable release. Rollback depends on a supported state/schema path; irreversible migrations require restore, not blind binary reversal. This is an operational workflow design, not evidence of a deployed observer, distributed control store or automated upgrade system. A published core alone does not fulfill these prerequisites.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Failure domains and M0–M7 custody semantics](../../failure-domains.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 15. Established products cover more ground today



| Option | Primary strength | Consider when… | SIGNAL comparison |
| --- | --- | --- | --- |
| Splunk Enterprise Security | Broad SIEM investigation, risk-based alerting and response ecosystem | A mature SOC needs rich security workflows | SIGNAL has predicates and read-only evidence UI; broad SOC workflows remain future |
| Elastic Security | Search platform with correlation, threshold and other detection types | You need flexible search and established detection tooling | SIGNAL targets selective Parquet scans; stateful detection is pending |
| Datadog Cloud SIEM | Cloud security investigation within a broad observability platform | Fast managed onboarding and shared vendor tooling matter | SIGNAL emphasizes self-hosted ownership; more engineering stays with adopter |

Comparison is a qualitative fit assessment, not a benchmark or feature-equivalence claim.

**Speaker notes**

Vendor capabilities depend on edition, configuration and contract. These are different products with different scopes. Splunk supports self-managed and cloud options; Elastic supports self-managed and cloud; do not label all incumbents SaaS-only. Datadog also has a BYOC log-management offering, so data ownership is not unique to SIGNAL. The comparative judgment is our inference from documented scope.

**Sources**

- [Splunk Enterprise Security](https://www.splunk.com/en_us/products/enterprise-security.html)
- [Splunk risk-based alerting](https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.3/introduction/about-risk-based-alerting-in-splunk-enterprise-security)
- [Elastic Security scope and deployment](https://www.elastic.co/docs/solutions/security)
- [Elastic detection rule types](https://www.elastic.co/docs/solutions/security/detect-and-alert/using-the-rule-ui)
- [Datadog Cloud SIEM](https://www.datadoghq.com/product/cloud-siem/)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 16. Some alternatives are complementary



| Option | What it provides | Tradeoff / fit judgment | Relationship to SIGNAL |
| --- | --- | --- | --- |
| CloudWatch Logs + GuardDuty + Security Lake | Managed log query, threat detection and an S3/OCSF security lake | Multiple services to integrate; AWS is the natural center | Preserve native protections. Any SIGNAL subscriber/adapter needs design and proof |
| Grafana Loki | Log aggregation with label indexing and compressed chunks | Good log-first option; broader security workflow needs other tooling | Evaluate for operational logs before building a new stack |
| PLATFORM::SIGNAL | Locally proven Rust core; target shared AWS log/security workflow | Private policy and focused mechanisms; adopter owns product gaps | Pilot a specific unmet need rather than replace the estate |

S3, Parquet and data ownership are useful design choices; other platforms offer them too.

**Speaker notes**

Security Lake normalizes supported security data into OCSF Parquet in the customer's AWS account. SIGNAL's canonical event schema is different: an adapter is required, and none is claimed here. GuardDuty is a managed threat detector, not a general application-log search engine. Loki is a logging system, not an equivalent complete SIEM. AWS native services can remain authoritative while SIGNAL is evaluated.

**Sources**

- [CloudWatch Logs scope](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html)
- [GuardDuty scope](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [Security Lake / S3 / OCSF / Parquet](https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html)
- [Grafana Loki architecture overview](https://grafana.com/docs/loki/latest/get-started/overview/)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)

## 17. Compare total ownership, not the license alone



| Option | Cost structure to validate | Work retained by the company |
| --- | --- | --- |
| Splunk | Ingest/workload/activity options; ES package and contract quote | Source onboarding, detection tuning; infrastructure if self-managed |
| Elastic | Deployment resources and chosen subscription/features | Schemas, detections and tuning; cluster operations if self-managed |
| Datadog | Log/SIEM plans, retention and other enabled products | Collection scope, integration, detections and response policy |
| AWS native stack | Log ingest/store/scan, detector/lake fees and downstream services | Cross-service configuration, permissions and investigation workflow |
| SIGNAL | Apache-2.0 core + AWS infrastructure + engineering/support | Runtime, upgrades, adapter maintenance, security and detection content |

No like-for-like quote or capacity trial has been run. No percentage saving is claimed.

**Speaker notes**

Commercial pages change; verify quotes at procurement. Datadog's current public pricing and billing documentation are not perfectly aligned on SIEM units, so this deck deliberately omits unit prices. Elastic costs depend on deployment and subscription. An open core does not provide a contracted support SLA by itself. Include migration and the engineering needed to finish target features when comparing SIGNAL today.

**Sources**

- [Splunk pricing options](https://www.splunk.com/en_us/products/pricing.html)
- [Elastic Security scope and deployment](https://www.elastic.co/docs/solutions/security)
- [Datadog pricing by product](https://www.datadoghq.com/pricing/)
- [CloudWatch pricing dimensions](https://aws.amazon.com/cloudwatch/pricing/)
- [Security Lake pricing dimensions](https://aws.amazon.com/security-lake/pricing/)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)

## 18. Why the example company might adopt



**Data and policy control**

- Choose storage and retention in its AWS environment.
- Keep sensitive policy, topology and routing private.
- Inspect public mechanisms and contribute generic improvements.

**Focused team workflow**

- Use shared resource context for operations and security.
- Build detections around company services and owners.
- Target independently recoverable evidence and visible coverage gaps.

**Architecture discipline**

- Start with a small modular deployment.
- Avoid mandatory broker or search-cluster tiers in the target.
- Measure selective query acceleration before adding indexes.

Adopt when measured control and workflow benefits justify the engineering responsibility.

**Speaker notes**

Target storage and retention control is an opportunity, not a completed integration. Open code may reduce dependency on a vendor-specific query/storage system, but switching still costs money: event mapping, private enrichment, rules and operational processes are investments. Rust and Parquet are implementation choices; neither proves reliability, low memory or cheap operation for the customer's workload.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Architecture / canonical event / OSS boundary](../../01-architecture.md)

## 19. Why the company might choose another option



**Product maturity**

- AWS/SaaS adapters and durable notification are incomplete.
- No advanced cases, SOAR, full APM or broad integrations today.
- No supported production capacity or qualified Standard HA.

**Operating responsibility**

- Company owns on-call, dependencies and restore acceptance.
- Small has one writer and an explicit outage boundary.
- Unindexed historical scans may exceed query budgets.

**Security and economics**

- Production authorization and transport controls need work.
- No established commercial support promise in this checkout.
- Engineering and migration can outweigh license savings.

If mature SOC workflows or managed service accountability are immediate requirements, buy them.

**Speaker notes**

This is the central decision constraint. A small security team should not become an accidental platform vendor. Existing enterprise solutions may be the lower-cost choice after staffing and time-to-value are included. Target security controls must pass before production access; putting the current static-token API behind an IdP does not automatically establish per-scope authorization.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 20. Account count is an inventory assumption



| Illustrative inventory | 1 account | 10 accounts | 100 accounts | 1,000 accounts |
| --- | --- | --- | --- | --- |
| EC2 hosts (outside EKS) | 5 | 40 | 400 | 4,000 |
| EKS clusters | 1 | 2 | 20 | 200 |
| EKS worker nodes | 3 | 12 | 120 | 1,200 |
| Selected running pods | 20 | 120 | 1,200 | 12,000 |
| Aurora clusters / instances | 1 / 2 | 4 / 8 | 40 / 80 | 400 / 800 |
| Other RDS instances | 1 | 8 | 80 | 800 |

EC2 excludes EKS nodes; count Aurora once. The 1,000-account case is outside the target envelope.

**Speaker notes**

Resource counts describe an illustrative selected estate, not a discovered organization or empirical average. Counts include the organization’s central accounts where they exist. Only the 1-account case lacks an independent security account. The 1000-account case is beyond the design envelope. Pods are running monitored workload units, not additional EC2 nodes. Aurora reader/writer instances are not also counted under other RDS. Business workload compute and database prices are excluded from SIGNAL cost.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)

## 21. Separate workload resources from SIGNAL resources



| Illustrative inventory | 1 account | 10 accounts | 100 accounts | 1,000 accounts |
| --- | --- | --- | --- | --- |
| Lambda functions | 5 | 30 | 300 | 3,000 |
| Selected S3 buckets | 5 | 30 | 300 | 3,000 |
| Workload load balancers | 1 | 10 | 100 | 1,000 |
| SIGNAL servers / collectors | 1 / 0 | 1 / 1 | 3 / 2 | 30 / 20 |
| SIGNAL control DB deployments | 0 | 0 | 1 | 10 |
| SIGNAL EBS GiB | 100 | 300 | 1,900 | 19,000 |

Existing EKS control planes and workload databases are not incremental SIGNAL infrastructure.

**Speaker notes**

The scenario allocates c6i.xlarge Linux workers to SIGNAL for costing, not as a capacity prescription: 1 server; 1 server+1 collector; 3 servers+2 collectors; ten 100-account cells. 100 and 1000 accounts use 1/10 separate Multi-AZ PostgreSQL control DB deployments with 200 GiB each. These are not the workload RDS instances above. Cells are independent hypothetical deployments, with no implemented cross-cell federation. Add a dedicated SIGNAL EKS cluster only if desired; the base uses EC2/container hosts. Existing EKS standard-support control-plane fees alone would be $73/$146/$1460/$14600 per 730-hour month, excluding workers and add-ons.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [EKS control-plane pricing](https://aws.amazon.com/eks/pricing/)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)

## 22. Derive messages from source bytes and size



| Source class | Daily bytes per entity | Mean canonical message |
| --- | --- | --- |
| EC2 / selected EKS pod logs | 0.50 / 0.15 GB per host/pod | 1,000 bytes |
| EKS audit / AWS management | 0.50 / 0.20 GB per cluster/account | 3,000 bytes |
| Selected database logs | 1.00 GB per Aurora/RDS instance | 2,000 bytes |
| Lambda / bucket / load-balancer | 0.05 / 0.02 / 0.20 GB per entity | 1,000 bytes |

messages/day = Σ(source GB/day × 1,000,000,000 ÷ mean canonical bytes/message).

**Speaker notes**

Daily GB are decimal; billing storage is converted to GiB. Message sizes are canonical JSON-equivalent payload means, not vendor object sizes, HTTP framing or compressed wire bytes. Planning ranges: application 0.5–4 KB, database 1–8 KB, audit 2–12 KB; these ranges are assumptions, not a measured percentile distribution. Per-event caps still apply. This selected mix excludes blanket VPC Flow Logs, S3 CloudTrail data-event coverage, full database query auditing, traces, metrics and SaaS/network sources. Bucket events refer to selected application/native event messages, not blanket paid CloudTrail object data events. Change volume and size together when discovery finds a different mix.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)

## 23. The example estates produce very different loads



| Selected traffic / 30-day month | 1 account | 10 accounts | 100 accounts | 1,000 accounts |
| --- | --- | --- | --- | --- |
| Canonical GB/day | 9.75 | 61.10 | 611.00 | 6,110.00 |
| Messages/day (millions) | 7.78 | 51.10 | 511.00 | 5,110.00 |
| Mean canonical bytes/message | 1,253 | 1,196 | 1,196 | 1,196 |
| Average EPS / 5× burst EPS | 90 / 450 | 591 / 2,957 | 5,914 / 29,572 | 59,144 / 295,718 |
| Stored normalized / original TiB | 0.20 / 0.49 | 1.25 / 3.04 | 12.50 / 30.42 | 125.03 / 304.25 |

5× bursts are 60-second planning stress cases. Neither sustained rates nor bursts are qualified here.

**Speaker notes**

Each monthly message total is daily messages ×30: about 233.5M, 1.533B, 15.33B and 153.3B. Canonical monthly volumes are 292.5 GB, 1.833 TB, 18.33 TB and 183.3 TB. Baseline searchable retention is 90 days at 25% stored/input ratio; protected originals are a separate 30% input subset retained 365 days at 50% stored/input. These steady-state quantities are not first-month ramp-up usage. The 1000-account case averages 6.11 TB/day and a 5× burst is approximately 296K EPS, outside the current 5-TB/day and 200K burst-experiment envelope. At that size use no capacity claim without new design and qualification.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)

## 24. Workload bytes dominate the scale question



The 1,000-account case is a ten-cell cost extrapolation; one global deployment is not promised.

**Speaker notes**

Bars show calculated canonical uncompressed GB/day from the explicit inventory and source assumptions. Axis is logarithmic so all four scenarios remain visible. Employee or AWS account count does not imply traffic. Quieter accounts can have little traffic; one busy account can exceed this entire estate. Resources, message sizes, rules and query concurrency determine sizing.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)

## 25. Estimate monthly AWS cost in USD



Planning estimate, not a quote or capacity guarantee. The 1,000-account case remains outside scope.

**Speaker notes**

Controls operate offline and update only this calculator. Static tables and graphs elsewhere show the frozen baseline. Direct SIGNAL infrastructure includes compute, disks, snapshots, control DB, retained telemetry/originals, requests, KMS/secrets, ALB, selected private API endpoints, cross-AZ allowance, optional SQS source transport and a monitoring allowance. Source delivery adds selected CloudWatch ingest/storage. Turn that off if already budgeted and retained independently: it does not mean collection is free. Labor is a separate assumed fully loaded rate. Compute/disk allocation may be multiplied; changing traffic alone does not prove those nodes are sufficient. No planned capacity, labor hours or database shape is auto-qualified.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [Pinned AWS regional rate records](pricing-snapshot.json)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)

## 26. The baseline bill is traceable by category



| Assumption / monthly USD | 1 account | 10 accounts | 100 accounts | 1,000 accounts |
| --- | --- | --- | --- | --- |
| EC2 + EBS/snapshots + control DB | $135 | $280 | $1,126 | $11,259 |
| S3 retained telemetry + originals | $16 | $101 | $1,011 | $10,110 |
| Network/API + requests/security + monitoring | $84 | $127 | $555 | $5,552 |
| Direct SIGNAL AWS subtotal | $234 | $508 | $2,692 | $26,921 |
| Selected CloudWatch source delivery | $53 | $262 | $2,621 | $26,206 |
| AWS baseline / +40% planning reserve | $288 / $403 | $770 / $1,078 | $5,313 / $7,438 | $53,127 / $74,377 |

1,000 accounts is an extrapolation. Excludes workload bills, support, tax and regional disaster recovery.

**Speaker notes**

Amounts are rounded for presentation; unrounded values drive totals. Direct SIGNAL subtotal is about $234/$508/$2692/$26921. Optional source delivery is about $53/$262/$2621/$26206. Total is about $288/$770/$5313/$53127. Source charges assume custom Standard CloudWatch rates without free tiers or negotiated/vended-log reductions, and conservatively charge 7 days of source storage without a separate compression discount. Avoid double-counting these costs if already on the workload bill. Baseline S3 Standard retention is mature steady state. +40% is a planning reserve, not a statistical confidence interval or an upper bound.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [Pinned AWS regional rate records](pricing-snapshot.json)

## 27. Prices and allocations are separate inputs



**Verified unit prices**

- Linux c6i.xlarge: $0.17/hour; gp3: $0.08/GiB-month.
- S3 Standard: $0.023 / $0.022 / $0.021 per GiB-month by tier.
- PostgreSQL db.m6i.large Multi-AZ: $0.356/hour + $0.23/GiB-month.
- CloudWatch custom Standard ingest: $0.50/GiB; storage: $0.03/GiB-month.

**Explicit planning choices**

- 90 days normalized at 25%; 365 days originals at 30% × 50%.
- S3 files: target 16 MiB normalized / 1 MiB original; count small-file floors.
- Private EC2 hosting; optional ALB and five API endpoint services per AZ.
- No free-tier/discount savings; monitoring allowance is an assumption.

Regional product records and rate codes are retained in pricing-snapshot.json; assumptions remain editable.

**Speaker notes**

Selected regional AWS price-list files were downloaded and filtered, retaining product SKU, rate code, publicationDate, source URL and full-file SHA256. Exact c6i.xlarge, gp3, snapshot, RDS Multi-AZ, S3, CloudWatch, KMS, SQS and Secrets Manager rates are pinned. ELB, PrivateLink and transfer rates use official pricing pages. Native ARM64 prices are not substituted without runtime qualification. c6i.xlarge has 4 vCPU/8 GiB; counts are a costing allocation, not a throughput claim. RDS price includes the Multi-AZ deployment; do not multiply standby compute/storage again.

**Sources**

- [Pinned AWS regional rate records](pricing-snapshot.json)
- [S3 storage and request pricing](https://aws.amazon.com/s3/pricing/)
- [RDS PostgreSQL pricing](https://aws.amazon.com/rds/postgresql/pricing/)
- [EC2 / EBS regional pricing](https://aws.amazon.com/ec2/pricing/on-demand/)

## 28. AWS spend rises with the selected estate



Total includes direct SIGNAL AWS and selected source delivery; labor is separate.

**Speaker notes**

This graph uses the same calculator engine as the tables and interactive view. Total baseline amounts are rounded only for display. After stable release, the estate must still qualify queries, burst recovery, access controls and capacity. 1000 accounts are modeled as ten independent 100-account cells with conservative per-cell S3 price tiers, not one globally available service.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [Pinned AWS regional rate records](pricing-snapshot.json)

## 29. Retention, delivery and routing can change the bill



**Storage and source policy**

- 30→90 days searchable adds 60 × stored normalized daily bytes.
- 365-day originals can cost more than searchable Parquet.
- CloudWatch source delivery may already be on the workload bill.

**Network and deployment**

- A new EKS cluster adds $73/month in standard support, plus workers.
- NAT adds $32.85/month per gateway + $0.045/GiB processed.
- Cross-Region copies, internet egress and extra endpoints add separately.

**Workload contention**

- Doubling modeled EC2 + disks adds capacity cost; it does not prove capacity.
- Queries scan about 469 GiB/account/month in this example.
- Query CPU, caches and burst headroom need measured sizing.

Excluded high-volume sources and blanket flow/data-event logging can overwhelm this estimate.

**Speaker notes**

The baseline includes a modeled 25% one-pass cross-AZ share at $0.02/GiB combined endpoints, not all possible hops. Same-region S3 gateway access needs no NAT. Five interface services per AZ are an illustrative subset; ECR/SSM deployment needs can add more. ALB LCU calculation uses a minimum 1/cell and a processed-byte assumption; real connections/rules can be larger. No Athena scan fee is charged: SIGNAL queries use the allocated compute and S3 GETs. Native originals are one selected management-event copy; additional trails and data events have separate fees. Read detailed exclusions before using the headline totals.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [EKS control-plane pricing](https://aws.amazon.com/eks/pricing/)
- [VPC / NAT pricing](https://aws.amazon.com/vpc/pricing/)
- [PrivateLink interface endpoint pricing](https://aws.amazon.com/privatelink/pricing/)

## 30. Budget recurring work after a stable release



| Scheduled person-hours / month | 1 account | 10 accounts | 100 accounts | 1,000 accounts |
| --- | --- | --- | --- | --- |
| Health / capacity / failed retries | 2–4 | 4–8 | 10–20 | 40–80 |
| Release and dependency maintenance | 1–2 | 2–4 | 8–16 | 32–64 |
| Backup / restore exercises | 1–2 | 2–4 | 6–12 | 24–48 |
| Source / identity configuration | 1–2 | 2–4 | 10–20 | 40–80 |
| Cost / retention review | 1–2 | 2–4 | 6–12 | 24–48 |
| Platform operations subtotal | 6–12 | 12–24 | 40–80 | 160–320 |

Requires automated rollout, scoped adapters, managed DB, monitoring and rehearsed runbooks for the selected profile.

**Speaker notes**

These bands are engineering planning judgments, not operational telemetry or a vendor support SLA. Release maintenance includes applying qualified releases and checking dependencies, not writing new platform features or serving as upstream maintainer. Backup/restore effort is an amortized monthly average of scheduled exercises. Source configuration covers normal additions and credential/access checks within the assumed stable estate. New adapters, major migrations, audits and outages are separate project/incident work. Ten isolated cells create shared tooling plus repeated verification; the hours are not simply ten times the 100-account case.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [Target product architecture / profiles / budgets](../../27-product-architecture.md)

## 31. Platform effort and detection work need separate owners



| Post-stable-release estimate | 1 account | 10 accounts | 100 accounts | 1,000 accounts |
| --- | --- | --- | --- | --- |
| Platform operations hours/month | 6–12 | 12–24 | 40–80 | 160–320 |
| Detection / policy tuning hours/month | 4–8 | 8–16 | 24–48 | 80–160 |
| Total scheduled hours/month | 10–20 | 20–40 | 64–128 | 240–480 |
| FTE effort (160 hours/month) | 0.06–0.12 | 0.12–0.25 | 0.40–0.80 | 1.50–3.00 |
| Labor USD/month at assumed $100/hour | $1,000–$2,000 | $2,000–$4,000 | $6,400–$12,800 | $24,000–$48,000 |
| AWS + labor USD/month (no reserve) | $1,288–$2,288 | $2,770–$4,770 | $11,713–$18,113 | $77,127–$101,127 |

Hours ÷160 = effort FTE, not a 24/7 roster. The 1,000-account case is a planning extrapolation.

**Speaker notes**

Detection/policy work includes enabling supported packs, exceptions, tuning and periodic quality review; it excludes investigating every security finding and incident response. Loaded labor at $100/hour is an editable budget assumption, not an AWS price or salary benchmark. Scheduled total hours: 10–20, 20–40, 64–128 and 240–480 per month, equivalent to 0.06–0.13, 0.13–0.25, 0.40–0.80 and 1.5–3.0 FTE effort. Assign at least a primary and a backup operator even at fractional effort; 24/7 coverage requires an established shared rota or funded additional staffing. Assume the stable release covers the selected capabilities; a core-only release does not meet that premise. Fully loaded totals add baseline AWS and labor without the 40% AWS reserve.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)

## 32. An outage budget has a storage price



**Spool sizing example**

- 50 GB/day ≈ 0.579 MB/s of canonical input.
- Four hours ≈ 8.33 GB; 2× reserve ≈ 16.67 GB.
- Illustrative only: measure persisted bytes and per-shard peaks.

**Catch-up requirement**

- Replay throughput must exceed new arrivals.
- Backlog / (replay rate − arrival rate) gives catch-up time.
- Expiry or exhausted capacity means an explicit coverage gap.

**Standard objectives**

- 99.9% monthly control/API availability is a target.
- RPO 0 applies only to acknowledged object-backed custody in the tested model.
- Server/AZ failover objective: provisional 15 minutes.

Local WAL, protected originals, detection freshness and notification lag have separate guarantees.

**Speaker notes**

At the illustrative input rate, four hours is one sixth of the day. If measured persisted bytes differ, spool allocation must change. Fleet disk totals do not guarantee capacity for a hot source or shard. Today's 202 does not implement the target object-backed custody guarantee. 99.9% allows 43.2 minutes in a 30-day month; report platform-caused throttling and planned disruption under the target measurement definition. Region/account recovery is separate.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Failure domains and M0–M7 custody semantics](../../failure-domains.md)

## 33. Make the first commitment small and reversible



| Stage | Work | Exit evidence |
| --- | --- | --- |
| 1 · Define | One use case, owners, data classification and incumbent baseline | Fixed scope, cost ceiling, query/lag targets and rollback path |
| 2 · Core lab | Existing file/HTTP ingestion + UI + private rules; synthetic failures | Admission/replay, exact evidence navigation and operator effort |
| 3 · AWS slice | Only after source adapter, custody and security qualification | Native source → original → canonical event → finding → delivery |
| 4 · Decide | Run matched workload, tune detections and rehearse restore | Compare TCO/SLOs; expand, continue bounded work or stop |

No fixed production date: missing capabilities and external gates determine the schedule.

**Speaker notes**

This deck authorizes no AWS provisioning. The proposal can begin with a local lab on existing core mechanisms. Actual AWS work needs environment authority and qualified source semantics. Define deletion/retention and privacy rules before forwarding real logs. Keep incumbent collection running, and preserve independent originals, until the acceptance decision. Stop if source coverage, access isolation or recovery cannot be proved.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 34. Measure outcomes before expanding



| Owner | Proposed measurement | Expansion gate |
| --- | --- | --- |
| DevOps | Selected-rate replay + restart; p95 ≤3 s for agreed bounded queries | No missing admitted records in tested failures; ≤4 routine operator hours/week after setup |
| SecOps | Fixture attacks, native evidence and denied cross-scope access | Every agreed positive/negative case passes; coverage gaps are visible |
| Architects | Restore, custody/fencing for selected profile, native platform gates | Documented recovery and security controls; no unqualified scale claim |
| Shared | Fully loaded TCO and actionable findings reviewed weekly | Owners accept benefit/cost against the incumbent baseline |

These are proposed pilot criteria for agreement, not current performance results or product SLAs.

**Speaker notes**

The three-second query and four-hour weekly effort targets are illustrative choices for discussion. Fix query selectivity, data age, concurrency and hardware before testing. Set numeric native source delay, admitted-to-finding and delivery lag targets after source discovery; they cannot share one unconditional deadline. Access-denial and live coverage tests require the target controls, not just today's token check.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 35. Choose ownership deliberately



**Evaluate SIGNAL when…**

- AWS and company-specific context dominate the need.
- Focused log/security workflows are sufficient initially.
- An engineering owner can fund qualification and operation.

**Prefer an established platform when…**

- Broad integrations and mature SOC work must work now.
- Managed support and availability are purchase requirements.
- The team cannot sustain platform and detection maintenance.

Recommended next step: a bounded core lab, followed by an AWS pilot only when its gates pass.

**Speaker notes**

The recommendation is conditional on the hypothetical company's goals. Do not replace GuardDuty or a working SIEM to justify this project. Agree one high-value use case and compare measured alternatives. Successful adoption means improved evidence quality or operating economics with accepted responsibility, rather than adding another tool.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)

## 36. Architecture claims come from the checkout



Snapshot: 7 July 2026. Current evidence and target decisions have different authority.

**Speaker notes**

Read the product architecture for future direction, progress and release readiness for current proof, and failure domains for acknowledgement semantics. Sources link to repository documents beside this presentation. Concurrent work can change the checkout after this snapshot; regenerate or review the deck before treating it as a newer readiness report.

**Sources**

- [Target product architecture / profiles / budgets](../../27-product-architecture.md)
- [Architecture / canonical event / OSS boundary](../../01-architecture.md)
- [Logical architecture and trust boundaries](../../logical-architecture.md)
- [Failure domains and M0–M7 custody semantics](../../failure-domains.md)
- [External company overlay integration](../../17-external-overlay.md)
- [Read-only SecOps UI contract](../../28-secops-ui.md)
- [Current implementation and local evidence](../../07-progress.md)
- [Release readiness and open qualification gates](../../21-release-readiness.md)
- [Source/detection requirements catalog](../../source-detection-catalog.md)

## 37. Compare documented scope; request real quotes



Official sources checked 7 July 2026. Comparative fit judgments are our inference; no vendor benchmark was run.

**Speaker notes**

Context7 was consulted for Amazon S3, but returned general documentation rather than the needed Object Lock details; direct primary AWS documentation supplied those details. Source URLs are also clickable in the PowerPoint notes and HTML. Vendor editions and prices can change. This comparison deliberately avoids unsupported performance rankings, universal cost claims and precise price units.

**Sources**

- [Splunk Enterprise Security](https://www.splunk.com/en_us/products/enterprise-security.html)
- [Splunk risk-based alerting](https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.3/introduction/about-risk-based-alerting-in-splunk-enterprise-security)
- [Splunk pricing options](https://www.splunk.com/en_us/products/pricing.html)
- [Elastic Security scope and deployment](https://www.elastic.co/docs/solutions/security)
- [Elastic detection rule types](https://www.elastic.co/docs/solutions/security/detect-and-alert/using-the-rule-ui)
- [Datadog Cloud SIEM](https://www.datadoghq.com/product/cloud-siem/)
- [Datadog pricing by product](https://www.datadoghq.com/pricing/)
- [CloudWatch Logs scope](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html)
- [GuardDuty scope](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [Security Lake / S3 / OCSF / Parquet](https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html)
- [Grafana Loki architecture overview](https://grafana.com/docs/loki/latest/get-started/overview/)
- [S3 Object Lock retained-version protection](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [CloudWatch pricing dimensions](https://aws.amazon.com/cloudwatch/pricing/)
- [Security Lake pricing dimensions](https://aws.amazon.com/security-lake/pricing/)

## 38. AWS price sources and the reproducible model



Price snapshot: 7 July 2026. Units, rates, formulas, source assumptions and staffing exclusions are retained.

**Speaker notes**

The linked source files and detailed model note allow independent arithmetic review. Full-file price-list hashes bind the retained selected records to the downloaded AWS regional files, which remain in the local evidence folder where retained. USD estimates are hypothetical on-demand budgets without tax or contractual discounts. No supportable scale claim follows from cost arithmetic.

**Sources**

- [Scenario model / math / labor assumptions](cost-assumptions.md)
- [Pinned AWS regional rate records](pricing-snapshot.json)
- [EC2 / EBS regional pricing](https://aws.amazon.com/ec2/pricing/on-demand/)
- [S3 storage and request pricing](https://aws.amazon.com/s3/pricing/)
- [RDS PostgreSQL pricing](https://aws.amazon.com/rds/postgresql/pricing/)
- [EKS control-plane pricing](https://aws.amazon.com/eks/pricing/)
- [Elastic Load Balancing pricing](https://aws.amazon.com/elasticloadbalancing/pricing/)
- [PrivateLink interface endpoint pricing](https://aws.amazon.com/privatelink/pricing/)
- [VPC / NAT pricing](https://aws.amazon.com/vpc/pricing/)
- [KMS pricing](https://aws.amazon.com/kms/pricing/)
- [Secrets Manager pricing](https://aws.amazon.com/secrets-manager/pricing/)
- [CloudTrail management-copy cost boundary](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-trail-manage-costs.html)
