# AWS and staffing scenario assumptions

Planning snapshot: 7 July 2026. USD, US East (N. Virginia), on-demand Linux
AMD64. These fictional inventories describe selected telemetry, not a discovered
customer, supported capacity or procurement quote. The premise is a future stable
product whose selected adapters, access controls, custody, upgrade and recovery
paths have passed qualification. A stable core release alone does not meet that
premise. Current readiness remains in [the release audit](../../21-release-readiness.md).

[cost-model.json](cost-model.json) contains all inputs.
[cost-model.js](cost-model.js) is the same pure calculation engine in the browser
and at build time. [estimate-baseline.json](estimate-baseline.json) retains exact
results; [cost-estimates.csv](cost-estimates.csv) is the compact spreadsheet export.
[pricing-snapshot.json](pricing-snapshot.json) contains selected public AWS
products/rates, source URLs, publication dates, SKU/rate codes and source-file
SHA256 hashes. Published prices can change; recheck before procurement.

## Estate and data model

The 1/10/100/1,000 account counts mean total organization accounts. The inventories
are independent examples, not a formula for how many resources every account has.
The single-account case has separate IAM responsibilities but cannot have an
independent security-account failure boundary. Larger cases include central
observability/security accounts inside their organization count.

EC2 hosts exclude EKS nodes. Pods represent running monitored workloads, not more
EC2 instances. Aurora cluster counts describe topology; their reader/writer
instances contribute database-log volume once. Other RDS counts exclude Aurora.
Business workload resources and SIGNAL's own servers/control DB are distinct.
No blanket resource total adds pods, clusters and instances as interchangeable
units. Lambda functions are active selected functions, not invocation counts.

| Source | Canonical decimal GB/day per entity | Mean canonical bytes/message |
| --- | ---: | ---: |
| EC2 host/application | 0.50 | 1,000 |
| Selected EKS pod | 0.15 | 1,000 |
| EKS audit cluster | 0.50 | 3,000 |
| Aurora/other RDS instance | 1.00 | 2,000 |
| Lambda function | 0.05 | 1,000 |
| Account management/audit | 0.20 | 3,000 |
| Selected S3 bucket events | 0.02 | 1,000 |
| Selected load-balancer logs | 0.20 | 1,000 |

Means are assumptions, not measured distributions. Plausible planning size ranges
are application 0.5–4 KB, database 1–8 KB and audit 2–12 KB; these are not percentile
claims. The current bounded event-size contract remains authoritative. Source
originals, transport framing, HTTP overhead and compression can produce different
sizes from the canonical mean. The mean for the mix is byte-weighted correctly:
total canonical bytes / total messages, not a simple mean of source means.

```text
source_GB_day      = entity_count × per_entity_GB_day × traffic_multiplier
messages_day       = Σ(source_GB_day × 10^9 / source_mean_bytes)
mean_event_bytes   = total_GB_day × 10^9 / messages_day
average_EPS        = messages_day / 86,400
planning_burst_EPS = average_EPS × 5, for an initial 60-second experiment
```

At baseline the four estates produce 9.75 / 61.1 / 611 / 6,110 canonical GB/day,
approximately 7.78M / 51.1M / 511M / 5.11B messages/day. Monthly messages use 30
traffic days: 233.5M / 1.533B / 15.33B / 153.3B. The 1,000-account case exceeds
both the present product account/cluster design boundary and its 5-TB/day upper
volume. Its 5× burst of approximately 296K EPS also exceeds the current 200K
burst-experiment range. It is only a ten-cell cost extrapolation. Cross-cell
federation, total scale and shared operations require new design/qualification.

Excluded: blanket VPC Flow Logs, full database query auditing, CloudTrail object
data events, full APM/metrics/traces, SaaS/network integrations and debug-all logs.
Selected bucket events are application/native messages; they do not establish
CloudTrail S3 data-event coverage. Adding these sources can materially change the
bill and required hardware. Sampling is not silently applied to protected input.

## Storage and query assumptions

AWS storage inputs are GiB (`2^30` bytes); input traffic GB are decimal (`10^9`).
Compute resources use 730 hours/month; traffic/request calculations use 30 days.
This intentional budgeting convention differs slightly from an actual month's
hours/days. Storage is mature steady state after retention fills, not month one.

```text
normalized_GiB = GB_day × 10^9 × 0.25 × 90 / 2^30
original_GiB   = GB_day × 10^9 × 0.30 × 0.50 × 365 / 2^30
```

Normalized data retain 90 days at assumed 25% stored/input size. Protected originals
are a selected 30% raw-byte subset, independently retained for 365 days at assumed
50% stored/input size. This raw subset is an explicit scenario assumption and
does not equal a fixed CloudTrail share or prove source protection. Originals and
normalized data are charged separately. Both use immediately readable S3 Standard;
no archive-retrieval, lifecycle or Object Lock price saving is assumed.

S3 tiering uses the retained regional first-50-TiB / next-450-TiB / higher rates.
For 1,000 accounts, apply tiers separately to each of ten cells, conservatively
foregoing possible payer-level aggregation discounts. Security/telemetry placement
and actual AWS billing aggregation may change the eligible tier treatment.

Normalized target objects are 16 MiB, original objects 1 MiB. Publication floors
are 96 normalized and 48 original objects/account/day to avoid assuming every
partition fills. Count two normalized writes (publication/manifest or compaction
allowance), one original write, reads of each object, and hourly account listings.
Metadata overhead, retention maintenance and actual compaction can differ.

Queries assume ten/account/day, each reading 100 ×16-MiB files, approximately
468.75 GiB/account/month of repeated scan work. GET counts and compute allocation
are included. There is no Athena query fee: the model uses SIGNAL compute. It does
not price or promise arbitrary interactive scans at that allocation. Small files,
unselective queries, indexes/caches and concurrency require real measurements.

## Direct SIGNAL AWS estimate

- Linux `c6i.xlarge` (4 vCPU, 8 GiB): $0.17/hour. Allocate 1/2/5/50 total servers
  and collectors in the four scenarios. The 100-account case has three servers
  and two collectors; the 1,000-account case has ten such cells. These are priced
  allocations, not automatic sizing or sufficient-capacity claims.
- gp3: $0.08/GiB-month. Provision 100/300/1,900/19,000 GiB. Snapshot retained changed
  blocks are assumed to equal 50% of provisioned volume at $0.05/GiB-month. No
  additional IOPS/throughput, filesystem metadata overhead or WAL replica storage
  beyond these allocations is priced.
- Small has local control state, backed up with its disks. 100/1,000 accounts use
  1/10 control PostgreSQL `db.m6i.large` **Multi-AZ deployments** at $0.356/hour
  plus 200 GiB each at $0.23/GiB-month. These rates already include Multi-AZ; do not
  double-count the standby. Backup allowance assumes automated backup within the
  provisioned storage allowance; extra retained snapshots/export/cross-Region
  backup add separately. Control state is bounded workflow metadata, not a raw
  log database or per-event bulk broker. DB growth/load needs qualification.
- S3 storage and requests use pinned regional rates. SQS Standard transport is
  three metadata requests per original object (send/receive/delete), conservatively
  ignoring its free tier; no queue request is charged per log event. Selected
  source metadata fit the base billable chunk. KMS symmetric requests are estimated
  at one per object write/read; key counts are 3/3/3/30. No Bucket Key savings or
  free request allowance is assumed. Rotated key versions can add storage fees.
- Secrets: 3/6/12/120 at $0.40/month each, with one read/hour/secret at the pinned
  request rate. Workload-identity provider and API credentials may change this.
- One ALB/cell at $0.0225/hour plus $0.008/LCU-hour. Use the larger of one LCU/cell
  or modeled canonical processed GiB/hour/cell. No HTTP/framing multiplier is
  added; real connections, rules and bytes can cost more. All canonical intake is
  conservatively treated as traversing ALB even if a native source path differs.
- Five private interface services per AZ/cell at $0.01/endpoint-AZ-hour, plus five
  GiB/cell/month of metadata at $0.01/GiB. This is an illustrative deployment
  subset, not a complete service endpoint catalog. ECR/SSM, cross-account ingest
  PrivateLink, Transit Gateway and workload VPC endpoints add separately. The
  model uses same-region private routing and S3 gateway endpoints with no NAT.
- For three-AZ cells, reserve one combined charged cross-AZ passage on 25% of
  input bytes at $0.02/GiB. It is not a count of every possible replication/query
  hop. RDS Multi-AZ replication is not added again. Source Regions other than
  us-east-1, cross-Region archive copies and internet egress are excluded.
- Monitoring allowance: $20/$50/$150/$1,500 per month. This is a budget assumption,
  not a verified AWS SKU, blanket GuardDuty coverage or a paid-support entitlement.

NAT sensitivity, if selected: $32.85/gateway per 730-hour month plus $0.045/GiB
processed. EKS is optional for SIGNAL; a newly dedicated standard-support cluster
adds $73/month plus workers/add-ons/network. The existing estate's EKS cluster
fees of $73/$146/$1,460/$14,600 per month are workload costs, excluded from SIGNAL.
Additional private network resources can substantially affect a multi-account bill.

## Source delivery and exclusions

EKS audit, database and Lambda profiles are routed through CloudWatch in this
scenario: 3.75/18.5/185/1,850 decimal GB/day. Price custom Standard logs conservatively
at $0.50/GiB ingested and $0.03/GiB-month for seven retained days, without free-tier,
vended-log/volume discounts or source-storage compression savings. This is an
explicit source-path budget; actual service classes, transfer/logging and provider
delivery charges need verification. No blanket additional network delivery to S3
is assumed; additional source export/Firehose charges must be added if selected.

The first management-event trail copy per Region has no CloudTrail event-delivery
charge; S3 storage/request charges remain. Extra management copies, CloudTrail data
events, Lake and Insights are excluded. EventBridge/other source delivery and
Security Lake are not silently treated as included integrations. The detailed
selected source adapters are a stable-product premise, not today's behavior.

The calculator's source-delivery checkbox includes or excludes this **already
separate** CloudWatch line. Excluding it when already budgeted avoids double-counting;
it does not eliminate that organization's source collection bill. There is no
estimate of the business workload EC2, EKS worker or Aurora/RDS compute bill,
because their sizes and transaction patterns have not been supplied.

Totals omit tax, Savings Plans/reservations/Spot, AWS/commercial support, regulatory
audits, regional disaster recovery, internet egress, unspecified network transit,
IdP licensing, incident tooling and storage beyond the stated policies. Adding
40% to the modeled AWS sum is a **planning reserve**, not an upper bound or a
confidence interval. Changing traffic or retention in the calculator changes byte
costs; it does not automatically resize control DB, workers, collectors or labor.

## Scheduled operating and maintenance effort

Person-hours are additive hands-on time across people, not elapsed duration or
on-call availability. Estimates assume a stable qualified release for the selected
profile and sources, IaC/GitOps onboarding, automated updates/health checks, managed
HA control DB when used, reviewed runbooks and a fairly stable organization.

| Accounts | Platform hours/month | Detection/policy hours/month | Scheduled total | Effort FTE at 160 h/month |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 6–12 | 4–8 | 10–20 | 0.06–0.13 |
| 10 | 12–24 | 8–16 | 20–40 | 0.13–0.25 |
| 100 | 40–80 | 24–48 | 64–128 | 0.40–0.80 |
| 1,000 | 160–320 | 80–160 | 240–480 | 1.50–3.00 |

Platform totals split into health/capacity, qualified release/dependency updates,
amortized backup/restore drills, normal source/identity changes and cost/retention
review. Detection effort includes supported rule activation, exceptions, quality
checks and tuning. Each category's range is in the presentation's detailed table.
They are engineering estimates, not time studies or guarantees. Multi-cell tooling
may share work; repeated access/recovery validation still needs time.

Excluded labor: initial installation/migration, new adapter or core development,
upstream product maintenance, major version/state migrations, compliance projects,
security investigations, incident response and exceptional provider/host outages.
Those are additional projects or event-driven work, so hours must be re-estimated
when their observed frequency is known. No claim of zero unattended maintenance
or a specific incident frequency is made.

Budget loaded labor at editable $50/$100/$150 per hour; $100 is the baseline, not
an AWS price or wage benchmark. Fully loaded baseline = AWS + scheduled hours ×
loaded hourly rate, **without** the separate 40% AWS reserve. Effort FTE does not
fund 24/7 staffed coverage. Even a fractional-effort installation needs a named
primary and backup; use an existing staffed rota or budget extra coverage. At
1,000 accounts, 1.5–3 FTE effort is a multi-person operations/detection function.
