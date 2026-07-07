# MVP Definition of Done

`v0.1.0` is ready only when all required items below pass. As of 2026-10-06,
checked boxes mean observed **local Linux AMD64** proof, with evidence IDs from
[the release audit](21-release-readiness.md). Native ARM64, EKS, remote CI and
released external dependencies remain open. This checkout is `0.1.0-dev.0`;
it is not a released or production-qualified version.

The owner confirmed that native ARM64 and an authorized EKS environment are
unavailable and selected a minimal local Kubernetes target for the current
milestone. K records the passing owned kind cluster. Actual ARM64 and EKS
release qualification below remains deferred and unverified.
Git staging, commits, pushes and publication remain on hold until the first
minor release or alpha is ready, as requested by the owner. This local
acceptance does not change the development version or complete the full release
gates below.

[Local candidate preparation](23-local-candidate.md) packages the existing
development source, chart, qualified AMD64 image and selected evidence without
publication. Offline integrity, relocated workspace metadata and chart rendering
are preparation checks; they do not check any of the open release boxes below.

## Functional

- [x] Single-event ingestion works.
- [x] Batch ingestion works.
- [x] Invalid events are rejected.
- [x] Request size is bounded.
- [x] Admission queue is bounded.
- [x] WAL is bounded.
- [x] Accepted durable events survive restart.
- [x] Parquet persistence works.
- [x] Time-range query works.
- [x] Message contains query works.
- [x] Structured field filters work.
- [x] Rules load from YAML.
- [x] Invalid rules prevent readiness.
- [x] Matching events create findings.
- [x] Findings survive restart.
- [x] Agent supports stdin.
- [x] Agent supports file tail.
- [x] Agent retries with bounded spool.
- [x] Demo company enrichment works.
- [x] Demo private rule works.

Evidence: I/B/S/Q/R/A/P in the [audit ledger](21-release-readiness.md#evidence-ledger).

## Reliability

- [x] SIGTERM path tested.
- [x] Forced process kill/restart tested.
- [x] Truncated WAL record tested.
- [x] WAL quota exhaustion tested.
- [x] Queue saturation tested.
- [x] Storage write failure tested (D).
- [x] Duplicate replay is tolerated.
- [x] No unbounded Tokio channels.
- [x] Disk growth limits are documented.

Evidence: B/S/R/C/K/D and the source guard in W. Restart paths cover process
SIGTERM/SIGKILL and PVC replacement, not power loss. D exercises a real
create-time EEXIST error after durable admission, preserved checkpoint and
successful exact replay; it does not prove ENOSPC, hardware EIO or power-loss
behavior. Z adds a synthetic same-binary stopped-data restore on the same
filesystem and user; it does not qualify cross-version or production restore.

## Security

- [x] Non-root container.
- [x] Secrets are never logged.
- [x] Payload size limits exist.
- [x] Rule/config parsing has safe failure behavior.
- [x] Dependency audit passes or exceptions are documented.
- [x] Container vulnerability scan performed.
- [x] SECURITY.md exists.
- [x] Threat model document exists ([reviewed model](20-threat-model.md)).

Evidence: I/R/A/C/V and source review. Secret redaction was checked on exercised
paths; it is not a guarantee about trusted third-party extension code. The final
scan retains 23 MEDIUM and eight LOW occurrences. See V for exact report/image
identity and scanner coverage.

## Observability

- [x] Structured logs.
- [x] `/healthz`.
- [x] `/readyz`.
- [x] Prometheus/OpenMetrics endpoint.
- [x] Accepted event counter.
- [x] Rejected event counter.
- [x] Queue depth.
- [x] WAL bytes.
- [x] WAL replay count.
- [x] Storage write count/errors.
- [x] Rule evaluation count/errors.
- [x] Finding count.
- [x] Query count/latency.

Evidence: O plus actual process/container/Kubernetes endpoint checks in R/C/K.
Counters and cumulative query latency exist; dashboard/SLO integration is
external deployment work.

## Portability

- [x] Linux AMD64 build.
- [ ] Linux ARM64 build.
- [x] Docker Compose smoke test.
- [x] Kubernetes smoke test on local Linux AMD64.
- [ ] Kubernetes smoke test on native Linux ARM64.
- [ ] EKS test-environment persistent restart smoke.
- [x] Helm lint.

Evidence: C/K/T; native ARM64 and EKS are explicitly unverified.

## Engineering quality

- [x] `cargo fmt --check`.
- [x] `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] `cargo test --workspace`.
- [x] End-to-end test.
- [x] No company-specific identifiers in OSS.
- [x] ADRs for key architectural decisions.
- [x] Public API documentation.
- [x] Config reference.
- [x] Upgrade/versioning policy.
- [ ] Required remote native AMD64/ARM64 CI jobs pass on the reviewed revision.
- [ ] External overlay builds/tests against released OSS dependencies.

Evidence: W/P/Z and [public documentation](21-release-readiness.md#documentation-map).
The [upgrade policy](../UPGRADING.md) documents current contracts and the scoped
same-binary offline rehearsal; cross-version migration remains unqualified.

## Phase 10 hardening

These required items come from [the implementation plan](04-implementation-plan.md#phase-10--hardening-and-v010):

- [x] Bounded deterministic parser/property campaign and reviewed results (F).
- [x] Completed local security review and threat model (X).
- [x] Benchmark and load-test report with measured limitations (L/J/Y).
- [x] Bounded process RSS profile (L/J/Y).
- [x] Bounded process CPU-usage profile (L/J/Y).
- [ ] Native Linux ARM64 hardening campaign and measured benchmark.
- [x] Restart and corrupted-WAL tests (B/R/C/K).
- [x] Architecture diagram and configuration reference.
- [x] Reviewed Unreleased development notes ([changelog](../CHANGELOG.md)).
- [x] Migration/versioning statement ([policy](../UPGRADING.md)); actual migration remains unqualified.

Evidence: F/L/J/Y/D/W/H/X in the [audit ledger](21-release-readiness.md#evidence-ledger).
The parser/property campaign is deterministic and finite, not coverage-guided
fuzzing. L measures finite process RSS/CPU usage, without a universal RSS ceiling,
function-level CPU attribution, physical disk I/O profile or prolonged soak.
J adds two 120-second AMD64 loads with resource trends and process I/O counters;
its RSS samples cover the load and exclude the later drain/query phase.
Y adds a fixed 1 KiB Parquet header reader and three regressions included in
the current 231-test workspace. Matched release-image binary traces show fewer read
calls; process read-ahead bytes increased. Traced timings do not establish
capacity or physical-device throughput. The earlier old-image 600-second
profiles remain failed query diagnostics. Both buffered-image replacements
passed 600 seconds at 20 EPS: 24,000 durable events, 1,200 findings and forty
successful event queries in total, with clean shutdown. Their load-only resource
samples cover twelve buckets per profile; they do not establish a universal
memory plateau or production stability. The paired wrapper records
`scope: bounded-soak`, `full_qualification: false`.
Independent source review closed the original findings and verified campaign/report
hashes, cleanup, storage recovery and documentation scope. Native ARM64
hardening/benchmark measurement remains unverified.

## MVP demo

The local C/K/P gates exercise this flow. A clean-machine release demonstration
using published artifacts remains unverified:

```text
clone repository
-> docker compose up
-> send events
-> query events
-> trigger a rule
-> query finding
-> restart services
-> verify data remains available
```

The private application can add company metadata and rules without modifying
OSS source.

## Post-MVP backlog

Only after `v0.1.0`:

- S3-native object store;
- CloudWatch Logs integration;
- CloudTrail collection;
- Kubernetes log collector;
- query language;
- rule windows/thresholds;
- deduplication/suppression;
- alert sinks;
- OIDC/RBAC;
- multi-tenancy;
- hot index/cache;
- UI;
- retention/tiering;
- metrics ingestion beyond internal operational counters;
- traces/APM.
