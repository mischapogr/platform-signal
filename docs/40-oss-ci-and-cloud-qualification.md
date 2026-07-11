# OSS CI and cloud qualification

The repository is public. Standard public GitHub-hosted AMD64 and ARM64 runner
compute is free; job duration, concurrency and artifact storage remain bounded.
See [GitHub runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and [Actions limits](https://docs.github.com/en/actions/reference/limits).

## Observed remote execution — 2026-10-08

[Run 37809129533](https://github.com/mischapogr/platform-signal/actions/runs/37809129533)
executed public revision `66a9ce7f686f9b53f5447dd6798323d25b462d37`.
Anonymous repository/job/check-run API metadata is retained under
`target/goal-execution-20261007/GITHUB-OSS/` (`public-audit.json`,
`jobs-audit.json`, `annotations.json`). No credentials were used.

- ARM64 ran on `ubuntu-24.04-arm`: formatting, all-feature Clippy, build/tests
  and workspace boundaries passed. The combined health/cleanup helper step
  failed. Container, native campaign, kind and supply-chain checks were skipped.
- AMD64 formatting and Clippy passed; its build/tests step failed. Subsequent
  qualification steps were skipped.
- MCP tooling passed. Both architecture artifact steps failed because early
  failure produced none of the old selected report directories.

Job metadata does not expose the failing test name or exact test counts. The
local helper reproduction initially failed because this sandbox denied socket
creation; all 18 native-helper regressions passed when that capability was
enabled. This does not diagnose the remote failure. Complete remote logs and
workflow dispatch require GitHub authentication unavailable here. EXT-ARM64
and EXT-CI stay open for full qualification on the reviewed revision.

## Implemented workflow responsibilities

[`ci.yml`](../.github/workflows/ci.yml) runs native Rust checks on both Linux
architectures. Each command retains a finite log, source/run identity and
success/failure JSON, including early failures. Individual helper steps identify
the failing suite. Logs are capped at 8 MiB per command; commands have deadlines
and owned process-group cleanup. Command arguments must not contain secrets.
A cancelled VM can interrupt artifact upload; absent evidence never counts as
a pass.

Both Rust runners also run a finite2,048-event/8-hour query/cache diagnostic and
its failure-evidence helpers. It checks exact IDs/canonical fields, time selection,
mandatory remote reauthentication, empty-cache rebuild and no-data-read budget
denial. Local AMD64 evidence has33 passing samples; remote execution stays open.
It records debug structural timings, without claiming native production capacity,
cloud prices or cache GET savings. See the [retention contract](41-retention-contract.md).

Both Rust runners now also run the optional established local Keycloak/OIDC/browser
gate: locked test-only npm tools, lock-selected Chromium in a project cache,
manifest-pinned Keycloak, actual browser sign-in and native monolith scope/expiry/
revocation/outage denials. Eight helper failure regressions protect owned cleanup
and finite networking. Credentials stay in private temporary mounts outside
artifacts; cleanup uncertainty fails and records private recovery identifiers.
Local AMD64 passes11 compound checks; ARM64/remote execution on this revision
remains open. This does not add a production identity service or qualify live
provider/cloud authority. See [local IdP qualification](43-local-idp-qualification.md).

After both Rust jobs pass, fresh native runner jobs build the production image,
check host/daemon/ELF identity and persistence, run parsers and measured pipelines
with a finite 120-second soak, run kind persistence/restart, and produce dependency
audit, image vulnerability results and SBOMs. Separate jobs avoid keeping a full
workspace debug build beside a Docker release build on the runner's 14 GiB disk.
Rust jobs have 45-minute limits, native jobs 90 minutes. Reports expire after
seven days; release evidence needs durable retention. Ordinary CI uploads no
Cargo cache or image archive.

[`release-candidate.yml`](../.github/workflows/release-candidate.yml) is manually
dispatched on the selected revision and calls the same CI workflow. After
qualification it packages the **same native image ID** tested in that job,
server/agent/healthcheck binaries, public tracked source, Helm chart,
qualification records and supply-chain reports. It verifies native server hash,
scanned immutable image and retained evidence hashes, refuses partial/failed/
stale records, bounds exports and produces `candidate.json` and `SHA256SUMS`
separately for each architecture.

The candidate is unsigned, unpublished and explicitly `full_release: false`.
It does not close product ledger, AWS/live-vendor/released-dependency gates.
`signalctl`, a combined multiarch registry manifest, release notes, signing/
attestations, immutable publication and final release review remain in existing
release items. Preparation selects no version, creates no tags/releases, pushes
no images and merges no main branch. CI has only `contents: read`, without
persisted checkout credentials. Existing presentation publication on main
remains its own workflow.

## Test environments

| Environment | Evidence | Cost / boundary |
| --- | --- | --- |
| Native GitHub AMD64 / ARM64 | Rust, Docker runtime, ELF identity, finite load, scans and SBOMs | Standard public compute free; resource/time/storage limits apply |
| kind on native GitHub VM | Real Kubernetes API, Helm, probes, PVC permissions, process/pod restart and retained query/finding identities | No managed-cluster cost; proves kind, not EKS/IAM/EBS |
| Owned local source/service fixtures | Pagination, duplicates/redelivery, throttling, malformed input, permission failures, outages, checkpoints and crash/replay | Simulation only; no provider completeness/cloud guarantee |
| Authorized disposable AWS sandbox | Actual STS/source delivery/IAM denial/S3/KMS/Object Lock/EKS storage and identity | AWS charges or approved credits; account, budget, region and cleanup authority required |
| Authorized GKE/AKS/other Kubernetes | Chart/runtime portability and provider persistence/identity | Billed provider resources; cloud-neutral packaging alone does not qualify them |
| Live SaaS/network test tenants | Actual API scopes, audit availability/retention, collection coverage and feeds | Vendor licensing/tenant authority; local substitutes do not close the gate |

kind runs Kubernetes nodes as Docker containers; see its
[quick start](https://kind.sigs.k8s.io/docs/user/quick-start/).
The current public gate owns a temporary cluster and kubeconfig and never targets
an ambient production context. The monolith remains one replica and one writable
volume; additional runners do not permit multiple store writers.

For real AWS, use GitHub OIDC with a narrowly scoped test role instead of static
secrets. Restrict trust to the exact repository and protected test environment,
matching its actual subject format (including immutable repository IDs where
applicable). Untrusted PRs must receive no cloud identity. Account topology,
role IDs, credentials and deployment values stay private. A future authorized
test job must record resource ownership, TTL/cost bounds and cleanup results;
the current workflows provision no AWS resources. See
[GitHub OIDC for AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws).

AWS offers an application-based
[OSS credits program](https://aws.amazon.com/blogs/opensource/aws-cloud-credits-for-open-source-projects-affirming-our-commitment/).
Establish eligibility and approval before treating resources as funded. Other
cloud credits are conditional too. Owned simulators need no commercial emulator
subscription; check current licensing/API coverage before selecting a third-party
emulator.

## Eventual release trust

Existing RELEASE-REVIEW / RELEASE-TRUST / LOCAL-CANDIDATE items still govern release
work: owner-selected SemVer matching Cargo/chart/binaries, both native images
qualified, final ledger/exceptions review, source identity and release notes.
Publish binaries/Helm with hashes, Cargo/image SBOMs, signed OCI identities and
verifiable build provenance. GitHub supports
[artifact attestations for public repositories](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
Attestations prove origin, not runtime correctness. Signing/OIDC and release
write permissions belong only in the eventual protected publication job, after
authorization/readiness; they are absent from preparation. Configure protected
branches/environments/tags through owner administration before publication.
