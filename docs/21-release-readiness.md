# Release readiness audit — 2026-10-07

The current checkout has local Linux AMD64 mechanism proof through Phase 8 and
Phase 10 hardening. It is
`0.1.0-dev.0`, with no published release, image or crate. **`v0.1.0` is not ready.**
The [definition of done](06-definition-of-done.md) marks observed local checks;
its checked boxes do not substitute for the remaining release gates below.
Phase 9 AWS collection remains post-MVP.

The current SourceCoverage SDK/store source passes 273 workspace tests and the
13-package boundary guard. The fresh AMD64 image passes container, all six
supply-chain and native parser/pipeline/120-second-soak gates. The current kind
campaign fails before SIGNAL starts: kube-proxy reports `too many open files`,
and the PVC provisioner cannot reach the cluster API. The prior kind pass is
historical and does not close the current-image gate. Detailed counts and retained
paths are in [progress](07-progress.md#vendor-fixtures-and-current-source-release-refresh--2026-10-07).

The public synthetic corpus covers 55 cases across 11 requested source families.
The private overlay's version now matches `0.1.0-dev.0`; its three tests include
all 55 real Rust event validations and one intended private IAM finding. This is
source-path/local proof. The owner authorizes local Conventional Commits on
`develop` with deliberately assigned July 7 evening Berlin dates; validation
reports retain actual October 7 times. No revision is pushed, merged to `main`,
tagged or published; no release version is selected. Local commits close no
release gate.

## Evidence ledger

| ID | Observed proof | Exact source or retained artifact |
| --- | --- | --- |
| W | Current local OSS formatting, strict all-target Clippy and locked/offline workspace tests: 273 tests, zero failures; boundary gate validates 13 packages. Includes actual SourceCoverage library process-crash, quota, corruption and cancellation tests. | `target/source-coverage-store-20261007/validation.json`, acceptance logs and `sqlite-build.json`; [workspace guard](../scripts/check-workspace.py). Previous 255/231/228-test results remain historical. |
| P | Separate private package: two tests; external normal-server process gate preserved one event/finding through SIGKILL and successful SIGTERM | `/tmp/signal-phase7b-private-gates.log`, `/tmp/signal-phase7b-process-gate.log`; [external overlay gate](17-external-overlay.md), [harness](../scripts/check-overlay.py) |
| I | Single/batch validation, bounded request/queue admission, auth, cancellation, overload and exact partial admission | [HTTP integration tests](../crates/signal-ingest/tests/http.rs), included in W; [ingest API](09-phase1-ingest.md) |
| B | Real WAL truncation/corruption/restart, bounded count/byte/segment quotas, block timeout, checkpoint I/O failure and replay | [WAL recovery tests](../crates/signal-buffer/tests/recovery.rs), included in W; [WAL contract](10-phase2-wal.md) |
| S | Parquet roundtrip, replay content checks, quotas and partial-publication cleanup on bounded-writer quota error; time partition pruning | [Storage tests](../crates/signal-storage/tests/store.rs), [codec tests](../crates/signal-storage/tests/codec.rs), included in W; [storage contract](12-phase3-storage.md) |
| D | Actual filesystem EEXIST create failure after durable HTTP 202: server fails closed, checkpoint remains zero, owned blocker stays unchanged; repair replays exact event/finding, advances checkpoint to one and a third restart remains stable | `/tmp/signal-phase10-storage-failure.log`, one focused process test passes in 2.52 s; [gate source](../tests/integration/phase10-storage-process.py), registered in [foundation tests](../tests/integration/foundation.rs) |
| Q | URL time/message/structured filters, ordering and bounded query responses; process restart | [Query tests](../crates/signal-query/tests/), [process gate](../tests/integration/phase4-process.py), included in W; [query API](13-phase4-query.md) |
| R | Invalid rules/config prevent startup; event→Parquet→rule→findings→checkpoint; finding-quota fail-closed recovery and redaction | [Phase 5 process gate](../tests/integration/phase5-process.py), included in W; [rules/findings/config](14-phase5-core.md) |
| A | Agent stdin/file, retry/spool/cursor/rotation/quota/restart and token redaction: 36 library tests plus one process case | [Agent contract and recorded gate](15-phase6-agent.md#phase-6-verification), [process source](../tests/integration/phase6-process.py); current W retains this coverage |
| C | Fresh native container runtime on the buffered-reader image: nonroot 65532, read-only root, healthy probe, auth, SIGTERM/SIGKILL persistence and owned cleanup | `target/phase10-header-buffer-20261006/container.log`; [container gate](../scripts/check-container.py); image `sha256:77681eca22aa9b25668767d56b717bd9a66a3ccc58c73033fa5c3ebb7eb6b2c1`. Earlier C image remains historical. |
| K | Owner-selected local Kubernetes milestone completed using kind 1.34 and the refreshed exact image: one event/finding persisted, SIGKILL and replacement pod recovered via the same PVC; nonroot/read-only/auth/separate metrics and cleanup passed. This proves local kind behavior, not actual EKS/AWS storage/runtime. | `target/phase10-header-buffer-20261006/kubernetes-final.log`; [Kubernetes gate](../scripts/check-kubernetes.py); same image as C. |
| T | Helm 3.19.0 strict default/optional/private-values lint and render; single writer, regular-file config/rules mounts and decimal integer config | [Chart](../deploy/helm/signal/README.md), [packaging evidence](07-progress.md#phase-8-local-evidence--2026-10-06) |
| V | Refreshed image supply-chain run: all six checks passed; RustSec zero vulnerabilities; SPDX Cargo 328/image 15 packages; Trivy HIGH 0, CRITICAL 0, MEDIUM 23, LOW 8 | `target/phase10-header-buffer-20261006/supply-chain/20261006T211924.305016Z/`; image matches C; [supply-chain scope](18-supply-chain.md) |
| O | Structured bounded/redacted logging; health/readiness and finite queue/WAL/storage/query/rule/finding metrics | [Metrics source](../crates/signal-ingest/src/lib.rs), [logging](../apps/signal-server/src/logging.rs), R/C/K process gates; [architecture](01-architecture.md) |
| F | Focused deterministic parser/property campaign: nine tests pass in 15.971 s; 512 event/512 URL/512 rule models, 104 record and 28 checkpoint mutations, 303 tail cuts, nine ack prefixes | `target/phase10-hardening/20261006T185925.121730Z/{campaign.json,campaign.log}`; [threat model/campaign scope](20-threat-model.md); independently reviewed |
| L | Historical eight-profile finite load/CPU/RSS campaign: 13,994 attempts, 3,217 HTTP-confirmed/3,223 WAL/Parquet durable events, 197 findings; eight-slot queue reached 8/8 with 48 accepted/9,952 rejected | `/tmp/signal-phase10-pipeline.json`, `/tmp/signal-phase10-overload.json`; [measured benchmark report](../BENCHMARKS.md); native AMD64 on historical image `sha256:757c60b68c34259d4279ecd62e4ab435db7f812279bbbf0628178c32cd314e97`; independently reviewed |
| H | Hardening orchestrator cleanup kills/reaps its owned process group; current one-test regression passes in 2.209 s; native cancellation/identity/report suite passes fifteen tests separately from Cargo | `target/native-qualification/local-gates/{hardening-cleanup-final.log,native-runner-tests-final.log}`; [hardening regression](../scripts/test-hardening.py), [native regressions](../scripts/test-native-qualification.py); independently verified |
| Z | Synthetic same-binary offline restore on native AMD64: 18 copied files verified for SHA-256/mode/ownership, stopped original and backup unchanged; one pending WAL and two pending spool events retain canonical IDs, two findings stable, copied-source reread/cursor reuse and appended line verified, final checkpoint nine through another restart | Original `target/phase10-restore-qualified/`; independent repeat `target/phase10-restore-review-20261006/{review.log,rehearsal/report.json,rehearsal/inventory.json}`. [Gate](../tests/integration/phase10-restore-process.py), registered in the agent process target; subsequent independent review found no source issue. |
| N | Refreshed native AMD64 qualification passed: nine property tests and seven pipeline profiles, 13,480 attempts/3,175 HTTP-confirmed/3,176 durable events/191 findings/140 queries; zero transport uncertainty or drops. Eight-slot profile accepted 56/rejected 9,944; one event beyond an HTTP 408 prefix stayed within the uncertainty bound. | `target/phase10-header-buffer-20261006/native/20261006T211925.268888Z-edd4602c/{qualification.json,pipeline.json,hardening/campaign.json}`; image/binary match C. Runner scope is native qualification with `full_qualification: true`; this does not complete external release gates. |
| J | Refreshed native campaign included two 120-second profiles: 8,050/6,490 events accepted and WAL/persisted/rule-evaluated, 403/325 findings and 20 queries each; zero rejection, uncertainty, query or cleanup errors. Rates 67.030/54.059 EPS; campaign scope is native qualification, `full_qualification: true`. | Same native report directory as N, `soak.json` SHA256 `66b5e0b002b7ae6e3b14cba1326cb644709e7996e3e6e90ab721d66f0b3130f9`. The earlier 120-second soak-only result is historical `scope: native-soak`, `full_qualification: false`, preserved at `target/phase10-soak-team-20261006/final/20261006T203345.246930Z-6640d177/`. |
| Y | Fixed 1 KiB Parquet header `BufReader`, three storage regressions and matched release-image 20-file/40-event diagnostic: calls 37,920→702; successful one-byte reads 37,698→0; process-returned bytes 532,926→968,300. Old-image 600-second profiles failed their first query with HTTP 408. Refreshed-image 1 KiB/4 KiB 600-second profiles both passed with 12,000 durable events, 600 findings and 20 queries each; zero rejection, uncertainty or failures. | Syscall reports `target/phase10-query-reads-20261006/run-{1,3-image}/report.json`; old failed soak reports `target/phase10-longer-soak-20261006/{validation.json,soak-1024.json,soak-4096.json}`; refreshed reports and pair validation under `target/phase10-longer-buffered-20261006/` and `target/phase10-longer-soak-20261006/review/longer-pair-validation.json`; current 231-test workspace in W. The call reduction is structural; strace timings are not capacity evidence and returned bytes are not physical-device I/O. Finite load RSS does not establish a universal plateau or prolonged stability. |
| X | Final independent source approval: no unresolved findings; campaign/log/test hashes, both benchmark hashes/eight-profile counts, cleanup, storage EEXIST and threat-model/security/upgrade/changelog/audit claims checked | Consolidated review acceptance recorded in [progress](07-progress.md); local source/mechanism scope only |
| LC | The 2026-10-07 dev0 candidate preview passed local preparation, offline integrity verification, relocated source-path-graph checks and four packaged-chart checks. It preserves the accepted AMD64 image and remains `full_release: false`; this is not alpha, release or remote-dependency evidence. | `target/local-candidate-team-20261007/preview2/` and `preview2-relocated/{validation.json,bundled-offline-verify.json}`; [procedure and scope](23-local-candidate.md). Final candidate export/review is separate. |

W is the current full workspace result: the prior 231-test gate plus 24
SourceCoverage SDK and local-store tests totals 273. Focused F/D/Z and Y results are
already included and must not be added again. Earlier phase counts
(including the 203-test Phase 6 run) remain historical evidence. The three
Kubernetes cleanup tests, two standalone health-helper tests and H's one
hardening cleanup test pass separately; they are not part of that Cargo count.
Some historical `/tmp` logs have disappeared; their references describe earlier
observations, not currently retained files. Current W/N and independently repeated
Z evidence is retained under ignored `target/` and needs preservation before
cleanup. Both OSS and private repositories were checked
during the earlier audit: zero index rows and zero commits. That zero-commit state is historical. The public and private repositories now
have owner-authorized local development histories; the current continuation also
aligns private versioning and validates the shared corpus. Neither is published.

The earlier 227-test final log records the first agent result separately and an
interleaved seven-test codec summary. The original combined command exited two
only after attempting nonexistent `scripts/check-boundaries.py`; the intended
`scripts/check-workspace.py` subsequently exited zero. Local Actionlint also
exited zero (`/tmp/signal-phase10-actionlint.log`). The cleanup finding is fixed
and its regression independently passed. Final independent source review found
no unresolved findings and accepted the scoped campaign and documentation
claims. The offline restore addition subsequently passed independent review and
a focused rerun against the same 14 areas. The native runner and cancellation
corrections also passed independent source review and fifteen focused tests,
separate from the 228 Cargo tests. Earlier approval X remains historical;
the continuation's acceptance is recorded in progress. Those approvals preceded
the buffered-reader change; the current reader preserves disk formats. The source
tree has no committed release revision; the local baseline commits are development
imports with deliberately assigned historical dates. Report hashes bind
recorded inputs/artifacts but are unsigned local evidence.

## Required gates still open

| Gate | Current boundary | Completion evidence needed |
| --- | --- | --- |
| Native ARM64 build/runtime/container/Kubernetes and measured hardening benchmarks | Owner confirmed no ARM64 host is available. The current AMD64 image passed container, Helm, supply-chain, parser/pipeline and 120-second soak gates; its kind run is blocked before application startup. No native ARM64 execution observed | Native ARM64 runner logs and reviewed architecture-specific runtime, persistence and benchmark evidence |
| Current local kind deployment | Three attempts timed out on the PVC; owned-cluster diagnosis records kube-proxy `too many open files` and provisioner API timeout. Prior image proof is historical | Restore host-resource preconditions and pass the current-image standard-chart persistence/restart gate |
| EKS deployment | Deferred: no authorized EKS environment is available. The preceding kind milestone was local proof; the fresh kind gate is currently blocked by host-resource exhaustion. Neither establishes EKS or AWS storage/runtime behavior. | Actual approved cluster/namespace/storage/image/architecture evidence and persistent restart checks |
| Remote CI | Workflow source and local checks pass; no pushed revision/job execution | Successful required native jobs and retained report artifacts for the reviewed revision |
| Released external dependency | Private application uses separate checkout/source-path dependencies | External application build/test against the actual released version and locked dependency graph |
| Release artifacts/publication | Owner authorized local commits on `develop`; push/publication remain unapproved. No release version was selected or bumped; `main` receives changes only when release ready | Qualified release artifacts after required gates pass and the owner-directed release workflow; ARM64, EKS, remote CI and released dependencies remain external gates |

## Security and operational limits

The final container scan passes the HIGH/CRITICAL gate; it retains 23 MEDIUM and
eight LOW occurrences. Scanner coverage does not determine exploit reachability
or establish absence of vulnerabilities in static Rust executables; the separate
Cargo audit covers locked Rust dependencies. SPDX license metadata is inventory,
not legal approval. The first image's failed 65 HIGH/four CRITICAL report describes
the previous image and is retained separately; it must not be mixed into final
image qualification.

Authentication is an optional static token. Keep it configured before exposing
admission outside trusted clients. There is no MVP OIDC/RBAC, per-tenant isolation,
TLS termination or arbitrary-extension sandbox. Extensions are trusted,
cooperative in-process code. Network exposure, certificate handling, credentials
and organization-specific policy are external deployment responsibilities.

This is one writer on a bounded local filesystem. ReadWriteOnce does not prevent
two writers on one node. Logical file-byte limits do not establish physical
block/inode exhaustion behavior or a whole-process RSS ceiling. Z establishes a
synthetic local offline restore with identical development binaries and the same
user/filesystem. Cross-version migration, backup-media crash durability, different
ownership/storage environments and production operator acceptance remain unqualified.
Copied source files have different inodes and can reread lines with new IDs;
the restored spool preserves its queued IDs. See the [upgrade policy](../UPGRADING.md).
Process SIGKILL
is not hardware power-loss proof. No HA, horizontal scaling, network-filesystem
qualification, retention/tiering or native S3 store is established. At-least-once
replay protects identical stored sequence content, while independent admissions
can duplicate event IDs.

The finite shared-host campaign L observed peak RSS 43.36–57.02 MiB and CPU
1.52–16.54% of one core; these are sampled process measurements, not a universal
memory ceiling or function-level CPU attribution. High configured EPS targets
were not attained. Deadline responses left six more events durable than
HTTP-confirmed across three profiles, within the recorded in-flight append
uncertainty bound. HTTP rejection/timeout counts therefore do not prove absence
from storage; retries must tolerate duplicates. The eight-slot pressure run
returned 100 partial 429 responses, preserved all 48 accepted events, dropped
none and shut down normally. J adds a 120-second-per-size AMD64 soak with
load-phase RSS sampling; it does not establish prolonged stability or a memory
plateau. The old-image pair of 600-second profiles completed load and
persistence but failed the first event query with HTTP 408. Both refreshed-image
600-second profiles subsequently passed and their paired results were
independently validated. This finite local run does not establish prolonged
stability or a memory plateau. The final 14-area review accepted the bounded
local evidence with no findings; record:
`target/phase10-longer-soak-20261006/review/final-header-buffer-review.json`.
Native ARM64 and physical disk I/O profiling remain unqualified. D exercises a
real create-time EEXIST error, not
physical disk exhaustion, hardware EIO or power-loss behavior.

## Documentation map

Public usage/configuration already live in [ingest](09-phase1-ingest.md),
[WAL](10-phase2-wal.md), [storage](12-phase3-storage.md),
[query](13-phase4-query.md), [rules/findings/server YAML](14-phase5-core.md),
[agent](15-phase6-agent.md), [SDK](16-collector-sdk.md),
[external overlay](17-external-overlay.md), [packaging](19-packaging.md) and
[native qualification](22-native-qualification.md).
The [threat model and bounded campaign](20-threat-model.md) and
[measured benchmark report](../BENCHMARKS.md) record Phase 10 scope and limits.
The [Unreleased development notes](../CHANGELOG.md) describe the implemented
slice without claiming a publication.
The [upgrade/versioning policy](../UPGRADING.md) records independent versioned
contracts and a conservative offline restore rehearsal. The [architecture
reference](01-architecture.md) and [ADRs](adr/) describe the existing boundaries.
Keep private identity, metadata, policies, fixtures and environment values in the
separate application; this audit adds no company content to OSS.
