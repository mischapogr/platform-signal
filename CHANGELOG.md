# Changelog

## Unreleased — `0.1.0-dev.0`

This is a development inventory, not a published `v0.1.0` release. Local evidence
and remaining required gates are recorded in the
[release audit](docs/21-release-readiness.md) and
[definition of done](docs/06-definition-of-done.md).

### Implemented

- Add 55 synthetic native/canonical examples across 11 vendor source families,
  separate log/finding severity metadata, hash bindings and fixture regressions.
- Close current 13-package source exports over required compile-time JSON data
  and explicitly named public samples; preserve historical archive support.
- Retain bounded, redacted diagnostics when owned Kubernetes checks fail.

- A standalone bounded SourceCoverage SQLite library preserves original report
  bytes, profile pins, full bindings, immutable receipts and checked commit
  prefixes under one local owner. Eighteen focused tests cover frozen encodings,
  restart, process-crash boundaries, cancellation, corruption, page/count/byte
  exhaustion and closed relocation. Trusted intake/retry, corrections, pruning,
  scans and server/source integration remain separate tasks.
- Pure SourceCoverage v1 validation and current/historical assessment in the
  generic SDK: bounded strict JSON, exact bindings/profiles, nanosecond time
  budgets, gap/summary consistency and typed rejection reasons. The new 24-test
  suite executes 60 record cases, 39 assessments and seven transition sequences;
  observers, durable history, source proofs and detection wiring remain separate.
- Version 1 canonical events preserve nested JSON attributes and numeric
  precision; HTTP ingestion validates single events and batches, authenticates
  with an optional Bearer token, and bounds admission and request work.
- Synced bounded WAL admission returns HTTP 202. The monolith publishes immutable
  Parquet events, evaluates stateless YAML rules, persists deterministic findings,
  then advances its checkpoint. Restart replay checks stored sequence content.
- URL-only event and finding queries provide bounded time, text and structured
  filters. Health/readiness and Prometheus metrics expose finite queues, disk
  budgets, processing and query work.
- The edge agent collects stdin and regular files with bounded parsing, durable
  spool/cursors, retry and shutdown behavior. The generic SDK permits cooperative
  collectors, enrichers and external metadata/rule providers without private
  policy in OSS core.
- The separate overlay compiles against checkout paths and passes local package
  and normal-server persistence gates. Its policy, identities and fixtures remain
  external.
- Production container packaging and a single-replica Helm chart run nonroot with
  a read-only root and explicit writable data. The chart provides a persistent
  volume, probes, resources, optional PDB/ServiceMonitor and external Secret/rule
  references. Regular `subPath` files satisfy strict loader contracts; count
  configuration renders decimal integers.
- Pinned checksum-verified tooling produces dependency/image SPDX inventories,
  RustSec audit, all-severity image reports and unsigned artifact evidence. The
  remediated AMD64 runtime passes its HIGH/CRITICAL scanner gate with 23 MEDIUM
  and eight LOW occurrences retained.
- Deterministic parser/property and WAL mutation campaigns, finite load/CPU/RSS
  profiles, and a real filesystem create-error recovery gate extend local
  hardening evidence. The [threat model](docs/20-threat-model.md),
  [benchmark report](BENCHMARKS.md) and [upgrade policy](UPGRADING.md) document
  boundaries and measured limits.
- A synthetic offline restore gate copies stopped server/agent state with
  verified hashes, modes and ownership; pending WAL/spool events and existing
  findings recover under the same binaries. Copied source files can reread lines
  with new IDs; the restored file's new cursor then prevents repeated rereads.
- A bounded native image-to-parser/pipeline runner checks host/daemon/image/ELF
  architecture and records exact report and command hashes. CI runs and retains
  measured campaigns per native architecture using each already-built image;
  fifteen focused custody/cancellation/identity/report regressions pass.
- A native AMD64 soak-only campaign completed 120 seconds each for 1 KiB and
  4 KiB events at a 100 EPS target. It records bounded 12-bucket load RSS trends
  and process I/O counters, with separate load and post-load intervals. This is
  finite local evidence, not prolonged stability, physical-device throughput,
  or release qualification.
- Parquet header reads now use a fixed 1 KiB buffered reader at the two header
  sites. Logical byte limits, CRC checks, formats and cancellation guards remain
  covered by three focused regressions. A matched `strace` diagnostic reduced
  read calls across 20 files/40 events from 37,920 to 702, while process-returned
  bytes increased. The accepted comparison used distinct release-profile
  binaries from two release images; an earlier host-debug comparison is
  historical. Tracing overhead prevents a timing or capacity claim.
- The refreshed original-Dockerfile AMD64 image
  `sha256:77681eca22aa9b25668767d56b717bd9a66a3ccc58c73033fa5c3ebb7eb6b2c1`
  passed fresh container, local kind PVC recovery, strict Helm, six supply-chain
  checks and native parser/pipeline/120-second-soak campaign gates. The native
  campaign recorded 13,480 attempts, 3,176 durable events, 191 findings and 140
  queries across seven pipeline profiles; its two soak profiles processed
  8,050/6,490 events with 403/325 findings and 20 queries each. Detailed results
  and artifact hashes are in [BENCHMARKS.md](BENCHMARKS.md).

### Qualification and compatibility

Native Linux AMD64 workspace/process/container/local Kubernetes mechanisms have
executed gates. The current workspace passes 231 tests; the prior 228-test
post-restore result remains historical. The restore addition and native runner subsequently passed independent
review with no unresolved source findings. Seven new AMD64 load profiles passed;
configured ARM64 CI jobs have not executed and no ARM64 host is available. Native ARM64
execution/benchmarks, EKS, remote CI and
released dependency integration remain open. The soak-only run records
`full_qualification: false`; that older run remains separate from the refreshed
full native campaign. Neither campaign closes the release gate. Configured high
pipeline target rates were not attained; finite sampled RSS/CPU measurements
are not production capacity or a universal memory ceiling, and a 120-second
soak is not prolonged stability proof. HTTP deadline outcomes can race WAL synchronization, so retries must
retain at-least-once semantics.

The old-image 600-second/20-EPS diagnostic accepted and durably processed 12,000
events per event size, then both profiles failed their first query with HTTP 408
and recorded zero successful event queries. It remains a failed soak attempt;
the earlier accepted 120-second soak-only evidence remains separate. The
refreshed image's native campaign now passes. Both replacement 600-second
profiles passed with 12,000 durable events, 600 findings and 20 successful
queries per size, with zero rejection, uncertainty or errors. This finite local
campaign does not establish prolonged stability, a universal resource plateau
or physical-device throughput. Independent 14-area review accepted the bounded
local evidence with no findings; see
`target/phase10-longer-soak-20261006/review/final-header-buffer-review.json`.

Events/HTTP responses/server configuration and existing storage contracts retain
their documented version 1 formats. No automatic format migration or qualified
cross-version upgrade is introduced. Use a consistent stopped-data backup and
an isolated rehearsal as described in [UPGRADING.md](UPGRADING.md).

There is no released artifact, registry publication, signing or production
acceptance claim. S3-native storage, cloud collection, OIDC/RBAC, multi-tenancy,
windowed rules, alert delivery, retention/tiering and other post-MVP features
remain outside this development slice.
