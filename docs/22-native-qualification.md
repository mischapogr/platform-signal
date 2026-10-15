# Native architecture qualification

Runtime revision`7fa481e` passes complete nativeAMD64/ARM64 Rust/sensor, production
image, finite-soak, supply-chain and Standard kind WAL/PVC qualification in
[CI run38898992993](https://github.com/mischapogr/platform-signal/actions/runs/38898992993).
Both unsigned CI candidates pass archive/file checksums, exact source/chart
contents, offline source relocation and saved-image config/ordered-layer hashes.
Evidence:`target/candidate-replay-retry-20261016/NATIVE-ACCEPTANCE.json`.
This remains finite native/synthetic-provider development evidence; final
LOCAL-CANDIDATE prerequisites, independent current-source review and external/
owner release gates remain open.

Earlier runtime revision`e1763e3` passes complete nativeAMD64/ARM64 Rust, sensor process,
production image, hardening/pipeline/finite-soak, supply-chain and Standard kind
WAL/PVC qualification in [CI run38882944855](https://github.com/mischapogr/platform-signal/actions/runs/38882944855).
Primary artifact digests, exact source/ELF/binary identities and owned cleanup are
verified in`target/sensor-health-standard-20261016/ci-e1763e3/NATIVE-ACCEPTANCE.json`.
This qualifies that runtime source and finite synthetic/local provider scope;
independent current-source release review, actual AWS/EKS/vendor, released
dependency and owner version/publication gates remain open.
See [release readiness](21-release-readiness.md) for current boundaries and
[OSS CI and cloud qualification](40-oss-ci-and-cloud-qualification.md) for history.

The Phase 10 runner uses an existing image on **native Linux AMD64 or ARM64**.
It verifies host, Docker daemon, image and extracted ELF64 architecture; resolves
the immutable image configuration ID; and hashes the server binary. Cross-builds
or emulation do not establish native runtime proof.

```bash
python3 scripts/check-native-qualification.py \
  --image platform-signal:phase8 --expect-architecture amd64
# On a native ARM64 host with its already-built image:
python3 scripts/check-native-qualification.py \
  --image platform-signal:phase8 --expect-architecture arm64
```

It creates an exclusively owned stopped container with `--pull=never`, copies
the server into an owned temporary directory, and runs the binary on the host.
It does not build, pull, start that container, provision a cluster or publish.
Measurements describe the host process, rather than enforced container limits.
Docker supports copying from stopped containers
([copy reference](https://github.com/docker/cli/blob/master/docs/reference/commandline/cp.md)).

## Reports and acceptance

Each invocation creates a unique ignored `target/native-qualification/` directory;
`--output-root` changes its parent. Existing reports are preserved. It records
`qualification.json` (scope, architecture, image/binary identities, command
statuses, source/report/log hashes and cleanup), `hardening/campaign.json` and
`campaign.log` (nine deterministic tests and exact counts/source hashes),
`pipeline.json` (seven [measured profiles](../benchmarks/README.md)), and
bounded command logs.

Wrong architecture/ELF, incomplete profiles, missing/malformed reports, nonzero
commands, hash/accounting mismatch or failed cleanup fail the gate. High target
EPS does not mean achieved EPS. `--quick` records one diagnostic profile with
`scope: smoke` and `full_qualification: false`. A successful default run records
`full_qualification: true` for the complete **native Phase 10 campaign**;
it does not certify `v0.1.0`. The owner-selected local Kubernetes milestone is
complete with the kind 1.34/current standard-chart gate; that proves local kind
behavior only, not actual EKS or AWS storage/runtime. Container/Kubernetes,
EKS and overlay release gates have separate evidence.

Commands have deadlines and exclusively owned process groups. Nested harnesses
receive finite cleanup grace before forced termination and reap. Signal handlers
defer cancellation only during child ownership registration, without changing
the child's OS signal mask. Regressions exercise spawn, initialization and cleanup
cancellation while preserving unrelated processes.

## Optional paced soak

The runner accepts `--soak-seconds 10..600` (default `0`, disabled). It runs two
profiles in order, with exactly 1 KiB and 4 KiB events at a paced target of 100
EPS. Both use the selected duration, separate temporary server state, and bounded
admission/storage settings. For example, add `--soak-seconds 120` to the normal
command above to retain `soak.json` alongside the parser and pipeline evidence.
The soak-only mode avoids repeating those completed campaigns:

```bash
python3 scripts/check-native-qualification.py \
  --image platform-signal:phase8 --expect-architecture amd64 \
  --soak-seconds 120 --soak-only
```

At 10–119 seconds, soak-only is labeled `diagnostic-soak`; at 120–600 seconds
it is `native-soak`. Soak-only reports never set `full_qualification`, because
they omit parser and pipeline campaigns. An optional soak attached to the normal
runner does not change its native Phase 10 campaign scope. In either mode, the
runner binds `soak.json` to the image, architecture, binary and source hashes.
Each profile must cover its requested load duration, reconcile response and WAL
admission counts within the bounded in-flight uncertainty, drain storage/rules,
complete 20 bounded queries and shut down cleanly. The report has fixed 12 time
buckets with load-phase RSS range/mean, CPU time, queue/storage peaks and process
I/O counters; aggregate storage remains bounded. These RSS buckets stop at load
completion, before drain and query work, so they are not whole-profile peaks.
The report's load-only I/O delta and its load-through-drain-and-queries delta
cover distinct intervals.

The runner fixes the soak rate at 100 EPS. The standalone
[`benchmarks/soak.py`](../benchmarks/README.md) harness accepts 10–200 EPS,
10–600 seconds, and either or both event sizes. It attempts at most
`ceil(duration × rate)` events per size, with one synchronous sender and batches
of at most 20. Events are exactly 1 or 4 KiB; HTTP responses are capped at 1 MiB
and the JSON report at 256 KiB. Profile limits are WAL 64 MiB, event storage
256 MiB/8,192 files, findings 16 MiB, query memory 256 MiB and a 30-second
drain. The short pipeline harness uses a separate fixed 128 MiB query budget.
Shutdown allows 12
seconds of graceful termination followed by a five-second kill/reap deadline.
Resource sampling attempts about once per second; each sample includes a
metrics request with a five-second timeout. Sample count, failures and maximum
gap are recorded, so actual cadence can be reviewed in the report.

Query validation preserves the original HTTP status: a non-200 result fails the
profile, with no retry under a larger budget or success reinterpretation. The
failure report keeps bounded context (up to 2 KiB response preview and a
512-character transport/error excerpt). Completed load, admission, drain and
resource observations remain in the failed profile report for diagnosis.

Process I/O values come from Linux [process I/O accounting](https://docs.kernel.org/filesystems/proc.html#proc-pid-io-display-the-io-accounting-fields). The report retains deltas
for `rchar`, `wchar`, `syscr`, `syscw`, `read_bytes`, `write_bytes` and
`cancelled_write_bytes`. Linux defines `rchar` and `wchar` as bytes returned by
read/write-like calls, including non-disk I/O. `write_bytes` is counted when
pages are dirtied; actual writeback can happen later. `cancelled_write_bytes` is
retained separately. These counters do not measure physical device
throughput or latency. Bucket RSS drift is descriptive only; passing the soak
does not establish a universal memory plateau or ceiling, prolonged stability,
production capacity, or physical-device throughput.

Command capture is capped at 1 MiB; reports at 2 MiB each; extracted binary at
128 MiB; report totals at 64 MiB. Generated-file limits are polled thresholds
and may briefly overshoot, rather than filesystem quotas or universal memory
limits. Recorded command deadlines and [benchmark limits](../BENCHMARKS.md) apply.

## CI and current environment

The native AMD64/ARM64 CI matrix builds once per architecture and reuses that
image for runtime, Kubernetes, scanning and this measured campaign. Both Rust
jobs also prebuild the exact all-feature Standard executable fixture, then run
`check-shared-runtime.py --standard-only` against the pinned PostgreSQL manifest.
No default-feature Cargo operation may intervene between prebuild and the
harness's immutable executable capture. This exercises actual Standard TLS/native
admission, original WAL, versioned loopback S3 query/findings, stopped retirement
and crash/restart on each native runner; it does not require the private checkout.
The library18case matrix remains a separate preceding gate.

Each command has a finite deadline; Standard prebuild is1200s, its external gate
300s, internal fixture240s and Standard process180s. These are qualification
budgets, not extensions of application/SQL/context deadlines. Failed steps stop
subsequent qualification; `if: always()` retains reports under`target/ci/` with
1-day retention. Archive needed reports before expiration. Each native container
job runs120-second soaks per event size. Workspace/property/benchmark checks
remain separate.

Current source and evidence are in [release readiness](21-release-readiness.md).
The earlier`8f14fb0` run failed the ARM64 helper; correction`71e45a9` subsequently
passed native CI. Run38212500862 at`16ca254` passes both native Rust jobs,
including five Standard executable scenarios per architecture. Retained GitHub
artifact digests, native ELF/binary hashes,159current runtime source hashes and
owned PostgreSQL cleanup are verified in
`target/native-ci-monitor-20261012/VERIFIED-NATIVE-STANDARD.json`.
Real PostgreSQL TLS and simulated versioned S3 establish this process scope;
Standard Kubernetes and private consumer/restore remain separate. Both native
container/Kubernetes jobs are still running at the retained observation. Full
current image/remote/release gates remain open. No local
ARM64 host or authorized actual EKS environment is available; public hosted ARM64
runners supply native CI, while loopback S3/local clusters do not prove AWS custody
or actual EKS behavior. No release version or publication is selected.

The local soak-only run passed on AMD64 using the same image and binary as the
native pipeline campaign. Both 120-second profiles accepted and durably
processed all events: 11,170 at 1 KiB and 9,680 at 4 KiB, with actual rates of
93.017 and 80.628 EPS. Findings were 559 and 484; each profile completed 20
event queries, with zero rejections, admission uncertainty, query failures or
timeouts. Each captured 121 samples across 12 buckets; load RSS, drift, process
I/O intervals, exact hashes and the retained report directory are in
[BENCHMARKS.md](../BENCHMARKS.md). The report records
`scope: native-soak`, `full_qualification: false`, and successful owned
container/temp-directory cleanup.

An earlier 4 KiB diagnostic using 64 MiB query memory accepted and durably
processed 9,630 events, evaluated 9,630 rules and persisted 482 findings before
an event query returned HTTP 413 `resource_limit` after load and drain. Its
failed profile is preserved at
`target/phase10-soak-team-20261006/diagnostic-4k-verified/soak.json` with
completed observations, up to 2 KiB of response preview and a 512-character
error excerpt. The harness neither retries nor reinterprets the status. The
longer soak harness now records its explicit 256 MiB query budget; the short
pipeline budget and production configuration remain unchanged. No cause beyond
the returned resource-limit response is inferred.

## Header-reader and longer-soak continuation

The storage implementation now uses a fixed 1 KiB `BufReader` at two Parquet
header-reading sites. Three regressions cover read-ahead skips, prefetched-byte
logical limits and cancellation after a logical skip. Existing logical
accounting, limits, CRC checks, formats and cancellation guards are preserved.

A matched `strace` diagnostic queried 40 events across 20 files. Matched
release-image binaries made 37,920 `read`/`pread64` calls, including 37,698
successful one-byte reads, before the change and 702 calls, with zero one-byte
reads and 480 successful 1,024-byte requests, after. Process-returned bytes
increased 532,926→968,300. The earlier host-debug comparison remains historical.
Because tracing adds overhead, this is structural syscall evidence only; it
does not establish a timing, CPU or capacity ratio. Process counters do not
establish physical-device I/O. See the paired artifacts in
[BENCHMARKS.md](../BENCHMARKS.md).

Two old-image 600-second soak profiles at 20 EPS accepted and persisted 12,000
events and produced 600 findings each, with zero admission rejection or
uncertainty. Both failed their first post-load event query with HTTP 408
`request_timeout`; zero planned event-query samples completed. Their servers
exited cleanly, but these artifacts remain failed diagnostics rather than a
passing soak gate. The refreshed original-Dockerfile image subsequently passed
its container, local kind, Helm, supply-chain and native parser/pipeline/
120-second-soak campaign gates. Both 1 KiB and 4 KiB profiles ran 600 seconds at a 20 EPS target and
accepted, WAL-durably admitted, stored and rule-evaluated 12,000 events each;
each produced 600 findings and completed 20 event queries. There were no
rejections, uncertain admissions, errors or timeouts, and both servers exited
cleanly. The raw reports use `scope: bounded-soak` without a
`full_qualification` field. The wrapper and root runtime validator passed with
`scope: bounded-soak`, `full_qualification: false`; an independent pair report
validated the exact results. The final 14-area review accepted the bounded
local AMD64 evidence with no findings at
`target/phase10-longer-soak-20261006/review/final-header-buffer-review.json`.

Each profile captured 600 successful RSS samples in 12 populated 50-second
buckets. Sampled load RSS was 13,631,488–19,267,584 bytes for 1 KiB events and
13,631,488–20,197,376 bytes for 4 KiB events; warmup-to-final mean drift was
1,965,925.798 and 2,716,827.005 bytes. These values exclude drain and query
intervals and do not establish a universal plateau or prolonged stability. See
[BENCHMARKS.md](../BENCHMARKS.md) for query statistics, distinct process-I/O
intervals, configuration hashes and report locations.

The actual local AMD64 campaign is recorded in
[progress](07-progress.md#native-qualification-continuation--2026-10-06) and the
[release audit](21-release-readiness.md). Hashes bind the script versions that
executed. Subsequent cancellation-only corrections have separate regression and
review evidence; final validators checked the retained successful reports
without repeating the unchanged load campaign.


## Public native qualification corrections — 2026-10-11

Public run38119398746 (38b3c6f) passed Rust jobs and built native production
images on AMD64 and ARM64, then failed pipeline qualification. Verified public
artifact digests and bounded archives are retained under
`target/shared-main-restart-20261011T092414+0200/ci-diagnosis/`. AMD64 returned
HTTP413 on the4 KiB/10,000 profile; ARM64's artifact monitor attempted to stat
an atomic diagnostic sidecar after its rename.

Evidence: `target/native-ci-fixes-20261011T095750+0200/`; acceptance requires
the matching source-bound writer review and passed final campaign. A controlled
filesystem regression reproduces the disappearing-sidecar failure. Monitoring
now captures each size once and tolerates only a missing file, including a file
that disappears before its per-file check. Persistent size, aggregate, type,
permission and underlying child failures remain failures with owned cleanup.

A retained production-image binary diagnostic reaches exactly10,000 events
under a longer finite90-second local window. Its selected333 Parquet files
contain81,613,095 uncompressed bytes, exceeding the former64 MiB scan preflight
budget; the original query returns413. The pipeline harness now configures a
fixed128 MiB query budget from startup and records it in its report; the native
validator rejects a missing or mismatched declared budget. The corrected
10,000-row diagnostic completes all20 queries and shuts down cleanly. WAL/storage
64 MiB, findings16 MiB, response1 MiB, query limit100 and strict non-200/no-retry
checks remain in force. This changes the laboratory configuration; production
defaults remain unchanged. The retained image and longer-window reproduction
are diagnostic evidence, not current-image or native ARM64 acceptance. Fresh
public jobs must qualify the complete reviewed revision.
