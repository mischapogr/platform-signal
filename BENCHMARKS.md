# Pipeline benchmark evidence

Measured on 2026-10-06 using the qualified release image binary on native Linux AMD64. This is a finite local campaign on a shared workstation; ARM64 measurement remains pending.

## Artifact and environment

- Image: `sha256:757c60b68c34259d4279ecd62e4ab435db7f812279bbbf0628178c32cd314e97`.
- Server: `signal-server 0.1.0-dev.0`; binary SHA-256 `6dfbf81f61a6f7a415c2518b7c3f008471bc281a64552334f40cc4ca4ea09ed5`.
- Host: Intel Xeon E3-1275 v3 @ 3.50 GHz, eight logical CPUs; Linux 6.8.0-146-generic, glibc 2.39. The release binary was copied from a uniquely owned temporary image container, then run directly. No Rust rebuild was performed.
- No CPU affinity, exclusive host reservation, process memory limit, or disk I/O counters were used. Concurrent work can affect these numbers.
- Seven-profile JSON: `/tmp/signal-phase10-pipeline.json`; SHA-256 `24007fe24c802466e56314cee479fe0ff2b030461a6e95e9b6b3fa1f95a28c9e`.
- Additional eight-event queue profile: `/tmp/signal-phase10-overload.json`; SHA-256 `3d32884029924dd1fc3041984e3947b335662403654aa984000e8ee96a55e25c`.
- Reports contain exact configuration, final metrics, sampled metric peaks, response statuses and accounting. This document retains the measured results after temporary JSON artifacts are removed.

```bash
python3 benchmarks/pipeline.py \
  --server /tmp/signal-benchmark-release-f1oumy48/signal-server \
  --image-id sha256:757c60b68c34259d4279ecd62e4ab435db7f812279bbbf0628178c32cd314e97 \
  --output /tmp/signal-phase10-pipeline.json
python3 benchmarks/pipeline.py \
  --server /tmp/signal-benchmark-release-f1oumy48/signal-server \
  --image-id sha256:757c60b68c34259d4279ecd62e4ab435db7f812279bbbf0628178c32cd314e97 \
  --output /tmp/signal-phase10-overload.json --overload-only
```

The first campaign used a 64-event queue for its final diagnostic profile. Its sampled depth reached only 29, so the harness was narrowed to an eight-event queue and that profile was rerun separately. The current default campaign uses the eight-event overload.

## Bounds and workload

Events are exactly 1,024 or 4,096 compact JSON bytes, including ID/timestamps, source and nested attributes. Padding is repeated `x`; Parquet compression results therefore apply to this synthetic workload. Every twentieth attempted event matches the public login-failure example rule; rejected events need not retain that proportion.

Each profile has a five-second generation window, at most 10,000 attempted events, four synchronous clients and at most 100 events per batch. Requests that started before the window ends can finish afterward, so actual load intervals reach eight seconds. The event cap ended the eight-event overload after 1.09 seconds. No requests were retried. Server request deadlines are four seconds and HTTP client deadlines five seconds. Each profile retained only twenty query timings and aggregate samples.

Normal queue capacity is 4,096 events / 16 MiB. WAL quota is 64 MiB with 1 MiB segments / 64 segments / 16 KiB records. Parquet quota is 64 MiB / 2,048 files; flush is 1,000 events or 100 ms. Findings quota is 16 MiB / 10,000 findings. Query memory is 64 MiB, concurrency two, response limit 100 events / 1 MiB. Server defaults bound the remaining queues; actual capacities are in each JSON report. Temporary data directories and owned processes were cleaned up after each profile.

## Admission, CPU and memory

Accepted and rejected columns are counts reported in HTTP responses. Durable counts come from WAL metrics and must equal Parquet persisted events and rule evaluations after drain. CPU percentage uses one core as 100%. Peak RSS includes ingestion, drain and query work.

| Event KiB | Target EPS | Queue cap | Load s | Attempted | HTTP accepted / rejected | WAL durable | HTTP accepted EPS | CPU % | Peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 100 | 4096 | 5.031 | 504 | 504 / 0 | 504 | 100.18 | 4.37 | 46.66 |
| 1 | 1000 | 4096 | 6.599 | 300 | 300 / 0 | 300 | 45.46 | 1.52 | 43.36 |
| 1 | 10000 | 4096 | 8.024 | 800 | 408 / 392 | 409 | 50.85 | 1.62 | 44.49 |
| 4 | 100 | 4096 | 5.086 | 390 | 390 / 0 | 390 | 76.68 | 3.34 | 51.09 |
| 4 | 1000 | 4096 | 6.351 | 400 | 400 / 0 | 400 | 62.98 | 2.20 | 52.68 |
| 4 | 10000 | 4096 | 8.043 | 800 | 642 / 158 | 645 | 79.82 | 2.61 | 53.36 |
| 4 | 20000 | 64 | 8.025 | 800 | 525 / 275 | 527 | 65.42 | 2.24 | 57.02 |
| 4 | 20000 | 8 | 1.088 | 10000 | 48 / 9952 | 48 | 44.11 | 16.54 | 48.29 |

Across all eight measured profiles: **13,994 attempted, 3,217 HTTP-confirmed accepted, 10,777 response-rejected, 3,223 durable WAL/Parquet events, 197 findings, zero transport failures and zero event drops**. Each profile drained in 0.10–0.30 seconds after load and exited normally after SIGTERM. These include the initial 64-event diagnostic, which is not the current default overload configuration.

The configured high target rates were not attained. The observed low single-core CPU percentages and admission timeouts show time spent waiting, but this campaign did not attribute that wait to filesystem sync, scheduling or another cause. No performance optimization was made.

## Storage, queue pressure and query

WAL peak is sampled retained WAL occupancy, not physical bytes written. Parquet bytes are final logical file growth, including manifests; growth rate is divided by load plus drain time. Neither is a physical disk throughput measurement. Queries select `source_name=pipeline-benchmark`, return at most 100 events, and use twenty post-drain observations; p95 is nearest rank.

| Event KiB / target EPS / cap | Queue peak | WAL peak KiB | Parquet KiB | Findings | Admit payload MiB/s | Parquet growth MiB/s | Query median / p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 / 100 / 4096 | 33 | 518.91 | 235.89 | 28 | 0.0978 | 0.0432 | 66.568 / 111.592 |
| 1 / 1000 / 4096 | 27 | 308.93 | 167.91 | 16 | 0.0444 | 0.0241 | 45.312 / 49.517 |
| 1 / 10000 / 4096 | 28 | 421.13 | 225.80 | 24 | 0.0497 | 0.0265 | 58.042 / 60.284 |
| 4 / 100 / 4096 | 34 | 1075.99 | 311.28 | 20 | 0.2995 | 0.0575 | 55.035 / 62.690 |
| 4 / 1000 / 4096 | 29 | 1100.16 | 329.52 | 20 | 0.2460 | 0.0499 | 57.342 / 60.203 |
| 4 / 10000 / 4096 | 35 | 1116.28 | 498.99 | 36 | 0.3118 | 0.0591 | 78.037 / 83.852 |
| 4 / 20000 / 64 | 29 | 1067.93 | 430.84 | 32 | 0.2555 | 0.0511 | 80.761 / 97.547 |
| 4 / 20000 / 8 | 8 | 32.38 | 60.37 | 21 | 0.1723 | 0.0496 | 18.845 / 20.902 |

The eight-event overload reached sampled depth **8/8**. All 100 batch responses were **429** with partial admission: **48 accepted and 9,952 rejected**, exactly 48 durable/persisted/evaluated events and 21 findings. The 10,000-event cap ended the profile; actual attempted throughput was approximately 9,189 EPS, below its 20,000 target. Event drops, rule failures and storage failures were zero; readiness/query remained functional and shutdown exited zero. This proves graceful `reject_new` pressure for this configuration.

## Deadline admission uncertainty

Each of the 1 KiB/10,000, 4 KiB/10,000 and 4 KiB/20,000 cap-64 profiles returned eight **408** batch responses. Respectively **1, 3 and 2** events became durable beyond the HTTP-confirmed accepted prefixes. HTTP accepted/rejected metrics still matched response counts. The harness records the response-rejected timeout suffix as a conservative admission uncertainty bound, checks that durable excess fits the stricter bound of one in-flight append per received 408/503 response, and requires WAL/storage/rule totals to agree. It does not count a deadline response as proof that every reported rejected event was absent from storage.

This matches the existing deadline/cancellation boundary: append cancellation can race WAL durability, so retries must tolerate duplicates. All measured profiles use `reject_new`, where a received 429 confirms capacity
rejection of the suffix. This does not apply to `block_with_timeout`: its timeout
429 can leave one in-flight suffix append uncertain, and that policy was not
measured here. A received 408/503
can leave one suffix event uncertain; a transport failure can hide an entire
batch, including an admitted prefix. The generic harness budgets all events
of a transport-failed batch as uncertain. There were no HTTP transport errors
or 503 responses in this campaign. Admission response accounting and actual durability are reported separately.

## Limits of this evidence

The sampled RSS range was 43.36–57.02 MiB. It is an observed peak over these finite workloads, not a universal memory ceiling or a proof of stable RSS under prolonged saturation. The sampler kept at most aggregate metrics; no unbounded event or measurement history was retained. Actual payload admission ranged approximately 0.04–0.31 MiB/s, and this cannot be promoted to production capacity.

Native ARM64 benchmarks, prolonged-soak/resource-plateau evidence, physical-device I/O profiling, WAL/storage quota saturation in this performance harness, and customer production load remain unqualified. The local paired 600-second profiles below passed their bounded campaign; they do not establish prolonged stability or a resource plateau. Functional quota/recovery/security proofs live in the existing tests and deployment gates. Full release qualification is governed by the definition of done.

## Native qualification continuation — 2026-10-06

The new image-to-campaign gate ran seven profiles against the same qualified
AMD64 image/binary above. It reused the existing image without building or pulling.
Raw reports are retained under `target/native-qualification/20261006T195653.677830Z-3f2af04a/`.
Its normal successful measurement run preceded cancellation-only cleanup fixes;
final validators and independent review accepted the immutable reports.

| Event KiB | Target EPS | Attempted | HTTP accepted / rejected | WAL durable | Accepted EPS | Peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 100 | 504 | 504 / 0 | 504 | 99.12 | 45.28 |
| 1 | 1000 | 500 | 500 / 0 | 500 | 91.81 | 43.33 |
| 1 | 10000 | 800 | 800 / 0 | 800 | 108.25 | 45.04 |
| 4 | 100 | 480 | 480 / 0 | 480 | 95.14 | 51.18 |
| 4 | 1000 | 500 | 500 / 0 | 500 | 95.76 | 56.25 |
| 4 | 10000 | 800 | 662 / 138 | 664 | 82.11 | 57.61 |
| 4 | 20000 | 10000 | 96 / 9904 | 96 | 52.79 | 51.48 |

Totals: **13,584 attempted, 3,542 HTTP-confirmed, 10,042 response-rejected,
3,544 durable/persisted/evaluated events, 230 findings and 140 successful query
samples**. Transport failures and event drops were zero. Two in-flight timeout
events became durable beyond response prefixes. The eight-slot overload reached
8/8 and preserved all 96 accepted events while rejecting 9,904. High target rates
were not attained; the shared-host sampling limits above still apply.

- `qualification.json` SHA256: `f3d3d1354ea540d97b7caa7f256a18f60be9d6fdd97135187c65bd6ec6bac414`.
- `pipeline.json` SHA256: `575179e2d5dde28eb2c4f4e509bdcf489ee71056b5e7ed072193b67d7029d91e`.
- `hardening/campaign.json` SHA256: `9f16f0bcca7dc37d199980e737c61f7077647ee196748b309250cfc57aa26f5a`.

This extends local AMD64 evidence and CI source coverage. No ARM64 host is
available, so no native ARM64 measurement or remote CI success is claimed.
See [native qualification](docs/22-native-qualification.md).

## Native AMD64 bounded soak — 2026-10-06

The soak-only native runner extracted the same qualified image binary listed
above, without building or pulling. It completed 120 seconds at a 100 EPS target
for each event size. The run is `scope: native-soak` and
`full_qualification: false`; it does not replace the parser/pipeline campaign or
close `v0.1.0` release gates. The profile configuration used 256 MiB query memory
for the longer 4 KiB corpus; the separate short pipeline harness remains at
64 MiB.

| Event KiB | Load s | Attempted / accepted / rejected | Accepted EPS | WAL / Parquet / rules | Findings | Queries | CPU s | Load RSS min–max MiB | Warmup-to-final RSS mean drift MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 120.085 | 11,170 / 11,170 / 0 | 93.017 | 11,170 / 11,170 / 11,170 | 559 | 20/20 | 7.97 | 13.38–18.12 | +1.615 |
| 4 | 120.058 | 9,680 / 9,680 / 0 | 80.628 | 9,680 / 9,680 / 9,680 | 484 | 20/20 | 8.09 | 13.25–19.66 | +1.691 |

Both profiles had zero transport uncertainty, query failures/timeouts, event
drops or storage/rule failures, and exited cleanly. Each collected 121 samples
across 12 fixed buckets with no sampling failures; the largest observed gap was
about 1.007 seconds. Load-only RSS maxima were 19,005,440 and 20,615,168 bytes;
the RSS buckets stop at load completion, before drain and queries. Their mean
drift is descriptive only, not a memory plateau or ceiling.

`/proc/<pid>/io` deltas below are ordered as `rchar / wchar / syscr / syscw /
read_bytes / write_bytes / cancelled_write_bytes`. Load-only and
load-through-drain-and-queries are separate intervals:

| Event KiB | Load-only I/O deltas | Load through drain/queries I/O deltas |
| --- | --- | --- |
| 1 | 5,538,764 / 19,007,332 / 1,117 / 48,658 / 0 / 71,307,264 / 0 | 362,637,807 / 21,292,675 / 21,594,507 / 69,071 / 0 / 71,331,840 / 0 |
| 4 | 8,202,339 / 49,689,965 / 1,132 / 44,124 / 0 / 95,158,272 / 0 | 511,693,664 / 58,120,471 / 21,582,362 / 64,593 / 0 / 95,182,848 / 0 |

These are process counters, not physical device throughput; `write_bytes` is
counted when pages are dirtied and writeback can follow later. The report,
configuration and source hashes bind the run. `qualification.json` SHA256 is
`137c29454fd732235b2b910692ceac08c926ccaf967165af73a2320b740d7ebc`; `soak.json`
SHA256 is `32e951e9158ce8aa72e6e3cd505c9b3ca388f1c5a74f48d041cc06862d229e60`.
Both reports are under
`target/phase10-soak-team-20261006/final/20261006T203345.246930Z-6640d177/`.

The earlier 4 KiB diagnostic with a 64 MiB query budget accepted and durably
processed 9,630 events, evaluated 9,630 rules and persisted 482 findings before
an event query returned HTTP 413 `resource_limit` after load and drain. It is retained at
`target/phase10-soak-team-20261006/diagnostic-4k-verified/soak.json`. The harness
preserved completed profile observations and bounded failure context (2 KiB
response preview, 512-character error excerpt); it did not retry or reinterpret
the query result. The long-soak fixture now explicitly uses the query core's 256 MiB
default; this is a bounded harness configuration correction, not a production
optimization or a change to the short pipeline budget.

## Parquet header-read diagnostic — 2026-10-06

`signal-storage` now wraps the Parquet file reader in a fixed 1 KiB `BufReader`
at the two header-reading sites. It preserves logical byte accounting, limits,
CRC checks, formats and cancellation guards. Three regressions cover logical
skipping across read-ahead, prefetched bytes at the logical limit, and
cancellation after a logical skip.

A matched diagnostic queried 40 events across the same 20 Parquet files. Before
the change, release-image binary SHA256 `6dfbf81f61a6f7a415c2518b7c3f008471bc281a64552334f40cc4ca4ea09ed5` made 37,920 `read`/`pread64`
calls in the query interval, including 37,698 successful one-byte reads. The
post-change release binary SHA256 `338561e7bbfb4fd639d5a5bad0ae6f51a7716bce9bddc385f765d4751a93efed` made 702 calls (580 `read`, 122 `pread64`), zero
successful one-byte reads, including 480 successful 1,024-byte requests. Both
queries returned the same 40 events and two findings; owned process and
temporary-directory cleanup passed. This matched workload comparison used
distinct release-profile binaries from two release images. Paired reports are in
`target/phase10-query-reads-20261006/run-1/` and `run-3-image/`; the earlier
run-2 host-debug result remains historical. The run-3 report says
`image_id: null`, while its companion
`target/phase10-header-buffer-20261006/extraction/origin.json` binds the binary
hash to the immutable image ID.

Returned Parquet-read bytes increased from 532,926 to 968,300 across the matched
release-image binaries. The byte counts are process-level reads, not physical-device
I/O; read-ahead trades fewer small calls for more returned bytes. The comparison
shows a structural syscall reduction only. `strace` overhead means the reported
elapsed values do not support a timing, CPU, throughput or capacity ratio. The
exact pre-change profiler is retained as
`target/phase10-query-reads-20261006/profile-before.py` (SHA256
`9ee5b3dfa10c0a223a640e7ac36ba216a3254055d0d442a403809457fcb63539`).
For the accepted matched release-image pair, the baseline run-1 report SHA256 is
`5663f3b07b8c7902035e857c7cac63dea0cfb9539864aaad5de9085402b52fcf` and
post-change run-3 report SHA256 is
`e28e3d018e692cca941d9ae17126c845b3ec9f1f374ef5f7450572dea249a991`. The
earlier historical run-1/run-2 release/debug pair has report hashes
`5663f3b07b8c7902035e857c7cac63dea0cfb9539864aaad5de9085402b52fcf` and
`b82bb7f2677c846a583fb331c5bcf0278bd1394e51c3887371dc4c8548210ee5`. The
current [header reader source](crates/signal-storage/src/pages.rs) SHA256 is
`5aba32895d2755acf8b3808e71ae817b1026b48ace175c2c325b568c98709f23`.

## Failed 600-second soak diagnostic — 2026-10-06

Two 600-second profiles paced at 20 EPS each attempted and accepted 12,000
events with zero rejections or transport uncertainty. WAL admission, Parquet
storage and rule evaluation each reached 12,000, with 600 findings per profile.
Both then failed their first event query with HTTP 408 `request_timeout`; zero of
the 20 planned event queries completed. The server exited cleanly, but the
campaign remains failed and is not a passing soak result. Reports and per-profile
resource observations are retained in
`target/phase10-longer-soak-20261006/{validation.json,soak-1024.json,soak-4096.json}`.
Their report SHA256 values are `7d115b8498109c5c409ca5c64779a7011e43fe1173ac15465ae7c0ea05c4141f`, `5334e415e0f69440895d56b85cdf35861848632cbcfcaa175d2902f5e5e7a494` and `d23f0d7750038caa2733e832cb16d7a4d9d36f08fdfa388364ef01290ddbbd11`, respectively. No later query cause is inferred.

## Refreshed buffered-reader image campaign — 2026-10-06

The original Dockerfile produced AMD64 image
`sha256:77681eca22aa9b25668767d56b717bd9a66a3ccc58c73033fa5c3ebb7eb6b2c1`,
with release binary SHA256
`338561e7bbfb4fd639d5a5bad0ae6f51a7716bce9bddc385f765d4751a93efed`. The
native qualification run completed its parser, seven pipeline profiles and two
120-second soak profiles; `qualification.json` records
`scope: native-qualification`, `full_qualification: true` for that campaign,
and successful cleanup. It does not close the remaining release gates.

| Campaign | Observed results |
| --- | --- |
| Seven pipeline profiles | 13,480 attempted; 3,175 HTTP-confirmed accepted; 10,305 response-rejected; 3,176 WAL/persisted/rule-evaluated; 191 findings; 140 successful queries. Zero transport uncertainty, drops, storage/rule/query errors. One event persisted beyond an HTTP 408 accepted prefix within the recorded uncertainty bound. |
| Eight-slot pressure profile | 56 accepted and 9,944 capacity-rejected across 100 HTTP 429 responses; no event drops. |
| Two native soak profiles | 120 seconds at the fixed 100 EPS target each: 8,050 1 KiB and 6,490 4 KiB events accepted and durably processed; 403 and 325 findings; 20 event queries each; zero rejection, uncertainty or query errors. Actual accepted rates 67.030 and 54.059 EPS. |

The native report directory is
`target/phase10-header-buffer-20261006/native/20261006T211925.268888Z-edd4602c/`.
SHA256 values: qualification `6ae02692123607e175883cdfac1487fe63841f6ff27f874e0d9f27ddf824860d`,
pipeline `5b721457bda8d46d27f5e5241b52c4b5958d8132099224511b6dbc48c1240e93`,
soak `66b5e0b002b7ae6e3b14cba1326cb644709e7996e3e6e90ab721d66f0b3130f9`.
The release-image container and Kubernetes PVC replacement/recovery gates
passed; fresh Helm 3.19 default and optional renders exited zero using the
current chart and its default `platform-signal:0.1.0-dev.0` tag (four default
resources, six optional resources). The rendered manifests are chart checks,
not deployment evidence for the refreshed image. Outputs and validation are
retained as `target/phase10-header-buffer-20261006/helm-{default,optional}-render.yaml`
and `target/phase10-longer-soak-20261006/review/helm-render-validation.json`.
All six supply-chain checks passed on the
refreshed image: Cargo audit zero vulnerabilities, SBOMs 328
Cargo/15 image packages, Trivy HIGH 0/CRITICAL 0/MEDIUM 23/LOW 8. Full local
gate references are in [progress](docs/07-progress.md) and the
[release audit](docs/21-release-readiness.md).

The matched release-image syscall diagnostic reduced query read calls from
37,920 to 702 (successful one-byte reads from 37,698 to zero), while process-
returned Parquet bytes increased from 532,926 to 968,300. `strace` adds overhead,
so this remains structural syscall evidence and supports no latency or capacity
ratio. Process read/write counters do not establish physical-device throughput.
The refreshed image's two replacement profiles passed 600 seconds each at a
20 EPS target. Each attempted, accepted, WAL-durable, stored and rule-evaluated
12,000 events; each produced 600 findings and completed 20 event queries with
zero rejection, uncertainty, failure or timeout and clean shutdown.

| Event KiB | Load seconds / accepted EPS | Query median (min–max ms) | Load CPU s | Sampled load RSS min–max bytes (warmup-to-final mean drift) | Samples / buckets / max gap s | Storage files / bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 600.000072 / 19.9999976 | 2,130.036612 (1,962.854885–2,694.437158) | 78.84 | 13,631,488–19,267,584 (+1,965,925.798 B) | 600 / 12 / 1.013130 | 5,348 / 19,579,894 |
| 4 | 600.000077 / 19.9999974 | 2,360.353032 (2,161.778833–2,585.884824) | 93.89 | 13,631,488–20,197,376 (+2,716,827.005 B) | 600 / 12 / 1.014591 | 5,804 / 24,561,488 |

Every sample succeeded and each bucket spans 50 seconds. RSS is sampled during
load only; collection stops before drain and query work. These finite samples
are observations, not a universal plateau, ceiling or prolonged stability
result.

`/proc/<pid>/io` fields below are ordered `rchar / wchar / syscr / syscw /
read_bytes / write_bytes / cancelled_write_bytes`. Load-only and load-through-
drain-and-query deltas cover separate intervals:

| Event KiB | Load-only process I/O deltas | Load through drain and queries process I/O deltas |
| --- | --- | --- |
| 1 | 18,913,066 / 37,553,534 / 5,343 / 109,645 / 0 / 109,076,480 / 0 | 2,337,378,275 / 40,288,482 / 1,655,133 / 186,425 / 0 / 109,092,864 / 0 |
| 4 | 23,837,910 / 79,494,764 / 5,799 / 121,002 / 12,288 / 155,090,944 / 0 | 2,694,517,285 / 88,499,941 / 1,796,509 / 213,057 / 12,288 / 155,107,328 / 0 |

Linux `/proc/PID/io` `write_bytes` is counted when pages are dirtied; actual
writeback can occur later. `cancelled_write_bytes` is retained separately;
`rchar` and `wchar` include non-disk I/O. These process counters are not physical
device throughput or latency measurements.

Each raw report uses `scope: bounded-soak` and has no `full_qualification`
field. The wrapper observation and runtime validation both passed with
`scope: bounded-soak`, `full_qualification: false`; validation records
`runtime_passed: true`. The independent pair record passed with
`scope: completed-local-amd64-two-size600-second-soak`, also
`full_qualification: false`. The independent 14-area review accepted this
bounded local AMD64 evidence with no findings; see
`target/phase10-longer-soak-20261006/review/final-header-buffer-review.json`.
Reports and configuration SHA256 values:

| Event KiB | Raw report SHA256 | Configuration SHA256 |
| --- | --- | --- |
| 1 | `889c652339e737ef777316b7bc867d908909d213d43736fff0a4a2bd2b75694e` | `662601ff29ac3545d29ada46d811ebed24778910feb39b821e401b6562cc5a31` |
| 4 | `c614ca275b9e0b4eb207436397bf31c041cca7978a29a0f57720c93323eaa531` | `51339c7c425a5caf1ed5cde567924f7b66f8da0c0d2acdbc45f26fb2322b56fb` |

Pair validation SHA256 is `4f25cc57a82b317d9dbfecfb4ac0bdc5b9ae5cdc2e6ae40741963ef8bbb89acd`;
wrapper observation SHA256 is `4d525de65befeba5985a401ccf2f439b23745cd572053cf7e881524b7fd894ce`;
runtime validation SHA256 is `3467bd6b81029d8592a1b0ee65e1b9f8d0271ceded54fb6a263b1b05a642d3c3`.
They are retained under `target/phase10-longer-buffered-20261006/` and
`target/phase10-longer-soak-20261006/review/`. The earlier old-image failed
600-second pair above remains separate. This bounded local pass is not physical-
device throughput evidence or a production-capacity claim.
