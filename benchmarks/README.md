# Benchmark harness

Run `cargo bench -p signal-server --bench harness`. Override the bounded loop
with `SIGNAL_BENCH_ITERATIONS=1000000`. Invalid or zero counts fail.

Phase 0 measures harness overhead only. It makes no ingest, WAL, storage, query
or memory claim. Add component workloads as those components exist; Phase 10
records reproducible 1 KiB/4 KiB event workloads, resource use, saturation,
rejections and target architecture in `BENCHMARKS.md` before optimizing.

## Native pipeline campaign

To extract the server from an existing native image and retain parser and load
reports together, use [the native qualification runner](../docs/22-native-qualification.md).

`pipeline.py` runs a supplied release server binary directly on native Linux
AMD64 or ARM64. It creates separate temporary data/configuration for each
profile, uses loopback listeners, and terminates the owned process with a
bounded SIGTERM/SIGKILL fallback. It does not build, pull, deploy or publish.

```bash
python3 benchmarks/pipeline.py --server /path/to/release/signal-server \
  --image-id sha256:<source-image-id> --output /tmp/signal-pipeline.json
```

The seven profiles use exactly 1 KiB/4 KiB compact JSON events at target
100/1,000/10,000 EPS, followed by a 4 KiB/20,000 target EPS overload with a
eight-event queue. Each load window is five seconds, with at most 10,000 attempted
events, four synchronous clients and 100 events per batch. HTTP calls have
five-second deadlines; server ingestion has a four-second deadline. Requests
are not retried. A lower actual rate is reported as measured, without claiming
the configured target was attained. `--quick` runs one diagnostic profile;
`--quick-rate 10000` selects its higher target rate. `--overload-only` runs
only the queue pressure profile.

All queues/storage use the server's existing bounds. WAL and event storage are
limited to 64 MiB each, findings to 16 MiB, and query memory to 64 MiB. Every
profile must drain within 30 seconds. Each request/response is bounded to 1 MiB;
only four current batches and twenty query durations are retained. A sampler
retains aggregates rather than a sample history and samples at most ten times
per second. The JSON report contains configuration, CPU time, observed RSS,
queue/WAL peaks, accepted/rejected/drop counts, Parquet/finding totals, and
median/p95 query latency. Query samples return at most 100 events; exact persisted
counts come from metrics checked against durable WAL admission counts.

HTTP response counts and durable WAL counts are separate. A received 408 or 503 response
can race a durable append: its reported rejected suffix is an upper bound on
uncertain admissions. Transport failures are recorded separately. The harness
requires HTTP counters to match responses when transport is certain, and
requires storage/rule counts to match WAL admissions. Any durable excess over
HTTP-confirmed acceptance must fit the stricter bound of one in-flight append per received 408/503 response, plus
all events in each transport-failed batch. This harness fixes admission policy
to `reject_new`, so a received 429 suffix is confirmed capacity rejection.
With `block_with_timeout`, a timeout 429 can also leave one append uncertain;
that policy is outside this harness. Received 408/503 suffixes can contain one
uncertain durable append.
The report separates these categories.
Neither WAL occupancy nor Parquet size growth measures physical disk I/O.

The synthetic padding is repeated `x`, so compression ratios are workload
specific. Every twentieth input matches the public example rule. RSS is an
observed finite-campaign peak, and includes post-load query work. CPU load time
is measured from `/proc/<pid>/stat` in clock ticks; its percentage uses one CPU
core as 100%. The shared host has no CPU affinity or process memory limit.
These observations establish neither a universal memory ceiling nor a production
capacity guarantee. Current measurements and limitations are in
[../BENCHMARKS.md](../BENCHMARKS.md).

## Native soak and process I/O

The native qualification runner can add a finite paced soak for each event size.
The default is disabled; `--soak-seconds` accepts 10–600 seconds per size and
uses a fixed 100 EPS. It runs the 1 KiB profile followed by the 4 KiB profile.
Append `--soak-seconds 120` to a normal native runner invocation to
retain `soak.json` with the parser and pipeline reports. To rerun only the soak
against an existing image, use:

```bash
python3 scripts/check-native-qualification.py \
  --image platform-signal:phase8 --expect-architecture amd64 \
  --soak-seconds 120 --soak-only
```

Soak-only runs at 10–119 seconds are diagnostic; 120 seconds or more records
`scope: native-soak`. Neither sets `full_qualification`: this mode measures the
soak profiles without repeating parser or pipeline campaigns. A normal runner
with the optional soak keeps its usual native qualification scope. The soak
records event and admission totals, drain/query/shutdown results, and sampled
load-phase process resources in 12 fixed elapsed-time buckets. RSS buckets stop
at load completion, before drain and query work; they are not whole-profile
peaks. It retains bounded
aggregates, not a growing sample history, and checks final resource coverage and
accounting.

For standalone use, `soak.py` accepts `--duration` (or `--seconds`) from 10 to
600 and `--rate` from 10 to 200 EPS; it can run both sizes or one selected with
`--event-bytes`:

```bash
python3 benchmarks/soak.py --server /path/to/signal-server \
  --image-id sha256:<source-image-id> --output /tmp/signal-soak.json \
  --duration 120 --rate 100
```

The finite attempt bound is `ceil(duration × rate)` per size. A single
synchronous sender uses batches of at most 20 events; each event is exactly 1 or
4 KiB and each HTTP response is limited to 1 MiB. The report is capped at 256
KiB. WAL is bounded to 64 MiB; event storage to 256 MiB and 8,192 files; findings
to 16 MiB; query memory is explicitly 256 MiB for these longer profiles. The
short pipeline campaign retains its separate 64 MiB query budget. The load must drain within 30 seconds. The owned server gets 12
seconds for graceful shutdown, then a five-second kill/reap deadline. Sampling
attempts occur about once per second (up to `ceil(duration)+1`); each read
includes a metrics HTTP request with its own five-second deadline. The report
records actual sample count, largest observed gap and sample failures, so this
cadence is observable rather than guaranteed.

Query responses are checked at their original status. A non-200 response fails
the profile; the harness keeps bounded failure context, including up to 2 KiB
of response preview and a 512-character transport/error excerpt. It does not
retry with a larger budget or reinterpret a resource-limit response as success.
Completed load, admission, drain and resource observations are retained in the
failed `soak.json` profile before the harness exits.

Each bucket includes load-phase RSS range/mean, CPU time, queue/storage metric
peaks and process I/O counter deltas. The report also includes load-only I/O and
an interval from load start through drain and queries; these cover different
time spans. Linux [process I/O accounting](https://docs.kernel.org/filesystems/proc.html#proc-pid-io-display-the-io-accounting-fields) exposes `read_bytes`,
`write_bytes` and `cancelled_write_bytes` alongside `rchar`, `wchar`, `syscr`
and `syscw`. These are process accounting counters: `rchar`/`wchar` count bytes
returned by read/write-like calls, including non-disk I/O; `write_bytes` is
counted when pages are dirtied, and actual writeback can happen later.
`cancelled_write_bytes` is reported separately. These counters are not physical-device throughput or latency
measurements. RSS drift and bucket means are observations, not a universal
memory plateau, ceiling, prolonged stability result or production capacity
guarantee. Current retained results and platform gaps are recorded in
[../BENCHMARKS.md](../BENCHMARKS.md) and
[native qualification](../docs/22-native-qualification.md).

## Parquet header-read diagnostic

The storage reader uses a fixed 1 KiB `BufReader` at the two Parquet header
sites. Three focused regressions check logical skips across read-ahead,
prefetched bytes at the logical limit and cancellation after a logical skip.
The change retains existing logical-byte limits, CRC checks, serialization
formats and cancellation guards.

A matched diagnostic queried 40 events in the same 20 files. Matched
release-image binaries recorded 37,920 `read`/`pread64` calls (37,698
successful one-byte reads) before and 702 calls (zero successful one-byte
reads) after; the post-change trace includes 480 successful 1,024-byte calls.
The earlier host-debug comparison is retained as historical evidence.
`strace` adds overhead, so this supports a structural call-count comparison
only, not query-time or capacity ratios. Process-returned Parquet bytes
increased from 532,926 to 968,300; these are not physical-device reads. The
run-3 report records `image_id: null`; its companion extraction-origin record
binds the binary hash to the immutable image. Parsed reports and traces are retained
under `target/phase10-query-reads-20261006/run-{1,3-image}/`.

The old-image pair of 600-second profiles at 20 EPS accepted and persisted
12,000 events each but both failed their first event query with HTTP 408;
neither completed a planned query sample. They are failed diagnostic runs, not
passing soak evidence. On the refreshed image, both replacement profiles
passed 600 seconds at 20 EPS: 12,000 accepted/WAL/storage/rule events, 600
findings and 20 successful queries per size, with clean exits and no
rejections, uncertainty or failures. Both captured 600 load samples in 12
populated buckets. Sampled load RSS ranged from 13,631,488 to 19,267,584 bytes
for 1 KiB events and 13,631,488 to 20,197,376 bytes for 4 KiB events. These
finite load observations do not establish a universal plateau or prolonged
stability. Independent 14-area review accepted this bounded local evidence with
no findings; see `target/phase10-longer-soak-20261006/review/final-header-buffer-review.json`.
The raw reports are `scope: bounded-soak` without a
`full_qualification` field; the wrapper passed with
`full_qualification: false`. See detailed metrics, hashes and remaining limits
in [../BENCHMARKS.md](../BENCHMARKS.md).
