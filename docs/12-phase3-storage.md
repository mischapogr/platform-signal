# Phase 3: durable Parquet persistence

The server now runs one storage consumer alongside HTTP ingest. HTTP 202 still
acknowledges only a synced WAL append. The consumer reads a bounded prefix,
coalesces events until the configured batch limit or flush interval, commits
Parquet, then acknowledges the covered WAL sequence. If the process stops before
that acknowledgment, the records replay from WAL and storage verifies their
sequence and full event content before treating them as duplicates.

The server also exposes `GET /v1/events` URL queries; the Phase 4 implementation
is under qualification. Rules/findings and the integrated Compose slice remain
later work. See [Phase 2 WAL behavior](10-phase2-wal.md) for admission, recovery
and the ingest contract, and [Phase 4 query behavior](13-phase4-query.md) for
query syntax, limits and evidence.

## Storage configuration

Values are read from environment before the listener reports ready. Capacity
settings must be positive and bounded; storage batch/event limits must fit the
maximum WAL record. `SIGNAL_STORAGE_EVENT_BYTES` and the consumer's effective
batch-byte limit must each be at least `SIGNAL_WAL_RECORD_BYTES`.

| Variable | Default | Meaning |
| --- | ---: | --- |
| `SIGNAL_STORAGE_DIR` | `data/events` | Dedicated local storage root, owned by one process |
| `SIGNAL_STORAGE_BATCH_EVENTS` | `1000` | Maximum events per append batch (up to 1,000,000) |
| `SIGNAL_STORAGE_BATCH_BYTES` | `8388608` | Maximum batch bytes; consumer limit is the minimum of this and `SIGNAL_MEMORY_BYTES` |
| `SIGNAL_STORAGE_EVENT_BYTES` | `2097152` | Maximum encoded event bytes; must fit the WAL record limit |
| `SIGNAL_STORAGE_BYTES` | `1073741824` | Maximum inventoried file contents in the storage root |
| `SIGNAL_STORAGE_FILES` | `100000` | Maximum inventoried filesystem entries, including directories |
| `SIGNAL_STORAGE_COMMANDS` | `8` | Bounded storage command and outstanding operation/reply capacity |
| `SIGNAL_STORAGE_TIMEOUT_MS` | `120000` | Storage operation deadline; positive and at most one hour |
| `SIGNAL_STORAGE_COMPRESSION` | `snappy` | `snappy`, `zstd` or `uncompressed` Parquet compression |
| `SIGNAL_STORAGE_FLUSH_MS` | `1000` | Coalescing delay for a partial batch; must be 1–60000 ms |

The effective event count is the minimum of storage batch events and the WAL
pending-event limit. The effective batch bytes are the minimum of storage batch
bytes and the WAL pending-memory byte limit. Startup rejects configurations in
which either effective storage event or batch-byte limit cannot hold one maximum
WAL record. Storage `FILES` bounds directory entries as well as regular files;
the byte quota sums file lengths, not allocated filesystem blocks, inode use or
other filesystem overhead.

## Files, publication and replay

Events are partitioned by the event timestamp in UTC-compatible date/hour
directories, `date=YYYY-MM-DD/hour=HH/`. A batch may publish one Parquet file
for each partition it touches. Files are written under temporary names, finished
and synced, renamed to their final names, and their partition directories synced.
A bounded manifest records stream UUID, sequence range, rows, relative paths,
file lengths, CRC32 values and per-file row counts. The manifest is written and
synced to a temporary file, atomically renamed, and the storage root synced. That
manifest publication is the committed storage boundary. Only after the append
receipt covers the batch does the consumer checkpoint the WAL.

At startup storage binds to the WAL stream UUID. A missing identity can be
created only for a storage root without committed manifests; existing identity
mismatch, missing identity alongside manifests, malformed manifests, bad file
checksums or invalid Parquet content fail startup. On replay, sequence overlap
is accepted only when the stored canonical event content matches the WAL event.
Conflicting content fails closed. The WAL is at-least-once; replay-safe storage
does not make HTTP admission exactly once.

Storage has its own exclusive root lock and one synchronous filesystem worker
behind bounded asynchronous commands. Operation deadlines and cancellation are
tracked; once a commit has started it may finish after the caller becomes
uncertain. Storage failure closes admission. Shutdown stops admission, drains
the consumer and storage under the server's shared shutdown deadline, and leaves
unfinished records in WAL for restart replay. A stuck filesystem syscall can
outlive the bounded wait until it returns or the process exits.

The storage quota is a retention ceiling, not an automatic retention policy.
There is no age-based deletion or compaction. When disk or entry capacity is
exhausted, append fails and ingest closes; operators must preserve the data and
recover capacity through an explicit future retention/operations mechanism.

## Metrics

`GET /metrics` includes these storage series when the storage sink is wired:

```text
signal_storage_persisted_total
signal_storage_replayed_total
signal_storage_bytes
signal_storage_byte_capacity
signal_storage_files
signal_storage_file_capacity
signal_storage_command_depth
signal_storage_command_capacity
signal_storage_operations_in_flight
signal_storage_operation_capacity
signal_storage_timeouts_total
signal_storage_full_total
signal_storage_failures_total
signal_storage_high_water
signal_storage_fail_closed
```

Replay/failure/timeout counts are per process; the persisted count is restored
from committed manifests at startup. `signal_storage_bytes` reports inventoried file
lengths; `signal_storage_files` reports filesystem entries, including
directories. `signal_storage_high_water` is the greatest committed
sequence; intentional `drop_oldest` losses may leave sequence gaps. Metrics do not prove power-loss behavior, filesystem portability or
throughput.

## Qualification gate

The storage million-event roundtrip gate is:

```bash
cargo run --release -p signal-storage --example million-roundtrip -- 1000000
```

The 2026-10-06 gate verified all 1,000,000 canonical events after reopen:
169,188,021 bytes, 1,028 Parquet files; write 86.735 s, reopen 32.178 s,
read/verify 38.852 s, maximum RSS 16,292 KiB. The gate uses 1,000-row / 2 MiB
batches, Snappy, a 4 GiB quota and a 120 s operation deadline. Its timings exclude
HTTP, WAL, query and rules. The measured reopen exceeded 30 s, so the library and
server storage deadline default is now 120 s; larger datasets or slower disks
may require an explicit deadline and capacity adjustment.

See [phase evidence](07-progress.md). Local crate/process evidence does not prove
ARM64, container, power-loss or production qualification.
