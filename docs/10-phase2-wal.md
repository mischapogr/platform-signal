# Phase 2: durable WAL admission

Run `cargo run -p signal-server`. The [HTTP examples](09-phase1-ingest.md) still
apply. HTTP 202 now means every reported accepted event was appended and synced
to the WAL. Restart with the same `SIGNAL_WAL_DIR` to replay unacknowledged events.
`GET /metrics` reports recovered depth and `signal_wal_replayed_total`.

There is no storage consumer or event query yet. With `reject_new`, the server
fills its configured bounds and returns 429; restart retains that backlog and
**does not free capacity**. Parquet persistence and automatic checkpointing are
Phase 3. Query is Phase 4, and the complete Compose/finding slice is Phase 5.

## Additional configuration

Existing HTTP limits and token configuration are in [09-phase1-ingest.md](09-phase1-ingest.md).
Memory count/byte limits now apply to retained unacknowledged canonical payloads.
All configuration and recovery must succeed before a listener reports ready.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIGNAL_WAL_DIR` | `data/wal` | Dedicated persistent local directory; one process may own it |
| `SIGNAL_MEMORY_EVENTS` | 10000 | Maximum pending event count |
| `SIGNAL_MEMORY_BYTES` | 67108864 | Maximum pending encoded JSON bytes |
| `SIGNAL_WAL_RECORD_BYTES` | 2097152 | Maximum encoded canonical event size |
| `SIGNAL_WAL_BYTES` | 268435456 | Segment file contents plus 128 reserved metadata bytes |
| `SIGNAL_WAL_SEGMENT_BYTES` | 8388608 | Maximum segment file contents |
| `SIGNAL_WAL_SEGMENTS` | 128 | Maximum segment count |
| `SIGNAL_WAL_COMMANDS` | 64 | Command queue and outstanding operation/reply limits |
| `SIGNAL_WAL_WAITERS` | 64 | Concurrent admission attempts, including blocked callers |
| `SIGNAL_ADMISSION_POLICY` | `reject_new` | `reject_new`, `drop_oldest`, `block_with_timeout` |
| `SIGNAL_WAL_TIMEOUT_MS` | 5000 | Startup, command and worker shutdown deadline |
| `SIGNAL_WAL_BLOCK_TIMEOUT_MS` | 1000 | Capacity wait deadline; bounded by operation timeout |

Record size must fit the memory budget and segment with 40 framing bytes; a
segment plus 128 metadata bytes must fit the WAL quota. The reserve holds two
28-byte checkpoint slots and two 36-byte stream-identity slots, including the
temporary/rename publication space. Initial WAL identity is written and synced
as `identity.tmp`, atomically renamed to `identity`, then the directory is
synced. Capacities must be positive;
timeouts must be positive and at most one hour. Recovery refuses lowered limits
that cannot hold existing segments/backlog. Move/archive data through a future
explicit operational tool, rather than deleting WAL files to bypass a limit.

`drop_oldest` deliberately loses oldest pending events, with a durable checkpoint
and drop counter. A later append failure does not reverse those drops. Its use is
an explicit operational policy choice. Default `reject_new` never discards an
accepted event to make room. `block_with_timeout` waits within both HTTP and WAL
deadlines and returns 429 on capacity timeout; excess waiters/commands reject
immediately. Other WAL operation failures return 503; HTTP request timeout is 408.

## Consumer API and shutdown

`DurableBuffer` implements the generic `EventSink`. Consumers use
`read_batch(max_events, max_bytes)` and only call `ack(last_sequence)` after every
required persistence operation succeeds. Reads repeat the pending prefix; empty
reads can mean the byte limit is too small. Ack cannot exceed a delivered sequence.
Use one coordinated consumer: concurrent consumers must not advance each other's
unfinished work. Phase 3 persistence verifies the stream identity, sequence and complete event
content on replay; a repeated HTTP submission with the same ID is still a new admission.

The Phase 2 server stopped admission and retained its unconsumed backlog. The
current Phase 3 server drains HTTP and its storage consumer under one shutdown
deadline, checkpointing only after storage receipts. Unfinished records remain
on disk. See [current storage behavior](12-phase3-storage.md). Complete CRC/sequence/canonical event corruption
fails startup. Only incomplete final tails are truncated and synced.

Queued commands cancelled by HTTP/client shutdown are skipped. Once disk mutation
starts, the tracked worker completes it; a client timeout may have an uncertain
commit. Retry with the same ID and tolerate duplicates. A worker deadline or I/O
failure closes admission/readiness until restart; readiness/metric checks detect
an overdue active operation even after its caller cancels. A stuck kernel write
cannot be safely aborted; shutdown waiting is bounded, with at most one worker
remaining until the syscall finishes or the process exits. The format and exact
sync/checkpoint/rename/reclamation boundary are in [ADR-006](adr/006-wal-durability.md).

## Metrics and resource bounds

In addition to HTTP/queue metrics, `/metrics` exposes WAL bytes/capacity, segment
count, committed admissions, replayed events, CRC corruption count, recovered
truncations, command queue depth/capacity, outstanding operations/capacity,
admission waiters/capacity and operation timeouts. Accepted/rejected HTTP totals
count caller-visible results; WAL totals count commits/unsuccessful admission
attempts. Cancelled uncertain commits can appear in both WAL accepted and rejected
counts. These counters must not be added to derive distinct event totals.

Counters are per process, except cumulative intentional drops in the checkpoint.
Startup corruption is a typed startup failure in stderr; an HTTP corruption metric
cannot be served when startup has failed. The WAL quota bounds file contents,
not filesystem allocated blocks or inode overhead. Encoded queue bytes do not
claim an exact RSS bound: bounded command payloads/replies, JSON allocations,
request/connection buffers and allocator overhead also use memory. No spill cache
or replay deduplication is implemented.

## Verification

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-workspace.py
```

The actual process gate submits an authenticated event, verifies its on-disk
CRC/ID, sends SIGKILL, restarts and checks replay. It fills a count-limited queue
with exact partial batch counts, verifies all ten accepted IDs, performs graceful
SIGTERM/restart, tests exclusive ownership, invalid config and corrupt startup,
and checks logs for request secrets. Real-file tests cover rotation, quota policies,
read bounds, checkpoint/reclaim and tail/interior damage. Worker control tests
exercise queued cancellation, command bounds and deadlines without mocking WAL I/O.

These tests establish local process recovery on Linux AMD64, not power-loss,
network filesystem, ARM64, container or throughput qualification. Per-event fsync
has not been benchmarked. Console logging still has the Phase 1 stalled-stderr
hardening item recorded in [07-progress.md](07-progress.md).

Primary references fetched for implementation: [Tokio bounded channels](https://docs.rs/tokio/latest/tokio/sync/mpsc/),
[Tokio blocking work cancellation](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html),
[Rust file sync and advisory locking](https://doc.rust-lang.org/std/fs/struct.File.html),
[IEEE CRC32](https://docs.rs/crc32fast/latest/crc32fast/).
