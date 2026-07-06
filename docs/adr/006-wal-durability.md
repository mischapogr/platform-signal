# ADR-006: bounded durable admission

Status: implemented under the supplied Phase 2 specification, 2026-10-06.

## Decision

Use a single filesystem worker per WAL directory, protected by an exclusive
advisory file lock. A bounded Tokio command channel feeds that worker. Retained
events are also bounded by count and encoded JSON bytes; the MVP keeps all
unacknowledged payloads in memory, rather than providing a disk spill cache.
Replay exceeding configured bounds fails startup without discarding records.

Successful admission requires `write_all` and `sync_all` on the segment. New directory entries are synced through their parents. New
segments are synced and their directory entry synced before use. Consumer reads
are repeatable and do not remove events. Only `ack(sequence)` after persistence
advances a contiguous checkpoint. Replayed IDs remain unchanged. Phase 2's server
has no persistence consumer and therefore never acknowledges or drains the WAL.

The checkpoint is written to `checkpoint.tmp`, synced, renamed to `checkpoint`,
and its directory synced before queue removal or segment reclamation. Fully
checkpointed segments, including the active segment, are deleted and the
directory synced. A crash before reclamation merely retains redundant segments.
The checkpoint preserves the high-water sequence even when all segments vanish.

### Format, version 1

Integers are unsigned little endian. CRC is IEEE CRC32 (`crc32fast`).

- Segment filename: zero-padded 20-digit first sequence followed by `.wal`.
- Segment header (20 bytes): `SIGWAL01` (8), first sequence (8), CRC of those
  16 bytes (4).
- Record header (20 bytes): JSON length (4), sequence (8), CRC of the first
  12 header bytes (4), CRC of JSON payload (4). Payload is canonical version 1
  event JSON. Sequences start at 1 and must be contiguous.
- Checkpoint (28 bytes): `SIGACK01` (8), acknowledged sequence (8), cumulative
  intentionally dropped events (8), CRC of the preceding 24 bytes (4).

Only an incomplete last record/header in the final segment is recoverable by
truncation. A complete invalid header, CRC, sequence, JSON/event, checkpoint or
interior truncation fails startup. A partial final segment header may be removed
only at the expected next sequence. Recovery syncs any truncation before readiness.
Missing checkpoint with existing segments is corruption, not a fresh WAL.

WAL quota counts segment contents and reserves 56 bytes for checkpoint plus its
temporary replacement; the empty lock file adds no content bytes. Segment count,
record size, pending event count/bytes and command count are independently bounded. Outstanding operation replies also
have a bounded permit count, preventing accumulation by callers that stop polling.
This is a file-content quota, not filesystem block/inode or Parquet retention.
Unexpected entries and symlinks in the dedicated WAL directory fail startup.
Files are created with mode 0600 and new directories with mode 0700 on Linux.

### Overload and cancellation

- `reject_new` (default): reject with `Full` when a retained queue/disk/segment or
  command admission bound is reached.
- `drop_oldest`: durably checkpoint and count oldest pending events until room
  exists, then append. Loss is intentional and can occur even if the later append
  fails or its caller cancels. Never use this policy where loss is unacceptable.
- `block_with_timeout`: retry capacity checks until the configured deadline;
  waiting callers have a separate bounded permit count. Ack/close wakes waiters.
  Deadline exhaustion is counted and returns `Full` to the ingest caller.

Commands carry deadlines and a cancellation flag. Cancelled/expired queued
commands do not start disk work. Once filesystem mutation starts, it completes
on the same tracked worker: ordinary filesystem writes/fsync cannot safely be
aborted. A caller timeout can therefore have an uncertain commit; retry with the
same event ID. This does not spawn additional workers or reuse a partially written
segment. I/O failure or an overdue active operation makes the buffer unavailable and stops admission until restart.

`close()` atomically stops new admission and wakes waiters; an already started
commit may finish. Consumer reads/acks remain available until `shutdown()`.
Shutdown waits within a deadline for the worker, leaves unacknowledged events
durable, and never acknowledges on behalf of a future consumer. A stuck kernel
I/O call may outlive that wait on the single worker; process termination ends it.

## Consequences

Admission is at least once, with no exactly-once promise or cross-request
deduplication. One outstanding consumer batch is the intended integration model;
ack cannot exceed a sequence returned by `read_batch`. Later event/finding
consumers must share persistence completion before advancing this checkpoint.
Per-event fsync prioritizes correctness; performance is measured in hardening
before introducing group commit or a bounded disk-backed replay cache.
