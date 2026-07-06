# ADR-010: replaceable bounded storage and durable consumer completion

Status: implemented under the supplied Phase 3 specification, 2026-10-06. Concrete public signatures and phase
verification must agree with the implementation before the phase is accepted.

## Context

HTTP ingest depends on `signal-protocol::EventSink`; it never writes Parquet.
The WAL exposes bounded repeatable reads and explicit acknowledgment. Storage
must remain replaceable without a storage/query crate dependency cycle. Later
rules/findings must share the completion boundary before the same WAL is acked.

## API decision

`EventStore` belongs in `signal-storage`. Its `StoredEvent` input contains a
`sequence: u64` and canonical `event: SignalEvent`; the consumer maps the WAL
read into this storage-owned contract. Storage never depends on the WAL
implementation. The shared `EventQuery` filter belongs in `signal-protocol`;
`EventStream` and storage errors belong in storage.
`signal-query` depends on storage and protocol; storage does not depend on query
or DataFusion. The Phase 3 store reports a typed unavailable-query error until
the Phase 4 query adapter is implemented.

The implemented seam follows the existing boxed-future `EventSink` style:

```rust,ignore
pub trait EventStore: Send + Sync + 'static {
    fn append(
        &self,
        batch: Vec<StoredEvent>,
        context: OperationContext,
    ) -> StoreFuture<'_, StoreReceipt>;
    fn query(
        &self,
        query: EventQuery,
        context: OperationContext,
    ) -> StoreFuture<'_, EventStream>;
    fn metrics(&self) -> StorageMetrics;
    fn close(&self);
}
```

`StoreFuture` is a boxed `Send` future returning `Result<T, StorageError>`.
`EventStream` yields `Result<SignalEvent, StorageError>` without materializing a
complete query corpus. `OperationContext` contains `deadline: tokio::time::Instant`
and `cancellation: tokio_util::sync::CancellationToken`. `StoreReceipt` contains
`first_sequence`, `last_sequence`, `new_count` and `replay_count`. A successful receipt means
all newly required files and commit metadata are synced; it cannot mean queued or
partially published. Empty or oversized batches and sequence/payload conflicts
fail with typed errors before publication.

`EventQuery` contains a schema version, optional UTC `from`/`to`, contains,
severity, source, resource and account, an attribute filter list, limit and order.
Each attribute filter has a path and JSON value. `QueryOrder` is `asc` or `desc`;
the default query has version 1, limit 100 and ascending order. These are shared
serialized contracts, with no textual query language or execution engine state.
URL parsing, `[from,to)` validation, exact source/resource selector semantics,
actual predicates, stable timestamp/ID ordering, result/memory limits and
partition pruning remain Phase 4. `ParquetStore::query` currently returns
`QueryUnavailable` without executing the filter.

`ParquetStore::open(config, stream_id)` creates the filesystem implementation.
Its additional public API is `read_batch(after_sequence, max_events, max_bytes,
context)`, returning a bounded sequence-ordered page with an exclusive cursor;
`flush(context)` syncs the root and `shutdown(context)` stops and joins its worker
within the caller's deadline. There is no public unbounded file listing. Immutable
manifest metadata is held in a map bounded by `max_files`, and file reading loads
one bounded manifest batch at a time. Manifest version, identity, sequence ranges,
relative file paths, byte lengths, CRC32, row counts and full decoded Parquet
contents are checked before exposing events.

## Ownership and replay

One process holds exclusive ownership of the dedicated storage root, and one
server consumer owns event persistence and WAL acknowledgment. Bind storage to a
stable durable WAL stream identity. A pathname is not an incarnation identity:
deleting/resetting a WAL while keeping storage can reuse sequence numbers. Such
reuse must fail explicitly rather than cause old high-water metadata to skip new
events. The WAL publishes a 36-byte canonical UUID `identity` through
`identity.tmp`, file sync, rename and directory sync, and exposes the UUID in
`BufferMetrics::stream_id`. Recovery removes recognized temporary identities of
at most 36 bytes; an incomplete or invalid final identity fails startup. Existing
Phase 2 WALs receive an identity once. The WAL's 128-byte metadata reservation
covers both checkpoint copies (`2 * 28`) and both identity copies (`2 * 36`).
Storage binds the same UUID in its 36-byte `stream-id`: temporary write, file sync,
rename and root sync. A missing identity with committed manifests is corruption;
a UUID mismatch returns `StreamMismatch`.

Within that stream, publish bounded immutable batch manifests in sequence order.
The persisted sequence frontier plus bounded manifest metadata is sufficient to locate
replay overlap; validate matching sequence/event content before returning a replay
receipt. Batch boundaries need not match across restart. A replay may contain an
already committed prefix and a new suffix; publish only the latter. Maintain no
unbounded ID or sequence hash map. Different admitted WAL sequences with the same
event UUID are not automatically deduplicated across HTTP requests.

Phase 3 completion is:

```text
bounded WAL read -> durable event publication -> successful store receipt -> WAL ack
```

Ack only the last sequence covered by that receipt. An error, timeout, cancelled
call or incomplete publication cannot authorize an ack. A crash after publication
before ack repeats the same original events and returns verified replay coverage.
Server startup rejects a storage frontier beyond the WAL's last sequence, or a
WAL checkpoint beyond storage by more than the WAL's cumulative intentionally
dropped count. Incompatible state fails readiness rather than guessing a fresh
stream. Storage batches require positive strictly increasing sequences; they may
have gaps and do not require contiguous ranges.

`drop_oldest` can intentionally advance the WAL checkpoint beyond event storage.
That documented loss is counted in the durable WAL checkpoint and used by the
server startup compatibility check. Storage gaps are not counted as persisted
events: receipt counts reflect actual submitted rows, and replay requires matching
stored rows rather than only a sequence below the frontier.
The default `reject_new` avoids this intentional-loss case.

In Phase 5 replace this consumer's completion step with event publication, rule
evaluation and durable finding persistence before WAL ack. A second independently
acking consumer would violate the shared completion guarantee.

## Resource, cancellation and failure contract

Use one tracked filesystem worker with a bounded command channel and a matching
outstanding-operation semaphore. Capacity admission uses `try_acquire`/`try_send`
and rejects immediately; there is no storage waiter queue. Every append/read has a
deadline and cancellation state. Before disk work
starts, cancellation prevents mutation. Once filesystem mutation starts, finish
on that same worker: ordinary filesystem write/sync cannot safely be aborted.
A timeout therefore reports uncertain commit; restart/replay determines coverage.
Never spawn replacement workers on every timeout. An overdue active operation or
I/O corruption makes the store unavailable until recovery.

`StorageConfig` bounds batch events/bytes, individual event bytes, retained disk
bytes, root entries, command capacity and operation timeout, and selects a codec.
Row group size and per-file/manifest bounds are derived from those limits as
specified in ADR-004. Capacity includes temporary data and metadata. Saturation returns `Full`, retains the WAL
backlog, and is visible through quota/rejection metrics. It never deletes old
committed events implicitly. Quotas count file contents, not filesystem blocks or
inodes; filesystem disk-full still has typed I/O failure semantics.

Public errors distinguish invalid config/batch, replay conflict, capacity full,
committed corruption, I/O, timeout with uncertain commit, cancellation, closed
worker, exclusive-lock conflict, stream identity mismatch and deferred query
execution. Replay-content conflicts use `InvalidBatch`. Diagnostics omit event payloads and secrets.
Metrics expose queue depth/capacity, in-flight work, retained bytes/files and their
limits, persisted/replayed counts, write failures, quota failures and timeouts.

The server consumer coalesces events already retained in the bounded WAL until
the pending count reaches its batch event-count limit or the flush interval
elapses after first observing a pending event. `SIGNAL_STORAGE_FLUSH_MS` defaults
to 1000 ms and validates the range 1–60000 ms. Drain bypasses that delay. The
consumer polls at 10 ms intervals and retries saturated WAL control commands;
it never creates a second unbounded staging queue.
Shutdown stops HTTP admission first, drains bounded WAL batches within the server
deadline, then flushes and stops storage and WAL workers. The server captures one
deadline when the shutdown signal arrives and shares it across HTTP shutdown,
consumer drain, flush and both worker waits. Each wait uses the time remaining,
so successive shutdown stages do not each receive a fresh full timeout.
Events left unacknowledged remain
replayable. A stuck kernel I/O operation may outlive the caller's wait on its
single tracked worker; no timeout is promoted to successful durability.

## Verification

Use real Parquet/WAL files for restart and failures. Prove no ack before a durable
store receipt; crash after each publication stage and before/after WAL ack; replay
with changed batch sizing; conflicting sequence content; fresh WAL against old
storage; quota exhaustion; corrupt committed metadata/data; cancelled queued
work; bounded concurrent callers; and server shutdown with an unpersisted backlog.
Record Cargo gates and the phase review in `docs/07-progress.md`.
