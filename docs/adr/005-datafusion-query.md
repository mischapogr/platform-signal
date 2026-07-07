# ADR-005: bounded DataFusion event queries

- Status: accepted for Phase 4 after local gates and independent review
- Date: 2026-10-06

## Decision

Use DataFusion 55.1.0 with Arrow/Parquet 59.2.0 (compatible Arrow components
59.3.0 in the lockfile). Queries use the version 1 URL filter contract; the
implementation builds DataFrame expressions and never accepts SQL or another
textual query language.

The storage worker selects only immutable files named by committed manifests in
UTC date/hour partitions intersecting `[from,to)`. It validates selected files'
CRC, schema, footer and decoded-page bounds before DataFusion opens them. Files
outside the requested partition range and unpublished files are excluded before
filesystem reads. The storage worker canonicalizes the root and query passes
percent-encoded `file://` URLs, avoiding synchronous DataFusion filesystem probes
on Tokio. The selected file catalog has a configured maximum; exceeding
it returns a resource error, rather than silently dropping files.

DataFusion reads those exact file paths with the version 1 storage schema.
Parquet row-group statistics pruning is explicitly enabled for typed time,
severity, source and resource predicates. Time comparisons and ordering use
signed epoch seconds plus unsigned nanoseconds, retaining the full supported
RFC3339 year range and leap-second values. Ordering is timestamp, event ID and
WAL sequence, all in the requested direction, providing deterministic replay ties.
The lower bound is inclusive and the upper bound exclusive.

Message substring and typed attribute equality are immutable scalar predicates.
Attribute JSON uses arbitrary-precision serde values and the shared dotted-key
lookup contract. Dotted object keys take precedence over nested traversal;
missing values differ from JSON null. Strings, booleans, numbers, arrays and
objects retain their types without flattening or SQL conversion.

## Resource and cancellation contract

A single shared `GreedyMemoryPool` limits DataFusion operator reservations across
all sessions. The disk manager is disabled: exhausting operator memory fails
explicitly instead of spilling to unbounded temporary storage. DataFusion's
statistics, listing and metadata caches are disabled. The memory metric reports
operator reservations, not process RSS; bounded storage validation, file
metadata, Arrow read buffers, predicate JSON and response envelopes also consume
memory outside this pool. A second preflight ceiling rejects a selected scan when
the sum of validated footer uncompressed-column byte counts exceeds the configured
operator memory value, before any DataFusion decoding; this deliberately bounds
large compressed inputs conservatively. The physical I/O adapter has a separate
global read-byte lease retained through returned Arrow byte buffers.

Admission uses a semaphore with immediate rejection and no waiter queue. Defaults
are four concurrent queries, 256 MiB operator memory, 1,024 selected files,
1,000 returned events, 8 MiB serialized response bytes, 128 rows per batch,
one execution partition and a ten-second deadline. Configurations are validated
before readiness. Query parameter complexity is bounded in the shared protocol
contract. Metadata fetch concurrency is one within a session.

Selection, planning and stream consumption share the earlier caller/server
deadline and caller cancellation token. Dropping the DataFusion stream aborts
its execution tasks. Physical filesystem work runs on a fixed pool of ordinary threads (four by
default, at most sixteen), with separately bounded operation and waiter queues.
An operation slot stays owned through kernel completion and reply consumption;
returned byte buffers retain the global read-byte lease across buffer slices.
Dropping or timing out a query cannot launch replacement workers while its
physical I/O slots remain occupied. A shutdown deadline can stop waiting while
the existing fixed threads finish their kernel calls; Tokio runtime teardown
does not wait on them. Query timeout must
not poison the independent storage writer; corrupt committed data still fails
closed.

Results are streamed, never collected without a limit. Each returned row passes
the authoritative codec's complete twenty-column projection check. Rows are
decoded individually and checked against the serialized response byte budget
before insertion. A final envelope check includes metadata and punctuation.
No partial successful response is emitted after corruption or resource failure.

Safe typed errors classify invalid input, admission saturation, timeout,
cancellation, resource exhaustion and unavailability without embedding query
values or filesystem paths. Metrics expose active/capacity, requests,
completions/failures/rejections, deadlines/cancellation, selected files and
partitions, total latency and memory reservations.

## Evidence and consequences

Phase 4 uses real Parquet integration tests for each filter, nested and dotted
attributes, arbitrary-precision numbers, missing/null/type distinctions, UTC
partition exclusion, year boundaries, leap seconds, timestamp ties, limits,
memory exhaustion, admission saturation, cancellation and recovered capacity.
The process gate exercises persistence/query after server restart. Current gate
results are recorded in `docs/07-progress.md`.

This filesystem query implementation lives in `signal-query` above the storage
selection seam, preserving the dependency direction. The existing
`EventStore::query` method remains an unavailable storage-only seam until a future
backend supplies its own implementation; the monolith routes HTTP queries through
`QueryEngine`. Indexes, aggregation, SQL, S3 and retention remain outside Phase 4.

Documentation was retrieved through Context7 `/apache/datafusion`, then checked
against downloaded 55.1.0 source. In particular the pinned runtime uses
`DiskManagerBuilder::with_mode(DiskManagerMode::Disabled)`, rather than the older
`DiskManagerConfig` examples.

References:

- [DataFusion DataFrame guide](https://datafusion.apache.org/library-user-guide/using-the-dataframe-api.html)
- [DataFusion 55.1.0 DataFrame API](https://docs.rs/datafusion/55.1.0/datafusion/dataframe/struct.DataFrame.html)
- [DataFusion 55.1.0 runtime builder](https://docs.rs/datafusion-execution/55.1.0/datafusion_execution/runtime_env/struct.RuntimeEnvBuilder.html)
