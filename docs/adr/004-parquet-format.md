# ADR-004: version 1 Parquet event storage

Status: implemented under the supplied Phase 3 specification, 2026-10-06. Implementation and phase review evidence
are recorded in `docs/07-progress.md`; this document alone proves no runtime gate.

## Context

Phase 3 consumes the durable WAL into local immutable Parquet files. It must
preserve the canonical version 1 event, tolerate replay after publication before
acknowledgment, and bound memory and disk use. Phase 4 adds DataFusion queries.

## Dependency decision

Resolve DataFusion before selecting Arrow/Parquet. DataFusion **55.1.0** declares
Rust **1.94.0** and Arrow/Parquet **59.2.0** in its tagged workspace manifest;
Arrow/Parquet 59.2.0 declares Rust 1.85. These fit the pinned Rust 1.94.1 toolchain.
The direct Phase 3 Arrow and Parquet dependencies are pinned to `=59.2.0`;
`Cargo.lock` resolves compatible Arrow component crates to 59.3.0. This is one
compatible Arrow type family, not a second incompatible major. DataFusion
`=55.1.0` is selected for Phase 4 and is not yet a runtime dependency.
Disable default features and enable Parquet `arrow`, `snap` and `zstd` explicitly.
Configured codecs are uncompressed, Snappy and Zstd; reject unknown codecs before
readiness. A locked dependency graph and actual compilation remain the final
compatibility check.

Current Context7 retrieval used `/apache/datafusion` for Arrow/Parquet coupling
and `/apache/arrow-rs` for the Rust writer, row group state and codecs. Its returned
DataFusion release examples were older, so exact versions were corroborated with
primary tagged Cargo manifests rather than inferred from those examples or main:

- [DataFusion 55.1.0 Cargo manifest](https://github.com/apache/datafusion/blob/55.1.0/Cargo.toml)
- [Arrow/Parquet 59.2.0 Cargo manifest](https://github.com/apache/arrow-rs/blob/59.2.0/Cargo.toml)
- [Parquet 59.2.0 features](https://github.com/apache/arrow-rs/blob/59.2.0/parquet/Cargo.toml)
- [Rust ArrowWriter implementation](https://github.com/apache/arrow-rs/blob/59.2.0/parquet/src/arrow/arrow_writer/mod.rs)

## Event schema

Storage schema version 1 is independent of canonical event schema version 1.
Keep an authoritative `event_json: Utf8` column containing the complete canonical
event serialized with `serde_json` arbitrary precision. It preserves nested maps,
arrays, nulls, large integer/decimal JSON numbers, optional fields and tags without
inventing a fixed attribute schema. Decode through `SignalEvent`, validate the
event and check the searchable projections against it; disagreement is corruption.

The schema additionally contains the WAL sequence and stable searchable
projections. Field names and Arrow types are part of the storage version:

| Column | Arrow type | Nullable | Meaning |
| --- | --- | --- | --- |
| storage_schema_version | UInt16 | no | Storage layout version, initially 1 |
| wal_sequence | UInt64 | no | Original durable WAL sequence |
| event_json | Utf8 | no | Authoritative complete canonical event, including its schema version |
| id | Utf8 | no | Canonical hyphenated UUID |
| timestamp | Utf8 | no | Canonical UTC RFC3339 event timestamp |
| observed_at | Utf8 | no | Canonical UTC RFC3339 observed timestamp |
| timestamp_seconds | Int64 | no | Event timestamp whole Unix seconds |
| timestamp_nanos | UInt32 | no | Original Chrono fractional nanoseconds |
| source_type | Utf8 | no | `source.type` |
| source_name | Utf8 | yes | `source.name` |
| severity | Utf8 | no | Canonical lowercase event severity |
| message | Utf8 | yes | Original optional message |
| attributes_json | Utf8 | no | Lossless arbitrary nested JSON object |
| resource_kind | Utf8 | yes | Optional resource kind |
| resource_id | Utf8 | yes | Optional resource ID |
| resource_account_id | Utf8 | yes | Optional generic resource account ID |
| resource_region | Utf8 | yes | Optional generic resource region |
| trace_id | Utf8 | yes | Original optional trace ID |
| span_id | Utf8 | yes | Original optional span ID |
| tags_json | Utf8 | no | Original ordered JSON tag list |

Do not convert JSON numbers through `f64`. Do not narrow timestamps to signed
64-bit nanoseconds: canonical RFC3339/Chrono supports dates outside that range.
The seconds/nanoseconds pair preserves the full accepted range and original
fractional precision, including Chrono leap-second values. Phase 4 ordering and
filtering must compare that pair or parsed timestamps rather than RFC3339 strings
with variable fractional precision. All 20 columns, including projection values,
types, nullability and order, are checked on decode by re-encoding the event.

## Partitioning and bounds

Partition by the event timestamp in UTC under
`date=YYYY-MM-DD/hour=HH/`. Observed time does not choose the partition. An input
batch spanning hours is split into one bounded file per hour. The existing batch
limits bound rows and encoded JSON bytes. A transaction opens one writer at a
time; it may contain at most one file per input row. Row groups contain at most
`min(max_batch_events, 128)` rows, writes use chunks of 128 rows, dictionaries are
disabled and target data pages are 64 KiB. One record larger than the read byte
bound returns `InvalidBatch` instead of yielding an empty page indefinitely.
The server coalesces pending WAL events until the batch event-count limit or
`SIGNAL_STORAGE_FLUSH_MS` elapses after first observing a pending event. The
interval defaults to 1000 ms and accepts 1–60000 ms; shutdown drain bypasses the
interval. Encoded batch bytes remain independently bounded when reading the WAL.

The writer closes each Parquet file, including its footer, before syncing and
publishing it. Use Parquet's row limits and writer memory/row group state to flush
bounded groups. Estimates alone are not a hard memory or file-size quota: the
input limit and bounded output writer enforce the actual limits. A file is capped
at `4 * max_batch_bytes + 1 MiB`; manifest encoding is capped at
`4096 + 256 * max_batch_events` bytes. Reserve that manifest capacity before
writing files; a quota writer bounds the actual remaining file bytes, including
unfinished temporary data. `max_files` counts files and date/hour directories.

## Publication and recovery

Files are immutable once committed. Write into owned temporary paths, finish the
footer, sync each file, atomically rename on the same filesystem, and sync affected
directories including new partition ancestors. An immutable manifest is the batch
visibility boundary: publish it only after all referenced files are durable, by
temporary write, file sync, rename and directory sync. Query/readback uses only
committed manifest entries, never a wildcard over every `.parquet` file. This
avoids partial visibility when a single batch spans several partitions.

Use deterministic WAL sequence ranges in transaction and file identities; a
restarted consumer may choose different batch sizes. Detect the already committed
overlap, verify original sequence/event identity and skip that overlap rather than
publish it again. Do not keep an ever-growing event-ID set. This deduplicates WAL
replay; independently admitted requests reusing an ID remain distinct admissions.
See [ADR-010](010-storage-interface.md) for checkpoint and ownership rules.
Names are `batch-{first:020}-{last:020}.parquet` inside each partition and
`batch-{first:020}-{last:020}.manifest` at the storage root; incomplete writes use
the corresponding `.tmp` suffix. The immutable JSON manifest carries version,
WAL stream UUID, first/last sequence, row count, and each file's relative path,
byte length, IEEE CRC32 and row count. Strictly increasing sequences may have gaps;
manifest ranges therefore do not by themselves assert every intervening sequence
is stored.

Recovery ignores or removes owned incomplete temporary publications without
advancing the WAL checkpoint. Validate manifest version, ranges, relative paths,
file sizes/checksums and referenced Parquet schema/footer before accepting committed
state. Missing/corrupt committed data fails startup; it is never treated as a
fresh store. Unreferenced final files are unfinished publications and must not
become visible merely because their suffix is `.parquet`. Metadata and recovery
scanning are themselves bounded by configured file/manifest limits. Inventory and
the in-memory manifest map are bounded by `max_files`; each manifest read loads at
most one configured batch of rows. Payloads are not accumulated across all
manifests, and there is no persistent or in-memory global event-ID index.
Only recognized owned entries are accepted; unexpected entries and symlinks fail
startup. Root ownership uses an exclusive advisory `.lock`; Linux files and newly
created directories use modes 0600 and 0700. Capacity errors clean unfinished
files for the current transaction; I/O failures close the worker and leave owned
unfinished files for recovery.

Before parsing Parquet metadata, the reader bounds the serialized footer and its
Compact Thrift container lengths, depth and flat schema child counts. Before
Arrow decoding it checks row groups, column/page ranges and aggregate actual
uncompressed page sizes. The v1 writer disables dictionaries; recovery rejects
dictionary pages. This prevents compressed or forged owned-file metadata from
allocating beyond the configured read budgets before event validation.

## Consequences and verification

JSON columns trade compression and future attribute query speed for faithful
canonical preservation. Parquet remains useful for typed top-level filtering and
UTC partition pruning. Retention, compaction, S3, bloom filters and a global ID
index are deferred; exhaustion stops persistence while the WAL retains replay.

Phase 3 evidence must cover nested/large-number/optional-field roundtrip, UUID and
nanosecond timestamp equality, UTC boundaries, all supported codecs, restart,
partial publication, quota and I/O errors, publish-before-ack replay with changed
batch size, and a streaming 1,000,000-event gate without an unbounded test corpus.
