# Phase 4: bounded URL event queries

`GET /v1/events` queries persisted Parquet events. Phase 4 is accepted locally
after the workspace gates, real-process gate and independent review passed.
This is local Phase 4 evidence; it does not complete the `v0.1.0` release gates.
Findings are exposed separately by `GET /v1/findings`. Query results include only events that have
reached Parquet; a recently accepted WAL event can be briefly invisible while
the storage consumer is writing it.

Queries use URL parameters only. Unknown or repeated keys fail closed. When
`SIGNAL_API_TOKEN` is configured, use the same Bearer authorization header as
ingest. `from` and `to` require full RFC3339 timestamps; both are interpreted in
UTC and define the half-open interval `[from, to)`. At least one bound may be
omitted, but when both are supplied `from` must be earlier than `to`. Time bounds
select date/hour partitions before file scanning.

## Parameters

| Parameter | Meaning |
| --- | --- |
| `from`, `to` | Inclusive lower and exclusive upper event timestamp bounds |
| `event_id` | Exact non-nil lowercase hyphenated event UUID; all matching admission rows remain eligible |
| `contains` | Case-sensitive substring in the event message |
| `severity` | Exact lowercase severity: `trace`, `debug`, `info`, `warn`, `error`, or `critical` |
| `source_type`, `source_name` | Exact source fields |
| `source` | Compatibility alias for `source_type` |
| `resource_kind`, `resource_id` | Exact resource fields |
| `resource` | Compatibility alias for `resource_id` |
| `account` | Exact resource account ID |
| `attribute.<path>` | Exact typed equality against a relative path within `attributes` |
| `limit` | Maximum returned events; default `100`, configured maximum `1000` |
| `order` | `asc` (default) or `desc` |

If an alias and its explicit field are both present with different values, the
query is rejected. Equal alias/field values are accepted. Attributes support at
most 32 filters. Dotted paths have up to 512 UTF-8 bytes and 16 nonempty
components. At each lookup step an exact dotted map key takes precedence over
nested traversal; if there is no exact key, the longest existing dotted prefix
is traversed. Arrays do not support numeric path indexing.

Attribute values preserve JSON types. The decoded URL value is parsed as JSON
when possible, otherwise treated as a plain string. Thus an unquoted `7` is a
number, while JSON-quoted `"7"` is a string. For example:

```bash
curl -G 'http://127.0.0.1:8080/v1/events' \
  --data-urlencode 'from=2026-10-06T00:00:00Z' \
  --data-urlencode 'to=2026-10-07T00:00:00Z' \
  --data-urlencode 'severity=error' \
  --data-urlencode 'attribute.user.name=alice' \
  --data-urlencode 'attribute.status=500' \
  --data-urlencode 'limit=100' \
  --data-urlencode 'order=desc'
```

Use `--data-urlencode 'attribute.status="7"'` to match the string `7` rather
than numeric JSON value `7`.

## Exact event evidence lookup

`event_id` matches the persisted event's UUID projection by equality. It is not
a message substring search. The decoded value must use canonical lowercase
hyphenated UUID spelling; uppercase, compact, URN, braced, nil and malformed
values are rejected. Repeated keys, including percent-encoded aliases of the
same key, remain invalid. The optional typed field is compatible with existing
serialized version-1 queries that omit it, and is omitted from serialization
when absent. Programmatically constructed queries reject nil IDs too.

An event UUID can occur in multiple independent admissions, including admissions
with different content. Lookup returns all matching rows within the existing
result limit and ordering; it does not deduplicate them or select an authoritative
copy. Other filters apply in conjunction with `event_id`, and any supplied time
bounds still prune UTC date/hour partitions before scanning.

Finding `created_at` is the source event's observed time, not its original event
timestamp. A delayed event may therefore precede a finding by much more than a
day. Callers can omit time bounds for a retained-history lookup or supply their
own event-time interval. Omitting bounds keeps the existing file-selection,
scan-memory, response-byte, concurrency and deadline budgets; it does not create
an unbounded scan or an ID index. An overly broad lookup fails the whole query
with the existing resource error rather than returning a silent partial scan.

A successful empty result means no matching retained event was found within
the searched scope. It does not establish source completeness, original evidence
retention or that the event never existed; WAL-admitted events may still await
Parquet publication. A result count equal to `limit` may omit further matches.
Authorization and error responses are identical to other event queries; a failed
lookup must not be presented as a successful empty result.

## Response and errors

A successful response has `schema_version: 1`, `events`, and `metadata`. Metadata
contains `duration_ms`, `scanned_files`, and `candidate_partitions`. Results are
sorted by timestamp at nanosecond precision, then event ID, then WAL sequence;
the selected order applies to all three keys. This produces stable order for
events with equal timestamps and IDs.

| HTTP | Meaning |
| --- | --- |
| 200 | Query completed; response uses the versioned envelope |
| 400 | Invalid, repeated, conflicting, unknown, malformed or over-complex URL query parameters |
| 401 | Missing or invalid Bearer token when authentication is configured |
| 408 | Query deadline exceeded |
| 413 | Selected uncompressed-scan preflight, physical read-byte/listing bound, or serialized output limit exceeded |
| 429 | Query concurrency or physical filesystem I/O operation capacity is full |
| 503 | Query/storage unavailable or cancelled during shutdown |

Error bodies use `schema_version` and a static `error.code`/`error.message`;
caller-supplied filter data is not reflected in diagnostics.

## Configuration and resource bounds

All settings are validated before the server reports ready. Defaults shown are
the current server defaults.

| Variable | Default | Meaning |
| --- | ---: | --- |
| `SIGNAL_QUERY_MEMORY_BYTES` | `268435456` | Shared DataFusion operator memory-pool reservation capacity (256 MiB) |
| `SIGNAL_QUERY_CONCURRENCY` | `4` | Maximum active queries; excess requests are rejected immediately |
| `SIGNAL_QUERY_FILES` | `1024` | Maximum Parquet files selected for one query |
| `SIGNAL_QUERY_LIMIT` | `1000` | Maximum returned event count; API default limit remains 100 |
| `SIGNAL_QUERY_RESPONSE_BYTES` | `8388608` | Maximum serialized response size (8 MiB) |
| `SIGNAL_QUERY_BATCH_ROWS` | `128` | DataFusion execution batch row target |
| `SIGNAL_QUERY_PARTITIONS` | `1` | DataFusion target execution partitions |
| `SIGNAL_QUERY_TIMEOUT_MS` | `10000` | Query engine deadline; effective HTTP deadline is the smaller of this and `SIGNAL_REQUEST_TIMEOUT_MS` (default 5000 ms) |

The parser caps the raw URL query at 16 KiB, attribute filters at 32, each
filter value at 4 KiB, attribute paths at 512 bytes and 16 components, and
attribute JSON values at depth 32 and 4096 nodes. The response-byte ceiling
includes the versioned response envelope and serialized events. The tracked
DataFusion memory-pool value accounts for operator reservations; it is not a
process RSS ceiling. Before DataFusion decodes selected files, the query sums
validated footer uncompressed-column byte counts and rejects a scan above the
configured query memory budget. This conservative preflight is separate from
operator-pool reservations and does not establish a process RSS ceiling.
Response bytes, selected files, scan preflight bytes, active query count,
operator memory reservations and physical read-byte leases are separate bounds.
DataFusion spill is disabled.

Filesystem reads run through the storage worker's bounded, deadline-aware path.
Filesystem access runs on a fixed set of ordinary threads. The I/O slot and
bounded reply remain owned until physical work completes, even after a query
stops waiting. Returned `Bytes` clones/slices retain a shared read-byte lease.
The physical job queue, worker count and waiters have explicit bounds derived
from query concurrency and execution partitions, with a hard cap of sixteen
physical I/O slots and a fixed thread count cap. This avoids accumulating
detached reads or blocking Tokio runtime shutdown. A stuck kernel operation may
outlive the shared shutdown wait on its fixed worker.

## Metrics

`GET /metrics` exposes these query and physical-I/O series:

```text
signal_query_depth
signal_query_capacity
signal_query_requests_total
signal_query_completed_total
signal_query_failures_total
signal_query_rejections_total
signal_query_timeouts_total
signal_query_cancelled_total
signal_query_scanned_files_total
signal_query_selected_partitions_total
signal_query_latency_microseconds_total
signal_query_memory_bytes
signal_query_memory_capacity
signal_query_io_depth
signal_query_io_capacity
signal_query_io_rejections_total
signal_query_io_bytes
signal_query_io_byte_capacity
signal_query_io_waiters
signal_query_io_waiter_capacity
signal_query_io_queue_depth
signal_query_io_queue_capacity
signal_query_io_running
signal_query_io_worker_capacity
```

Counters are process-local. Latency is accumulated query execution time;
`signal_query_memory_bytes` is the shared DataFusion pool's current reserved
operator memory, not RSS. Query metrics establish activity and configured bounds,
not throughput or memory qualification.

## Qualification status

The full workspace gates passed: 127 tests across eight crates/targets and the
12-package dependency/source-boundary check. The earlier 80-test Phases 0–3
record is a historical baseline, not the Phase 4 result. The real-process gate
ingests four canonical events and verifies authentication, filters, ordering,
limit, a 413 resource response, SIGKILL/restart and repeat query results from
persisted Parquet. After that full run, wrapped physical-I/O operation-capacity
errors were corrected to return 429; byte/listing resource errors remain 413.
The post-fix query crate passed 29 tests (15 unit, 14 integration) and targeted
Clippy with warnings denied. No post-fix aggregate test count is claimed while
Phase 5 source work is in flight. An independent Sol high review covered 14
areas and found no new blocker, high, medium or low issues. The inherited
synchronous-stderr medium remains deferred to Phase 5 task 05-D. No query
throughput, process RSS ceiling, ARM64, container, power-loss or production claim
is made. See [phase evidence](07-progress.md).
