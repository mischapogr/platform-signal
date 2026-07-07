# HTTP ingest: Phase 1 contract

Start the development server from the repository root:

```bash
cargo run -p signal-server
```

In another terminal:

```bash
curl -i http://127.0.0.1:8080/readyz
curl -i http://127.0.0.1:8080/v1/events \
  -H 'content-type: application/json' \
  -d '{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"application","name":"example-api"},"message":"hello","attributes":{"user":{"name":"alice"}}}'
curl -i http://127.0.0.1:8080/v1/events/batch \
  -H 'content-type: application/json' \
  -d '{"events":[{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"application"},"message":"first"},{"timestamp":"2026-10-06T12:00:01Z","source":{"type":"application"},"attributes":{"status":200}}]}'
curl http://127.0.0.1:8080/metrics
```

The current server uses **durable WAL admission**, bounded by pending count,
encoded JSON bytes and WAL file contents. HTTP 202 requires a synced append. There
is no automatic consumer or query endpoint yet, so a full queue returns 429 and
restart retains its backlog. SIGTERM retains unacknowledged records. See
[Phase 2 WAL configuration and recovery](10-phase2-wal.md). The Phase 1 volatile
`MemorySink` remains available for ingest tests and embedding fixtures only.

## Contract and counts

See [ADR-003](adr/003-event-contract.md) for the schema and input defaults.
The input timestamp/source are required. Missing UUID, observed time, severity,
schema version, attributes and tags are normalized. Nested attributes and large
JSON numbers roundtrip; unknown envelope fields are rejected rather than discarded.

Success and failure both return `schema_version`, `accepted`, `rejected`,
`event_ids`, and an optional structured `error` with `code`, `message`, `index`.
Accepted IDs identify the admitted prefix in input order. Batch validation is
atomic: one invalid item rejects the entire batch before admission. Admission
itself is sequential; capacity/deadline/shutdown can interrupt it after a prefix.

| HTTP | Meaning |
| --- | --- |
| 202 | Every reported accepted event synced to WAL |
| 400 | Invalid JSON/event/schema or empty batch; no admission |
| 401 | Missing/wrong/duplicate Bearer credentials; no body decoding |
| 408 | Request deadline exceeded; inspect counts for a committed prefix |
| 413 | Body or batch limit exceeded; no admission |
| 415 | JSON content type required |
| 429 | Queue or in-flight request capacity full; inspect counts |
| 503 | Stopped/unavailable sink; inspect counts |

If the body cannot be decoded/counts cannot be determined, `rejected` is 0 and the
rejected-request counter accounts for the failure. A decoded invalid single event
counts as 1 rejection. Queue attempts, event rejections, request failures and
transport errors are separate counters; do not add them together as event totals.
After partial admission retry only the remaining items. A broken connection can
leave admission uncertain; this is not an exactly-once interface.

The accepted prefix in a received response is confirmed durable. With the
default `reject_new` policy, a received 429 confirms that the remaining suffix
was rejected by capacity admission. With `block_with_timeout`, a WAL admission
timeout can also return 429 while its one in-flight append can still finish;
that first suffix event is uncertain, as on 408 or 503.
On 408 or 503, cancellation or an unavailable sink can race the one in-flight
WAL append: at most one event immediately after the confirmed prefix can become
durable even though it is included in the response's `rejected` count. Later
suffix events were not attempted. If no response is received, the entire batch
can be uncertain, including an already admitted prefix. Retain IDs on retries
and tolerate duplicates. HTTP accepted/rejected counters describe response
accounting; WAL admission and persistence counters describe durable outcomes.

## Configuration

Environment variables configure this phase; YAML loading belongs to the integrated
server in Phase 5. An embedding application may pass validated `IngestConfig` and
`ServerLimits`. Configuration is checked before binding/reporting readiness.
`signal-server --help` and `--version` do not start a listener.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SIGNAL_LISTEN` | `127.0.0.1:8080` | IP socket address; use `0.0.0.0:8080` in a container |
| `SIGNAL_API_TOKEN` | unset | Optional Bearer token; empty/invalid tokens fail startup |
| `SIGNAL_MAX_REQUEST_BYTES` | 1048576 | Maximum decoded HTTP body bytes, including streamed bodies |
| `SIGNAL_MAX_BATCH_EVENTS` | 1000 | Maximum events per batch |
| `SIGNAL_MAX_IN_FLIGHT` | 64 | Concurrent ingest requests; no waiting request queue |
| `SIGNAL_MEMORY_EVENTS` | 10000 | Retained unacknowledged event count |
| `SIGNAL_MEMORY_BYTES` | 67108864 | Retained unacknowledged canonical JSON bytes |
| `SIGNAL_REQUEST_TIMEOUT_MS` | 5000 | Body/validation/admission deadline and header-read deadline |
| `SIGNAL_MAX_CONNECTIONS` | 128 | Maximum live TCP connection tasks |
| `SIGNAL_CONNECTION_TIMEOUT_MS` | 60000 | Total connection lifetime, including idle/read/write time |
| `SIGNAL_SHUTDOWN_TIMEOUT_MS` | 10000 | Graceful connection drain deadline |

Limits must be positive. Timeouts must not exceed one hour. The byte budget bounds
encoded retained payloads, not exact RSS: JSON objects/strings/allocator overhead,
bounded in-flight bodies and transport buffers also use memory. JSON recursion
remains limited by Serde JSON. Memory profiling is a later release gate.

Supply a token through the process environment or embedding configuration, never
through CLI arguments or tracked files. In requests use `Authorization: Bearer`
followed by the token. Scheme matching is case-insensitive; token comparison uses
the `subtle` constant-time comparison implementation. Health/readiness/metrics do
not require the ingest token. Logs contain status/counts and server state, never
headers, token values, event bodies or parser diagnostics.

SIGINT/SIGTERM stops admission first, cancels outstanding body/admission waits,
stops accepting sockets, drains connections within the shutdown deadline, then
waits for the WAL worker. Unacknowledged events remain durable and replayable.
`/readyz` now includes WAL availability/recovery; rule/storage checks arrive with
those implementations. `/healthz` remains live while the router is reachable.

## Verification

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-workspace.py
```

The real TCP gate sends 100 batches of 100 events into a sink with count capacity
5037 and 64 MiB byte capacity. It requires **5037 accepted, 4963 rejected** and
5037 unique accepted IDs, including an interrupted batch. This is deterministic
admission proof, not a throughput benchmark or durability test. The real process
gate now verifies authenticated durable HTTP, SIGKILL replay, SIGTERM retention,
quotas, exclusive WAL ownership, redaction and startup validation.

Primary transport references: [Axum](https://docs.rs/axum/0.8.9/axum/),
[Tokio timeouts](https://docs.rs/tokio/latest/tokio/time/fn.timeout.html),
[Hyper HTTP/1 transport](https://docs.rs/hyper/latest/hyper/server/conn/http1/struct.Builder.html).
