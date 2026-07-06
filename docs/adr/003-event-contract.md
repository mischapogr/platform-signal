# ADR-003: Version 1 event and ingest contracts

Status: Implemented for Phase 1 under the supplied specification.

## Decision

`IngestEvent` is a permissive input contract for omitted optional/default fields;
`SignalEvent` is the fully normalized persisted contract. Both reject unknown
envelope/source/resource fields rather than silently discarding them. Arbitrary
nested JSON keys belong in `attributes`, including externally owned namespaces.
The crate is independent of HTTP and Tokio.

Schema version is a `u16`, currently 1. Input defaults it to 1; unsupported versions
are rejected. Missing IDs become UUID v4 values and existing UUIDs are preserved.
Timestamp is required RFC3339; offsets normalize to UTC. Observed time defaults to
the normalization time. Severity defaults to `info` and uses the lowercase values
`trace/debug/info/warn/error/critical`. A nonblank message or nonempty attribute map
is required. Source type must be nonblank. Optional source name, resource kind/ID,
account/region and tags must be nonblank if supplied. A resource requires kind/ID.
Trace/span IDs, when supplied, are nonzero hexadecimal strings of 32/16 characters;
span requires trace. Validation never echoes attribute/message/token values.

Canonical serialization retains UUID, timestamps, all nested attributes, severity,
tags and schema version. Optional absent fields are omitted. Deserialization alone
does not validate semantic constraints; callers must use `validate` before storing
or processing a canonical event. Ingest normalization always validates.

## HTTP admission contract

`/v1` is the HTTP version; JSON responses additionally carry `schema_version: 1`.
POST single accepts an event. POST batch accepts `{ "events": [...] }` (optionally
with `schema_version: 1`). Validate every item before side effects; invalid batches
reject every item with the first invalid index. Empty batches are invalid.

Success is HTTP 202 with accepted/rejected counts and accepted `event_ids` in input
order. Saturation is HTTP 429; timeout is HTTP 408; stopping/unavailable is HTTP 503.
Those failures may carry an accepted prefix; rejected is the remaining count.
Retry only that remainder when its identity is known. Transport failure/cancellation
can leave the caller uncertain whether admission happened, as with any future
at-least-once transport. Sinks must document their cancellation commit boundary.
Invalid JSON is HTTP 400, oversized body/batch is HTTP 413, missing/wrong token is
HTTP 401. All errors use the same JSON envelope and stable error codes. If parsing
cannot determine an event count, rejected is 0 and the rejected-request counter
records the failure. Parser diagnostics and request headers/bodies are never logged.

`EventSink` lives in protocol and exposes admission, bounded-state metrics and stop
admission. Phase 1 uses a count/encoded-byte bounded volatile sink. HTTP 202 here
is explicitly **not a durability acknowledgment**. No consumer silently discards
events; the server fills and then rejects until restart. Shutdown reports the
volatile events lost. Phase 2 replaces this with durable admission before HTTP 202; this is now
implemented in [ADR-006](006-wal-durability.md). The volatile sink remains an ingest
test fixture. The statements above describe historical Phase 1 behavior.

## Verification

Event serialization/default/validation tests; real router and TCP tests for limits,
auth, batch atomic validation, partial overload, timeouts/cancellation, stop admission,
bounded queue metrics and 10,000-event accounting. No restart durability is claimed.
