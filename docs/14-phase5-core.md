# Phase 5: rules, findings and server integration

Phase 5 adds stateless event rules, durable findings and coordinated server
processing. Implementation, local gates and the Compose demonstration passed on
Linux AMD64. These results do not establish a v0.1.0 release, ARM64, remote CI
or production readiness.

## Event processing and durability

HTTP `202` acknowledges only a synced WAL append. The single pipeline consumer
persists the event to Parquet, evaluates configured rules, appends any findings
durably, and only then advances the WAL checkpoint. A failure stops admission
and leaves unacknowledged records available for restart replay. Finding writes
are idempotent for the same finding identity and content; a matching identity
with different content fails closed. The event and findings stores bind to the
same WAL stream UUID. Shutdown uses one shared deadline for draining and
flushing.

Findings are deterministic per rule/event pair. Their `created_at` is the
event's `observed_at`; the finding stores rule metadata and an event ID
reference, not a copy of the event payload. No rule directories means an empty
rule set.

## Rule documents

Rules are YAML documents with `apiVersion: signal.dev/v1`, `kind: Rule`,
`metadata.id`, `metadata.name`, and `spec.severity` (`low`, `medium`, `high`, or
`critical`). `spec.match` contains a nonempty `all` and/or `any` list. If both
are present, both groups must match. Predicates use exactly one of `eq`, `neq`,
`contains` (string values), or `exists` (boolean value). Field paths address
the event envelope or attributes; exact dotted attribute keys take precedence
over nested traversal. Duplicate rule IDs and invalid documents fail startup,
leaving readiness false.

Rule loading and evaluation are bounded. Integer rule values are represented as
exact signed or unsigned 64-bit integers; integers outside those ranges fail
validation. The YAML parser converts fractional numeric values through its
floating-point representation, so fractional rule values do not have an
arbitrary-precision guarantee. Event attributes retain the event contract's
arbitrary-precision JSON values.

## Findings API

`GET /v1/findings` uses the same optional Bearer token as ingestion and event
queries. Filters are URL parameters only; unknown, duplicate, malformed or
over-complex parameters fail closed.

| Parameter | Meaning |
| --- | --- |
| `from`, `to` | RFC3339 creation-time bounds in UTC, half-open `[from,to)` |
| `severity` | Exact finding severity: `low`, `medium`, `high`, `critical` |
| `rule_id` | Exact rule ID, at most 256 bytes |
| `limit` | Result limit; API default is `min(100, configured maximum)` |

Results are ordered ascending by `(created_at, id)`. The success body contains
`schema_version: 1` and `findings`. Static errors use 400 for invalid filters,
401 for missing/invalid configured authentication, 408 for deadline expiry,
413 for request/response or finding resource limits, 429 for saturated query
or physical I/O capacity, and 503 for unavailable storage or shutdown.

## Configuration and defaults

The server accepts schema-versioned YAML via `--config PATH` or
`SIGNAL_CONFIG`; environment variables override YAML. The strict configuration
document is limited to 64 KiB. Unknown/duplicate keys and invalid types fail
startup. The API token is optional; configured secrets are never included in
diagnostics. See [Phase 3 storage](12-phase3-storage.md) and
[Phase 4 queries](13-phase4-query.md) for their configuration tables.

### Rules

`SIGNAL_RULE_DIRS` supplies a platform-separated list of rule directories and
overrides `rules.directories` in YAML. Defaults below are read from
`signal-server`:

| Variable | Default |
| --- | ---: |
| `SIGNAL_RULES_MAX_RULES` | 256 |
| `SIGNAL_RULES_MAX_DIRECTORY_ENTRIES` | 4096 |
| `SIGNAL_RULES_MAX_DOCUMENT_BYTES` | 65536 |
| `SIGNAL_RULES_MAX_TOTAL_BYTES` | 4194304 |
| `SIGNAL_RULES_MAX_PREDICATES` | 128 |
| `SIGNAL_RULES_MAX_VALUE_NODES` | 4096 |
| `SIGNAL_RULES_MAX_DEPTH` | 32 |
| `SIGNAL_RULES_MAX_FIELD_BYTES` | 512 |
| `SIGNAL_RULES_MAX_TITLE_BYTES` | 4096 |
| `SIGNAL_RULES_TIMEOUT_MS` | 5000 |

### Findings store

| Variable | Default |
| --- | ---: |
| `SIGNAL_FINDINGS_DIR` | `data/findings` |
| `SIGNAL_FINDINGS_BYTES` | 268435456 |
| `SIGNAL_FINDINGS_MAX_FINDINGS` | 100000 |
| `SIGNAL_FINDINGS_RECORD_BYTES` | 65536 |
| `SIGNAL_FINDINGS_BATCH_EVENTS` | 1000 |
| `SIGNAL_FINDINGS_BATCH_BYTES` | 1048576 |
| `SIGNAL_FINDINGS_QUERY_LIMIT` | 1000 |
| `SIGNAL_FINDINGS_QUERY_BYTES` | 8388608 |
| `SIGNAL_FINDINGS_INDEX_BYTES` | 16777216 |
| `SIGNAL_FINDINGS_COMMANDS` | 8 |
| `SIGNAL_FINDINGS_TIMEOUT_MS` | 5000 |

The query memory accounting is a conservative bounded estimate, not an RSS
ceiling. Finding storage, index memory and serialized response limits are
separate. The response limit includes its versioned envelope.

### Bounded logging

The server writes structured JSON records through a bounded queue and one
dedicated stderr worker. Queue records, queued bytes and individual record size
are limited independently. Saturation, oversize records, closed queues and
write failures are observable through logger metrics; event data and secrets
are not reflected in error messages.

| Variable | Default |
| --- | ---: |
| `SIGNAL_LOG_RECORDS` | 1024 |
| `SIGNAL_LOG_BYTES` | 1048576 |
| `SIGNAL_LOG_RECORD_BYTES` | 8192 |

## Verification and qualification

After the final rule-limit correction, the workspace gates passed: format,
Clippy with warnings denied, 166 workspace tests, and the 12-package boundary
check. The real process gate passed in 3.58 seconds. The fresh Linux AMD64
production image build and Compose harness passed as well. Exact test counts,
Compose coverage and remaining platform boundaries are in
[Phase 5 progress](07-progress.md).

The process gate exercised five canonical events and four findings, query and
finding filters/authentication, configured rules, invalid-rule startup,
environment/YAML/CLI configuration, secret redaction, SIGKILL replay and
SIGTERM drain, and fail-closed behavior when the finding quota is reached. It
verified that events are not acknowledged before findings persist. A separate
metrics listener served metrics/readiness while returning 404 for the events
route. Compose runtime qualification and the final workspace gate passed locally.

The findings journal begins with a 24-byte header containing the `SIGFND02`
magic and WAL stream UUID; the header is atomically published but is not
checksummed. Each record has a 12-byte frame header with a header CRC and a
payload CRC. Only an incomplete final frame is recoverable by truncation;
interior corruption fails closed. Findings use temporary-file publication for
atomic creation. The findings disk quota counts regular-file lengths, not
allocated filesystem blocks or directory entries. These mechanisms have local
tests; they do not establish power-loss or network-filesystem behavior.

Next: Phase 6 agent collection. Full release qualification remains outstanding.
See [progress](07-progress.md) and the
[implementation plan](04-implementation-plan.md).
