# ADR-011: Stateless rules and durable findings

**Status:** Implemented and locally verified under the supplied Phase 5
specification.

**Phase:** 5

## Context

The event pipeline needs deterministic, replay-safe rule evaluation and durable
findings. A replay must not create duplicate findings or advance the WAL past
work that was not persisted. Rule configuration and finding storage also need
bounded resource use and startup validation.

## Decision

- Rules are stateless YAML predicates using the versioned `signal.dev/v1` Rule
  document. Predicates support `eq`, `neq`, string `contains`, and boolean
  `exists`; `all` and `any` groups may be combined, in which case both groups
  must match.
- Finding IDs are deterministic UUIDv5 values derived from a fixed finding
  namespace, the length-prefixed rule ID, and event UUID. Findings reference
  event IDs and do not duplicate event payloads.
- A finding's creation time is the source event's `observed_at` timestamp.
- A single WAL consumer persists Parquet, evaluates rules, persists findings,
  then acknowledges the WAL sequence. Findings are synced before the WAL
  checkpoint advances. Replay is at least once and finding appends are
  idempotent for identical content; ID/content conflicts fail closed.
- The finding journal is bound to the WAL stream UUID. Its atomically published
  24-byte magic/stream-ID header is not checksummed; each record frame has a
  header CRC and payload CRC. An incomplete final frame may be truncated;
  interior corruption fails startup. Finding disk, index, append and response
  bounds are configured independently.
- Rule loading and findings queries have explicit limits and deadlines.
  Configuration and rules validate before readiness. Shutdown uses a shared
  deadline for pipeline drain and store/logger flush.

## Consequences

The WAL checkpoint represents completion of both event and finding persistence.
Rule evaluation does not require a second consumer or a second checkpoint.
Finding identity remains stable across restart and batch boundaries. Retention
and archival policy remain outside the OSS mechanism and must be selected by an
integrating deployment.

Integer rule values are represented as exact signed/unsigned 64-bit integers;
integer values outside those ranges fail validation. Fractional values pass
through the YAML parser's floating-point representation and have no
arbitrary-precision guarantee. This does not limit arbitrary JSON numeric event
attributes outside rule documents.

## Verification

Local Phase 5 verification includes rule and finding crate tests, workspace
gates, a real server process/restart gate, and an independent 14-area review.
The final workspace gates passed 166 tests with formatting, workspace Clippy
warnings denied and the 12-package boundary check. The post-correction process
gate and Compose harness also passed. See [Phase 5 progress](../07-progress.md)
for exact scope and platform limits.
