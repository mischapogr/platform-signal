# ADR-013: Generic collector and enrichment extension hooks

**Status:** Phase 7 locally accepted as mechanism and source-path proof on Linux
AMD64. Root and private package gates, external process gate and independent
review passed. Released dependency and deployment qualification remain open.

**Phase:** 7-A

## Context

The OSS core needs generic extension points that preserve the canonical event
contract and reuse bounded admission. They must not introduce company policy,
unbounded queues, implicit application wiring, or an unsupported promise that
arbitrary in-process code is sandboxed.

## Decision

- `signal-collector-sdk` exposes async `Collector::run` and
  `Enricher::enrich` traits through a re-exported `extension` macro. A collector
  receives `Arc<dyn EventSink>` and `ExtensionContext`; an enricher receives a
  mutable `SignalEvent` and context.
- `ExtensionContext` carries cancellation and an absolute deadline. Its timeout
  must be positive and no more than 24 hours. `run_collector` and
  `apply_enricher` check the context and drop the invoked future on cancellation
  or deadline; the helpers spawn no workers and add no queue.
- `EventLimits` defaults to 64 KiB serialized event bytes, attribute depth 32,
  and 16,384 nodes. Positive configured ceilings are 2 MiB, depth 64, and
  65,536 nodes. Validation applies before and after enrichment.
- `apply_enricher` stages a clone and commits it to the caller only after the
  enrichment future, output validation, context checks, and identity checks
  succeed. Schema version, event ID, event timestamp, and observed timestamp
  are immutable. Other canonical metadata is mutable subject to event
  validation.
- Arbitrary nested attributes, dotted keys, and precise JSON numbers follow
  the canonical event model. The SDK defines no private namespace or company
  policy. Static error variants avoid exposing extension diagnostics or
  credentials.
- Extensions are trusted, cooperative in-process code. They must bound their
  own allocations and I/O and stop their own work on cancellation. Helpers
  cannot forcibly cancel synchronous blocking operations, detached tasks, or
  external side effects. Collector admission may be uncertain at cancellation.
- `OverlayPath` selects an external path explicitly or via
  `SIGNAL_OVERLAY_PATH`; explicit selection wins, and there is no default.
  Selection does not read data. The application owns provider construction and
  invokes enrichment before ingest.
- `EnrichmentProvider::load` returns a validated enricher. `load_enricher`
  applies the cooperative context deadline without spawning worker tasks.
  Provider implementations own and validate their metadata schemas and bound
  their own reads and allocations.
- `RuleProvider::load` returns strict versioned `RuleDocument` envelopes.
  Version 1 carries the existing consumer YAML format. `load_rules` enforces
  finite document count and byte bounds; default limits are 64 documents,
  64 KiB per document and 1 MiB total, with ceilings of 1,024 documents, 2 MiB
  per document and 16 MiB total. The consumer validates YAML predicates and
  duplicate IDs before readiness.
- The SDK and server do not contain a compiled private extension or dynamic
  loader. The application owns provider invocation; the normal server consumes
  configured external rule directories. Private policy, schemas and fixtures
  remain in the external repository.
- The external local gate uses a separate private runner and the normal OSS
  server to verify enrichment, rule findings, persisted event/finding queries,
  forced restart recovery and graceful shutdown. Local workspace path
  dependencies do not qualify released crate versions, containers, Helm or
  deployment.

## Consequences

The event sink remains the admission boundary for collectors. Enrichment is
transactional with respect to the caller's in-memory event value, but arbitrary
external effects cannot be rolled back. An extension that ignores cancellation
or creates detached work can outlive the helper's invocation; the API does not
claim to isolate such behavior. Integrating applications must choose which
extensions to run and provide external policy and wiring. Providers are trusted
cooperative code, not sandboxed plugins; cancellation cannot undo external
side effects or stop synchronous blocking work.

## Verification

Six Phase 7-A crate-scoped integration tests, the root workspace build/format/
Clippy/test gates, the 12-package boundary check, and SDK source review passed
on Linux AMD64. The workspace passed 212 tests with no failures. The final
14-area review approved the implementation with no unresolved blocker, high,
medium, or low findings. During this gate, a deterministic existing WAL
`BlockWithTimeout` near-deadline failure was
fixed and covered by three new regression tests. The subsequent Phase 7-B root
workspace passed 217 tests; the separate private package passed two tests and
build/format/Clippy; the normal-server external process gate passed; and final
independent review found no unresolved findings. This local acceptance does
not qualify ARM64, process RSS, an agent container, released dependencies, or
production. Local path dependency proof does not complete the full release
gate. See the [SDK contract](../16-collector-sdk.md)
and [implementation progress](../07-progress.md).
