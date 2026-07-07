# Phase 7 — Collector, Enricher, and Provider SDK

`signal-collector-sdk` defines generic in-process extension hooks and provider
loading contracts for the OSS core. It provides bounded invocation and output
validation; it does not create a queue, chain extensions, spawn workers, or
wire private providers into `signal-agent` or `signal-server`. Applications
own provider setup and invoke enrichment before ingest; the normal server
consumes configured external rule directories. Local Phase 7-B gate evidence
is recorded in [implementation progress](07-progress.md).

## External provider contracts

`OverlayPath::new`, `OverlayPath::from_env`, and `OverlayPath::resolve` select
the overlay directory explicitly or from `SIGNAL_OVERLAY_PATH`. An explicit
path has priority. There is no implicit path and selecting a path does not read
its contents.

`EnrichmentProvider::load` returns an `Arc<dyn Enricher>`. Providers own their
metadata schema and reads and must validate before returning. Use
`load_enricher` to apply the extension context's deadline and cancellation; it
does not spawn tasks. The application invokes the enricher before normal
server ingest.

`RuleProvider::load` returns `RuleDocument` values: a strict versioned envelope
with `schema_version` and YAML text. Version 1 preserves the consumer's
existing rule language. `load_rules` checks version and bounded output, with
defaults of 64 documents, 64 KiB per document and 1 MiB total. Configurable
ceilings are 1,024 documents, 2 MiB per document and 16 MiB total. The SDK does
not interpret rule predicates. The consuming rule engine parses YAML and
validates predicates and duplicate IDs before readiness.

Providers are trusted, cooperative code. Context checks do not bound
allocations performed inside a provider; providers must bound reads, yield,
and honor cancellation. The server has no compiled private extension or
dynamic loader. Private schemas, rule documents and fixtures belong in the
external application.

## API

Implementations use the re-exported `#[signal_collector_sdk::extension]` macro
to implement async traits. A collector emits canonical events through the
existing `EventSink` admission seam. An enricher receives a mutable canonical
event. Both receive an `ExtensionContext` with a cancellation token and absolute
deadline.

```rust
use signal_collector_sdk::{
    Collector, Enricher, ExtensionContext, ExtensionError, extension,
};
use signal_event::SignalEvent;
use signal_protocol::EventSink;
use std::sync::Arc;

#[extension]
impl Collector for MyCollector {
    async fn run(
        &self,
        sink: Arc<dyn EventSink>,
        context: ExtensionContext,
    ) -> Result<(), ExtensionError> {
        context.check()?;
        // Construct and validate an event, then admit it through `sink`.
        Ok(())
    }
}

#[extension]
impl Enricher for MyEnricher {
    async fn enrich(
        &self,
        event: &mut SignalEvent,
        context: ExtensionContext,
    ) -> Result<(), ExtensionError> {
        context.check()?;
        // Annotate allowed fields; identity and timestamps are immutable.
        Ok(())
    }
}
```

Use `run_collector` and `apply_enricher` as the invocation helpers. They check
cancellation/deadline and drop the extension future on cancellation or timeout;
they spawn no worker tasks. `ExtensionContext::new` rejects a zero timeout or a
timeout greater than 24 hours. Extensions should check the context before
synchronous work and pass the remaining budget to their I/O.

## Bounds and event behavior

`EventLimits::default()` permits serialized event JSON up to 64 KiB, attribute
depth 32, and 16,384 attribute nodes. Each limit must be positive; configured
maximums are 2 MiB serialized event bytes, depth 64, and 65,536 nodes. Limits
apply before enrichment and after enrichment. They are runtime controls, not
serialized fields in the event contract.

`apply_enricher` validates the input before cloning it, invokes the enricher on a
staged copy, validates the result, checks identity, and replaces the caller's
event only after all checks succeed. Any returned error, cancellation, timeout,
invalid output, or identity change leaves the caller's event unchanged. The
enricher may update source, severity, message, attributes, resource, trace/span
IDs, and tags subject to normal event validation. It must preserve schema
version, event ID, `timestamp`, and `observed_at`.

`validate_event` is public so external providers and fixture consumers can
apply the SDK's bounded canonical event validation without invoking or cloning
an event.

Nested JSON attributes, dotted keys, and precise JSON numbers are preserved by
the event contract and the SDK helpers unless an extension deliberately edits
them. The SDK adds no private attribute namespace or company policy.

`ExtensionError` uses static error classes and does not carry extension data or
credentials. Extension implementations should map their private diagnostics to
`Failed` rather than exposing them through returned errors.

## Trust and cancellation boundary

Extensions are trusted, cooperative in-process code, not sandboxed plugins.
The helpers add no queue and cannot bound allocations made internally by an
extension, forcibly stop synchronous blocking work, or prevent a detached task
or external side effect. Extensions must bound their own input buffers and
allocations, yield during asynchronous work, apply the context budget to I/O,
and ensure cancellation stops their own work. A collector may have admitted an
event before its future is cancelled; admission status can then be uncertain,
and duplicate tolerance follows the supplied sink's delivery contract.

The generic consumer tests cover public API compatibility and canonical event
identity. The separate external gate covers application-owned provider loading,
private enrichment/rules, and the normal server persistence path; see
[implementation progress](07-progress.md) for its recorded result.

## Phase 7 status

Phase 7-A is complete locally. The root workspace passed 212 tests with no
failures, build/format/Clippy gates, and the 12-package boundary check. The
SDK source and final 14-area review approved the implementation with no
unresolved blocker, high, medium, or low findings. Phase 7-B is also complete
locally: the workspace passed 217 tests, the external private package passed
two tests and its build/format/Clippy gates, the normal-server process gate
passed, and final independent review found no unresolved findings. Details are
in [implementation progress](07-progress.md).
This establishes local Linux AMD64 behavior only; ARM64, process RSS, an agent
container build, released crate versions, and production qualification are not
established. Local Phase 7 completion does not complete the full release gate.
The Phase 7-B path-dependency gate is distinct from released crate and
deployment qualification. The root workspace gate also corrected a
deterministic WAL `BlockWithTimeout` near-deadline failure; full gate details
are in [implementation progress](07-progress.md). See the
[model work plan](11-model-work-plan.md), and [ADR-013](adr/013-extension-sdk.md).
