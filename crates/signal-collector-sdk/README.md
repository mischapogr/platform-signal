# Collector and enrichment hooks

This SDK provides generic `Collector` and `Enricher` traits. Implementations use
`#[signal_collector_sdk::extension]` (the re-exported `async_trait` macro) and may
be stored as `Box<dyn Collector>` or `Box<dyn Enricher>`. Collectors receive an
`Arc<dyn signal_protocol::EventSink>`; successful admission transfers ownership
according to that sink's documented durability boundary. The SDK adds no queue.

Use `run_collector` and `apply_enricher` to invoke extensions with a validated
`ExtensionContext`, containing a cancellation token and an absolute deadline.
Timeouts must be positive and at most 24 hours. Helpers drop unfinished futures
on timeout or cancellation and spawn no workers. Extensions must yield, bound
all input and buffers, apply remaining deadlines to network/disk operations,
and ensure future cancellation stops their work. Synchronous blocking or tasks
spawned inside an extension cannot be forcibly cancelled by these helpers.
Admission cancelled after a sink's commit may be uncertain; duplicate-tolerant
replay remains the sink's responsibility.

`apply_enricher` validates the canonical event before cloning it, enriches a
staged copy, validates the result, and commits only on success. Failures,
cancellation and timeout preserve the caller's event. Schema version, event ID,
event timestamp and observed timestamp are immutable. Other fields can be
annotated subject to canonical semantic validation. No attribute namespace or
company metadata is built into the SDK. Arbitrary nested JSON and precise JSON
numbers remain unchanged unless the extension edits them.

`EventLimits` defaults to 64 KiB serialized JSON, attribute depth 32 and 16,384
attribute nodes. Positive configurable ceilings are 2 MiB, depth 64 and 65,536
nodes. Borrowed string, key and numeric digit lengths are charged before serialization,
with a minimum charge per attribute node and tag. Iterative attribute traversal
checks cancellation and deadlines and precedes capped serialization and cloning.
Programmatic timestamps must use wire years 0000 through 9999. Limits and context
are runtime options, not serialized contracts; `SignalEvent` remains the
versioned serialization contract.

Extensions are trusted in-process code. Their own allocations and external side
effects cannot be rolled back; limits bound accepted input/output and SDK work.
Extension errors contain static classifications rather than plugin diagnostics
or credentials. Implementers should return `Failed` for private error details.

`OverlayPath::resolve(Some(path))` selects an explicit external directory;
`resolve(None)` reads `SIGNAL_OVERLAY_PATH`. Missing or empty paths return
`MissingOverlayPath`. Selection does not access the filesystem, and there is no
compiled default. Providers own that path and implement their own bounded,
cancellable reads. Private configuration and policy remain in the external repo.

`EnrichmentProvider::load(context)` returns `Arc<dyn Enricher>` after validating
the provider's metadata schema. `RuleProvider::load(context)` returns
`Vec<RuleDocument>`, each with `schema_version: 1` and a nonempty `yaml` string.
Both traits are object safe. Invoke them using `load_enricher` and `load_rules`
to enforce deadlines and cancellation without worker tasks. Returned rules are
transport documents: the consumer must compile their YAML using its rule engine,
including predicate and duplicate-ID validation, before readiness or processing.
The SDK does not depend on the rule engine or accept private policy itself.

`RuleDocumentLimits` defaults to 64 documents, 64 KiB per document and 1 MiB total
YAML bytes. Positive configurable ceilings are 1,024 documents, 2 MiB per
document and 16 MiB total. An empty document list is allowed. Helpers enforce
these bounds on returned output; trusted providers must bound their own reads
and allocations before returning. `RuleDocument` serialization rejects unknown
envelope fields, and the loader rejects unsupported schema versions.

Use `validate_event(&fixture, limits, &context)` to validate canonical fixtures
or collected events without mutation or cloning. It uses the same bounded
canonical validation as enrichment; `apply_enricher` adds transactional mutation
and immutable identity checks.

The public integration tests establish local compatibility of generic hooks.
They do not provide proof of an external overlay integration, private detection,
released dependency, or deployment.
