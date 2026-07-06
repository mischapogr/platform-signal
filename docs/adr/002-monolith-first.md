# ADR-002: Monolith first

Status: Established by the supplied architecture specification.

## Context and decision

Deployment complexity would delay the useful ingest-to-finding slice. Run ingest,
WAL, storage, query, rules and findings inside `signal-server`. Keep crate ownership
clear; split processes only when measured scaling needs justify it.

`signal-event` is the base. `signal-protocol` owns the future `EventSink` and
transport contracts so buffer and ingest do not depend on one another. Storage
owns `EventStore`; query consumes it. Shared query filters belong in protocol so
storage does not depend on query. SDK depends on event/protocol, allowing external
collectors and enrichers without importing the server. Apps compose the libraries.

## Consequences and verification

`scripts/check-workspace.py` checks the dependency direction with Cargo metadata.
The Phase 5 process integration gate proves the composed pipeline and restart.
