# Architecture decisions

Record status, context, decision, consequences and verification for each ADR.
Use `Proposed` for details that still need design review; do not mark an owner
decision accepted on their behalf. The supplied spec establishes Rust,
monolith-first deployment, the OSS boundary and both Linux architectures.

| ADR | Topic | Phase |
| --- | --- | --- |
| [001](001-rust.md) | Rust | 0 |
| [002](002-monolith-first.md) | Monolith first | 0 |
| [003](003-event-contract.md) | Canonical event contract | 1 |
| [004](004-parquet-format.md) | Parquet format | 3 |
| [005](005-datafusion-query.md) | DataFusion query | 4 |
| [006](006-wal-durability.md) | Bounded WAL and backpressure | 2 |
| [007](007-oss-boundary.md) | OSS mechanisms and private policy | 0 |
| [008](008-linux-architectures.md) | Linux AMD64 and ARM64 | 0 |
| 009 | Stateless rules | 5 |
| [010](010-storage-interface.md) | Replaceable storage interfaces | 3 |
| [011](011-rules-findings.md) | Stateless rules and durable findings | 5 |
| [012](012-agent-spool.md) | Durable edge-agent spool and source cursors | 6 |
| [013](013-extension-sdk.md) | Generic collector and enrichment extension hooks | 7-A |
| [014](014-packaging.md) | Minimal runtime and single persistent Kubernetes writer | 8 |
