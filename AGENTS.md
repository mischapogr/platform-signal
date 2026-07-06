# AGENTS.md

<!-- context7 -->
Use Context7 MCP for current library, framework, SDK, API, CLI or cloud-service
documentation, even for familiar tools. Prefer it over web search for library docs.
Start with `resolve-library-id` unless an exact `/org/project` ID was supplied;
select by relevance, reputation, snippet coverage and version, then call
`query-docs` for one concept at a time. Use fetched documentation in the result.
Do not use it for generic programming, business-logic debugging, refactoring,
script writing or code review. Never send confidential data in documentation queries.
<!-- context7 -->

Guidance for AI coding agents (Claude Code, Codex, Cursor, Copilot, Gemini CLI, etc.) working in this repository.

## Current state

Phases 0–8 and bounded Phase 10 hardening have local Linux AMD64 evidence.
HTTP 202 means synced WAL admission; the consumer publishes Parquet, evaluates
rules, persists findings, then advances the checkpoint. The dev0 local candidate
is unpublished and is not an alpha or release. Native ARM64, actual EKS, remote
CI and released-dependency qualification remain open. Local kind and finite
soaks do not prove AWS runtime, prolonged stability or physical-device throughput.

Start with `docs/07-progress.md` and `docs/21-release-readiness.md` for current
work and evidence; historical counts, images and review paths live there.
The docs remain the spec. Read the relevant contracts and ADRs before writing code:

- Architecture/scope/order/review: `docs/01-architecture.md`, `02-mvp.md`,
  `04-implementation-plan.md`, `05-implementation-prompts.md`, `06-definition-of-done.md`.
- Ingest/WAL/storage/query/rules/agent/SDK: `docs/09-phase1-ingest.md`,
  `10-phase2-wal.md`, `12-phase3-storage.md`, `13-phase4-query.md`,
  `14-phase5-core.md`, `15-phase6-agent.md`, `16-collector-sdk.md`.
- External overlay: `docs/03-demo-company-overlay.md`, `17-external-overlay.md`;
  spool/SDK decisions: `docs/adr/012-agent-spool.md`, `013-extension-sdk.md`.
- Packaging/security/native/candidate: `docs/19-packaging.md`, `20-threat-model.md`,
  `22-native-qualification.md`, `23-local-candidate.md`.
- AI setup/routing: `docs/08-development-tooling.md`, `11-model-work-plan.md`.

Work **one phase at a time** in plan order, with one reviewable change set and
recorded phase review/evidence. Continue remaining Phase 10/release work from
the progress and release audit; do not repeat completed local work. Phase 5
includes server wiring/Compose. Phase 7-B uses the separate
`platform-signal-private/overlays/example` checkout. Phase 9 AWS collection is
post-MVP and requires a new task.

The owner holds staging, commits, pushes and publication until alpha or first
minor readiness. No release version has been selected. Do not stage or commit
unless requested; publication and external environments need their own authority.

## Development workflow

Use one writer for a coherent task, one focused review when required, then a
settled documentation pass. Delegate only when the user explicitly requests
parallel agents for the current task; historical team authorization is not a
standing instruction. Give authorized agents owned paths, runnable acceptance
and a stop condition; finish them when their deliverable is accepted. Use scripts
for bulk processing and runtime waits, with compact result summaries.

New project sessions default to Sol 6.1/medium (Codex) or Sonnet/medium (Claude).
Use Luna/low or Haiku for settled mechanical work; Sol/high for durability,
cancellation, replay and critical review; escalate unresolved reproduced problems
as described in `docs/11-model-work-plan.md`. Keep Standard speed and existing
permissions. Use Context7 for required documentation and built-in shell tools for
Cargo, search and local Git; task-specific MCPs need a concrete use.

Project skills in `.agents/skills/` are shared with Claude via `.claude/skills/`:
`signal-task` prepares a compact task packet, `signal-validate` selects checks,
and `signal-handoff` records evidence and usage. Capture model/effort, elapsed
time, correction cycles and available usage deltas per accepted task; do not
translate subscription telemetry into an API bill.

## Validation

Run focused regressions during implementation. At a phase/code acceptance boundary,
CI and the definition of done require:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-workspace.py
```

To run a single crate or test: `cargo test -p signal-buffer`, or `cargo test -p signal-buffer <test_name>`.

Apply the phase review and applicable process/container/cluster/security gates
from the relevant spec. Rerun checks affected by corrections. For tooling-only
changes, validate configuration, skills and helpers directly; Cargo gates apply
when Rust behavior or build inputs change. Preserve retained `target/` evidence
and reuse qualified images only when their source/config/image inputs still match.

## Architecture

PLATFORM::SIGNAL is a lightweight log and security-event pipeline in Rust (Tokio, Axum, Serde, Arrow/Parquet, DataFusion). It targets linux/amd64 and linux/arm64 equally.

```
collectors/agent → ingest (validate, normalize, limits, auth) → bounded buffer + WAL
                                                               ├→ storage writer → Parquet (date=YYYY-MM-DD/hour=HH/) → DataFusion query → HTTP/CLI
                                                               └→ rule engine → findings
```

- **Monolith first.** `apps/signal-server` runs ingest, buffer, storage, query, rules, and findings in one process. Crate boundaries (`crates/signal-{event,protocol,ingest,buffer,storage,query,rules,findings,collector-sdk}`) must keep a later split into `signal-ingest`, `signal-query`, and `signal-rules` possible, but don't split them yet. The other apps are `signal-agent` (edge collector) and `signalctl` (CLI).
- **`signal-event` is the central contract.** Everything depends on the canonical, versioned event envelope (`schema_version`, `id`, `timestamp`, `observed_at`, `source`, `severity`, `message`, `attributes`, plus optional `resource`, `trace_id`/`span_id`, and `tags`). Arbitrary nested attributes must be preserved so external applications can add private metadata through attributes without adding OSS event fields.
- **Decoupling seams:** HTTP ingest writes to an `EventSink` trait and never touches storage directly. Storage sits behind `EventStore` (`append`/`query`) so S3 can replace the filesystem later. `Collector` and `Enricher` traits in `signal-collector-sdk` are the extension points for external repos.
- **Buffer/WAL semantics:** append-only segments with a sequence number and CRC per record, replay on restart, truncation of an incomplete final record, ack/checkpoint after persistence, and reclaim of fully acked segments. Admission policies are `reject_new` (the default), `drop_oldest`, and `block_with_timeout`. Delivery is at least once, so consumers must tolerate duplicates on replay.
- **Rules (MVP):** stateless per-event YAML predicates (`all`/`any`; `eq`/`neq`/`contains`/`exists`) on dot-path fields such as `attributes.user.name`. Invalid rules or duplicate rule IDs fail startup and keep `/readyz` false.
- **Query (MVP):** URL parameters only on `GET /v1/events` (from/to, contains, severity, source, resource, account, attribute equality, limit, order). Do not invent a query language. Time ranges must prune date/hour partitions.

## OSS / company boundary (hard rule)

This repo holds **mechanisms**. The separate `platform-signal-private/overlays/example` application holds policy, environment, identity, metadata, detections, alert routing, deployment values and fixtures. The private application depends on `platform-signal`, never the other way around. Never put private identifiers, namespaces or policy in OSS core. If an overlay needs a missing hook, add the smallest *generic* extension point here.

## Engineering rules (from the plan)

- No unbounded channels or queues. Every queue exposes depth and capacity metrics, and every drop or rejection is counted.
- No `.unwrap()`/`.expect()` in production paths unless the invariant is documented. Use typed, contextual errors.
- Every async network or disk operation needs timeout and cancellation semantics.
- Validate config and rules before reporting ready. Graceful shutdown stops admission first, then flushes.
- Never log secrets. The API token comes only from env or config.
- Public structs use versioned serialization contracts.
- Prefer integration tests over mocks for storage and the WAL.
- Optimize only after a benchmark identifies the bottleneck.
