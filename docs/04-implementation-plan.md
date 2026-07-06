# Signal MVP Implementation Plan

## Execution plan (2026-10-06)

Implement one phase per reviewable change set. Record evidence and the next task
in [07-progress.md](07-progress.md). Do not treat a scaffold or a configured CI
job as runtime/release proof.

Phases 0–6 are implemented and locally verified, including Phase 5 Compose
and Phase 6 agent collection. Phase 7-A generic SDK hooks are locally complete.
Phase 7-B implementation uses the sibling `platform-signal-private` repository
and its `overlays/example` application. Root, private package, external process
and independent review gates passed locally. The full `v0.1.0` release gate
remains outstanding.
See the [external overlay gate](17-external-overlay.md) for the command and
scope.
Phase 8 container/Helm/local Kubernetes and scans passed on Linux AMD64.
Phase 10's bounded hardening and finite benchmark campaigns, actual storage
failure/replay test and release documentation now have local evidence.
Native ARM64, EKS, remote CI and released external dependencies remain open in
[the release audit](21-release-readiness.md); configured jobs are not executed
qualification.
Remaining task IDs,
model/effort recommendations, subscription/API cost distinctions and review
boundaries are in [11-model-work-plan.md](11-model-work-plan.md). This is a
planning guide; it does not change the active model, enable delegation or alter
the phase/release gates.

The shortest useful milestone is **Phases 0–5**, including server wiring and
Docker Compose in Phase 5. The full `v0.1.0` gate additionally requires the agent,
external overlay proof, packaging and hardening. Keep those requirements in
`06-definition-of-done.md`; do not rename the core slice a completed release.

| Order | Change set | Exit evidence |
| --- | --- | --- |
| 0 | Workspace, tooling, license, CI, container and benchmark skeleton | Three Cargo gates; dependency direction; executable smoke test |
| 1 | Event contract + HTTP ingest with bounded test sink | Validation/auth/body/batch limits; 10,000-event accounting |
| 2 | Durable bounded WAL + real ingest admission | Forced restart, CRC/truncation, rotation/reclaim, quotas, overload policies |
| 3 | Parquet + consumer persistence/checkpoint | Nested-attribute roundtrip; partition/restart tests; 1M-event verification |
| 4 | URL query filters + DataFusion | Real Parquet filtering, partition pruning, deterministic order, deadlines |
| 5 | Rules, persistent findings, server wiring + Compose | HTTP → WAL → Parquet → query → finding; graceful and forced restart |
| 6 | Stdin/file agent + bounded persistent retry spool | Agent → server → query; disconnect/restart and spool quota |
| 7 | Overlay integration proof in a separate repository | External SDK enrichment and private rules verified through normal OSS server ingest, query and restart |
| 8 | Multi-arch image, Helm, SBOM, scanning | AMD64/ARM64 builds, Compose and Kubernetes smoke, Helm lint |
| 10 | Hardening and `v0.1.0` | Every definition-of-done gate with measured evidence |
| 9 (post-MVP) | AWS starter integrations | Optional extension after the release gate |

AWS collection is already post-MVP in `06-definition-of-done.md`; Phase 9 remains
numbered for document stability but is not on the release critical path. Phase 8's
EKS test needs credentials/environment evidence and must be recorded as pending
when unavailable. Phase 7 policy and fixtures stay in the separate repository;
the generic OSS gate and synthetic local SDK tests do not contain that policy.

### Decisions to settle before their implementation phase

- **Phase 1:** `EventSink` belongs in `signal-protocol`, shared by ingest and the
  buffer. Normalization generates missing ID/observed time and defaults severity
  to `info`. Timestamp/source are required; either message or nonempty structured
  attributes must exist. Reject unsupported schema versions. Record the final
  wire contract in ADR-003 before adding public event structs.
- **Phase 1/2:** document batch validation/admission accounting, including partial
  admission on overload. Phase 1 uses a bounded volatile sink and explicitly
  makes no durability promise. Phase 2 success requires a durable WAL append
  before acknowledgment to the HTTP caller.
- **Phase 2:** bound retained bytes as well as event count. Specify CRC framing,
  fsync/checkpoint/rename behavior and cancellation before implementing it.
  An incomplete final record may be truncated; interior corruption must fail
  explicitly. Do not silently discard accepted data. Record overload policy
  semantics, including the intentional loss permitted by `drop_oldest`, in ADR-006.
- **Phase 3:** `EventStore` belongs in storage; shared query filter contracts belong
  in protocol to prevent a storage/query dependency cycle. Resolve DataFusion
  first and match its Arrow/Parquet versions. Preserve nested attributes; publish
  files atomically and make replay duplicates safe.
- **Phase 4:** specify `[from,to)` UTC ranges and stable timestamp/ID ordering;
  enforce server-side result/memory bounds and cancellation. No textual query
  language or unrelated-partition scan for a bounded time range.
- **Phase 5:** detection severity is `low/medium/high/critical`, independent of
  event severity `trace/debug/info/warn/error/critical`. Rules produce deterministic
  finding identity for a rule/event pair so replay is safe. A WAL sequence is
  checkpointed only after event and finding persistence complete; independent
  consumers must not acknowledge each other's unfinished work.
- **Phase 5:** config/rules validate before readiness; shutdown stops admission,
  drains pending work within a deadline and leaves unacknowledged records replayable.
  Check disk quotas for findings as well as WAL; retention/archival policy remains
  external, and quota exhaustion is observable.

Apache-2.0 is the owner-selected OSS license. Runtime dependencies are added only
in the phase using them. Project tooling uses a locked Context7 installation for
both Codex and Claude Code; shell, Cargo and Git remain the direct build tools.

## Guiding principle

Build a **vertical slice first**.

The first useful path is:

```text
HTTP event
  -> validate
  -> normalize
  -> bounded queue
  -> WAL
  -> Parquet
  -> query
  -> rule
  -> finding
```

Do not build collectors, Kubernetes deployment or advanced AWS integration before this path works end-to-end.

---

# Phase 0 — Project foundation

## Objective

Create a buildable, testable, documented repository.

## Deliverables

- Cargo workspace;
- license;
- README;
- CONTRIBUTING;
- SECURITY;
- CODE_OF_CONDUCT;
- ADR directory;
- CI;
- formatting/clippy/testing;
- multi-arch container build skeleton;
- basic benchmark harness;
- versioning policy.

## Initial crates

```text
signal-event
signal-protocol
signal-ingest
signal-buffer
signal-storage
signal-query
signal-rules
signal-findings
signal-collector-sdk
signal-server
signal-agent
signalctl
```

Most crates may initially contain only APIs and tests.

## Exit criteria

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

all succeed in CI.

---

# Phase 1 — Canonical event model + ingest

## Objective

Accept and validate events.

## Implement

- event structs;
- schema version;
- ULID/UUID event ID;
- timestamp validation;
- source;
- severity;
- resource;
- attribute map;
- HTTP server;
- single ingest endpoint;
- batch endpoint;
- request limits;
- API token hook;
- structured error responses;
- health endpoints.

## Tests

- valid event;
- missing required field;
- invalid timestamp;
- oversized request;
- invalid batch item;
- authentication enabled/disabled.

## Exit criteria

A user can submit 10,000 events and receive deterministic acceptance/rejection counts.

---

# Phase 2 — Bounded queue + WAL

## Objective

Guarantee bounded resource use and restart recovery.

## Implement

- in-memory queue capacity;
- append-only WAL;
- segment rotation;
- sequence numbers;
- replay;
- checkpoint after successful persistence;
- maximum disk capacity;
- explicit full behavior;
- metrics.

## Failure policies

Configurable:

```text
reject_new
drop_oldest
block_with_timeout
```

Default for server MVP:

```text
reject_new
```

## Tests

- crash/restart;
- truncated final WAL record;
- full disk quota;
- queue full;
- ordering;
- duplicate replay tolerance.

## Exit criteria

Accepted durable events survive a forced process restart.

---

# Phase 3 — Parquet persistence

## Objective

Persist events efficiently and cheaply.

## Implement

- Arrow schema;
- event -> Arrow conversion;
- Parquet writer;
- row batches;
- date/hour partitions;
- file rotation;
- compression;
- atomic publish/rename;
- storage manifest abstraction.

## Tests

- roundtrip;
- attributes;
- partition selection;
- partial file behavior;
- restart.

## Exit criteria

1M generated events can be persisted and read back with matching IDs and timestamps.

---

# Phase 4 — Query API

## Objective

Make persisted events useful.

## Implement

- DataFusion integration;
- partition pruning;
- time range;
- contains;
- severity;
- source;
- resource;
- attribute equality;
- ordering;
- limit;
- query timeout;
- query metrics.

## Tests

- filtering;
- empty results;
- limit;
- ordering;
- mixed partitions;
- malformed filters;
- timeout.

## Exit criteria

The MVP demo can ingest, persist and query events after restart.

---

# Phase 5 — Rules + findings

## Objective

Create the first security/alerting capability.

## Implement

- YAML parser;
- rule schema;
- validation;
- `all`;
- `any`;
- `eq`;
- `neq`;
- `contains`;
- `exists`;
- findings;
- finding persistence;
- finding query endpoint.
- server composition, Prometheus metrics and validated configuration;
- Docker Compose with data/config/rules mounts;
- admission-stop/drain/flush/ack behavior with deadlines;
- end-to-end process tests before adding collectors.

## Tests

- matching;
- non-matching;
- invalid rule;
- nested fields;
- missing field;
- multiple rules.

## Exit criteria

A failed-login event creates a persisted finding. The Compose demo can ingest,
query event/finding, restart, and query both again. Forced kill is tested separately
from graceful SIGTERM. Run prompts 06 and 07 together for this phase's change set.

---

# Phase 6 — Agent

## Objective

Collect logs without requiring applications to call the server directly.

## Implement

- file tail;
- stdin;
- event parser;
- batching;
- retry with exponential backoff;
- local bounded spool;
- server endpoint config;
- API token;
- graceful shutdown.

## Exit criteria

```text
echo '{"message":"hello"}' | signal-agent ...
```

results in a queryable server event.

---

# Phase 7 — External overlay integration

## Objective

Prove a separate application can use generic SDK mechanisms and private rule
documents without changing or embedding private policy in OSS.

## Implement

- separate `platform-signal-private/overlays/example` application;
- workspace path dependencies for local co-development, with released crate
  dependencies required for released deployment;
- private-owned, schema-validated enrichment metadata and implementation;
- private rule documents returned through `RuleProvider` and compiled by the
  normal consumer before readiness;
- application-owned provider invocation before normal server ingest;
- external integration gate using the normal OSS server and private fixtures.

The SDK selects external inputs through `OverlayPath`; explicit paths take
precedence over `SIGNAL_OVERLAY_PATH`, with no implicit default. Rule documents
are versioned and bounded. Providers own their schemas and file reads. OSS does
not compile a private extension into the server or dynamically load one. Keep
actual policy, metadata, rules, expected outputs and deployment values in the
external repository. Helm integration belongs to Phase 8 and must use values
rendered by the public chart.

## Exit criteria

The separate application enriches an event and returns private rules; the
configured OSS server admits, persists, queries and recovers the event/finding
through restart without source changes to the OSS repository. Released crate
qualification is a separate release gate.

---

# Phase 8 — Packaging + Kubernetes

## Objective

Make MVP deployable.

## Implement

- production Dockerfile;
- SBOM;
- provenance/signing if available;
- Helm chart;
- PodDisruptionBudget;
- readiness;
- liveness;
- resource limits;
- persistent volume configuration;
- optional S3 config;
- ARM64/AMD64 images.

## Exit criteria

Deploy successfully into a local Kubernetes cluster and EKS test environment.

---

# Phase 9 — AWS starter integrations

Post-MVP extension; not a prerequisite for `v0.1.0`.

## Objective

Begin real AWS value after the platform core is stable.

## Implement in this order

1. CloudTrail event parser.
2. CloudWatch Logs pull/forward integration.
3. EKS container log integration.
4. EC2/journald deployment example.
5. cross-account assume-role abstraction.
6. AWS account/region resource metadata.

Do not couple AWS IAM/account topology into OSS core.

---

# Phase 10 — Hardening and `v0.1.0`

## Objective

Produce an MVP release that can be used by another engineer.

## Required

- fuzz parser boundaries;
- security review;
- dependency audit;
- benchmark report;
- memory profile;
- CPU profile;
- restart tests;
- corrupted WAL test;
- load test;
- documentation;
- architecture diagram;
- configuration reference;
- release notes;
- migration/versioning statement.

---

# Recommended implementation order

```text
0 foundation
↓
1 event + ingest
↓
2 bounded WAL
↓
3 parquet
↓
4 query
↓
5 rules/findings
↓
6 agent
↓
7 demo overlay
↓
8 packaging/k8s
↓
10 hardening
↓
v0.1.0 release gate
↓
9 optional AWS collectors
```

---

# Workstreams

Some work may run in parallel after Phase 2:

```text
                    ┌─ query
event -> WAL -> storage
                    ├─ rules
                    ├─ agent
                    └─ packaging
```

But the event model, WAL semantics and storage schema should stabilize before broad parallel development.

---

## Security requirements roadmap

Added 2026-10-07 from the owner-requested
[15-detection catalog](source-detection-catalog.md),
[logical architecture](logical-architecture.md) and
[failure domains](failure-domains.md). Historical Phase 0–10 numbering and the
existing release gates remain intact. These PS task groups are proposed post-MVP
capability phases, not accepted runtime features or permission to provision AWS.
Design/fixtures can be prepared locally before release; source deployment and new
runtime implementation need a bounded task. Phase 9 remains the source-collection
workstream and uses PS-01/PS-02 contracts when selected after the release gate.

| Group | Capability and motivating requirements | Dependencies | Acceptance / stop condition |
| --- | --- | --- | --- |
| PS-01 | Versioned normalization profile and SourceCoverage mechanism; all detections, especially D15 | Existing event envelope/SDK; no private fields | Pure SDK validator, history contract and bounded local library accepted. [ADR-015](adr/015-source-coverage-store.md) records frozen encodings, explicit ownership, atomic prepared append and process recovery. Next trusted local intake/authorization and exact-byte original-receipt replay; correction admission, GC and scans separately. No observers/collectors/cloud calls yet |
| PS-02 | Source adapters and first real predicates: D01/D02/D03/D05/D07 | PS-01; existing predicate engine | Select one source per change set, CloudTrail management events first. Raw positive/negative/missing/duplicate fixtures → normalized fields, coverage declarations and findings; federated MFA excluded without IdP evidence. EKS audit is a separate adapter task; no claim of runtime hooks from file logs |
| PS-03 | Durable finding delivery and disposition seam | Existing journal; [cursor contract](25-findings-cursor-proposal.md); does not require new state engine | Public cursor runtime/restart/divergent-history gates first. Separate private cursor+outbox transaction, destination uncertainty and disposition acceptance. No destination-specific policy in public core; listing is not already a feed |
| PS-04 | Independent protected evidence and object-store query copies | PS-01/PS-02 source identity/coverage; [M3](failure-domains.md#acknowledgement-milestones) | Separate source-native evidence route, proof validation and security permissions from S3 query `EventStore` publication/manifests. Test observability-account outage, validation failure and recovery. Cloud/retention settings require authorized private environment; no ingest/detection HA claim |
| PS-05 | Bounded windows and versioned state: D04/D06/D08/D09/D10/D12/D13/D15 | PS-01; selected PS-02 sources; durable finding/state recovery contract | Begin with one window operator (D10) and bounded replay/watermark/overflow tests, then separately add trusted state lookups. D15 requires independent observer; effective IAM/RBAC evaluation needs a scoped supported-semantics task, not a universal permission solver |
| PS-06 | Multi-stream correlation and incident/feedback context: D11/D14 | PS-05; adequate sources; PS-03 outcome seam | One join/episode at a time; late/duplicate inputs, missing streams, bounded state, crash recovery, stable evidence/incident identity and dispositions. Investigative correlation does not prove causal RCA |

PS-03 can consume existing normalized findings before new source adapters are
deployed. PS-04 evidence delivery must be established before claiming security
independence; stateful detection may be developed locally against fixtures while
that external gate remains open. Each row is a group of bounded tasks, never an
instruction to implement all listed capabilities in one change set. The original
design handoff selected PS-01's SourceCoverage contract/fixture subtask; the
accepted contract below advances that locally runnable sequence.

PS-01's contract/fixture subtask now has the
[formal SourceCoverage v1 contract](source-coverage-contract.md), two structural
schemas, 60 record cases, 39 assessment expectations and seven transition sequences.
Offline structural acceptance does not execute the semantic assessments. The SDK's
pure validator now executes all 60 record cases, 39 assessments and seven transition
sequences in 24 integration tests; its acceptance had 255 workspace tests.
The [bounded intake/history contract](source-coverage-history-contract.md) now
defines exact raw-byte retry identity, finite retention/deduplication guarantees,
durable receipts, immutable corrections, prefix-aware reads/recovery and ownership.
Its offline inventory has 16 requirements, 12 candidates and 56 planned cases;
none is a storage runtime pass. [ADR-015](adr/015-source-coverage-store.md) now
selects SQLite with one dedicated worker, freezes fingerprint/binding/commit/prefix/
state/identity vectors and defines finite accounting/reserves. Its local Python
projection passes 13 SQLite mechanics checks; 33 golden rejection guards and four
relationship checks pass. The bounded `signal-coverage` library now passes 18
focused tests for explicit initialization/root ownership, frozen encodings,
atomic prepared append/recovery, process crashes, corruption, quotas and
cancellation. Fresh local acceptance passes 273 workspace tests and the
13-package boundary guard; SDK/agent remain free of database dependencies.
The subsequent trusted intake/retry slice passes 31 focused tests and 286 workspace
tests, covering exact application grants, observed-time admission age, fixed checked
retention and original-byte receipt replay without renewal. The complete 56-outcome
history state machine remains unimplemented. Bounded correction admission now
passes 45 focused tests and 300 workspace tests: same full binding/observer,
available earlier target, overlapping interval/later verification, preserved
original and atomic immutable link. Payload-prefix pruning is next; identity GC
and scans follow
in separate bounded slices. Observer/source/server integration stays separate;
no pipeline/detection wiring is implied.

Splitting services is a subsequent evidence-based decision: benchmark query versus
protected-ingest contention, verify permission/isolation requirements, then define
partition ownership and commit fencing before HA. No new graph database, query
language, hot index, eBPF agent or additional server process follows automatically
from this roadmap. Member-account IAM, scopes, deployment values and operational
SLOs remain private. ARM64/EKS/remote-CI/released-dependency qualification is still
required by the existing definition of done.

---

# Suggested milestones

Historical milestone names below remain unchanged; AWS-useful M8 is a post-MVP
capability and is not a prerequisite for the existing initial release gate.

## M0 — Skeleton

Repository compiles and CI is green.

## M1 — Ingest

Events accepted over HTTP.

## M2 — Durable

Events survive restart.

## M3 — Searchable

Persisted events can be queried.

## M4 — Detecting

Rules generate findings.

## M5 — Collecting

Agent forwards file/stdin logs.

## M6 — Extensible

Demo company overlay works without fork.

## M7 — Deployable

Helm + multi-arch container.

## M8 — AWS useful

At least CloudTrail and one log source integrated.

## M9 — MVP release

`v0.1.0`.

---

# Engineering rules for MVP

1. No unbounded channels.
2. No `.unwrap()` in production paths unless invariants are documented.
3. Every async operation touching network/disk has timeout/cancellation semantics.
4. Every queue exposes metrics.
5. Config is validated before server readiness.
6. Rules are validated before readiness.
7. No internal/demo namespace appears in OSS core.
8. Public structs use versioned serialization contracts.
9. Prefer integration tests over mocks for storage/WAL.
10. Optimize only after benchmarks identify a bottleneck.
