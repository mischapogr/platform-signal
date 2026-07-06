# Implementation Prompts

These prompts are designed to be given to a coding agent one phase at a time.

Do not give the whole project to a coding agent in one prompt. Each prompt should produce a reviewable change set.

Follow the phase mapping and contract decisions in `04-implementation-plan.md`.
Phase 1 uses prompts 01+02; Phase 5 uses prompts 06+07 so end-to-end wiring lands
before the agent. Prompt 11 is post-MVP. Every completed phase needs recorded exit
evidence and the review below in `07-progress.md`; do not invent CI/runtime proof.

For remaining phases, select a bounded task and recommended model/effort from
[11-model-work-plan.md](11-model-work-plan.md), then use the corresponding prompt
below. Preserve phase acceptance criteria; model routing is a planning recommendation.

---

# Prompt 00 — Bootstrap repository

```text
You are implementing the open-source project PLATFORM::SIGNAL in Rust.

Goal:
Create the initial Cargo workspace and engineering foundation.

Architecture constraints:
- Rust stable.
- Tokio async runtime.
- No unbounded queues.
- Linux AMD64 and ARM64 are target platforms.
- Project starts monolith-first but uses clean crate boundaries.
- Public OSS must contain no company-specific code.
- Prefer small dependencies.
- All production errors must use typed/contextual error handling.
- Avoid unwrap/expect in production execution paths.

Create this workspace:

crates/
  signal-event
  signal-protocol
  signal-ingest
  signal-buffer
  signal-storage
  signal-query
  signal-rules
  signal-findings
  signal-collector-sdk

apps/
  signal-server
  signal-agent
  signalctl

Also add:
- rustfmt config if needed
- clippy settings
- GitHub Actions CI
- README.md
- CONTRIBUTING.md
- SECURITY.md
- CODE_OF_CONDUCT.md
- docs/adr/
- tests/integration/
- benchmarks/

CI must run:
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

Do not implement business functionality yet.
Every crate must compile.
Document dependency direction between crates.
Return:
1. files changed;
2. key decisions;
3. commands to verify;
4. unresolved decisions.
```

---

# Prompt 01 — Implement Signal Event

```text
Implement the canonical Signal event model in crates/signal-event.

Requirements:
- serde serialization/deserialization;
- schema_version: u16, current value 1;
- id generated when absent;
- timestamp required;
- observed_at default to ingestion time;
- source.type required;
- source.name optional;
- severity enum: trace/debug/info/warn/error/critical;
- message optional but at least message or structured body must exist;
- resource optional:
  kind
  id
  account_id
  region
- attributes must support nested JSON-compatible values;
- trace_id/span_id optional;
- tags list;
- validation API;
- preserve unknown attributes;
- stable JSON representation;
- documentation examples.

Add tests for:
- minimal valid event;
- full event;
- generated ID;
- invalid event;
- severity serde;
- nested attributes;
- round-trip serialization.

Do not include company-specific fields.
Do not add AWS-only concepts outside optional generic resource metadata.

Expose a public validation error enum.
Keep schema evolution in mind.
```

---

# Prompt 02 — HTTP ingest

```text
Implement HTTP ingestion in signal-ingest and signal-server.

Use Axum.

Endpoints:
POST /v1/events
POST /v1/events/batch
GET /healthz
GET /readyz

Requirements:
- validate SignalEvent;
- add ID/observed_at where needed;
- configurable maximum request body size;
- configurable maximum batch event count;
- typed JSON errors;
- HTTP 400 for invalid events;
- HTTP 413 for oversized requests;
- HTTP 429 when downstream admission is full;
- optional Bearer token configured only through environment/config;
- never log the token;
- structured tracing;
- graceful shutdown.

Define an EventSink trait so HTTP ingestion does not know about storage.

Add integration tests with an in-memory bounded sink.

Do not implement persistence in this change.
```

---

# Prompt 03 — Bounded WAL

```text
Implement signal-buffer as a durable bounded write-ahead event queue.

Requirements:
- bounded memory channel;
- append-only WAL segments;
- configurable WAL directory;
- configurable max total WAL bytes;
- sequence number per record;
- CRC/checksum per record;
- segment rotation;
- replay on restart;
- tolerate/truncate an incomplete final record;
- checkpoint/ack records after consumer persistence;
- reclaim fully acknowledged segments;
- never grow memory without bound.

Admission policies:
- reject_new
- block_with_timeout
- drop_oldest

Default:
reject_new

API should allow:
append(event)
read_batch(max_events, max_bytes)
ack(sequence)

Expose metrics hooks/state:
- memory queue depth;
- WAL bytes;
- WAL segments;
- accepted;
- rejected;
- replayed;
- corruption count.

Add tests:
- normal append/read/ack;
- restart replay;
- incomplete final record;
- checksum failure;
- quota reached;
- segment reclamation;
- ordering.

Favor correctness and recoverability over optimization.
Document on-disk format.
```

---

# Prompt 04 — Parquet storage

```text
Implement the MVP event store using Apache Arrow + Parquet.

Requirements:
- define Arrow schema for SignalEvent;
- convert event batches to Arrow RecordBatch;
- write Parquet;
- partition paths by UTC date/hour:
  date=YYYY-MM-DD/hour=HH/
- configurable max rows per file;
- configurable flush interval;
- configurable compression;
- atomic publication using temporary file + rename;
- preserve all event IDs/timestamps;
- preserve nested attributes in a forward-compatible way.

Implement EventStore::append.

Add read support sufficient for round-trip tests.

Tests:
- one event;
- batch;
- nested attributes;
- multiple partitions;
- compression;
- restart;
- temp/incomplete file ignored;
- full roundtrip.

Do not implement S3 yet, but ensure filesystem operations are behind a storage abstraction so S3 can be added later.
```

---

# Prompt 05 — Query engine

```text
Implement signal-query using Apache DataFusion over stored Parquet files.

Supported filters:
- from timestamp;
- to timestamp;
- full message contains;
- severity;
- source.type;
- source.name;
- resource.kind;
- resource.id;
- account_id;
- arbitrary top-level/nested attribute equality;
- limit;
- ascending/descending timestamp.

Requirements:
- derive candidate partitions from time range;
- do not scan unrelated date/hour partitions when time range is provided;
- query timeout;
- deterministic output ordering;
- structured query result including elapsed_ms and scanned_files;
- max result limit configured server-side.

Add:
GET /v1/events

Do not create a custom query language.
Use URL query parameters only for MVP.

Add integration tests against real Parquet files.
```

---

# Prompt 06 — Rule engine and findings

```text
Implement signal-rules and signal-findings.

Rule format:
apiVersion: signal.dev/v1
kind: Rule
metadata:
  id: string
  name: string
spec:
  severity: <detection severity: low/medium/high/critical>
  match:
    all: [...]
    any: [...]
  finding:
    title: string

Predicates:
- eq
- neq
- contains
- exists

Fields use dot notation:
source.type
resource.account_id
attributes.user.name

Requirements:
- load all *.yaml/*.yml files from configured directories;
- validate all rules at startup;
- duplicate rule IDs are fatal;
- deterministic evaluation;
- missing fields do not panic;
- every accepted event may be evaluated;
- produce Finding with:
  id
  rule_id
  created_at
  severity
  title
  event_ids
  attributes
- persist findings using a simple append-oriented implementation;
- expose GET /v1/findings.

Tests:
- all;
- any;
- missing field;
- nested attribute;
- contains;
- duplicate IDs;
- invalid YAML;
- event produces exactly expected finding.
```

---

# Prompt 07 — Wire vertical slice

```text
Wire signal-server end to end:

HTTP ingest
 -> validate
 -> durable buffer/WAL
 -> storage writer
 -> Parquet
 -> rule engine
 -> finding store

Requirements:
- one server process;
- bounded channels only;
- graceful shutdown;
- shutdown stops admission first;
- flush/ack semantics documented;
- readiness must be false if:
  config invalid
  rule loading failed
  storage unavailable
- expose Prometheus metrics;
- structured tracing.

Create docker-compose.yml that runs Signal locally with mounted data/config/rules.

Add an end-to-end test:
1. start server;
2. send matching event;
3. wait for persistence;
4. query event;
5. query finding;
6. restart;
7. query both again.

This test is the main MVP vertical-slice gate.
```

---

# Prompt 08 — Agent

```text
Implement signal-agent.

Inputs for MVP:
- stdin;
- tail one or more files.

Output:
- Signal HTTP batch API.

Requirements:
- parse plain lines into SignalEvent.message;
- optionally parse each line as JSON and store keys in attributes;
- source metadata configured per input;
- batching by event count and time;
- exponential backoff with jitter;
- local bounded spool;
- persist unsent events across restart;
- configurable maximum spool disk;
- graceful shutdown;
- metrics endpoint optional;
- no unbounded memory.

Add integration test:
agent -> signal-server -> query.
```

---

# Prompt 09 — External overlay integration

```text
Work in the sibling private repository platform-signal-private/overlays/example.
For local co-development, use workspace path dependencies on platform-signal
crates. Keep released crate qualification as a separate release gate.

Goal:
Prove an external application can use the generic SDK and normal OSS server
without embedding its policy or fixtures in this repository.

Implement:
- private-owned metadata schema and EnrichmentProvider implementation
- OverlayPath selection using explicit path or SIGNAL_OVERLAY_PATH
- version 1 RuleDocument output through RuleProvider
- consumer compilation and duplicate-ID validation before readiness
- application-owned provider loading and enrichment before normal ingest
- private runner --check contract returning event, findings, and
  overlay-relative rule_directories
- run scripts/check-overlay.py with the separate private runner and the normal
  OSS server; verify enrichment, findings, authenticated admission, exact event
  and finding queries, SIGKILL recovery, and SIGTERM shutdown
- record local path-dependency evidence separately from released-crate,
  container, Helm, and deployment qualification

Keep all actual metadata, policy, rules, expected fixtures, and deployment
values in the external repository. Do not add their schemas or sample values to
OSS documentation. Do not add a compiled private extension or dynamic loader to
the OSS server. If a required hook is missing, propose the smallest generic SDK
change and keep the private implementation external.
```

---

# Prompt 10 — Docker + Helm + multi-arch

```text
Productionize packaging for the MVP.

Docker:
- multi-stage build;
- minimal runtime image;
- non-root;
- read-only root filesystem compatible where possible;
- explicit writable data paths;
- amd64 and arm64;
- healthcheck;
- OCI labels.

Helm:
- Deployment;
- Service;
- ConfigMap;
- optional Secret references;
- readiness/liveness probes;
- resource requests/limits;
- PVC;
- PodDisruptionBudget;
- ServiceMonitor optional;
- topology spread/anti-affinity optional.

CI:
- build multi-arch image;
- vulnerability scan;
- SBOM;
- run chart lint;
- run Kubernetes smoke test.

Document minimal EKS deployment.
```

---

# Prompt 11 — CloudTrail starter

```text
Add generic AWS CloudTrail event support.

Requirements:
- parser/normalizer only first;
- map CloudTrail JSON into SignalEvent;
- source.type = aws.cloudtrail;
- resource/account/region where available;
- preserve original important fields in attributes;
- tests using public/synthetic fixtures;
- no company account IDs;
- no company IAM names;
- no internal ARNs.

Add example security rules:
- root ConsoleLogin;
- StopLogging;
- DeleteTrail;
- DisableSecurityHub;
- DeleteDetector.

Rules are examples and must be clearly labeled as generic starter content, not universal policy.
```

---

# Prompt 12 — Benchmark and hardening

```text
Create a reproducible benchmark suite for Signal MVP.

Measure:
- ingest events/sec;
- CPU;
- resident memory;
- WAL throughput;
- Parquet write throughput;
- query latency;
- rule evaluation throughput.

Workloads:
- 1 KiB event;
- 4 KiB event;
- 100 events/sec;
- 1k events/sec;
- 10k events/sec;
- stress until saturation.

Platforms:
- linux/amd64;
- linux/arm64 where CI/environment permits.

Requirements:
- report saturation behavior;
- prove memory remains bounded;
- report dropped/rejected event counts;
- test graceful overload rather than only maximum throughput;
- create BENCHMARKS.md with exact command lines and environment.

Do not optimize blindly. First identify the dominant bottleneck and provide profiling evidence before changing architecture.
```

---

# Review prompt — Use after every phase

```text
Review this implementation as a senior Rust/platform/security engineer.

Check:
1. correctness;
2. unbounded memory/disk risks;
3. blocking work on async runtime;
4. crash consistency;
5. data-loss scenarios;
6. API/schema compatibility;
7. security issues;
8. secret leakage;
9. excessive dependencies;
10. company-specific concepts leaking into OSS;
11. ARM64 portability;
12. missing tests;
13. observability;
14. performance traps.

Classify findings:
- blocker
- high
- medium
- low

For each finding provide:
- file/symbol;
- failure mode;
- concrete fix;
- test that should prevent regression.

Do not redesign working components unless there is a concrete benefit.
```
