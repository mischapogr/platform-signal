# PLATFORM::SIGNAL Architecture

## 1. Architectural intent

Signal is a lightweight event/log platform focused on:

- application logs;
- EC2 host/system logs;
- EKS/Kubernetes events and logs;
- AWS service events;
- security-relevant events;
- rule-based findings and alerting;
- low operating cost;
- predictable resource usage;
- multi-account AWS environments;
- ARM64 and AMD64 support.

The platform should favor simple components, stable contracts and cheap storage before sophisticated UI features.

---

## 2. OSS versus company boundary

```text
                              PUBLIC OSS
┌───────────────────────────────────────────────────────────────────┐
│                         platform-signal                           │
│                                                                   │
│  collectors -> ingest -> normalize -> buffer -> persist -> query  │
│                                   \-> rules -> findings            │
│                                                                   │
│  event model                                                      │
│  protocol                                                         │
│  collector SDK                                                    │
│  pipeline SDK                                                     │
│  rule engine                                                      │
│  storage interfaces                                               │
│  query interfaces                                                 │
│  generic AWS/Kubernetes adapters                                  │
│  CLI                                                              │
│  Helm/Terraform examples                                          │
└───────────────────────────────┬───────────────────────────────────┘
                                │ stable public APIs/contracts
                                ▼
                         PRIVATE / INTERNAL
┌───────────────────────────────────────────────────────────────────┐
│                            demo-signal                            │
│                                                                   │
│  company account topology                                         │
│  IAM roles and trust policies                                     │
│  environment metadata                                             │
│  service/application ownership                                    │
│  custom enrichers                                                 │
│  internal detections                                              │
│  alert routing                                                    │
│  dashboards                                                       │
│  retention rules                                                  │
│  production deployment                                            │
└───────────────────────────────────────────────────────────────────┘
```

The OSS repository contains **mechanisms**.
The company repository contains **policy and environment**.

---

## 3. Logical data flow

```text
       +-------------------+
       | Applications      |
       | EC2 / systemd     |
       | EKS / containers  |
       | AWS services      |
       +---------+---------+
                 |
                 v
       +-------------------+
       | Collectors/Agents |
       +---------+---------+
                 |
                 | Signal Event API
                 v
       +-------------------+
       | Ingest Gateway    |
       +---------+---------+
                 |
                 v
       +-------------------+
       | Normalizer        |
       +---------+---------+
                 |
                 v
       +-------------------+
       | Bounded Buffer    |
       | + WAL             |
       +----+----------+---+
            |          |
            |          +--------------------+
            v                               v
   +------------------+              +--------------+
   | Storage Writer   |              | Rule Engine  |
   +--------+---------+              +------+-------+
            |                               |
            v                               v
   +------------------+              +--------------+
   | Parquet / S3     |              | Findings     |
   +--------+---------+              +------+-------+
            |                               |
            v                               v
   +------------------+              +--------------+
   | Query Engine     |              | Alert Sinks  |
   | DataFusion       |              +--------------+
   +--------+---------+
            |
            v
   +------------------+
   | HTTP/CLI/API     |
   +------------------+
```

---

## 4. Component model

### 4.1 `signal-event`

Owns the canonical event envelope.

Responsibilities:

- event identifiers;
- timestamps;
- source metadata;
- severity;
- message/body;
- structured attributes;
- resource identity;
- trace/span correlation;
- tenant/account/environment metadata;
- schema version.

Example:

```json
{
  "schema_version": 1,
  "id": "9e59c9d0-5ccf-4425-97b2-d8280a39fd74",
  "timestamp": "2026-10-06T12:00:00Z",
  "observed_at": "2026-10-06T12:00:01Z",
  "source": {
    "type": "application",
    "name": "checkout-api"
  },
  "resource": {
    "kind": "k8s.pod",
    "id": "checkout-7b9f",
    "account_id": "111111111111",
    "region": "eu-central-1"
  },
  "severity": "warn",
  "message": "payment provider timeout",
  "attributes": {
    "environment": "prod",
    "service": "checkout",
    "duration_ms": 2500
  }
}
```

### 4.2 `signal-protocol`

Defines transport contracts.

MVP:

- HTTP `POST /v1/events`;
- HTTP `POST /v1/events/batch`;
- health/readiness endpoints;
- JSON payloads.

Later:

- OTLP ingestion;
- streaming transport;
- compressed batches;
- Protobuf;
- authenticated multi-tenant ingest.

### 4.3 `signal-ingest`

Responsibilities:

- request validation;
- payload limits;
- authentication hook;
- backpressure;
- normalization;
- admission metrics;
- queue handoff.

### 4.4 `signal-buffer`

A bounded durable queue.

Properties:

- bounded memory;
- disk spill/WAL;
- restart recovery;
- batch reads;
- configurable max disk;
- explicit behavior when capacity is exhausted.

The component must prefer dropping or rejecting data in a controlled, measurable manner rather than consuming unbounded memory.

### 4.5 `signal-storage`

Public storage interface:

```rust
#[async_trait]
pub trait EventStore {
    async fn append(&self, batch: EventBatch) -> Result<()>;
    async fn query(&self, query: EventQuery) -> Result<EventStream>;
}
```

MVP implementation:

```text
events
└── date=2026-10-06
    └── hour=14
        ├── events-00001.parquet
        └── events-00002.parquet
```

Production-capable implementation may later use:

- S3;
- local SSD cache;
- Iceberg/Delta-compatible metadata;
- specialized search indexes.

### 4.6 `signal-query`

MVP query model:

```text
time range
+ full-text contains
+ equality filters
+ severity filter
+ source filter
+ resource/account filter
+ limit/order
```

Do not invent a complex query language in phase 1.

Example HTTP API:

```text
GET /v1/events?from=...&to=...&contains=error&service=checkout&limit=100
```

A textual query language can be introduced after real use cases exist.

### 4.7 `signal-rules`

Generic rule execution engine.

Example:

```yaml
apiVersion: signal.dev/v1
kind: Rule
metadata:
  id: auth.login-failure
  name: Failed login
spec:
  severity: medium
  match:
    all:
      - field: source.type
        eq: application
      - field: message
        contains: "login failed"
  finding:
    title: "Failed login"
```

MVP rules are stateless per-event predicates.

Later phases can add:

- windows;
- thresholds;
- aggregation;
- correlation;
- sequence rules;
- suppression;
- deduplication.

### 4.8 `signal-findings`

Canonical result of detection.

```json
{
  "id": "finding-...",
  "rule_id": "auth.login-failure",
  "created_at": "2026-10-06T12:00:01Z",
  "severity": "medium",
  "title": "Failed login",
  "event_ids": ["9e59c9d0-5ccf-4425-97b2-d8280a39fd74"],
  "attributes": {}
}
```

### 4.9 `signal-collector-sdk`

Interfaces for collectors and enrichers.

```rust
#[async_trait]
pub trait Collector {
    async fn run(&self, sink: EventSink) -> Result<()>;
}

#[async_trait]
pub trait Enricher {
    async fn enrich(&self, event: &mut SignalEvent) -> Result<()>;
}
```

### 4.10 `signal-agent`

Small edge process.

MVP inputs:

- stdin/file tail;

Later:

- journald;
- HTTP receiver;
- Kubernetes container logs;
- CloudWatch Logs;
- CloudTrail/S3;
- syslog;
- Windows Event Log.

---

## 5. Process topology

### Development

```text
signal-server
├── ingest
├── buffer
├── storage writer
├── query
├── rules
└── findings
```

One process first.

This is deliberate. Avoid premature microservices.

### Production evolution

Only split processes when scaling evidence requires it:

```text
signal-ingest
signal-query
signal-rules
```

The event model and storage contracts must make this split possible without requiring it for MVP.

---

## 6. AWS topology

For a multi-account environment:

```text
AWS Organization
│
├── workload account A ----\
├── workload account B -----\
├── workload account C ------> centralized ingest
├── ...
└── workload account N -----/
                              |
                              v
                    Observability account
                    ├── Signal ingest
                    ├── Signal query
                    ├── storage
                    └── dashboards

                    Security account
                    ├── company rule content
                    ├── security integration
                    └── finding consumers
```

MVP should support account metadata in the event model even if cross-account collection is implemented later.

---

## 7. Security architecture

MVP minimum:

- ingestion body-size limit;
- request timeout;
- no unbounded queues;
- structured validation;
- optional static API token;
- least-privilege containers;
- non-root images;
- no secrets in logs;
- separate `/healthz` and `/readyz`;
- checksum/version metadata on rule files;
- immutable event ID after ingestion.

Later:

- mTLS;
- AWS IAM/SigV4 authentication;
- OIDC;
- RBAC;
- per-tenant isolation;
- encryption/key management policies;
- signed rules/config bundles.

---

## 8. Reliability principles

1. Bounded memory.
2. Bounded disk.
3. Observable drops/rejections.
4. Durable handoff before acknowledgement when configured.
5. Idempotent event IDs where possible.
6. At-least-once ingestion is acceptable.
7. Duplicate tolerance is required.
8. Backpressure must propagate.
9. Every queue exposes depth/capacity metrics.
10. Every failure mode has an explicit policy.

---

## 9. Performance principles

Prioritize:

- batch processing;
- zero/minimal-copy parsing where practical;
- append-oriented persistence;
- Parquet column pruning;
- predicate pushdown;
- asynchronous I/O;
- memory limits;
- compression;
- ARM64 parity.

Initial performance target:

```text
single node:
  >= 20,000 events/sec ingest
  1 KiB average event
  < 1 GiB steady-state memory
  bounded queue/WAL
```

This is a target for engineering validation, not an MVP release blocker until benchmark tooling exists.

---

## 10. Repository layout

```text
platform-signal/
├── Cargo.toml
├── crates/
│   ├── signal-event/
│   ├── signal-protocol/
│   ├── signal-ingest/
│   ├── signal-buffer/
│   ├── signal-storage/
│   ├── signal-query/
│   ├── signal-rules/
│   ├── signal-findings/
│   └── signal-collector-sdk/
├── apps/
│   ├── signal-server/
│   ├── signal-agent/
│   └── signalctl/
├── collectors/
│   ├── file/
│   ├── journald/
│   └── http/
├── deploy/
│   ├── docker/
│   ├── helm/
│   └── terraform/
├── examples/
├── benchmarks/
├── docs/
└── tests/
    └── integration/
```

---

## 11. Architectural decisions to record as ADRs

Create ADRs for:

- ADR-001: Rust as implementation language
- ADR-002: monolith-first deployment
- ADR-003: canonical Signal Event model
- ADR-004: Parquet as MVP persisted format
- ADR-005: DataFusion as MVP query engine
- ADR-006: bounded WAL/backpressure behavior
- ADR-007: OSS mechanism / private policy boundary
- ADR-008: multi-arch Linux support
- ADR-009: stateless rule engine for MVP
- ADR-010: storage interfaces remain replaceable
