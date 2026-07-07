# Signal MVP

## 1. MVP objective

The [product design envelope](27-product-architecture.md) positions this core as
the foundation for a self-hosted AWS-first log/security telemetry product for
small and mid-sized teams. Product profiles and production security/HA/S3 goals
are subsequent qualification milestones; they do not silently expand this core
MVP's existing release checklist or claim capabilities it lacks.

Prove that Signal can provide a useful, low-footprint log/security-event pipeline with a clean OSS/internal extension boundary.

The MVP must answer:

1. Can events be ingested reliably?
2. Can the process remain memory-bounded?
3. Can events be persisted cheaply?
4. Can users query recent persisted events?
5. Can simple rules generate findings?
6. Can a company-specific overlay enrich events and supply private rules without modifying OSS core?
7. Can the same artifacts run on AMD64 and ARM64?

### Security requirements and acceptance boundary — 2026-10-07

Security-event detection and SecOps response are target requirements. The current
MVP proves durable normalized-event ingestion, stateless detection and persisted
findings; it does not yet prove complete source collection or SecOps delivery.
The linked [source/detection catalog](source-detection-catalog.md),
[logical architecture](logical-architecture.md) and
[failure-domain contract](failure-domains.md) derive the next capabilities from
15 concrete requirements across AWS control-plane, IAM/security controls,
Kubernetes audit, authentication and host/runtime evidence.

The first five predicate requirements fit the current engine after external
normalization. Their synthetic fixtures are executable against `signal-server`.
The SDK now validates SourceCoverage assertions and assesses current/historical
coverage as a pure local mechanism; see the [accepted contract](source-coverage-contract.md).
The standalone coverage library also implements bounded history append/recovery,
authorized intake/retry and immutable corrections; pruning/scans and runtime
integration remain incomplete. Real source adapters and observers, independent
protected-evidence storage, window/state/correlation, alert delivery and SecOps feedback remain
post-MVP work. An absent finding is not proof that collection was healthy or that
no suspicious activity occurred. HTTP 202 continues to mean synced WAL admission,
not archive validation, completed detection or notification.

Preserve one server process and the current versioned event envelope. Public
mechanisms and generic requirements remain here; account topology, approvals,
asset classifications, actual detections, retention durations and SecOps policy
remain private. The [derived roadmap](04-implementation-plan.md#security-requirements-roadmap)
adds bounded tasks without turning every logical component into a service or
expanding the current release definition of done.

The [ingestion architecture audit](26-ingestion-architecture-audit.md) evaluates
AWS-native delivery, EKS, SaaS and site syslog against this implemented baseline.
It preserves the v1 envelope and monolith; its proposed source sequence remains
post-MVP rather than expanding this release's scope.

---

## 2. MVP user stories

### Developer

> As a developer, I can send application events to Signal and query them later.

### Platform engineer

> As a platform engineer, I can run Signal locally, in Docker and in Kubernetes with predictable CPU/memory limits.

### Security engineer

> As a security engineer, I can define a simple rule in YAML and receive a finding when an event matches.

### Company integrator

> As an internal integrator, I can add company metadata and private rules without forking the OSS repository.

---

## 3. In scope

### Ingest

- `POST /v1/events`
- `POST /v1/events/batch`
- JSON
- max request size
- input validation
- API token option
- admission metrics

### Event model

Required:

- schema version;
- ID;
- event timestamp;
- observed timestamp;
- source;
- severity;
- message or nonempty structured attributes;
- attributes.

Optional:

- resource;
- trace ID;
- span ID;
- tenant/account;
- tags.

### Buffer

- bounded in-memory queue;
- local WAL;
- restart replay;
- configurable disk maximum;
- queue depth metrics;
- rejection/drop counters.

### Storage

- local filesystem;
- Parquet;
- date/hour partitioning;
- batched writes;
- configurable compression.

### Query

Filters:

- from/to;
- contains;
- severity;
- source name/type;
- resource kind/id;
- arbitrary attribute equality;
- limit.

Output:

- JSON;
- deterministic ordering;
- query duration metadata.

### Rules

- YAML rule files;
- stateless per-event match;
- `all` / `any`;
- `eq`;
- `neq`;
- `contains`;
- `exists`;
- severity/title output;
- rule validation on startup.

### Findings

- persisted findings;
- list endpoint;
- rule ID;
- source event IDs;
- timestamp;
- severity;
- title.

### Agent

- file tail;
- stdin;
- HTTP output;
- batch;
- retries;
- local bounded buffer.

### Operations

- `/healthz`;
- `/readyz`;
- `/metrics`;
- structured logs;
- Docker image;
- Helm chart;
- AMD64 + ARM64 images.

---

## 4. Explicitly out of scope for MVP

- UI;
- distributed search cluster;
- metrics backend;
- APM;
- traces backend;
- eBPF;
- anomaly detection;
- ML;
- topology maps;
- full SIEM correlation;
- multi-region replication;
- exactly-once processing;
- complex query language;
- user management;
- enterprise SSO;
- long-term index optimization;
- automatic tiering;
- alert escalation workflows.

These may become later projects. They should not delay MVP.

The security roadmap also excludes these capabilities from the initial release:
coverage-aware assessments; tiered protected-stream reserves; source-native audit
validation; security-owned S3/Object Lock deployment; durable findings delivery;
stateful/time-window/correlation engines; and automated SecOps response. These are
explicit follow-on requirements with separate acceptance, rather than implied
features of the current WAL or stateless engine. Open ARM64, actual EKS, remote
CI and released-dependency gates in [release readiness](21-release-readiness.md)
continue to apply to the existing MVP.

---

## 5. MVP API sketch

### POST `/v1/events`

```json
{
  "timestamp": "2026-10-06T12:00:00Z",
  "source": {
    "type": "application",
    "name": "demo-api"
  },
  "severity": "info",
  "message": "request completed",
  "attributes": {
    "environment": "dev",
    "status": 200
  }
}
```

Response:

```json
{
  "accepted": 1,
  "rejected": 0
}
```

### POST `/v1/events/batch`

```json
{
  "events": [
    {
      "timestamp": "2026-10-06T12:00:00Z",
      "source": {"type":"application","name":"demo-api"},
      "message": "hello"
    }
  ]
}
```

### GET `/v1/events`

Example:

```text
/v1/events?from=2026-10-06T00:00:00Z&to=2026-10-07T00:00:00Z&contains=failed&attribute.environment=prod&limit=100
```

### GET `/v1/findings`

Filters:

- from/to;
- severity;
- rule ID;
- limit.

---

## 6. MVP rule format

```yaml
apiVersion: signal.dev/v1
kind: Rule
metadata:
  id: auth.login-failure
  name: Failed login example
spec:
  severity: medium
  match:
    all:
      - field: source.type
        eq: application
      - field: message
        contains: "login failed"
  finding:
    title: "Failed login detected"
```

Validation must fail fast on invalid rule files.

Detection severity is `low`, `medium`, `high` or `critical`; it is independent of
the event's log severity. Example rules illustrate mechanisms and are not company
policy. Private namespaced rules remain in the overlay repository.

---

## 7. Configuration

Example:

```yaml
server:
  listen: "0.0.0.0:8080"

ingest:
  max_request_bytes: 1048576
  api_token_env: SIGNAL_API_TOKEN

buffer:
  memory_events: 10000
  wal_directory: "./data/wal"
  max_wal_bytes: 1073741824

storage:
  type: parquet
  directory: "./data/events"
  flush_events: 5000
  flush_interval: "5s"

rules:
  directories:
    - "./rules"

findings:
  directory: "./data/findings"

telemetry:
  metrics_listen: "0.0.0.0:9090"
```

---

## 8. MVP success criteria

### Functional

- ingest single event;
- ingest batch;
- invalid events rejected;
- accepted events survive restart;
- events become queryable;
- filters return correct results;
- matching rule produces finding;
- non-matching event produces no finding;
- `demo` enricher attaches company metadata;
- private `demo` rule executes without OSS modification.

### Operational

- server runs as non-root;
- graceful shutdown;
- SIGTERM flush/recovery behavior tested;
- queue is bounded;
- WAL is bounded;
- health/readiness work;
- metrics include:
  - events accepted;
  - events rejected;
  - queue depth;
  - WAL bytes;
  - storage writes;
  - rule evaluations;
  - findings emitted;
  - query count;
  - query latency.

### Build

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --check`
- AMD64 container builds
- ARM64 container builds

---

## 9. MVP demo scenario

1. Start Signal.
2. Start `demo-signal` configuration.
3. Send application login events.
4. Demo enricher adds:

```json
{
  "company": "demo",
  "application_owner": "identity-team",
  "environment": "prod"
}
```

5. Private rule matches failed login.
6. Query original event.
7. Query emitted finding.
8. Restart Signal.
9. Query event/finding again.
10. Show metrics.

This scenario is the release gate for `v0.1.0`.
