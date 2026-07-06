# PLATFORM::SIGNAL — OSS + External Overlay MVP Starter Pack

## Implementation status

The core provides versioned events, validated HTTP ingest, bounded durable WAL
admission and recovery, Parquet persistence, URL queries, rule evaluation, and
durable findings. HTTP 202 means the event was synced to WAL; the consumer
then publishes Parquet, evaluates configured rules, persists findings, and
advances the WAL checkpoint. Phases 0–6 are implemented and verified locally,
including the Docker Compose demonstration and edge agent on Linux AMD64. Phase
7-A generic SDK is locally accepted on Linux AMD64. Phase 7-B uses the sibling
`platform-signal-private/overlays/example` application; implementation is
complete locally: the private package and external server process gates passed.
Phase 8's hardened container, Helm chart, local Kubernetes persistence and
fresh supply-chain scans passed on Linux AMD64. Phase 10 adds bounded parser/WAL
property campaigns, a real storage failure/replay gate, measured pipeline load
profiles, a threat model and upgrade/release documentation.
Native ARM64, EKS, remote CI and released external dependencies remain unverified.
This is not a v0.1.0 release. Current evidence and next tasks are in
[docs/07-progress.md](docs/07-progress.md).

```bash
cargo run -p signal-server -- --version
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-workspace.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[development tooling](docs/08-development-tooling.md) for setup. Licensed under
[Apache-2.0](LICENSE). No production release is available yet.

Run the current server with `cargo run -p signal-server`, then use the
[HTTP ingest examples](docs/09-phase1-ingest.md) and
[durable WAL configuration](docs/10-phase2-wal.md) and
[Parquet storage configuration](docs/12-phase3-storage.md),
[Phase 4 query documentation](docs/13-phase4-query.md), and
[Phase 5 rules and findings](docs/14-phase5-core.md), and the
[Phase 6 agent](docs/15-phase6-agent.md) and
[Collector and Enricher SDK](docs/16-collector-sdk.md). The generic external
overlay contract and local gate are in [03](docs/03-demo-company-overlay.md)
and [17](docs/17-external-overlay.md). See [packaging](docs/19-packaging.md),
[benchmark measurements](BENCHMARKS.md), [threat model](docs/20-threat-model.md)
and [release readiness](docs/21-release-readiness.md) for current qualification.
The [native qualification runner](docs/22-native-qualification.md) reuses an
existing image and retains parser/load reports without another image build.
The findings endpoint is
`GET /v1/findings`; Compose was locally qualified on Linux AMD64.

This package defines the starting point for an open-source **Signal** observability/security-event platform and a separate private integration layer.

## Recommended repository split

```text
platform-signal                         # public OSS checkout
platform-signal-private/overlays/example # private integration application
```

The dependency direction is always:

```text
platform-signal-private/overlays/example  --->  platform-signal
```

`platform-signal` must never import or depend on the private repository.

## Core rule

> **Open source contains mechanisms. Company repositories contain policy, environment, identity, ownership and proprietary detections.**

## MVP goal

Ingest structured and unstructured logs/events, normalize them into a stable event envelope, persist them cheaply, query them, evaluate simple rules, and produce findings.

The MVP intentionally does **not** attempt to reproduce Datadog/Dynatrace feature breadth.

## Default implementation assumptions

- Language: Rust
- Async runtime: Tokio
- HTTP/API: Axum
- Serialization: Serde
- Internal event encoding: JSON initially; Protobuf/Arrow-compatible interfaces can follow
- Object storage: S3-compatible abstraction
- MVP local storage: filesystem + Parquet
- Query engine: Apache DataFusion
- Metadata/config: files first; SQLite/PostgreSQL later if required
- Metrics: Prometheus/OpenMetrics endpoint
- Tracing: OpenTelemetry
- Deployment: Docker + Helm
- AWS deployment target: EKS or EC2
- Architectures: `linux/amd64` and `linux/arm64`

## Documents

1. [01-architecture.md](docs/01-architecture.md)
2. [02-mvp.md](docs/02-mvp.md)
3. [03-demo-company-overlay.md](docs/03-demo-company-overlay.md)
4. [04-implementation-plan.md](docs/04-implementation-plan.md)
5. [05-implementation-prompts.md](docs/05-implementation-prompts.md)
6. [06-definition-of-done.md](docs/06-definition-of-done.md)
7. [07-progress.md](docs/07-progress.md)
8. [08-development-tooling.md](docs/08-development-tooling.md)
9. [09-phase1-ingest.md](docs/09-phase1-ingest.md)
10. [10-phase2-wal.md](docs/10-phase2-wal.md)
11. [11-model-work-plan.md](docs/11-model-work-plan.md)
12. [12-phase3-storage.md](docs/12-phase3-storage.md)
13. [13-phase4-query.md](docs/13-phase4-query.md)
14. [14-phase5-core.md](docs/14-phase5-core.md)
15. [15-phase6-agent.md](docs/15-phase6-agent.md)
16. [16-collector-sdk.md](docs/16-collector-sdk.md)
17. [17-external-overlay.md](docs/17-external-overlay.md)

The [company integration design proposal](docs/24-company-integration-proposal.md)
walks through source identity, enrichment, detection and external delivery. It
describes candidate post-MVP work; the current contracts and release gates remain
the implementation baseline.

The [findings cursor contract proposal](docs/25-findings-cursor-proposal.md)
specifies a bounded append-order feed and history validation across restart and
restore; it is a draft for future implementation.

The security requirements are linked as three artifacts:
[source/detection catalog](docs/source-detection-catalog.md),
[logical architecture](docs/logical-architecture.md) and
[failure domains](docs/failure-domains.md). They define 15 generic requirements,
SourceCoverage and the post-MVP roadmap while preserving the single-server MVP.
The [synthetic requirement checker](scripts/check-security-requirements.py)
validates the catalog and optionally exercises five existing predicates; source
collection, coverage-aware detection and stateful detection remain proposed.

The [SourceCoverage v1 contract](docs/source-coverage-contract.md) formalizes
bounded record/profile schemas and recovery fixtures. Its offline checker verifies
structural cases; the SDK now implements pure semantic validation and current/historical
assessment. The standalone
[`signal-coverage` library](crates/signal-coverage/README.md) now adds explicit
local-root ownership, atomic prepared append, immutable receipts and bounded
recovery/inspection. It passes local process-crash and cancellation tests without
changing server admission or assessing live source coverage.
The [intake/history contract](docs/source-coverage-history-contract.md) defines
bounded retry/retention/correction and recovery expectations; its 56 storage cases
are planned fixtures. Trusted application-grant intake and exact-byte original
receipt replay and bounded append-only correction admission now have 45 focused
library tests. Payload-prefix pruning is next; identity pruning, scans and observers
follow separately.

## First executable milestone

Phase 5 is locally complete: the server persists events to Parquet, evaluates
configured rules, writes findings and serves the findings API. The Compose
demonstration passed locally. Phases 6–8 and 10 and the remaining external/release
gates are still required for v0.1.0.

A developer should be able to run:

```bash
docker compose up
```

then send:

```bash
curl -X POST http://localhost:8080/v1/events \
  -H 'content-type: application/json' \
  -d '{
    "timestamp":"2026-10-06T12:00:00Z",
    "source":{"type":"application","name":"example-api"},
    "message":"user login failed",
    "attributes":{"user":"alice","env":"dev"}
  }'
```

and query:

```bash
curl 'http://localhost:8080/v1/events?contains=login'
```

If a configured rule matches, Signal should also expose a finding through:

```bash
curl http://localhost:8080/v1/findings
```

The public [synthetic vendor log corpus](examples/logs/README.md) supplies 55 native/canonical reference cases across 11 AWS, Cloudflare, Microsoft 365, Cato VPN and FortiGate source families. Private overlays reuse these fixtures while retaining their own policy and response expectations.
