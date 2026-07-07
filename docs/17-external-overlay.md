# Phase 7-B — External overlay integration gate

This document describes generic local verification for an external application.
The separate repository `platform-signal-private` owns its
`overlays/example` application, schemas, metadata, rules, expected outputs and
fixtures. None of those policy inputs belong in this repository.

The private application uses path dependencies into this workspace during local
co-development. The path dependencies prove local source compatibility only;
released crate qualification is still required before a published deployment.
The application constructs its providers, validates its own metadata schema,
loads enrichment and returns version 1 `RuleDocument` values. The normal OSS
server consumes the external YAML rule directories. There is no private module
compiled into the server and no dynamic plugin loader.

## Prerequisites and command

Run in this checkout with the sibling repository available:

```bash
cargo build --workspace --locked
cargo build -p signal-server
cargo build --manifest-path ../platform-signal-private/Cargo.toml --locked
python3 scripts/check-overlay.py \
  --runner ../platform-signal-private/target/debug/platform-signal-private \
  --overlay ../platform-signal-private/overlays/example
```

The gate accepts `--overlay PATH` or `SIGNAL_OVERLAY_PATH`, with the command
option taking precedence. `--server PATH` overrides the default local
`target/debug/signal-server`. The runner and selected overlay must resolve
outside the OSS checkout. The private runner implements `--check` and prints a
bounded JSON object containing `event`, `findings`, and overlay-relative
`rule_directories`. The gate reads private fixtures from the overlay; fixture
content and policy are not copied here.

The gate compares the enriched event with the external expected fixture and
checks canonical identity against the external input fixture. It then starts
the normal OSS server with the external rule directories, checks authenticated
admission, queries the exact event and expected findings, stops the process
with SIGKILL, confirms both records remain after restart, and exits through
SIGTERM. Server data is temporary. The runner output and errors are bounded;
the gate prints no private fixture or provider diagnostics.

## Evidence boundary

This is Linux local integration evidence for path dependencies, provider
loading, enrichment, native rule evaluation and durable event/finding behavior.
It does not establish released crate compatibility, multi-architecture images,
Helm rendering, Kubernetes behavior, EKS behavior, or production readiness.
The local gate passed: one event and one finding persisted through forced
server restart, followed by successful graceful shutdown. Root workspace and
private package counts and the independent review result are recorded in
[implementation progress](07-progress.md). Phase 8 owns packaging and deployment
qualification.
