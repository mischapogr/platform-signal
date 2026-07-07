# External Overlay Integration

PLATFORM::SIGNAL provides generic mechanisms. An integrating repository owns
its metadata schemas, enrichment implementation, detection documents, runtime
configuration and deployment policy. Keep those files and fixtures in the
external repository; this guide and the SDK contain no organization policy or
sample private data.

## Repository and dependency boundary

The external repository is a sibling checkout named `platform-signal-private`
with its application under `overlays/example/`. The dependency points from the
private application into this OSS workspace during local co-development:

```toml
[dependencies]
signal-event = { path = "../../../platform-signal/crates/signal-event" }
signal-collector-sdk = { path = "../../../platform-signal/crates/signal-collector-sdk" }
signal-rules = { path = "../../../platform-signal/crates/signal-rules" }
```

The relative paths above are resolved from
`platform-signal-private/overlays/example/Cargo.toml`.
Published deployments must replace path dependencies with released crate
versions. No released-version qualification or publication is established by
this local workflow.

## SDK loading boundary

`OverlayPath::new`, `OverlayPath::from_env`, and `OverlayPath::resolve` select
the external directory. An explicit path takes precedence over
`SIGNAL_OVERLAY_PATH`; the SDK has no implicit default. Selection itself does
not read files. Implementations of `EnrichmentProvider::load` own and validate
their metadata schemas before returning an `Enricher`. `load_enricher` applies
the cooperative invocation deadline without spawning workers or tasks.

Implementations of `RuleProvider::load` return versioned `RuleDocument`
envelopes. The SDK accepts schema version 1 and bounds output to 64 documents,
64 KiB per YAML document, and 1 MiB total by default. Configurable ceilings are
1,024 documents, 2 MiB per document, and 16 MiB total. `load_rules` checks those
bounds and the document version; the consumer compiles the YAML and rejects
invalid predicates or duplicate rule IDs before readiness. The rule document
envelope uses strict serde fields. Provider code is trusted cooperative code:
it must bound its own reads and allocations, yield during async work, and honor
cancellation.

The application owns provider construction and invokes the enricher before
normal ingest. The normal server loads rule YAML from its configured external
rule directories. There is no compiled private extension or dynamic loader in
the OSS server. The event and finding APIs remain the integration surface.

## Local external integration gate

Build the private runner and OSS server, then run this command from the OSS
checkout. The runner's `--check` output is private-owned JSON with `event`,
`findings`, and overlay-relative `rule_directories`; private expected and input
fixtures are also read only from the external overlay.

```bash
cargo build --workspace --locked
cargo build -p signal-server
cargo build --manifest-path ../platform-signal-private/overlays/example/Cargo.toml
python3 scripts/check-overlay.py \
  --runner ../platform-signal-private/target/debug/platform-signal-private
```

Set `SIGNAL_OVERLAY_PATH` or pass `--overlay PATH` to select a different
external overlay. `--overlay` takes precedence. `--server PATH` can select a
different local OSS debug server binary. The gate requires both runner and
overlay paths to resolve outside the OSS checkout. It checks the private
enrichment result and expected detections, loads private rules into the normal
server, verifies authenticated admission and exact event/finding persistence,
forces a server restart with SIGKILL, verifies persistence again, and finishes
with SIGTERM. The gate uses temporary local data and does not publish artifacts
or qualify a released crate, container, or deployment.

Private metadata, rule content, expected event/finding fixtures, and their
schema details stay in the external repository. Extend this document only with
generic SDK or integration mechanics.
