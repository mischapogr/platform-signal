# Integration tests

`foundation.rs` is registered in `apps/signal-server/Cargo.toml`, so it runs with
`cargo test --workspace`. Its five tests check build identity and invoke bounded
Python standard-library process gates for WAL/Parquet/query/rule/finding recovery,
configuration failure, authentication, SIGTERM/SIGKILL and secret redaction.
`phase10-storage-process.py` causes a real OS file-create failure after durable
202 admission, checks no publication/checkpoint advancement, removes its own
fault sentinel, and verifies exact event/finding replay and a further restart.

Event tests are in `crates/signal-event/tests/contract.rs`. Ingest tests are in
`crates/signal-ingest/tests/http.rs`, including a real TCP gate sending 10,000
events with exact admission counts. Run the gate with:

```bash
cargo test -p signal-ingest ten_thousand_events -- --nocapture
```

The Phase 5 vertical-slice gate sends events, queries events/findings and verifies
both graceful and forced recovery. The Phase 6 agent process gate is registered
in `apps/signal-agent/tests/process.rs`. Container, Kubernetes and external overlay
gates are separate scripts under `scripts/`; their counts are separate from the
workspace Cargo tests. Process kill is not hardware power-loss evidence.

The same agent test target also registers `offline_backup_restore_process_gate`.
`phase10-restore-process.py` copies stopped synthetic server data, configuration,
rules, source fixture and pending agent spool twice, verifying SHA-256, modes and
ownership before restore startup. It checks pending WAL/spool replay, canonical
events/findings, the copied source's inode change and new cursor, and another
server restart. Original and backup inventories remain unchanged. This uses the
same local binaries, not a cross-version upgrade or a production backup tool.

For retained evidence, build both binaries and supply a **new** output directory:

```bash
cargo build -p signal-server -p signal-agent --locked
python3 tests/integration/phase10-restore-process.py target/debug/signal-agent target/debug/signal-server target/my-restore-rehearsal
```

The directory retains process logs, the immutable original/backup, restored
data, `inventory.json` and `report.json` with source/binary/inventory hashes.
Cargo uses an owned temporary directory and removes these artifacts afterward.
