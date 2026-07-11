//! Real monolith, TLS provider, scoped WAL admission and persisted query proof.
#[test]
fn identity_fixture_bounds_output_interruptions_and_silent_tls_handshakes()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("python3")
        .arg(root.join("scripts/run-ci-check.py"))
        .args(["--name", "identity-fixture", "--timeout", "20", "--output"])
        .arg(temp.path().join("qualification"))
        .args(["--", "python3"])
        .arg(root.join("scripts/test-access-fixture.py"))
        .output()?;
    assert!(
        output.status.success(),
        "identity fixture failures: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[tokio::test]
async fn authenticated_server_scopes_persisted_rows_and_recovers_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    // Seed real durable but unprocessed WAL before native-mode startup. Its
    // canonical account matches the reader, but admission provenance is unknown.
    use signal_protocol::EventSink;
    let event: signal_event::SignalEvent = serde_json::from_value(serde_json::json!({
        "schema_version":1,"id":uuid::Uuid::new_v4(),
        "timestamp":"2026-10-05T00:00:00Z","observed_at":"2026-10-05T00:00:00Z",
        "source":{"type":"synthetic"},"severity":"info","message":"synthetic retained backlog",
        "resource":{"kind":"host","id":"resource-a","account_id":"a"},"attributes":{},"tags":[]
    }))?;
    let wal = signal_buffer::DurableBuffer::open(signal_buffer::BufferConfig {
        directory: temp.path().join("retained-wal"),
        ..Default::default()
    })
    .await?;
    wal.admit(event.clone()).await?;
    assert_eq!(wal.snapshot().checkpoint, 0);
    wal.shutdown().await?;
    std::fs::write(
        temp.path().join("retained-event.json"),
        serde_json::to_vec(&event)?,
    )?;
    let coverage = signal_coverage::CoverageConfig::default();
    std::fs::write(
        temp.path().join("coverage-limits.json"),
        serde_json::to_vec(&serde_json::json!({
        "max_payloads":coverage.max_payloads,"max_identities":coverage.max_identities,
        "max_bindings":coverage.max_bindings,"max_ledger_bytes":coverage.max_ledger_bytes,
        "max_database_pages":coverage.max_database_pages,"max_journal_bytes":coverage.max_journal_bytes,
        "operation_capacity":coverage.operation_capacity,"transient_memory_bytes":coverage.transient_memory_bytes,
        "worker_memory_bytes":coverage.worker_memory_bytes,"max_vm_steps":coverage.max_vm_steps,
        "operation_timeout_ms":1000}))?,
    )?;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/access-server-process.py");
    let runner =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-ci-check.py");
    let output = std::process::Command::new("python3")
        .arg(runner)
        .args(["--name", "identity-server", "--timeout", "100", "--output"])
        .arg(temp.path().join("qualification"))
        .args(["--", "python3"])
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_signal-server"))
        .arg(temp.path())
        .output()?;
    assert!(
        output.status.success(),
        "identity server acceptance failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("Identity server gate passed"));
    Ok(())
}
