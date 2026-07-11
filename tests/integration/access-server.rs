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

#[test]
fn authenticated_server_scopes_persisted_rows_and_recovers_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
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
