//! Real monolith coverage lifecycle/HTTP/crash proof using synthetic assertions.
#[test]
fn coverage_history_http_bootstrap_and_crash_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/coverage-process.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_signal-server"))
        .arg(root.path())
        .output()?;
    assert!(
        output.status.success(),
        "coverage process gate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("Coverage process gate passed"));
    Ok(())
}
