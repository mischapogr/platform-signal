//! Actual private synthetic PKI -> agent -> monolith -> retained-ID rotation.
#[test]
fn mutual_tls_denial_retained_spool_and_restart_rotation() -> Result<(), Box<dyn std::error::Error>>
{
    let server = std::path::PathBuf::from(env!("CARGO_BIN_EXE_signal-server"));
    let agent = server.with_file_name("signal-agent");
    if !agent.is_file() {
        return Err("build signal-agent before the actual mTLS process gate".into());
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let scratch = tempfile::tempdir()?;
    let output = std::process::Command::new("python3")
        .arg(root.join("scripts/run-ci-check.py"))
        .args(["--name", "transport-server", "--timeout", "180", "--output"])
        .arg(scratch.path().join("runner"))
        .args(["--", "python3"])
        .arg(root.join("tests/integration/transport-server-process.py"))
        .arg(server)
        .arg(agent)
        .arg(scratch.path().join("qualification"))
        .output()?;
    assert!(
        output.status.success(),
        "actual transport gate failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("Transport server gate passed"));
    Ok(())
}
