//! Real agent/server acceptance gate, using isolated local child processes.

#[test]
fn offline_backup_restore_process_gate() -> Result<(), Box<dyn std::error::Error>> {
    let agent = std::path::PathBuf::from(env!("CARGO_BIN_EXE_signal-agent"));
    let server = std::env::var_os("SIGNAL_TEST_SERVER_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| agent.with_file_name("signal-server"));
    if !server.is_file() {
        return Err("build signal-server before running the offline restore gate".into());
    }
    let root = tempfile::tempdir()?;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/phase10-restore-process.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg(agent)
        .arg(server)
        .arg(root.path().join("rehearsal"))
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "offline restore gate failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    assert!(String::from_utf8(output.stdout)?.contains("Offline restore gate passed"));
    Ok(())
}

#[test]
fn agent_server_process_gate() -> Result<(), Box<dyn std::error::Error>> {
    let agent = std::path::PathBuf::from(env!("CARGO_BIN_EXE_signal-agent"));
    let server = std::env::var_os("SIGNAL_TEST_SERVER_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| agent.with_file_name("signal-server"));
    if !server.is_file() {
        return Err(format!(
            "build the real server first with cargo build -p signal-server, or set SIGNAL_TEST_SERVER_BINARY (missing {})",
            server.display()
        )
        .into());
    }
    let root = tempfile::tempdir()?;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/phase6-process.py");
    let output = std::process::Command::new("python3")
        .arg(script)
        .arg(agent)
        .arg(server)
        .arg(root.path())
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "agent process gate failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}
