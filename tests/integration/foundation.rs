//! Executable identity and real HTTP/WAL/Parquet restart evidence.

use std::process::Command;

#[test]
fn storage_os_create_failure_preserves_admitted_events_until_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/phase10-storage-process.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_signal-server"))
        .arg(temp.path())
        .output()?;
    assert!(
        output.status.success(),
        "storage failure gate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("Storage OS failure gate passed"));
    Ok(())
}

#[test]
fn server_binary_reports_its_build_identity() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_signal-server"))
        .arg("--version")
        .output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(concat!("signal-server ", env!("CARGO_PKG_VERSION"))));
    Ok(())
}

#[tokio::test]
async fn real_server_process_persists_acknowledged_events_across_restarts()
-> Result<(), Box<dyn std::error::Error>> {
    use signal_storage::{OperationContext, ParquetStore, StorageConfig};
    use std::time::Duration;

    let temp = tempfile::TempDir::new()?;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/phase3-process.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_signal-server"))
        .arg(temp.path())
        .output()?;
    assert!(
        output.status.success(),
        "process gate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("Process gate passed"));
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(temp.path().join("expected.json"))?)?;
    let stream = uuid::Uuid::parse_str(
        expected["stream_id"]
            .as_str()
            .ok_or("missing original WAL identity")?,
    )?;
    let events: Vec<signal_event::SignalEvent> =
        serde_json::from_value(expected["events"].clone())?;
    let store = ParquetStore::open(
        StorageConfig {
            directory: temp.path().join("events"),
            max_batch_events: 10,
            max_batch_bytes: 65_536,
            max_event_bytes: 2_048,
            ..Default::default()
        },
        stream,
    )
    .await?;
    assert_eq!(store.metrics().high_water as usize, events.len());
    let mut after = 0;
    let mut actual = Vec::new();
    loop {
        let batch = store
            .read_batch(
                after,
                10,
                65_536,
                OperationContext::new(Duration::from_secs(5)),
            )
            .await?;
        if batch.is_empty() {
            break;
        }
        for row in batch {
            assert_eq!(row.sequence, after + 1);
            after = row.sequence;
            actual.push(row.event);
        }
    }
    assert_eq!(actual.len(), 101);
    // Compare canonical events: IDs, nanosecond timestamps, nested numbers and every optional field.
    assert_eq!(actual, events);
    store
        .shutdown(OperationContext::new(Duration::from_secs(5)))
        .await?;
    Ok(())
}

#[test]
fn real_server_process_queries_persisted_events_across_restarts()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/phase4-process.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_signal-server"))
        .arg(temp.path())
        .output()?;
    assert!(
        output.status.success(),
        "query process gate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("Query process gate passed"));
    Ok(())
}

#[test]
fn real_server_process_coordinates_events_findings_and_wal_recovery()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/phase5-process.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_signal-server"))
        .arg(temp.path())
        .output()?;
    assert!(
        output.status.success(),
        "coordinated process gate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8(output.stdout)?.contains("Process slice gate passed"));
    Ok(())
}
