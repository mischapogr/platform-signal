//! Real filesystem recovery and admission policy contracts.
use signal_buffer::{BufferConfig, BufferError, DurableBuffer, Policy};
use signal_event::{IngestEvent, SignalEvent};
use signal_protocol::{AdmissionError, EventSink};
use std::{fs, time::Duration};
use tempfile::TempDir;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn config(directory: &TempDir) -> BufferConfig {
    BufferConfig {
        directory: directory.path().join("wal"),
        max_events: 8,
        max_memory_bytes: 8192,
        max_record_bytes: 1024,
        segment_bytes: 1064,
        max_wal_bytes: 8192,
        max_segments: 8,
        operation_timeout: Duration::from_secs(2),
        block_timeout: Duration::from_millis(500),
        ..Default::default()
    }
}
fn event(message: &str) -> Result<SignalEvent> {
    let input: IngestEvent =
        serde_json::from_value(serde_json::json!({"timestamp":"2026-10-06T12:00:00Z",
        "source":{"type":"test"}, "message":message,
        "attributes":{"tenant.owner":{"nested":[true,9223372036854775808123456789u128]}}}))?;
    Ok(input.normalize(chrono::Utc::now())?)
}
fn segments(config: &BufferConfig) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(&config.directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "wal") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

#[tokio::test]
async fn append_read_restart_ack_reclaim_preserves_ids_order_and_sequence() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let buffer = DurableBuffer::open(config.clone()).await?;
    let mut ids = Vec::new();
    for i in 0..7 {
        let event = event(&format!("event-{i}"))?;
        ids.push(event.id);
        buffer.admit(event).await?;
    }
    let batch = buffer.read_batch(8, 8192).await?;
    assert_eq!(
        batch.iter().map(|item| item.event.id).collect::<Vec<_>>(),
        ids
    );
    assert_eq!(
        batch.iter().map(|item| item.sequence).collect::<Vec<_>>(),
        (1..=7).collect::<Vec<_>>()
    );
    assert!(buffer.snapshot().wal_segments >= 3);
    assert!(matches!(buffer.ack(8).await, Err(BufferError::InvalidAck)));
    buffer.ack(3).await?;
    let before = buffer.snapshot();
    assert_eq!(before.depth, 4);
    assert!(before.wal_segments < 4);
    buffer.shutdown().await?;
    let replay = DurableBuffer::open(config.clone()).await?;
    assert_eq!(replay.snapshot().replayed, 4);
    assert!(matches!(replay.ack(7).await, Err(BufferError::InvalidAck)));
    let batch = replay.read_batch(8, 8192).await?;
    assert_eq!(
        batch.iter().map(|item| item.event.id).collect::<Vec<_>>(),
        ids[3..]
    );
    replay.ack(7).await?;
    replay.ack(7).await?;
    assert_eq!(replay.snapshot().wal_bytes, 128);
    assert_eq!(replay.snapshot().wal_segments, 0);
    replay.shutdown().await?;
    let next = DurableBuffer::open(config).await?;
    next.admit(event("after reclaim")?).await?;
    assert_eq!(next.read_batch(8, 8192).await?[0].sequence, 8);
    next.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn read_is_repeatable_bounded_and_does_not_ack() -> Result {
    let temp = TempDir::new()?;
    let buffer = DurableBuffer::open(config(&temp)).await?;
    let event = event("read bounds")?;
    let size = serde_json::to_vec(&event)?.len();
    let id = event.id;
    buffer.admit(event).await?;
    assert!(buffer.read_batch(1, size - 1).await?.is_empty());
    assert!(matches!(
        buffer.read_batch(0, 8192).await,
        Err(BufferError::Config(_))
    ));
    assert!(matches!(
        buffer.read_batch(9, 8192).await,
        Err(BufferError::Config(_))
    ));
    assert!(matches!(
        buffer.read_batch(8, 8193).await,
        Err(BufferError::Config(_))
    ));
    for _ in 0..2 {
        assert_eq!(buffer.read_batch(1, size).await?[0].event.id, id);
    }
    assert_eq!(buffer.snapshot().depth, 1);
    assert_eq!(buffer.snapshot().checkpoint, 0);
    buffer.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn incomplete_last_record_truncates_only_tail_and_reuses_uncommitted_sequence() -> Result {
    for tail in [0, 1, 7, 19, 20, 21, 40, 80] {
        let temp = TempDir::new()?;
        let mut config = config(&temp);
        config.segment_bytes = 4096;
        let buffer = DurableBuffer::open(config.clone()).await?;
        let first = event("surviving")?;
        let id = first.id;
        buffer.admit(first).await?;
        let path = segments(&config)?.remove(0);
        let valid = fs::metadata(&path)?.len();
        buffer.admit(event("uncommitted tail")?).await?;
        buffer.shutdown().await?;
        fs::OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(valid + tail)?;
        let replay = DurableBuffer::open(config.clone()).await?;
        let batch = replay.read_batch(8, 8192).await?;
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].event.id, id);
        assert_eq!(fs::metadata(&path)?.len(), valid);
        assert_eq!(replay.snapshot().truncated_records, u64::from(tail != 0));
        replay.admit(event("replacement")?).await?;
        assert_eq!(replay.read_batch(8, 8192).await?[1].sequence, 2);
        replay.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn partial_final_segment_header_is_recoverable() -> Result {
    for tail in [0, 1, 8, 19] {
        let temp = TempDir::new()?;
        let config = config(&temp);
        let buffer = DurableBuffer::open(config.clone()).await?;
        buffer.admit(event("first")?).await?;
        buffer.shutdown().await?;
        let path = config.directory.join("00000000000000000002.wal");
        fs::write(&path, vec![0; tail])?;
        let replay = DurableBuffer::open(config).await?;
        assert_eq!(replay.snapshot().depth, 1);
        assert!(!path.exists());
        replay.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn complete_header_payload_and_checkpoint_corruption_fail_without_truncation() -> Result {
    for offset in [0, 8, 16, 20, 24, 32, 36, 40, 80] {
        let temp = TempDir::new()?;
        let config = config(&temp);
        let buffer = DurableBuffer::open(config.clone()).await?;
        buffer.admit(event("CRC proof")?).await?;
        buffer.shutdown().await?;
        let path = segments(&config)?.remove(0);
        let mut bytes = fs::read(&path)?;
        bytes[offset] ^= 1;
        fs::write(&path, &bytes)?;
        assert!(
            matches!(
                DurableBuffer::open(config).await,
                Err(BufferError::Corrupt(_))
            ),
            "offset {offset}"
        );
        assert_eq!(fs::read(path)?, bytes);
    }
    for offset in [0, 8, 16, 24] {
        let temp = TempDir::new()?;
        let config = config(&temp);
        let buffer = DurableBuffer::open(config.clone()).await?;
        buffer.admit(event("checkpoint")?).await?;
        buffer.shutdown().await?;
        let path = config.directory.join("checkpoint");
        let mut bytes = fs::read(&path)?;
        bytes[offset] ^= 1;
        fs::write(&path, &bytes)?;
        assert!(matches!(
            DurableBuffer::open(config).await,
            Err(BufferError::Corrupt(_))
        ));
        assert_eq!(fs::read(path)?, bytes);
    }
    Ok(())
}

#[tokio::test]
async fn interior_truncation_missing_segment_and_missing_checkpoint_fail() -> Result {
    for damage in [0, 1, 2] {
        let temp = TempDir::new()?;
        let config = config(&temp);
        let buffer = DurableBuffer::open(config.clone()).await?;
        for _ in 0..5 {
            buffer.admit(event(&"x".repeat(300))?).await?;
        }
        buffer.shutdown().await?;
        let files = segments(&config)?;
        assert!(files.len() >= 3);
        match damage {
            0 => {
                let size = fs::metadata(&files[0])?.len();
                fs::OpenOptions::new()
                    .write(true)
                    .open(&files[0])?
                    .set_len(size - 1)?;
            }
            1 => fs::remove_file(&files[1])?,
            _ => fs::remove_file(config.directory.join("checkpoint"))?,
        }
        assert!(matches!(
            DurableBuffer::open(config).await,
            Err(BufferError::Corrupt(_))
        ));
    }
    Ok(())
}

#[tokio::test]
async fn reject_new_count_byte_disk_and_segment_quotas_preserve_accepted_events() -> Result {
    for dimension in [0, 1, 2, 3] {
        let temp = TempDir::new()?;
        let mut config = config(&temp);
        let first = event(&"x".repeat(300))?;
        let id = first.id;
        let size = serde_json::to_vec(&first)?.len();
        match dimension {
            0 => config.max_events = 1,
            1 => {
                config.max_memory_bytes = size;
                config.max_record_bytes = size;
                config.segment_bytes = size as u64 + 40;
            }
            2 => {
                config.max_wal_bytes = 1192;
            }
            3 => config.max_segments = 1,
            _ => {}
        }
        let buffer = DurableBuffer::open(config.clone()).await?;
        buffer.admit(first).await?;
        assert_eq!(
            buffer.admit(event(&"x".repeat(300))?).await,
            Err(AdmissionError::Full),
            "dimension {dimension}"
        );
        let metrics = buffer.snapshot();
        assert_eq!(metrics.depth, 1);
        assert_eq!(metrics.rejected, 1);
        assert_eq!(metrics.accepted, 1);
        assert!(metrics.wal_bytes <= config.max_wal_bytes);
        assert_eq!(buffer.read_batch(1, size).await?[0].event.id, id);
        buffer.shutdown().await?;
        let replay = DurableBuffer::open(config).await?;
        assert_eq!(replay.snapshot().depth, 1);
        replay.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn drop_oldest_checkpoints_loss_and_keeps_newest_across_restart() -> Result {
    let temp = TempDir::new()?;
    let mut config = config(&temp);
    config.policy = Policy::DropOldest;
    config.max_events = 2;
    let buffer = DurableBuffer::open(config.clone()).await?;
    let mut ids = Vec::new();
    for i in 0..5 {
        let event = event(&format!("drop-{i}"))?;
        ids.push(event.id);
        buffer.admit(event).await?;
    }
    assert_eq!(buffer.snapshot().dropped, 3);
    assert_eq!(buffer.snapshot().checkpoint, 3);
    buffer.shutdown().await?;
    let replay = DurableBuffer::open(config).await?;
    assert_eq!(replay.snapshot().dropped, 3);
    assert_eq!(replay.snapshot().depth, 2);
    assert_eq!(
        replay
            .read_batch(2, 8192)
            .await?
            .iter()
            .map(|item| item.event.id)
            .collect::<Vec<_>>(),
        ids[3..]
    );
    replay.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn drop_oldest_reclaims_disk_and_oversized_event_never_drops_existing() -> Result {
    let temp = TempDir::new()?;
    let mut config = config(&temp);
    config.policy = Policy::DropOldest;
    config.max_wal_bytes = 1192;
    let buffer = DurableBuffer::open(config).await?;
    for _ in 0..4 {
        buffer.admit(event(&"x".repeat(300))?).await?;
    }
    assert_eq!(buffer.snapshot().depth, 1);
    assert_eq!(buffer.snapshot().dropped, 3);
    assert_eq!(
        buffer.admit(event(&"x".repeat(2000))?).await,
        Err(AdmissionError::Full)
    );
    assert_eq!(buffer.snapshot().dropped, 3);
    buffer.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn block_timeout_and_ack_wakeup_are_bounded() -> Result {
    let temp = TempDir::new()?;
    let mut config = config(&temp);
    config.policy = Policy::BlockWithTimeout;
    config.max_events = 1;
    let buffer = std::sync::Arc::new(DurableBuffer::open(config).await?);
    buffer.admit(event("first")?).await?;
    assert_eq!(
        buffer.admit(event("timeout")?).await,
        Err(AdmissionError::Full)
    );
    assert_eq!(buffer.snapshot().rejected, 1);
    assert!(buffer.snapshot().timeouts >= 1);
    let task_buffer = buffer.clone();
    let next = event("after ack")?;
    let task = tokio::spawn(async move { task_buffer.admit(next).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    let batch = buffer.read_batch(1, 8192).await?;
    buffer.ack(batch[0].sequence).await?;
    task.await??;
    assert_eq!(buffer.snapshot().depth, 1);
    assert_eq!(buffer.snapshot().accepted, 2);
    buffer.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cancel_and_close_release_waiters_without_discarding_pending() -> Result {
    let temp = TempDir::new()?;
    let mut config = config(&temp);
    config.max_events = 1;
    config.max_waiters = 1;
    config.policy = Policy::BlockWithTimeout;
    config.block_timeout = Duration::from_secs(1);
    let buffer = std::sync::Arc::new(DurableBuffer::open(config.clone()).await?);
    buffer.admit(event("retained")?).await?;
    let task_buffer = buffer.clone();
    let pending = event("cancelled")?;
    let task = tokio::spawn(async move { task_buffer.admit(pending).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(buffer.snapshot().waiters, 1);
    assert_eq!(
        buffer.admit(event("exceeds waiters")?).await,
        Err(AdmissionError::Full)
    );
    task.abort();
    assert!(task.await.is_err());
    assert_eq!(buffer.snapshot().waiters, 0);
    let task_buffer = buffer.clone();
    let pending = event("closed")?;
    let task = tokio::spawn(async move { task_buffer.admit(pending).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    buffer.close();
    assert_eq!(task.await?, Err(AdmissionError::Closed));
    assert_eq!(
        buffer.admit(event("stopped")?).await,
        Err(AdmissionError::Closed)
    );
    assert_eq!(buffer.read_batch(1, 8192).await?.len(), 1);
    buffer.shutdown().await?;
    let replay = DurableBuffer::open(config).await?;
    assert_eq!(replay.snapshot().depth, 1);
    replay.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn directory_lock_unknown_files_symlinks_and_replay_capacity_fail_safely() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let buffer = DurableBuffer::open(config.clone()).await?;
    assert!(matches!(
        DurableBuffer::open(config.clone()).await,
        Err(BufferError::Locked)
    ));
    buffer.admit(event("a")?).await?;
    buffer.admit(event("b")?).await?;
    buffer.shutdown().await?;
    let mut small = config.clone();
    small.max_events = 1;
    assert!(matches!(
        DurableBuffer::open(small).await,
        Err(BufferError::Config(_))
    ));
    fs::write(config.directory.join("unexpected"), b"do not delete")?;
    assert!(matches!(
        DurableBuffer::open(config.clone()).await,
        Err(BufferError::Directory)
    ));
    fs::remove_file(config.directory.join("unexpected"))?;
    #[cfg(unix)]
    {
        let checkpoint = config.directory.join("checkpoint");
        fs::rename(&checkpoint, temp.path().join("outside"))?;
        std::os::unix::fs::symlink(temp.path().join("outside"), &checkpoint)?;
        assert!(matches!(
            DurableBuffer::open(config.clone()).await,
            Err(BufferError::Directory)
        ));
        fs::remove_file(&checkpoint)?;
        fs::rename(temp.path().join("outside"), &checkpoint)?;
    }
    let replay = DurableBuffer::open(config).await?;
    assert_eq!(replay.snapshot().depth, 2);
    replay.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn stale_temporary_checkpoint_never_advances_published_checkpoint() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let buffer = DurableBuffer::open(config.clone()).await?;
    buffer.admit(event("not yet persisted")?).await?;
    buffer.shutdown().await?;
    fs::write(
        config.directory.join("checkpoint.tmp"),
        b"partial temporary checkpoint",
    )?;
    let replay = DurableBuffer::open(config.clone()).await?;
    assert_eq!(replay.snapshot().depth, 1);
    assert!(!config.directory.join("checkpoint.tmp").exists());
    replay.shutdown().await?;
    Ok(())
}

#[test]
fn invalid_configuration_and_policies_are_rejected() {
    for config in [
        BufferConfig {
            max_events: 0,
            ..Default::default()
        },
        BufferConfig {
            max_record_bytes: 67_108_865,
            ..Default::default()
        },
        BufferConfig {
            operation_timeout: Duration::ZERO,
            ..Default::default()
        },
        BufferConfig {
            segment_bytes: u64::MAX,
            max_wal_bytes: u64::MAX,
            ..Default::default()
        },
    ] {
        assert!(config.validate().is_err());
    }
    for name in ["reject_new", "drop_oldest", "block_with_timeout"] {
        assert!(name.parse::<Policy>().is_ok());
    }
    assert!("other".parse::<Policy>().is_err());
}

#[tokio::test]
async fn checkpoint_before_reclamation_crash_keeps_sequence_without_replaying_acked_data() -> Result
{
    let temp = TempDir::new()?;
    let config = config(&temp);
    let buffer = DurableBuffer::open(config.clone()).await?;
    for _ in 0..3 {
        buffer.admit(event("persisted externally")?).await?;
    }
    let mut stale = Vec::new();
    for path in segments(&config)? {
        stale.push((path.clone(), fs::read(path)?));
    }
    buffer.read_batch(3, 8192).await?;
    buffer.ack(3).await?;
    buffer.shutdown().await?;
    // Re-create the state of a crash after checkpoint publication and before deletion.
    for (path, bytes) in stale {
        fs::write(path, bytes)?;
    }
    let replay = DurableBuffer::open(config).await?;
    assert_eq!(replay.snapshot().replayed, 0);
    assert_eq!(replay.snapshot().wal_bytes, 128);
    replay.admit(event("new")?).await?;
    assert_eq!(replay.read_batch(1, 8192).await?[0].sequence, 4);
    replay.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn checkpoint_io_failure_stops_admission_and_does_not_reclaim_unacked_data() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let buffer = DurableBuffer::open(config.clone()).await?;
    let event = event("must survive failed checkpoint")?;
    let id = event.id;
    buffer.admit(event).await?;
    buffer.read_batch(1, 8192).await?;
    fs::write(config.directory.join("checkpoint.tmp"), b"interrupted")?;
    assert!(matches!(buffer.ack(1).await, Err(BufferError::Io(_))));
    assert!(buffer.snapshot().closed);
    assert_eq!(buffer.snapshot().checkpoint, 0);
    assert_eq!(
        buffer.admit(self::event("cannot admit")?).await,
        Err(AdmissionError::Closed)
    );
    buffer.shutdown().await?;
    let replay = DurableBuffer::open(config).await?;
    assert_eq!(replay.read_batch(1, 8192).await?[0].event.id, id);
    replay.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn valid_crc_cannot_hide_sequence_or_invalid_canonical_event() -> Result {
    for damage in [0, 1, 2, 3] {
        let temp = TempDir::new()?;
        let config = config(&temp);
        let buffer = DurableBuffer::open(config.clone()).await?;
        buffer.admit(event("valid before corruption")?).await?;
        buffer.shutdown().await?;
        let path = segments(&config)?.remove(0);
        let original = fs::read(&path)?;
        let mut payload: serde_json::Value = serde_json::from_slice(&original[40..])?;
        match damage {
            1 => payload["schema_version"] = 2.into(),
            2 => payload["id"] = "00000000-0000-0000-0000-000000000000".into(),
            3 => payload["timestamp"] = "invalid".into(),
            _ => {}
        }
        let payload = serde_json::to_vec(&payload)?;
        let seq: u64 = if damage == 0 { 2 } else { 1 };
        let mut header = Vec::new();
        header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        header.extend_from_slice(&seq.to_le_bytes());
        header.extend_from_slice(&crc32fast::hash(&header).to_le_bytes());
        header.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
        let mut modified = original[..20].to_vec();
        modified.extend(header);
        modified.extend(payload);
        fs::write(&path, &modified)?;
        assert!(matches!(
            DurableBuffer::open(config).await,
            Err(BufferError::Corrupt(_))
        ));
        assert_eq!(fs::read(path)?, modified);
    }
    Ok(())
}

#[tokio::test]
async fn replay_preflights_disk_size_and_record_bound_before_allocating() -> Result {
    let temp = TempDir::new()?;
    let config = config(&temp);
    let buffer = DurableBuffer::open(config.clone()).await?;
    buffer.admit(event("preflight")?).await?;
    buffer.shutdown().await?;
    let path = segments(&config)?.remove(0);
    let size = fs::metadata(&path)?.len();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(config.max_wal_bytes + 1)?;
    assert!(matches!(
        DurableBuffer::open(config.clone()).await,
        Err(BufferError::Config(_))
    ));
    assert_eq!(fs::metadata(&path)?.len(), config.max_wal_bytes + 1);
    fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(size)?;
    let mut bytes = fs::read(&path)?;
    bytes[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    let crc = crc32fast::hash(&bytes[20..32]);
    bytes[32..36].copy_from_slice(&crc.to_le_bytes());
    fs::write(&path, &bytes)?;
    assert!(matches!(
        DurableBuffer::open(config).await,
        Err(BufferError::Config(_))
    ));
    assert_eq!(fs::read(path)?, bytes);
    Ok(())
}

#[tokio::test]
async fn stream_identity_is_stable_and_incomplete_upgrade_temp_preserves_backlog() -> Result {
    for upgrading in [false, true] {
        let temp = TempDir::new()?;
        let config = config(&temp);
        let buffer = DurableBuffer::open(config.clone()).await?;
        let original = buffer.snapshot().stream_id;
        let event = event("upgrade backlog")?;
        let id = event.id;
        buffer.admit(event).await?;
        buffer.shutdown().await?;
        if upgrading {
            fs::remove_file(config.directory.join("identity"))?;
        }
        fs::write(config.directory.join("identity.tmp"), b"partial")?;
        let replay = DurableBuffer::open(config.clone()).await?;
        assert_eq!(replay.read_batch(1, 8192).await?[0].event.id, id);
        assert!(!replay.snapshot().stream_id.is_nil());
        if !upgrading {
            assert_eq!(replay.snapshot().stream_id, original);
        }
        assert!(!config.directory.join("identity.tmp").exists());
        replay.shutdown().await?;
        let again = DurableBuffer::open(config).await?;
        if !upgrading {
            assert_eq!(again.snapshot().stream_id, original);
        }
        again.shutdown().await?;
    }
    Ok(())
}
