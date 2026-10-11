use signal_buffer::{BufferConfig, BufferError, DurableBuffer};
use std::{fs, io::Write, time::Duration};
use tokio::time::Instant;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn config(directory: std::path::PathBuf) -> BufferConfig {
    BufferConfig {
        directory,
        ..Default::default()
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[tokio::test]
async fn exact_slot_cas_restart_reservation_and_owned_partial_staging() -> Result {
    let root = tempfile::tempdir()?;
    let cfg = config(root.path().join("wal"));
    let buffer = DurableBuffer::open_with_recovery(cfg.clone(), 1024).await?;
    let initial = buffer.snapshot();
    assert_eq!(initial.recovery_capacity, 1024);
    assert_eq!(initial.wal_bytes, 128 + 2 * (1024 + 64));
    let first = buffer
        .replace_recovery(None, Some(b"original".to_vec()), deadline())
        .await?
        .ok_or("missing first")?;
    assert!(matches!(
        buffer
            .replace_recovery(None, Some(b"replacement".to_vec()), deadline())
            .await,
        Err(BufferError::RecoveryConflict)
    ));
    assert!(matches!(
        buffer
            .replace_recovery(Some([0; 32]), None, deadline())
            .await,
        Err(BufferError::RecoveryConflict)
    ));
    assert_eq!(buffer.read_recovery(deadline()).await?, Some(first.clone()));
    assert!(buffer.snapshot().rejected >= 2);
    let second = buffer
        .replace_recovery(Some(first.sha256), Some(b"prepared".to_vec()), deadline())
        .await?
        .ok_or("missing second")?;
    assert!(matches!(
        buffer
            .replace_recovery(Some(second.sha256), Some(vec![0; 1025]), deadline())
            .await,
        Err(BufferError::Config(_))
    ));
    assert_eq!(
        buffer.read_recovery(deadline()).await?,
        Some(second.clone())
    );
    buffer.shutdown().await?;
    drop(buffer);
    fs::write(cfg.directory.join("recovery.tmp"), b"partial")?;
    let reopened = DurableBuffer::open_with_recovery(cfg.clone(), 1024).await?;
    assert_eq!(reopened.snapshot().stream_id, initial.stream_id);
    assert_eq!(
        reopened.read_recovery(deadline()).await?,
        Some(second.clone())
    );
    assert!(!cfg.directory.join("recovery.tmp").exists());
    reopened
        .replace_recovery(Some(second.sha256), None, deadline())
        .await?;
    assert_eq!(reopened.snapshot().recovery_bytes, 0);
    reopened.shutdown().await?;
    drop(reopened);
    let empty = DurableBuffer::open_with_recovery(cfg, 1024).await?;
    assert!(empty.read_recovery(deadline()).await?.is_none());
    empty.shutdown().await?;
    Ok(())
}
#[tokio::test]
async fn corrupt_published_slot_never_resets_and_small_profile_never_ignores_it() -> Result {
    let root = tempfile::tempdir()?;
    let cfg = config(root.path().join("wal"));
    let tight_path = root.path().join("tight");
    let mut tight = config(tight_path.clone());
    tight.max_wal_bytes = tight.segment_bytes + 128;
    assert!(matches!(
        DurableBuffer::open_with_recovery(tight, 1024).await,
        Err(BufferError::Config(_))
    ));
    assert!(!tight_path.exists());
    let buffer = DurableBuffer::open_with_recovery(cfg.clone(), 1024).await?;
    buffer
        .replace_recovery(None, Some(b"retained".to_vec()), deadline())
        .await?;
    buffer.shutdown().await?;
    drop(buffer);
    assert!(matches!(
        DurableBuffer::open(cfg.clone()).await,
        Err(BufferError::Directory)
    ));
    let path = cfg.directory.join("recovery");
    let original = fs::read(&path)?;
    for offset in [0, 8, 24, 32, 64] {
        let mut broken = original.clone();
        broken[offset] ^= 1;
        fs::write(&path, &broken)?;
        fs::write(cfg.directory.join("recovery.tmp"), b"partial")?;
        assert!(matches!(
            DurableBuffer::open_with_recovery(cfg.clone(), 1024).await,
            Err(BufferError::Corrupt(_))
        ));
        assert_eq!(fs::read(&path)?, broken);
        assert_eq!(fs::read(cfg.directory.join("recovery.tmp"))?, b"partial");
    }
    fs::write(&path, &original)?;
    let reopened = DurableBuffer::open_with_recovery(cfg, 1024).await?;
    reopened.shutdown().await?;
    Ok(())
}
#[tokio::test]
async fn slot_survives_owned_producer_sigkill() -> Result {
    let root = tempfile::tempdir()?;
    let marker = root.path().join("marker");
    let wal = root.path().join("wal");
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "slot_crash_worker", "--nocapture"])
        .env("SIGNAL_SLOT_CRASH_ROOT", root.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let observed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if marker.exists() {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            if let Some(status) = child.try_wait()? {
                return Err(format!("child exited before marker: {status}").into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    let killed = child.kill();
    let reaped = child.wait()?;
    killed?;
    observed??;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(reaped.signal(), Some(9));
    }
    let reopened = DurableBuffer::open_with_recovery(config(wal), 1024).await?;
    assert_eq!(
        reopened
            .read_recovery(deadline())
            .await?
            .ok_or("lost slot")?
            .bytes,
        b"synced-before-kill"
    );
    reopened.shutdown().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "owned producer launched by slot_survives_owned_producer_sigkill"]
async fn slot_crash_worker() -> Result {
    let root = std::path::PathBuf::from(
        std::env::var_os("SIGNAL_SLOT_CRASH_ROOT").ok_or("owned child root missing")?,
    );
    let buffer = DurableBuffer::open_with_recovery(config(root.join("wal")), 1024).await?;
    buffer
        .replace_recovery(None, Some(b"synced-before-kill".to_vec()), deadline())
        .await?;
    let temporary = root.join("marker.pending");
    let mut marker = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    marker.write_all(b"slot synced")?;
    marker.sync_all()?;
    fs::rename(temporary, root.join("marker"))?;
    fs::File::open(&root)?.sync_all()?;
    tokio::time::sleep(Duration::from_secs(30)).await;
    Err("parent failed to kill owned child".into())
}
