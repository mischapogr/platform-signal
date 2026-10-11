//! Actual original-WAL exclusivity and recovery refusal before database I/O.
use signal_buffer::{BufferConfig, BufferError, DurableBuffer};
use signal_control::{ConnectionSettings, ControlContext, ControlError, Scope};
use signal_protocol::EventSink;
use signal_server::{
    shared_recovery::RECOVERY_BYTES,
    shared_retirement::{StoppedLifecycle, StoppedLifecycleError},
    shared_startup::CatalogProfile,
};
use std::time::Duration;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn cancelled_shutdown_retains_physical_handles_for_retry_and_original_wal_reopen() -> Result {
    let root = tempfile::tempdir()?;
    let config = BufferConfig {
        directory: root.path().join("wal"),
        ..Default::default()
    };
    let wal = DurableBuffer::open_with_recovery(config.clone(), RECOVERY_BYTES).await?;
    let original = scope(&wal);
    let stream = original.stream;
    wal.shutdown().await?;
    let mut lifecycle = begin(config.clone(), original)?;
    let cancelled = context()?;
    cancelled.cancel();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), lifecycle.shutdown(cancelled)).await?,
        Err(StoppedLifecycleError::Control(ControlError::Cancelled))
    ));
    lifecycle.shutdown(context()?).await?;
    let reopened = DurableBuffer::open_with_recovery(config, RECOVERY_BYTES).await?;
    assert_eq!(reopened.snapshot().stream_id, stream);
    assert_eq!(reopened.snapshot().checkpoint, 0);
    reopened.shutdown().await?;
    Ok(())
}

fn context() -> std::result::Result<ControlContext, ControlError> {
    ControlContext::new(Duration::from_secs(5))
}
fn connection() -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
        1,
        "unreachable".into(),
        "unreachable".into(),
        b"synthetic".to_vec(),
    )
}
fn scope(wal: &DurableBuffer) -> Scope {
    Scope {
        schema_version: 1,
        store_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        tenant: "synthetic-retirement".into(),
        stream: wal.snapshot().stream_id,
        partition_id: Uuid::new_v4(),
    }
}
fn begin(
    config: BufferConfig,
    scope: Scope,
) -> std::result::Result<StoppedLifecycle, StoppedLifecycleError> {
    StoppedLifecycle::begin(
        connection()?,
        CatalogProfile::Catalog4,
        scope,
        Uuid::new_v4(),
        config,
        "signal_control_owner".into(),
    )
}

#[tokio::test]
async fn live_original_wal_owner_prevents_retirement_and_failed_open_drains() -> Result {
    let root = tempfile::tempdir()?;
    let config = BufferConfig {
        directory: root.path().join("wal"),
        ..Default::default()
    };
    let wal = DurableBuffer::open_with_recovery(config.clone(), RECOVERY_BYTES).await?;
    let original = scope(&wal);
    let mut lifecycle = begin(config.clone(), original)?;
    assert!(matches!(
        lifecycle.start(Uuid::new_v4(), 15000, context()?).await,
        Err(StoppedLifecycleError::Wal(BufferError::Locked))
    ));
    lifecycle.shutdown(context()?).await?;
    assert!(!wal.snapshot().closed);
    wal.shutdown().await?;
    let reopened = DurableBuffer::open_with_recovery(config, RECOVERY_BYTES).await?;
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn pending_original_event_is_preserved_and_refuses_lifecycle_before_connect() -> Result {
    let root = tempfile::tempdir()?;
    let config = BufferConfig {
        directory: root.path().join("wal"),
        ..Default::default()
    };
    let wal = DurableBuffer::open_with_recovery(config.clone(), RECOVERY_BYTES).await?;
    let original = scope(&wal);
    let input: signal_event::IngestEvent = serde_json::from_value(serde_json::json!({
        "timestamp": chrono::Utc::now(), "source":{"type":"test"}, "message":"pending retirement guard"
    }))?;
    let event = input.normalize(chrono::Utc::now())?;
    let id = event.id;
    wal.admit(event).await?;
    wal.shutdown().await?;
    let mut lifecycle = begin(config.clone(), original)?;
    assert!(matches!(
        lifecycle.start(Uuid::new_v4(), 15000, context()?).await,
        Err(StoppedLifecycleError::Control(ControlError::Conflict))
    ));
    // Failed verification still retains the exclusive physical WAL lock.
    assert!(matches!(
        DurableBuffer::open_with_recovery(config.clone(), RECOVERY_BYTES).await,
        Err(BufferError::Locked)
    ));
    lifecycle.shutdown(context()?).await?;
    let reopened = DurableBuffer::open_with_recovery(config, RECOVERY_BYTES).await?;
    assert_eq!(reopened.snapshot().checkpoint, 0);
    assert_eq!(reopened.snapshot().last_sequence, 1);
    assert_eq!(reopened.read_batch(1, 4096).await?[0].event.id, id);
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn prepared_recovery_slot_is_preserved_and_denies_retirement() -> Result {
    let root = tempfile::tempdir()?;
    let config = BufferConfig {
        directory: root.path().join("wal"),
        ..Default::default()
    };
    let wal = DurableBuffer::open_with_recovery(config.clone(), RECOVERY_BYTES).await?;
    let original = scope(&wal);
    let retained = wal
        .replace_recovery(
            None,
            Some(b"original prepared request".to_vec()),
            context()?.deadline(),
        )
        .await?;
    wal.shutdown().await?;
    let mut lifecycle = begin(config.clone(), original)?;
    assert!(matches!(
        lifecycle.start(Uuid::new_v4(), 15000, context()?).await,
        Err(StoppedLifecycleError::Control(ControlError::Conflict))
    ));
    lifecycle.shutdown(context()?).await?;
    let reopened = DurableBuffer::open_with_recovery(config, RECOVERY_BYTES).await?;
    assert_eq!(
        reopened.read_recovery(context()?.deadline()).await?,
        retained
    );
    assert_eq!(reopened.snapshot().checkpoint, 0);
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn foreign_stream_and_cancelled_start_never_grant_lifecycle_authority() -> Result {
    let root = tempfile::tempdir()?;
    let config = BufferConfig {
        directory: root.path().join("wal"),
        ..Default::default()
    };
    let wal = DurableBuffer::open_with_recovery(config.clone(), RECOVERY_BYTES).await?;
    let original = scope(&wal);
    wal.shutdown().await?;
    let mut foreign = original.clone();
    foreign.stream = Uuid::new_v4();
    let mut lifecycle = begin(config.clone(), foreign)?;
    assert!(matches!(
        lifecycle.start(Uuid::new_v4(), 15000, context()?).await,
        Err(StoppedLifecycleError::Control(ControlError::Fenced))
    ));
    lifecycle.shutdown(context()?).await?;
    let mut lifecycle = begin(config.clone(), original)?;
    let cancelled = context()?;
    cancelled.cancel();
    assert!(matches!(
        lifecycle.start(Uuid::new_v4(), 15000, cancelled).await,
        Err(StoppedLifecycleError::Control(ControlError::Cancelled))
    ));
    lifecycle.shutdown(context()?).await?;
    let reopened = DurableBuffer::open_with_recovery(config, RECOVERY_BYTES).await?;
    reopened.shutdown().await?;
    Ok(())
}
