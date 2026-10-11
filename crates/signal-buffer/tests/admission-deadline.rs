//! Original caller deadlines survive WAL queueing and cancellation.
use signal_buffer::{BufferConfig, DurableBuffer, Policy};
use signal_event::{IngestEvent, SignalEvent};
use signal_protocol::{AdmissionError, EventSink};
use std::time::Duration;
use tokio::time::Instant;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn event() -> Result<SignalEvent> {
    let input: IngestEvent = serde_json::from_value(serde_json::json!({
        "timestamp":chrono::Utc::now().to_rfc3339(),"source":{"type":"test"},"message":"original deadline"
    }))?;
    Ok(input.normalize(chrono::Utc::now())?)
}
#[tokio::test]
async fn expired_original_budget_does_not_append_and_success_survives_restart() -> Result {
    let root = tempfile::tempdir()?;
    let cfg = BufferConfig {
        directory: root.path().join("wal"),
        ..Default::default()
    };
    let wal = DurableBuffer::open(cfg.clone()).await?;
    assert_eq!(
        wal.admit_at(event()?, Instant::now()).await,
        Err(AdmissionError::Unavailable)
    );
    assert_eq!(wal.snapshot().last_sequence, 0);
    assert_eq!(wal.metrics().rejected, 1);
    let input = event()?;
    let id = input.id;
    wal.admit_at(input, Instant::now() + Duration::from_secs(1))
        .await?;
    wal.shutdown().await?;
    let replay = DurableBuffer::open(cfg).await?;
    let rows = replay.read_batch(1, 65536).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event.id, id);
    assert_eq!(rows[0].sequence, 1);
    replay.shutdown().await?;
    Ok(())
}
#[tokio::test]
async fn full_wal_honors_short_original_budget_and_dropped_waiter_cannot_append_later() -> Result {
    let root = tempfile::tempdir()?;
    let wal = DurableBuffer::open(BufferConfig {
        directory: root.path().join("wal"),
        max_events: 1,
        policy: Policy::BlockWithTimeout,
        block_timeout: Duration::from_secs(2),
        ..Default::default()
    })
    .await?;
    wal.admit(event()?).await?;
    let started = Instant::now();
    assert_eq!(
        wal.admit_at(event()?, started + Duration::from_millis(30))
            .await,
        Err(AdmissionError::Full)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    {
        let waiting = wal.admit_at(event()?, Instant::now() + Duration::from_secs(1));
        tokio::pin!(waiting);
        tokio::select! { biased; r=&mut waiting => panic!("full WAL must wait: {r:?}"),
        _=tokio::time::sleep(Duration::from_millis(30)) => {} }
    }
    let rows = wal.read_batch(1, 65536).await?;
    wal.ack(rows[0].sequence).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(wal.snapshot().depth, 0);
    assert_eq!(wal.snapshot().last_sequence, 1);
    wal.admit_at(event()?, Instant::now() + Duration::from_secs(1))
        .await?;
    assert_eq!(wal.snapshot().last_sequence, 2);
    wal.shutdown().await?;
    Ok(())
}
