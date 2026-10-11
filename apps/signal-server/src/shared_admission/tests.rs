//! Real WAL and synthetic trusted-host grants; no native provider/enrollment claim.
use super::*;
use signal_buffer::BufferConfig;
use signal_control::Scope;
use signal_event::IngestEvent;
use signal_protocol::access::{AccessPolicy, AuthenticatedIdentity};
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn event(account: &str) -> Result<SignalEvent> {
    let input: IngestEvent = serde_json::from_value(serde_json::json!({
        "timestamp":chrono::Utc::now().to_rfc3339(),"source":{"type":"audit"},
        "resource":{"kind":"host","id":"host-a","account_id":account},
        "attributes":{"account_id":"a","roles":["administrator"]}
    }))?;
    Ok(input.normalize(chrono::Utc::now())?)
}
fn grant(operation: &str, expired: bool) -> Result<RequestGrant> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let issued = if expired { now - 2 } else { now };
    let expires = if expired { now - 1 } else { now + 60 };
    let policy = AccessPolicy::from_json(serde_json::to_string(&serde_json::json!({
        "schema_version":1,"roles":[{"id":"producer","permissions":[{
            "operation":operation,"scope":{"sources":{"mode":"all"},
            "resources":{"mode":"all"},"accounts":{"mode":"only","values":["a"]}}
        }]}],"bindings":[{"issuer":"https://identity.example.test","subject":"producer","roles":["producer"]}]
    }))?.as_bytes())?.compile()?;
    Ok(policy.grant(
        AuthenticatedIdentity::from_verified_backend(
            "https://identity.example.test".into(),
            "producer".into(),
            issued,
            expires,
        )?,
        issued,
    )?)
}
// Test-only construction deliberately bypasses native owner enrollment. Public
// construction still requires FindingScopePin; these tests establish admission
// and physical WAL semantics only, never activation or HTTP authentication.
fn synthetic(wal: Arc<DurableBuffer>) -> SharedAdmission {
    SharedAdmission {
        producer: ProducerEnrollment {
            scope: Scope {
                schema_version: 1,
                store_id: Uuid::new_v4(),
                generation: Uuid::new_v4(),
                tenant: "synthetic".into(),
                stream: wal.snapshot().stream_id,
                partition_id: Uuid::new_v4(),
            },
            scope_generation: Uuid::new_v4(),
            startup: Uuid::new_v4(),
            wal_floor: wal.snapshot().last_sequence,
        },
        wal,
        callers: Semaphore::new(1),
        accepted: AtomicU64::new(0),
        rejected: AtomicU64::new(0),
        closed: AtomicBool::new(false),
    }
}
#[tokio::test]
async fn grant_only_admission_rejects_legacy_spoof_expiry_deadline_and_wrong_operation() -> Result {
    let root = tempfile::tempdir()?;
    let wal = Arc::new(
        DurableBuffer::open_with_recovery(
            BufferConfig {
                directory: root.path().join("wal"),
                ..Default::default()
            },
            crate::shared_recovery::RECOVERY_BYTES,
        )
        .await?,
    );
    let native = synthetic(wal.clone());
    let allowed = grant("ingest_events", false)?;
    let deadline = || Instant::now() + Duration::from_secs(2);
    assert_eq!(
        native.admit(event("a")?).await,
        Err(AdmissionError::Unavailable)
    );
    assert_eq!(
        native
            .admit_with_grant(event("b")?, &allowed, deadline())
            .await,
        Err(AdmissionError::Unavailable)
    );
    assert_eq!(
        native
            .admit_with_grant(event("a")?, &grant("query_events", false)?, deadline())
            .await,
        Err(AdmissionError::Unavailable)
    );
    assert_eq!(
        native
            .admit_with_grant(event("a")?, &grant("ingest_events", true)?, deadline())
            .await,
        Err(AdmissionError::Unavailable)
    );
    assert_eq!(
        native
            .admit_with_grant(event("a")?, &allowed, Instant::now())
            .await,
        Err(AdmissionError::Unavailable)
    );
    assert_eq!(wal.snapshot().last_sequence, 0);
    assert_eq!(native.admission_metrics().rejected, 5);
    let input = event("a")?;
    let id = input.id;
    native.admit_with_grant(input, &allowed, deadline()).await?;
    assert_eq!(native.admission_metrics().accepted, 1);
    assert_eq!(native.admission_metrics().active, 0);
    assert_eq!(wal.snapshot().checkpoint, 0);
    assert_eq!(wal.read_batch(1, 65536).await?[0].event.id, id);
    native.close();
    assert_eq!(native.admit(event("a")?).await, Err(AdmissionError::Closed));
    assert_eq!(
        native
            .admit_with_grant(event("a")?, &allowed, deadline())
            .await,
        Err(AdmissionError::Closed)
    );
    wal.shutdown().await?;
    Ok(())
}
#[tokio::test]
async fn single_native_caller_and_cancellation_do_not_append_or_retain_caller_slot() -> Result {
    let root = tempfile::tempdir()?;
    let wal = Arc::new(
        DurableBuffer::open_with_recovery(
            BufferConfig {
                directory: root.path().join("wal"),
                max_events: 1,
                policy: Policy::BlockWithTimeout,
                block_timeout: Duration::from_secs(2),
                ..Default::default()
            },
            crate::shared_recovery::RECOVERY_BYTES,
        )
        .await?,
    );
    let native = synthetic(wal.clone());
    let allowed = grant("ingest_events", false)?;
    native
        .admit_with_grant(
            event("a")?,
            &allowed,
            Instant::now() + Duration::from_secs(2),
        )
        .await?;
    {
        let waiting = native.admit_with_grant(
            event("a")?,
            &allowed,
            Instant::now() + Duration::from_secs(2),
        );
        tokio::pin!(waiting);
        tokio::select! { biased; r=&mut waiting => panic!("full WAL must wait: {r:?}"),
        _=tokio::time::sleep(Duration::from_millis(30)) => {} }
        assert_eq!(native.admission_metrics().active, 1);
        assert_eq!(
            native
                .admit_with_grant(
                    event("a")?,
                    &allowed,
                    Instant::now() + Duration::from_secs(1)
                )
                .await,
            Err(AdmissionError::Full)
        );
    }
    assert_eq!(native.admission_metrics().active, 0);
    assert_eq!(native.admission_metrics().rejected, 2);
    let rows = wal.read_batch(1, 65536).await?;
    wal.ack(rows[0].sequence).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(wal.snapshot().depth, 0);
    assert_eq!(wal.snapshot().last_sequence, 1);
    native
        .admit_with_grant(
            event("a")?,
            &allowed,
            Instant::now() + Duration::from_secs(1),
        )
        .await?;
    assert_eq!(native.admission_metrics().accepted, 2);
    native.close();
    wal.shutdown().await?;
    Ok(())
}
