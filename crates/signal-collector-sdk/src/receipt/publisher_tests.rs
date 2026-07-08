use super::*;
use signal_protocol::AdmissionDisposition;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Publisher {
    mode: &'static str,
    calls: AtomicUsize,
}
impl Publisher {
    fn new(mode: &'static str) -> Self {
        Self {
            mode,
            calls: AtomicUsize::new(0),
        }
    }
}
#[crate::extension]
impl ReceiptPublisher for Publisher {
    async fn publish(
        &self,
        batch: &PreparedBatch,
        _: &ExtensionContext,
    ) -> Result<AdmissionReply, PublishFailure> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        match self.mode {
            "uncertain" => return Err(PublishFailure::Uncertain),
            "denied" => return Err(PublishFailure::Denied),
            "stall" => std::future::pending::<()>().await,
            _ => (),
        }
        let sent = batch.event_ids().len();
        let (status, accepted, error) = match self.mode {
            "partial" => (429, 1, json!({"code":"full","message":"full","index":1})),
            "reduce" => (
                413,
                0,
                json!({"code":"batch_too_large","message":"large","index":0}),
            ),
            _ => (202, sent, Value::Null),
        };
        let mut response = json!({"schema_version":1,"accepted":accepted,"rejected":sent-accepted,"event_ids":&batch.event_ids()[..accepted],"error":error});
        if self.mode == "forged" {
            response["event_ids"][0] = Uuid::new_v4().to_string().into();
        }
        let body = match self.mode {
            "duplicate" => b"{\"accepted\":1,\"accepted\":2}".to_vec(),
            "oversized" => vec![b'x'; 64 * 1024 + 1],
            "malformed" => b"lost-or-truncated".to_vec(),
            _ => serde_json::to_vec(&response).map_err(|_| PublishFailure::Uncertain)?,
        };
        Ok(AdmissionReply { status, body })
    }
}
async fn setup(
    d: &tempfile::TempDir,
) -> Result<(ReceiptStore, ReceiptBinding), Box<dyn std::error::Error>> {
    let (wire, b) = vector("prepared")?;
    let s = ReceiptStore::open(config(d)?, owner(), 1, ctx()).await?;
    s.publish(wire, b.clone(), ctx()).await?;
    Ok((s, b))
}

#[tokio::test]
async fn retained_payloads_enter_batch_envelope_byte_for_byte() -> TestResult {
    let d = root()?;
    let (s, b) = setup(&d).await?;
    let r = s.replay(b, ctx()).await?.ok_or("r")?;
    let batch = r.batch(ReceiptBatchLimits::default())?.ok_or("batch")?;
    let mut exact = b"{\"schema_version\":1,\"events\":[".to_vec();
    exact.extend_from_slice(r.suffix_bytes(0).ok_or("first")?);
    exact.push(b',');
    exact.extend_from_slice(r.suffix_bytes(1).ok_or("second")?);
    exact.extend_from_slice(b"]}");
    assert_eq!(batch.body(), exact);
    let input: signal_protocol::BatchInput = serde_json::from_slice(batch.body())?;
    assert_eq!(input.schema_version, 1);
    assert_eq!(input.events.len(), 2);
    assert_eq!(
        batch.event_ids(),
        &[
            format::uuid(&input.events[0]["id"])?,
            format::uuid(&input.events[1]["id"])?
        ]
    );
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn count_and_byte_limits_bound_selection_before_body_allocation() -> TestResult {
    for (count, bytes) in [(0, 1024), (1025, 1024), (1, 0), (1, 16 * 1024 * 1024 + 1)] {
        assert!(ReceiptBatchLimits::new(count, bytes).is_err());
    }
    let d = root()?;
    let (s, b) = setup(&d).await?;
    let r = s.replay(b, ctx()).await?.ok_or("r")?;
    let first = r
        .batch(ReceiptBatchLimits::new(1, 1024 * 1024)?)?
        .ok_or("one")?;
    let exact = r
        .batch(ReceiptBatchLimits::new(2, first.body().len())?)?
        .ok_or("fit")?;
    assert_eq!(exact.body(), first.body());
    assert_eq!(exact.event_ids().len(), 1);
    assert!(
        r.batch(ReceiptBatchLimits::new(2, first.body().len() - 1)?)
            .is_err()
    );
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn partial_admission_reopen_replays_pinned_suffix_and_then_completes() -> TestResult {
    let d = root()?;
    let (s, b) = setup(&d).await?;
    let original = s.replay(b.clone(), ctx()).await?.ok_or("r")?;
    let suffix = original.suffix_bytes(1).ok_or("suffix")?.to_vec();
    let p = Publisher::new("partial");
    let step =
        publish_receipt_batch(&s, b.clone(), &p, ReceiptBatchLimits::default(), ctx()).await?;
    match step {
        PublishStep::Attempt {
            sent,
            accepted,
            remaining,
            disposition,
            progress,
        } => {
            assert_eq!((sent, accepted, remaining), (2, 1, 1));
            assert_eq!(disposition, AdmissionDisposition::Retry);
            assert_eq!(progress.verified_prefix(), 1);
        }
        _ => return Err("attempt".into()),
    }
    s.close(ctx()).await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("reopen")?;
    assert_eq!(r.suffix_bytes(0).ok_or("suffix")?, suffix);
    let p = Publisher::new("full");
    match publish_receipt_batch(&s, b.clone(), &p, ReceiptBatchLimits::default(), ctx()).await? {
        PublishStep::Attempt {
            sent,
            accepted,
            remaining,
            disposition,
            ..
        } => {
            assert_eq!((sent, accepted, remaining), (1, 1, 0));
            assert_eq!(disposition, AdmissionDisposition::Complete);
        }
        _ => return Err("complete attempt".into()),
    }
    assert!(matches!(
        publish_receipt_batch(&s, b, &p, ReceiptBatchLimits::default(), ctx()).await?,
        PublishStep::Complete { .. }
    ));
    assert_eq!(p.calls.load(Ordering::Acquire), 1);
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn lost_response_denial_and_reduce_batch_never_advance_prefix() -> TestResult {
    let d = root()?;
    let (s, b) = setup(&d).await?;
    for (mode, expected) in [
        ("uncertain", AdmissionDisposition::Retry),
        ("denied", AdmissionDisposition::Permanent),
        ("reduce", AdmissionDisposition::ReduceBatch),
    ] {
        let p = Publisher::new(mode);
        match publish_receipt_batch(&s, b.clone(), &p, ReceiptBatchLimits::default(), ctx()).await?
        {
            PublishStep::Attempt {
                sent,
                accepted,
                remaining,
                disposition,
                progress,
            } => {
                assert_eq!((sent, accepted, remaining), (2, 0, 2));
                assert_eq!(disposition, expected);
                assert_eq!(progress.verified_prefix(), 0);
            }
            _ => return Err("attempt".into()),
        }
    }
    assert_eq!(s.replay(b, ctx()).await?.ok_or("r")?.progress.revision(), 3);
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn malformed_oversized_duplicate_and_forged_replies_leave_control_unchanged() -> TestResult {
    let d = root()?;
    let (s, b) = setup(&d).await?;
    let original = fs::read(d.path().join("control"))?;
    for mode in ["malformed", "oversized", "duplicate", "forged"] {
        let p = Publisher::new(mode);
        assert!(matches!(
            publish_receipt_batch(&s, b.clone(), &p, ReceiptBatchLimits::default(), ctx()).await,
            Err(ReceiptError::InvalidResponse)
        ));
        assert_eq!(fs::read(d.path().join("control"))?, original);
    }
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn stale_scope_deadline_and_live_cancel_hold_progress_and_source_work() -> TestResult {
    let d = root()?;
    let (s, b) = setup(&d).await?;
    let original = fs::read(d.path().join("control"))?;
    let mut foreign = b.clone();
    foreign.0["authority_revision"] = "foreign".into();
    let p = Publisher::new("full");
    assert!(matches!(
        publish_receipt_batch(&s, foreign, &p, ReceiptBatchLimits::default(), ctx()).await,
        Err(ReceiptError::Scope)
    ));
    assert_eq!(p.calls.load(Ordering::Acquire), 0);
    let p = Publisher::new("stall");
    let short = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(20))?;
    assert!(matches!(
        publish_receipt_batch(&s, b.clone(), &p, ReceiptBatchLimits::default(), short).await,
        Err(ReceiptError::Timeout)
    ));
    let token = CancellationToken::new();
    let context = ExtensionContext::new(token.clone(), Duration::from_secs(5))?;
    let result = tokio::join!(
        publish_receipt_batch(&s, b.clone(), &p, ReceiptBatchLimits::default(), context),
        async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            token.cancel();
        }
    );
    assert!(matches!(result.0, Err(ReceiptError::Cancelled)));
    assert_eq!(fs::read(d.path().join("control"))?, original);
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn empty_store_and_complete_quarantine_do_not_dispatch_or_authorize_ack() -> TestResult {
    let d = root()?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let (wire, b) = vector("object-quarantine")?;
    let p = Publisher::new("full");
    assert!(matches!(
        publish_receipt_batch(&s, b.clone(), &p, ReceiptBatchLimits::default(), ctx()).await?,
        PublishStep::Empty
    ));
    s.publish(wire, b.clone(), ctx()).await?;
    let progress =
        match publish_receipt_batch(&s, b.clone(), &p, ReceiptBatchLimits::default(), ctx()).await?
        {
            PublishStep::Complete { progress } => progress,
            _ => return Err("quarantine complete suffix".into()),
        };
    assert_eq!(p.calls.load(Ordering::Acquire), 0);
    let grant = ReceiptRecoveryGrant::from_trusted_checkpoint(
        b.clone(),
        progress.checksum(),
        "independent".into(),
    )?;
    assert!(matches!(
        s.acknowledge(
            b,
            progress,
            grant,
            ReceiptAckUpdate::BeginProcessLocal {
                delivery: SourceDelivery::new(Uuid::new_v4(), "delivery".into(), "handle".into())?,
                observed_at: "2026-10-07T12:00:02.000000000Z".into()
            },
            ctx()
        )
        .await,
        Err(ReceiptError::Ack)
    ));
    s.close(ctx()).await?;
    Ok(())
}

struct GatedPublisher {
    notify: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: tokio::sync::Mutex<tokio::sync::oneshot::Receiver<()>>,
}
#[crate::extension]
impl ReceiptPublisher for GatedPublisher {
    async fn publish(
        &self,
        batch: &PreparedBatch,
        ctx: &ExtensionContext,
    ) -> Result<AdmissionReply, PublishFailure> {
        let signal = self
            .notify
            .lock()
            .map_err(|_| PublishFailure::Uncertain)?
            .take();
        if let Some(signal) = signal {
            let _ = signal.send(());
        }
        let mut receiver = self.release.lock().await;
        (&mut *receiver)
            .await
            .map_err(|_| PublishFailure::Uncertain)?;
        Publisher::new("full").publish(batch, ctx).await
    }
}

#[tokio::test]
async fn progress_changed_during_request_cannot_accept_a_stale_response() -> TestResult {
    let d = root()?;
    let (store, b) = setup(&d).await?;
    let store = Arc::new(store);
    let (notify, entered) = tokio::sync::oneshot::channel();
    let (release, wait) = tokio::sync::oneshot::channel();
    let publisher = GatedPublisher {
        notify: std::sync::Mutex::new(Some(notify)),
        release: tokio::sync::Mutex::new(wait),
    };
    let s = store.clone();
    let scope = b.clone();
    let pending = tokio::spawn(async move {
        publish_receipt_batch(&s, scope, &publisher, ReceiptBatchLimits::default(), ctx()).await
    });
    tokio::time::timeout(Duration::from_secs(1), entered).await??;
    let r = store.replay(b.clone(), ctx()).await?.ok_or("replay")?;
    store
        .advance(b.clone(), r.progress, 2, ReceiptAttempt::Uncertain, ctx())
        .await?;
    release.send(()).map_err(|_| "receiver")?;
    assert!(matches!(pending.await?, Err(ReceiptError::StaleProgress)));
    let r = store.replay(b, ctx()).await?.ok_or("replay")?;
    assert_eq!(r.progress.verified_prefix(), 0);
    assert_eq!(r.progress.revision(), 1);
    let store = Arc::try_unwrap(store).map_err(|_| "shared store")?;
    store.close(ctx()).await?;
    Ok(())
}
