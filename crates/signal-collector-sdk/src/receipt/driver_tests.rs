use super::*;
use std::{
    io::Write,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Mutex;
struct Queue {
    mode: Mutex<&'static str>,
    receives: AtomicUsize,
    deletes: AtomicUsize,
}
impl Queue {
    fn new(mode: &'static str) -> Self {
        Self {
            mode: Mutex::new(mode),
            receives: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0),
        }
    }
}
#[crate::extension]
impl SourceQueue for Queue {
    async fn receive(
        &self,
        _: &ReceiptBinding,
        _: &ExtensionContext,
    ) -> Result<Option<QueueDelivery>, SourceFailure> {
        let n = self.receives.fetch_add(1, Ordering::AcqRel) + 1;
        let mode = *self.mode.lock().await;
        match mode {
            "idle" => return Ok(None),
            "throttle" => return Err(SourceFailure::Throttled),
            "receive_stall" => std::future::pending::<()>().await,
            _ => (),
        }
        let body = if mode == "malformed" {
            b"{\"Records\":[]}".to_vec()
        } else {
            serde_json::to_vec(&json!({"Records":[discovery_tests::record()]}))
                .map_err(|_| SourceFailure::Malformed)?
        };
        Ok(Some(
            QueueDelivery::new(
                body,
                "fixture-message-001".into(),
                format!("ephemeral-driver-handle-{n}"),
            )
            .map_err(|_| SourceFailure::Malformed)?,
        ))
    }
    async fn delete(
        &self,
        _: &ReceiptBinding,
        ticket: &SourceAckTicket,
        _: &ExtensionContext,
    ) -> Result<SourceAckOutcome, SourceFailure> {
        self.deletes.fetch_add(1, Ordering::AcqRel);
        if !ticket.handle().starts_with("ephemeral-driver-handle-") {
            return Err(SourceFailure::Malformed);
        }
        match *self.mode.lock().await {
            "delete_denied" => Err(SourceFailure::Denied),
            "delete_stall" => std::future::pending().await,
            "delete_uncertain" => Ok(SourceAckOutcome::uncertain()),
            _ => Ok(SourceAckOutcome::from_sqs_json_response(200, b"")),
        }
    }
}
struct Capture {
    original: Vec<u8>,
    calls: AtomicUsize,
}
#[crate::extension]
impl CaptureTransport for Capture {
    async fn open(
        &self,
        _: &ObjectDiscovery,
        _: &ExtensionContext,
    ) -> Result<CaptureStream, CaptureFailure> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Ok(CaptureStream {
            version_id: "fixture-version-001".into(),
            etag: None,
            body: Box::new(std::io::Cursor::new(self.original.clone())),
        })
    }
}
struct Policy {
    binding: ReceiptBinding,
    calls: AtomicUsize,
    revoke: usize,
    wrong_delivery: bool,
}
impl Policy {
    fn new(revoke: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut b = vector("prepared")?.1.0;
        b["ack_requires_m2"] = true.into();
        Ok(Self {
            binding: ReceiptBinding::from_json(&format::canonical(&b, 65536)?)?,
            calls: AtomicUsize::new(0),
            revoke,
            wrong_delivery: false,
        })
    }
}
#[crate::extension]
impl DeliveryPolicy for Policy {
    async fn binding(&self, _: &ExtensionContext) -> Result<ReceiptBinding, SourceFailure> {
        let n = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if self.revoke != 0 && n >= self.revoke {
            let mut b = self.binding.0.clone();
            b["authority_revision"] = "changed-grant".into();
            return ReceiptBinding::from_json(
                &format::canonical(&b, 65536).map_err(|_| SourceFailure::Malformed)?,
            )
            .map_err(|_| SourceFailure::Malformed);
        }
        Ok(self.binding.clone())
    }
    async fn preparation(
        &self,
        _: &ObjectDiscovery,
        d: &QueueDelivery,
        _: &ExtensionContext,
    ) -> Result<CapturePreparation, SourceFailure> {
        let p = preparation_tests::plan(2).map_err(|_| SourceFailure::Malformed)?;
        Ok(CapturePreparation {
            receipt_id: p.receipt_id,
            captured_at: p.original.captured_at,
            prepared_at: p.prepared_at,
            normalizer_sha256: p.normalizer_sha256,
            retention: p.retention,
            event_ids: p.event_ids,
            delivery_id: if self.wrong_delivery {
                "wrong-id".into()
            } else {
                d.message_id().into()
            },
        })
    }
    async fn acknowledge(
        &self,
        b: &ReceiptBinding,
        p: &ReceiptProgress,
        _: &ExtensionContext,
    ) -> Result<AckAuthorization, SourceFailure> {
        Ok(AckAuthorization {
            grant: ReceiptRecoveryGrant::from_trusted_checkpoint(
                b.clone(),
                p.checksum(),
                "unit-current-history".into(),
            )
            .map_err(|_| SourceFailure::Denied)?,
            observed_at: "2026-10-07T12:00:02.000000000Z".into(),
        })
    }
}
fn capture() -> Result<Capture, Box<dyn std::error::Error>> {
    let original = preparation_tests::original()?;
    let object = crate::cloudtrail::read_object(&original, &ctx())?;
    let mut raw = b"{\"Records\":[".to_vec();
    raw.extend_from_slice(object.record(0).ok_or("record")?);
    raw.push(b',');
    raw.extend_from_slice(object.record(1).ok_or("record")?);
    raw.extend_from_slice(b"]}");
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&raw)?;
    Ok(Capture {
        original: gzip.finish()?,
        calls: AtomicUsize::new(0),
    })
}

#[test]
fn bounded_ephemeral_delivery_rejects_poison_and_oversized_identity() -> TestResult {
    for (body, id, handle) in [
        (vec![], "i".into(), "h".into()),
        (vec![0; MAX_DISCOVERY_BYTES + 1], "i".into(), "h".into()),
        (vec![0], "i".repeat(129), "h".into()),
        (vec![0], "i".into(), "h".repeat(16385)),
        (vec![0], "i".into(), "h\n".into()),
    ] {
        assert!(QueueDelivery::new(body, id, handle).is_err());
    }
    let d = QueueDelivery::new(
        vec![0; MAX_DISCOVERY_BYTES],
        "i".repeat(128),
        "h".repeat(16384),
    )?;
    assert_eq!(d.body().len(), MAX_DISCOVERY_BYTES);
    assert_eq!(d.message_id().len(), 128);
    Ok(())
}
#[tokio::test]
async fn one_batch_then_fresh_redelivery_reuses_exact_pins_and_acks_only_full_prefix() -> TestResult
{
    let d = root()?;
    let store = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let policy = Policy::new(0)?;
    let source = capture()?;
    let q = Queue::new("ok");
    let pubr = publisher_tests::Publisher::new("ok");
    let receipt = match collect_delivery(
        &store,
        &q,
        &source,
        &pubr,
        &policy,
        ReceiptBatchLimits::new(1, 1024 * 1024)?,
        ctx(),
    )
    .await?
    {
        DeliveryStep::Pending {
            receipt,
            accepted: 1,
            remaining: 1,
            ..
        } => receipt,
        _ => return Err("pending".into()),
    };
    assert_eq!(q.deletes.load(Ordering::Acquire), 0);
    let old = store
        .inspect(policy.binding.clone(), ctx())
        .await?
        .ok_or("receipt")?;
    assert!(
        matches!(collect_delivery(&store,&q,&source,&pubr,&policy,ReceiptBatchLimits::new(1,1024*1024)?,ctx()).await?,DeliveryStep::Settled{receipt:r,progress} if r==receipt && progress.source_ack_state()==SourceAckState::Confirmed)
    );
    assert_eq!(q.deletes.load(Ordering::Acquire), 1);
    let retained = store
        .inspect(policy.binding.clone(), ctx())
        .await?
        .ok_or("receipt")?;
    assert_eq!(old.bytes, retained.bytes);
    assert!(
        !retained
            .bytes
            .windows(b"ephemeral-driver-handle".len())
            .any(|w| w == b"ephemeral-driver-handle")
    );
    store.close(ctx()).await?;
    Ok(())
}
#[tokio::test]
async fn idle_throttle_poison_wrong_message_and_ambiguous_admission_never_delete() -> TestResult {
    for mode in [
        "idle",
        "throttle",
        "malformed",
        "wrong_message",
        "uncertain",
        "denied",
        "partial",
    ] {
        let d = root()?;
        let store = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        let mut policy = Policy::new(0)?;
        policy.wrong_delivery = mode == "wrong_message";
        let source = capture()?;
        let q = Queue::new(mode);
        let pubr = publisher_tests::Publisher::new(mode);
        let result = collect_delivery(
            &store,
            &q,
            &source,
            &pubr,
            &policy,
            ReceiptBatchLimits::default(),
            ctx(),
        )
        .await;
        match mode {
            "idle" => assert!(matches!(result, Ok(DeliveryStep::Idle))),
            "throttle" | "malformed" | "wrong_message" => assert!(result.is_err()),
            "partial" => assert!(matches!(
                result,
                Ok(DeliveryStep::Pending {
                    accepted: 1,
                    remaining: 1,
                    ..
                })
            )),
            _ => assert!(matches!(
                result,
                Ok(DeliveryStep::Pending {
                    accepted: 0,
                    remaining: 2,
                    ..
                })
            )),
        }
        assert_eq!(q.deletes.load(Ordering::Acquire), 0);
        store.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn changing_authority_at_every_side_effect_seam_holds_and_preserves_intent() -> TestResult {
    for revoke in [2, 3, 4, 5, 7, 8, 9, 10] {
        let d = root()?;
        let store = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        let policy = Policy::new(revoke)?;
        let source = capture()?;
        let q = Queue::new("ok");
        let pubr = publisher_tests::Publisher::new("ok");
        assert!(matches!(
            collect_delivery(
                &store,
                &q,
                &source,
                &pubr,
                &policy,
                ReceiptBatchLimits::default(),
                ctx()
            )
            .await,
            Err(DeliveryError::Receipt(ReceiptError::Scope))
        ));
        assert_eq!(q.deletes.load(Ordering::Acquire), usize::from(revoke >= 9));
        if revoke <= 3 {
            assert!(
                store
                    .inspect(policy.binding.clone(), ctx())
                    .await?
                    .is_none()
            );
        } else {
            let r = store
                .replay(policy.binding.clone(), ctx())
                .await?
                .ok_or("receipt")?;
            assert_eq!(
                r.progress().verified_prefix(),
                if revoke == 4 { 0 } else { 2 }
            );
            assert_eq!(
                r.progress().source_ack_state(),
                if revoke >= 8 {
                    SourceAckState::Intent
                } else {
                    SourceAckState::NotRequested
                }
            );
        }
        store.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn lost_delete_or_live_cancel_recovers_intent_with_fresh_received_handle() -> TestResult {
    for mode in ["delete_denied", "delete_stall", "delete_uncertain"] {
        let d = root()?;
        let cfg = config(&d)?;
        let mut store = ReceiptStore::open(cfg.clone(), owner(), 1, ctx()).await?;
        let policy = Policy::new(0)?;
        let source = capture()?;
        let q = Queue::new(mode);
        let pubr = publisher_tests::Publisher::new("ok");
        let token = CancellationToken::new();
        let operation = ExtensionContext::new(token.clone(), Duration::from_secs(5))?;
        let (result, waiter) = tokio::join!(
            collect_delivery(
                &store,
                &q,
                &source,
                &pubr,
                &policy,
                ReceiptBatchLimits::default(),
                operation
            ),
            async {
                if mode == "delete_stall" {
                    tokio::time::timeout(Duration::from_secs(1), async {
                        while q.deletes.load(Ordering::Acquire) == 0 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await?;
                    token.cancel();
                }
                Ok::<(), Box<dyn std::error::Error>>(())
            }
        );
        waiter?;
        let p = store
            .replay(policy.binding.clone(), ctx())
            .await?
            .ok_or("receipt")?
            .progress()
            .clone();
        if mode == "delete_uncertain" {
            assert!(matches!(result, Ok(DeliveryStep::Settled { .. })));
            assert_eq!(p.source_ack_state(), SourceAckState::Uncertain);
        } else {
            assert!(result.is_err());
            assert_eq!(p.source_ack_state(), SourceAckState::Intent);
        }
        store.close(ctx()).await?;
        store = ReceiptStore::open_reconciled(
            cfg,
            owner(),
            1,
            ReceiptRecoveryGrant::from_trusted_checkpoint(
                policy.binding.clone(),
                p.checksum(),
                "unit-current-history".into(),
            )?,
            ctx(),
        )
        .await?;
        *q.mode.lock().await = "ok";
        assert!(
            matches!(collect_delivery(&store,&q,&source,&pubr,&policy,ReceiptBatchLimits::default(),ctx()).await?,DeliveryStep::Settled{progress,..} if progress.source_ack_state()==SourceAckState::Confirmed)
        );
        assert_eq!(q.receives.load(Ordering::Acquire), 2);
        assert_eq!(q.deletes.load(Ordering::Acquire), 2);
        store.close(ctx()).await?;
    }
    Ok(())
}
#[tokio::test]
async fn source_receive_timeout_has_no_worker_or_progress_and_quarantine_ack_stays_blocked()
-> TestResult {
    let d = root()?;
    let store = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let policy = Policy::new(0)?;
    let mut source = capture()?;
    let q = Queue::new("receive_stall");
    let pubr = publisher_tests::Publisher::new("ok");
    let budget = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(20))?;
    assert!(matches!(
        collect_delivery(
            &store,
            &q,
            &source,
            &pubr,
            &policy,
            ReceiptBatchLimits::default(),
            budget
        )
        .await,
        Err(DeliveryError::Receipt(ReceiptError::Timeout))
    ));
    assert_eq!(source.calls.load(Ordering::Acquire), 0);
    assert!(
        store
            .inspect(policy.binding.clone(), ctx())
            .await?
            .is_none()
    );
    source.original = b"invalid gzip".to_vec();
    *q.mode.lock().await = "ok";
    assert!(matches!(
        collect_delivery(
            &store,
            &q,
            &source,
            &pubr,
            &policy,
            ReceiptBatchLimits::default(),
            ctx()
        )
        .await,
        Err(DeliveryError::Receipt(ReceiptError::Ack))
    ));
    assert_eq!(q.deletes.load(Ordering::Acquire), 0);
    assert_eq!(
        store
            .inspect(policy.binding, ctx())
            .await?
            .ok_or("quarantine")?
            .info()
            .prepared_count,
        0
    );
    store.close(ctx()).await?;
    Ok(())
}

async fn replace_slot(
    store: &ReceiptStore,
    b: &ReceiptBinding,
    complete_new: bool,
) -> Result<(), ReceiptError> {
    let replay = store
        .replay(b.clone(), ctx())
        .await?
        .ok_or(ReceiptError::Uncertain)?;
    let p = if replay.remaining() > 0 {
        store
            .advance(
                b.clone(),
                replay.progress().clone(),
                replay.remaining() as u32,
                progress_tests::response(&replay, replay.remaining(), replay.remaining())
                    .map_err(|_| ReceiptError::Uncertain)?,
                ctx(),
            )
            .await?
    } else {
        replay.progress().clone()
    };
    let grant = |p: &ReceiptProgress| {
        ReceiptRecoveryGrant::from_trusted_checkpoint(
            b.clone(),
            p.checksum(),
            "unit-current-replacement".into(),
        )
    };
    let ReceiptAckCommit::Intent {
        ticket,
        progress: p,
    } = store
        .acknowledge(
            b.clone(),
            p.clone(),
            grant(&p)?,
            ReceiptAckUpdate::BeginProcessLocal {
                delivery: SourceDelivery::new(
                    Uuid::new_v4(),
                    "maintenance-source".into(),
                    "maintenance-handle".into(),
                )?,
                observed_at: "2026-10-07T12:00:02.000000000Z".into(),
            },
            ctx(),
        )
        .await?
    else {
        return Err(ReceiptError::Ack);
    };
    let p = settled_test(
        store
            .acknowledge(
                b.clone(),
                p.clone(),
                grant(&p)?,
                ReceiptAckUpdate::Finish {
                    ticket,
                    outcome: SourceAckOutcome::from_sqs_json_response(200, b""),
                    observed_at: "2026-10-07T12:00:03.000000000Z".into(),
                },
                ctx(),
            )
            .await?,
    )?;
    let done = store
        .retire(
            b.clone(),
            p.clone(),
            grant(&p)?,
            "2026-10-08T12:00:01.000000000Z".into(),
            ctx(),
        )
        .await?;
    let mut plan = preparation_tests::plan(2).map_err(|_| ReceiptError::Uncertain)?;
    plan.binding = b.clone();
    plan.receipt_id = Uuid::new_v4();
    plan.event_ids = vec![Uuid::new_v4(), Uuid::new_v4()];
    plan.original.version_id = "fixture-version-002".into();
    let next = prepare_receipt(
        &capture().map_err(|_| ReceiptError::Uncertain)?.original,
        plan,
        &ctx(),
    )
    .map_err(|_| ReceiptError::Uncertain)?;
    store
        .publish_next(next, b.clone(), done.clone(), grant(&done)?, ctx())
        .await?;
    if complete_new {
        let replay = store
            .replay(b.clone(), ctx())
            .await?
            .ok_or(ReceiptError::Uncertain)?;
        store
            .advance(
                b.clone(),
                replay.progress().clone(),
                2,
                progress_tests::response(&replay, 2, 2).map_err(|_| ReceiptError::Uncertain)?,
                ctx(),
            )
            .await?;
    }
    Ok(())
}
fn settled_test(c: ReceiptAckCommit) -> Result<ReceiptProgress, ReceiptError> {
    match c {
        ReceiptAckCommit::Settled(p) => Ok(p),
        _ => Err(ReceiptError::Ack),
    }
}
struct ReplacementPolicy<'a> {
    inner: Policy,
    store: &'a ReceiptStore,
    replace_at: usize,
}
#[crate::extension]
impl DeliveryPolicy for ReplacementPolicy<'_> {
    async fn binding(&self, c: &ExtensionContext) -> Result<ReceiptBinding, SourceFailure> {
        let b = self.inner.binding(c).await?;
        if self.inner.calls.load(Ordering::Acquire) == self.replace_at {
            replace_slot(self.store, &b, self.replace_at == 5)
                .await
                .map_err(|_| SourceFailure::Unavailable)?;
        }
        Ok(b)
    }
    async fn preparation(
        &self,
        o: &ObjectDiscovery,
        d: &QueueDelivery,
        c: &ExtensionContext,
    ) -> Result<CapturePreparation, SourceFailure> {
        self.inner.preparation(o, d, c).await
    }
    async fn acknowledge(
        &self,
        b: &ReceiptBinding,
        p: &ReceiptProgress,
        c: &ExtensionContext,
    ) -> Result<AckAuthorization, SourceFailure> {
        self.inner.acknowledge(b, p, c).await
    }
}
#[tokio::test]
async fn replaced_receipt_is_never_published_or_acked_by_the_previous_delivery() -> TestResult {
    for replace_at in [4, 5] {
        let d = root()?;
        let store = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
        let policy = ReplacementPolicy {
            inner: Policy::new(0)?,
            store: &store,
            replace_at,
        };
        let source = capture()?;
        let queue = Queue::new("ok");
        let pubr = publisher_tests::Publisher::new("ok");
        let result = collect_delivery(
            &store,
            &queue,
            &source,
            &pubr,
            &policy,
            ReceiptBatchLimits::default(),
            ctx(),
        )
        .await;
        assert!(
            matches!(
                result,
                Err(DeliveryError::Receipt(ReceiptError::StaleProgress))
            ),
            "replacement at {replace_at} was not fenced"
        );
        assert_eq!(queue.deletes.load(Ordering::Acquire), 0);
        assert_eq!(
            pubr.calls.load(Ordering::Acquire),
            usize::from(replace_at == 5)
        );
        let next = store
            .replay(policy.inner.binding.clone(), ctx())
            .await?
            .ok_or("new")?;
        assert_eq!(
            next.progress().verified_prefix(),
            if replace_at == 5 { 2 } else { 0 }
        );
        assert_eq!(
            next.progress().source_ack_state(),
            SourceAckState::NotRequested
        );
        store.close(ctx()).await?;
    }
    Ok(())
}
