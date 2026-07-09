//! Reproducible source HTTP simulation → owned receipt → real WAL/Parquet/findings.
//! Source service faults are simulated. Server durability is a real local process.
use serde_json::{Value, json};
use signal_collector_sdk::{ExtensionContext, cloudtrail::read_object, receipt::*};
use std::{io::Write, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
#[path = "cloudtrail-delivery/server.rs"]
mod server;
#[cfg(feature = "aws-source")]
#[path = "../support/aws_signature.rs"]
mod signature;
#[path = "cloudtrail-delivery/source.rs"]
mod source;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const INGEST_TOKEN: &str = "synthetic-ingest-auth-never-log";
const AT: &str = "2026-10-07T12:00:02.000000000Z";
const OWNER: Uuid = Uuid::from_u128(0x40000000000040008000000000000001);
fn ctx() -> TestResult<ExtensionContext> {
    Ok(ExtensionContext::new(
        CancellationToken::new(),
        Duration::from_secs(5),
    )?)
}
fn fixture() -> TestResult<Value> {
    Ok(serde_json::from_str(include_str!(
        "../fixtures/cloudtrail-receipt/contract.json"
    ))?)
}
fn unhex(s: &str) -> TestResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err("hex length".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| Ok(u8::from_str_radix(std::str::from_utf8(c)?, 16)?))
        .collect()
}
fn binding_bytes(v: &Value) -> TestResult<Vec<u8>> {
    // The fixed binding contains ASCII strings, arrays and a bool. Explicitly
    // sort keys: transitive serde_json preserve_order can vary feature unification.
    let fields: std::collections::BTreeMap<_, _> =
        v.as_object().ok_or("binding fields")?.iter().collect();
    Ok(serde_json::to_vec(&fields)?)
}
fn binding() -> TestResult<ReceiptBinding> {
    let mut b = fixture()?["receipt_vectors"][0]["metadata"]["binding"].clone();
    b["ack_requires_m2"] = true.into();
    Ok(ReceiptBinding::from_json(&binding_bytes(&b)?)?)
}
fn notification() -> Value {
    json!({"Records":[{"eventVersion":"2.1","eventSource":"aws:s3","eventName":"ObjectCreated:Put",
        "s3":{"bucket":{"name":"fixture-source-evidence"},"object":{
            "key":"AWSLogs%2Ffixture%2Fcaf%C3%A9+%2B+%25.json.gz","versionId":"fixture-version-001"}}}]})
}
fn original() -> TestResult<Vec<u8>> {
    let f = fixture()?;
    let gzip = unhex(
        f["receipt_vectors"][0]["original_hex"]
            .as_str()
            .ok_or("gzip")?,
    )?;
    let object = read_object(&gzip, &ctx()?)?;
    // Assemble a real two-record source object, not a descriptor-edited receipt.
    // The third fixture record is foreign-account and is tested separately.
    let mut native = b"{\"Records\":[".to_vec();
    native.extend_from_slice(object.record(0).ok_or("record")?);
    native.push(b',');
    native.extend_from_slice(object.record(1).ok_or("record")?);
    native.extend_from_slice(b"]}");
    let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    g.write_all(&native)?;
    Ok(g.finish()?)
}
fn pins(count: usize) -> TestResult<CapturePreparation> {
    let f = fixture()?;
    let m = &f["receipt_vectors"][0]["metadata"];
    Ok(CapturePreparation {
        receipt_id: Uuid::parse_str(m["receipt_id"].as_str().ok_or("id")?)?,
        captured_at: m["original"]["captured_at"]
            .as_str()
            .ok_or("time")?
            .parse()?,
        prepared_at: m["prepared_at"].as_str().ok_or("time")?.parse()?,
        normalizer_sha256: unhex(m["normalizer_sha256"].as_str().ok_or("hash")?)?
            .try_into()
            .map_err(|_| "hash length")?,
        retention: ReceiptRetention {
            retain_until: m["retention"]["retain_until"]
                .as_str()
                .ok_or("time")?
                .parse()?,
            source_replay_until: m["retention"]["source_replay_until"]
                .as_str()
                .ok_or("time")?
                .parse()?,
            recovery_budget_seconds: 3600,
        },
        event_ids: (0..count)
            .map(|i| Uuid::from_u128(0x20000000000040008000000000000001 + i as u128))
            .collect(),
        delivery_id: "fixture-message-001".into(),
    })
}
fn config(d: &tempfile::TempDir) -> TestResult<ReceiptConfig> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(ReceiptConfig::new(d.path().into(), MIN_QUOTA_BYTES)?)
}
fn grant(b: ReceiptBinding, p: &ReceiptProgress) -> TestResult<ReceiptRecoveryGrant> {
    // This test's live coordinator tracks the last acknowledged local revision.
    // Not a production history witness: independent custody is a later gate.
    Ok(ReceiptRecoveryGrant::from_trusted_checkpoint(
        b,
        p.checksum(),
        "local-fixture-coordinator".into(),
    )?)
}
fn begin(d: source::Delivery) -> TestResult<ReceiptAckUpdate> {
    Ok(ReceiptAckUpdate::BeginProcessLocal {
        delivery: SourceDelivery::new(Uuid::new_v4(), d.id, d.handle)?,
        observed_at: AT.into(),
    })
}
fn intent(c: ReceiptAckCommit) -> TestResult<(SourceAckTicket, ReceiptProgress)> {
    match c {
        ReceiptAckCommit::Intent { ticket, progress } => Ok((ticket, progress)),
        _ => Err("intent".into()),
    }
}
fn settled(c: ReceiptAckCommit) -> TestResult<ReceiptProgress> {
    match c {
        ReceiptAckCommit::Settled(p) => Ok(p),
        _ => Err("settled".into()),
    }
}
struct LostReply(HttpReceiptPublisher);
#[signal_collector_sdk::extension]
impl ReceiptPublisher for LostReply {
    async fn publish(
        &self,
        b: &PreparedBatch,
        c: &ExtensionContext,
    ) -> Result<AdmissionReply, PublishFailure> {
        let reply = self.0.publish(b, c).await?;
        // Deliberately lose a real valid server reply at the adapter boundary.
        if reply.status != 202 {
            return Ok(reply);
        }
        Err(PublishFailure::Uncertain)
    }
}
fn publisher(url: &str, authorized: bool) -> TestResult<HttpReceiptPublisher> {
    Ok(HttpReceiptPublisher::new(
        url,
        Some(if authorized {
            INGEST_TOKEN
        } else {
            "invalid-fixture-token"
        }),
        Duration::from_secs(1),
    )?)
}

#[tokio::test]
async fn native_source_to_real_server_replays_lost_admission_and_failed_storage_then_acks()
-> TestResult {
    let d = tempfile::tempdir()?;
    let cfg = config(&d)?;
    let raw = original()?;
    let mock = source::LocalSource::start(raw.clone(), notification()).await?;
    let src = source::SourceClient::new(mock.url.clone())?;
    let b = binding()?;
    let delivery = src.receive().await?.ok_or("delivery")?;
    assert!(src.receive().await?.is_none()); // Visibility lease suppresses repeats.
    let mut store = ReceiptStore::open(cfg.clone(), OWNER, 1, ctx()?).await?;
    let cap = capture_object(
        &src,
        discover_object(&delivery.body, &b, &ctx()?)?,
        &b,
        ctx()?,
    )
    .await?;
    let info = store
        .publish_capture(cap, pins(2)?, b.clone(), ctx()?)
        .await?;
    let r = store.replay(b.clone(), ctx()?).await?.ok_or("receipt")?;
    assert_eq!(r.receipt().original_bytes(), raw);
    assert_eq!(r.remaining(), 2);
    let expected: Vec<Value> = (0..2)
        .map(|i| {
            serde_json::from_slice(r.receipt().prepared_bytes(i).ok_or("payload")?)
                .map_err(Into::into)
        })
        .collect::<TestResult<_>>()?;
    assert!(matches!(
        store
            .acknowledge(
                b.clone(),
                r.progress().clone(),
                grant(b.clone(), r.progress())?,
                begin(delivery)?,
                ctx()?
            )
            .await,
        Err(ReceiptError::Ack)
    ));
    assert_eq!(mock.state.lock().await.deletes, 0);
    let runtime = tempfile::tempdir()?;
    let mut srv = server::Server::new(runtime.path())?;
    srv.start().await?;
    assert!(matches!(
        publish_receipt_batch(
            &store,
            b.clone(),
            &publisher(&srv.url, false)?,
            ReceiptBatchLimits::default(),
            ctx()?
        )
        .await?,
        PublishStep::Attempt {
            accepted: 0,
            remaining: 2,
            ..
        }
    ));
    assert_eq!(
        store
            .replay(b.clone(), ctx()?)
            .await?
            .ok_or("receipt")?
            .progress()
            .verified_prefix(),
        0
    );
    assert_eq!(mock.state.lock().await.deletes, 0);
    // A real create_new failure guarantees no Parquet/finding/checkpoint after M2.
    let canonical: signal_event::SignalEvent = serde_json::from_value(expected[0].clone())?;
    let at = canonical.timestamp;
    let partition = srv.root.join(format!(
        "events/date={}/hour={}",
        at.format("%Y-%m-%d"),
        at.format("%H")
    ));
    std::fs::create_dir_all(&partition)?;
    let blocker = partition.join("batch-00000000000000000001-00000000000000000001.parquet.tmp");
    std::fs::write(&blocker, b"owned source-delivery storage fault")?;
    let step = publish_receipt_batch(
        &store,
        b.clone(),
        &LostReply(publisher(&srv.url, true)?),
        ReceiptBatchLimits::new(1, 1024 * 1024)?,
        ctx()?,
    )
    .await?;
    assert!(matches!(
        step,
        PublishStep::Attempt {
            accepted: 0,
            remaining: 2,
            ..
        }
    ));
    srv.wait_failed().await?;
    assert_eq!(srv.checkpoint()?, 0);
    assert_eq!(
        std::fs::read(&blocker)?,
        b"owned source-delivery storage fault"
    );
    let old = store.replay(b.clone(), ctx()?).await?.ok_or("receipt")?;
    let checkpoint = old.progress().clone();
    store.close(ctx()?).await?;
    store = ReceiptStore::open_reconciled(
        cfg.clone(),
        OWNER,
        1,
        grant(b.clone(), &checkpoint)?,
        ctx()?,
    )
    .await?;
    assert_eq!(
        store
            .replay(b.clone(), ctx()?)
            .await?
            .ok_or("receipt")?
            .progress()
            .checksum(),
        checkpoint.checksum()
    );
    mock.expire().await;
    let delivery = src.receive().await?.ok_or("redelivery")?;
    let cap = capture_object(
        &src,
        discover_object(&delivery.body, &b, &ctx()?)?,
        &b,
        ctx()?,
    )
    .await?;
    let mut changed = pins(2)?;
    changed.receipt_id = Uuid::new_v4();
    changed.event_ids = vec![Uuid::new_v4()];
    changed.normalizer_sha256 = [7; 32];
    assert_eq!(
        store
            .publish_capture(cap, changed, b.clone(), ctx()?)
            .await?,
        info
    );
    std::fs::remove_file(&blocker)?;
    srv.start().await?;
    srv.persisted(1, 1).await?;
    // No implicit exactly-once promise: losing 202 requires exact duplicate replay.
    for remaining in [1, 0] {
        assert!(
            matches!(publish_receipt_batch(&store,b.clone(),&publisher(&srv.url,true)?,ReceiptBatchLimits::new(1,1024*1024)?,ctx()?).await?,PublishStep::Attempt{accepted:1,remaining:r,..} if r==remaining)
        );
    }
    srv.persisted(3, 3).await?;
    let events = srv.rows("events").await?;
    assert_eq!(events.iter().filter(|e| *e == &expected[0]).count(), 2);
    assert_eq!(events.iter().filter(|e| *e == &expected[1]).count(), 1);
    assert_eq!(
        srv.rows("findings").await?[0]["event_ids"],
        json!([expected[0]["id"]])
    );
    let r = store.replay(b.clone(), ctx()?).await?.ok_or("receipt")?;
    let (ticket, p) = intent(
        store
            .acknowledge(
                b.clone(),
                r.progress().clone(),
                grant(b.clone(), r.progress())?,
                begin(delivery)?,
                ctx()?,
            )
            .await?,
    )?;
    mock.state.lock().await.fault = "delete_uncertain";
    let _lost_result = src.delete(ticket.handle()).await?;
    drop(ticket); // Crash/lost result: never reconstruct its persisted handle.
    store.close(ctx()?).await?;
    store =
        ReceiptStore::open_reconciled(cfg.clone(), OWNER, 1, grant(b.clone(), &p)?, ctx()?).await?;
    let p = settled(
        store
            .acknowledge(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                ReceiptAckUpdate::RecoverUncertain {
                    observed_at: AT.into(),
                },
                ctx()?,
            )
            .await?,
    )?;
    assert!(mock.state.lock().await.pending);
    mock.state.lock().await.fault = "none";
    mock.expire().await;
    let latest = src.receive().await?.ok_or("latest delivery")?;
    let (ticket, p) = intent(
        store
            .acknowledge(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                begin(latest)?,
                ctx()?,
            )
            .await?,
    )?;
    let outcome = src.delete(ticket.handle()).await?;
    let p = settled(
        store
            .acknowledge(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                ReceiptAckUpdate::Finish {
                    ticket,
                    outcome,
                    observed_at: AT.into(),
                },
                ctx()?,
            )
            .await?,
    )?;
    assert!(!mock.state.lock().await.pending);
    assert_eq!(p.verified_prefix(), 2);
    // Standard-queue duplicate after confirmed deletion remains harmless.
    {
        let mut s = mock.state.lock().await;
        s.pending = true;
    }
    mock.expire().await;
    let repeat = src.receive().await?.ok_or("post-delete duplicate")?;
    assert!(matches!(
        publish_receipt_batch(
            &store,
            b.clone(),
            &publisher(&srv.url, true)?,
            ReceiptBatchLimits::default(),
            ctx()?
        )
        .await?,
        PublishStep::Complete { .. }
    ));
    let (ticket, p) = intent(
        store
            .acknowledge(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                begin(repeat)?,
                ctx()?,
            )
            .await?,
    )?;
    let outcome = src.delete(ticket.handle()).await?;
    let p = settled(
        store
            .acknowledge(
                b.clone(),
                p.clone(),
                grant(b.clone(), &p)?,
                ReceiptAckUpdate::Finish {
                    ticket,
                    outcome,
                    observed_at: AT.into(),
                },
                ctx()?,
            )
            .await?,
    )?;
    store.close(ctx()?).await?;
    store = ReceiptStore::open_reconciled(cfg, OWNER, 1, grant(b.clone(), &p)?, ctx()?).await?;
    assert_eq!(
        store.replay(b, ctx()?).await?.ok_or("receipt")?.remaining(),
        0
    );
    for entry in std::fs::read_dir(d.path())? {
        let e = entry?;
        if e.file_type()?.is_file() {
            assert!(
                !std::fs::read(e.path())?
                    .windows(b"ephemeral-private-handle".len())
                    .any(|w| w == b"ephemeral-private-handle")
            );
        }
    }
    store.close(ctx()?).await?;
    srv.crash()?;
    srv.start().await?;
    srv.persisted(3, 3).await?;
    assert_eq!(srv.rows("events").await?, events);
    srv.assert_redacted()?;
    mock.close().await?;
    Ok(())
}

#[tokio::test]
async fn source_throttles_outages_denials_versions_and_malformed_objects_hold_work() -> TestResult {
    let d = tempfile::tempdir()?;
    let store = ReceiptStore::open(config(&d)?, OWNER, 1, ctx()?).await?;
    let mock = source::LocalSource::start(original()?, notification()).await?;
    let src = source::SourceClient::new(mock.url.clone())?;
    let b = binding()?;
    for mode in ["queue_throttle", "queue_denied"] {
        mock.state.lock().await.fault = mode;
        assert!(src.receive().await.is_err());
    }
    for mode in [
        "object_throttle",
        "object_outage",
        "object_denied",
        "object_missing",
        "wrong_version",
    ] {
        mock.state.lock().await.fault = mode;
        assert!(
            capture_object(
                &src,
                discover_object(&serde_json::to_vec(&notification())?, &b, &ctx()?)?,
                &b,
                ctx()?
            )
            .await
            .is_err()
        );
        assert!(store.inspect(b.clone(), ctx()?).await?.is_none());
        assert!(mock.state.lock().await.pending);
        assert_eq!(mock.state.lock().await.deletes, 0);
    }
    let opens = mock.state.lock().await.opens;
    let mut v = fixture()?["receipt_vectors"][0]["metadata"]["binding"].clone();
    v["authority_revision"] = "revoked".into();
    v["ack_requires_m2"] = true.into();
    let fresh = ReceiptBinding::from_json(&binding_bytes(&v)?)?;
    assert!(matches!(
        capture_object(
            &src,
            discover_object(&serde_json::to_vec(&notification())?, &b, &ctx()?)?,
            &fresh,
            ctx()?
        )
        .await,
        Err(CaptureError::Operation(ReceiptError::Scope))
    ));
    assert_eq!(mock.state.lock().await.opens, opens);
    mock.state.lock().await.fault = "malformed_object";
    let cap = capture_object(
        &src,
        discover_object(&serde_json::to_vec(&notification())?, &b, &ctx()?)?,
        &b,
        ctx()?,
    )
    .await?;
    let info = store
        .publish_capture(cap, pins(2)?, b.clone(), ctx()?)
        .await?;
    assert_eq!(info.prepared_count, 0);
    let p = store
        .replay(b.clone(), ctx()?)
        .await?
        .ok_or("quarantine")?
        .progress()
        .clone();
    mock.state.lock().await.fault = "none";
    let delivery = src.receive().await?.ok_or("delivery")?;
    assert!(matches!(
        store
            .acknowledge(
                b.clone(),
                p.clone(),
                grant(b, &p)?,
                begin(delivery)?,
                ctx()?
            )
            .await,
        Err(ReceiptError::Ack)
    ));
    assert_eq!(mock.state.lock().await.deletes, 0);
    store.close(ctx()?).await?;
    mock.close().await?;
    Ok(())
}

#[tokio::test]
async fn expired_handle_success_does_not_prove_source_deletion() -> TestResult {
    let mock = source::LocalSource::start(original()?, notification()).await?;
    let src = source::SourceClient::new(mock.url.clone())?;
    let old = src.receive().await?.ok_or("old")?;
    mock.expire().await;
    let new = src.receive().await?.ok_or("new")?;
    assert_ne!(old.handle, new.handle);
    // Protocol-only negative probe, independent of collector ACK decisions.
    let _ = src.delete(&old.handle).await?;
    assert!(mock.state.lock().await.pending);
    let _ = src.delete(&new.handle).await?;
    assert!(!mock.state.lock().await.pending);
    mock.close().await?;
    Ok(())
}

struct LocalPolicy {
    binding: ReceiptBinding,
}
#[signal_collector_sdk::extension]
impl DeliveryPolicy for LocalPolicy {
    async fn binding(&self, _: &ExtensionContext) -> Result<ReceiptBinding, SourceFailure> {
        Ok(self.binding.clone())
    }
    async fn preparation(
        &self,
        _: &ObjectDiscovery,
        d: &QueueDelivery,
        _: &ExtensionContext,
    ) -> Result<CapturePreparation, SourceFailure> {
        let mut p = pins(2).map_err(|_| SourceFailure::Malformed)?;
        p.delivery_id = d.message_id().into();
        Ok(p)
    }
    async fn acknowledge(
        &self,
        b: &ReceiptBinding,
        p: &ReceiptProgress,
        _: &ExtensionContext,
    ) -> Result<AckAuthorization, SourceFailure> {
        // This fixture coordinator is live in-process; it cannot attest a copied
        // root or host-loss restore. Independent authority remains an external
        // application obligation and later object-custody qualification.
        Ok(AckAuthorization {
            grant: grant(b.clone(), p).map_err(|_| SourceFailure::Denied)?,
            observed_at: AT.into(),
        })
    }
}
#[tokio::test]
async fn bounded_collector_driver_runs_real_source_and_ingest_then_recovers_uncertain_delete()
-> TestResult {
    let d = tempfile::tempdir()?;
    let cfg = config(&d)?;
    let b = binding()?;
    let mut store = ReceiptStore::open(cfg.clone(), OWNER, 1, ctx()?).await?;
    let mock = source::LocalSource::start(original()?, notification()).await?;
    let src = source::SourceClient::new(mock.url.clone())?;
    let policy = LocalPolicy { binding: b.clone() };
    let runtime = tempfile::tempdir()?;
    let mut srv = server::Server::new(runtime.path())?;
    srv.start().await?;
    let publish = publisher(&srv.url, true)?;
    mock.state.lock().await.fault = "delete_uncertain";
    let p = match collect_delivery(
        &store,
        &src,
        &src,
        &publish,
        &policy,
        ReceiptBatchLimits::default(),
        ctx()?,
    )
    .await?
    {
        DeliveryStep::Settled { receipt, progress } => {
            assert_eq!(receipt.prepared_count, 2);
            assert_eq!(progress.source_ack_state(), SourceAckState::Uncertain);
            progress
        }
        _ => return Err("uncertain settlement".into()),
    };
    assert!(mock.state.lock().await.pending);
    assert_eq!(mock.state.lock().await.deletes, 1);
    srv.persisted(2, 2).await?;
    let events = srv.rows("events").await?;
    store.close(ctx()?).await?;
    store = ReceiptStore::open_reconciled(cfg, OWNER, 1, grant(b.clone(), &p)?, ctx()?).await?;
    mock.state.lock().await.fault = "none";
    mock.expire().await;
    assert!(
        matches!(collect_delivery(&store,&src,&src,&publish,&policy,ReceiptBatchLimits::default(),ctx()?).await?,
        DeliveryStep::Settled{progress,..} if progress.source_ack_state()==SourceAckState::Confirmed)
    );
    assert!(!mock.state.lock().await.pending);
    assert_eq!(mock.state.lock().await.deletes, 2);
    assert_eq!(srv.rows("events").await?, events);
    assert_eq!(srv.checkpoint()?, 2);
    assert!(matches!(
        collect_delivery(
            &store,
            &src,
            &src,
            &publish,
            &policy,
            ReceiptBatchLimits::default(),
            ctx()?
        )
        .await?,
        DeliveryStep::Idle
    ));
    store.close(ctx()?).await?;
    srv.crash()?;
    srv.start().await?;
    srv.persisted(2, 2).await?;
    srv.assert_redacted()?;
    mock.close().await?;
    Ok(())
}

#[cfg(feature = "aws-source")]
struct RuntimeCredentials(std::sync::atomic::AtomicUsize);
#[cfg(feature = "aws-source")]
#[signal_collector_sdk::extension]
impl AwsCredentialsProvider for RuntimeCredentials {
    async fn credentials(&self, _: &ExtensionContext) -> Result<SigningCredentials, SourceFailure> {
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        SigningCredentials::new(
            if n == 0 {
                source::ACCESS_A
            } else {
                source::ACCESS_B
            },
            source::SIGNING_SECRET,
            Some(source::SESSION_TOKEN),
            None,
        )
    }
}
#[cfg(feature = "aws-source")]
#[tokio::test]
async fn signed_aws_adapter_drives_real_server_throttle_rotation_and_redelivery_recovery()
-> TestResult {
    let d = tempfile::tempdir()?;
    let cfg = config(&d)?;
    let b = binding()?;
    let mut store = ReceiptStore::open(cfg.clone(), OWNER, 1, ctx()?).await?;
    let mock = source::LocalSource::start(original()?, notification()).await?;
    let credentials =
        std::sync::Arc::new(RuntimeCredentials(std::sync::atomic::AtomicUsize::new(0)));
    let src = AwsSourceClient::new(
        AwsSourceConfig::new(
            "arn:aws:sqs:us-east-1:111122223333:fixture",
            &format!("{}/111122223333/fixture", mock.url),
            "eu-central-1",
            &mock.url,
            30,
            true,
        )?,
        credentials.clone(),
        Duration::from_secs(1),
    )?;
    let runtime = tempfile::tempdir()?;
    let mut srv = server::Server::new(runtime.path())?;
    srv.start().await?;
    let publish = publisher(&srv.url, true)?;
    let policy = LocalPolicy { binding: b.clone() };
    mock.state.lock().await.fault = "object_throttle";
    assert!(matches!(
        collect_delivery(
            &store,
            &src,
            &src,
            &publish,
            &policy,
            ReceiptBatchLimits::default(),
            ctx()?
        )
        .await,
        Err(DeliveryError::Capture(CaptureError::Source(
            CaptureFailure::Throttled
        )))
    ));
    assert_eq!(mock.state.lock().await.deletes, 0);
    assert!(store.replay(b.clone(), ctx()?).await?.is_none());
    mock.expire().await;
    mock.state.lock().await.fault = "delete_uncertain";
    // A failed remote delete leaves the physical intent for recovery. The
    // driver returns an error instead of inventing a confirmed source result.
    assert!(matches!(
        collect_delivery(
            &store,
            &src,
            &src,
            &publish,
            &policy,
            ReceiptBatchLimits::default(),
            ctx()?
        )
        .await,
        Err(DeliveryError::Source(SourceFailure::Unavailable))
    ));
    let r = store
        .replay(b.clone(), ctx()?)
        .await?
        .ok_or("retained receipt")?;
    assert_eq!(r.progress().verified_prefix(), 2);
    assert_eq!(r.progress().source_ack_state(), SourceAckState::Intent);
    let receipt = r.receipt().info();
    let p = r.progress().clone();
    srv.persisted(2, 2).await?;
    let events = srv.rows("events").await?;
    store.close(ctx()?).await?;
    store = ReceiptStore::open_reconciled(cfg, OWNER, 1, grant(b.clone(), &p)?, ctx()?).await?;
    mock.state.lock().await.fault = "none";
    mock.expire().await;
    let recovered = collect_delivery(
        &store,
        &src,
        &src,
        &publish,
        &policy,
        ReceiptBatchLimits::default(),
        ctx()?,
    )
    .await?;
    assert!(
        matches!(recovered,DeliveryStep::Settled {receipt: current,progress} if current==receipt && progress.source_ack_state()==SourceAckState::Confirmed)
    );
    assert_eq!(srv.rows("events").await?, events);
    assert_eq!(srv.checkpoint()?, 2);
    assert!(!mock.state.lock().await.pending);
    assert_eq!(mock.state.lock().await.deletes, 2);
    assert!(matches!(
        collect_delivery(
            &store,
            &src,
            &src,
            &publish,
            &policy,
            ReceiptBatchLimits::default(),
            ctx()?
        )
        .await?,
        DeliveryStep::Idle
    ));
    assert_eq!(mock.state.lock().await.signatures, 9);
    assert_eq!(credentials.0.load(std::sync::atomic::Ordering::Acquire), 9);
    store.close(ctx()?).await?;
    srv.crash()?;
    srv.start().await?;
    srv.persisted(2, 2).await?;
    srv.assert_redacted()?;
    mock.close().await?;
    Ok(())
}
