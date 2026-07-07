use super::*;
use std::{
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

struct Source {
    bytes: Arc<[u8]>,
    mode: &'static str,
    calls: AtomicUsize,
    dropped: Arc<AtomicBool>,
}
impl Source {
    fn new(bytes: Vec<u8>, mode: &'static str) -> Self {
        Self {
            bytes: bytes.into(),
            mode,
            calls: AtomicUsize::new(0),
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }
}
struct Reader {
    inner: std::io::Cursor<Arc<[u8]>>,
    mode: &'static str,
    dropped: Arc<AtomicBool>,
}
impl Drop for Reader {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}
impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.mode {
            "stall" => Poll::Pending,
            "read_error" => Poll::Ready(Err(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset,
            ))),
            _ => Pin::new(&mut self.inner).poll_read(cx, buf),
        }
    }
}
#[crate::extension]
impl CaptureTransport for Source {
    async fn open(
        &self,
        d: &ObjectDiscovery,
        _: &ExtensionContext,
    ) -> Result<CaptureStream, CaptureFailure> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        assert_eq!(d.expected_bucket_owner(), "111122223333");
        assert_eq!(d.bucket(), "fixture-source-evidence");
        match self.mode {
            "denied" => return Err(CaptureFailure::Denied),
            "missing" => return Err(CaptureFailure::MissingVersion),
            "restore" => return Err(CaptureFailure::RestorePending),
            "throttled" => return Err(CaptureFailure::Throttled),
            "outage" => return Err(CaptureFailure::Unavailable),
            "open_stall" => std::future::pending::<()>().await,
            _ => (),
        }
        Ok(CaptureStream {
            version_id: if self.mode == "wrong_version" {
                "different-version".into()
            } else {
                d.version_id().to_owned()
            },
            etag: Some(if self.mode == "large_header" {
                "x".repeat(1025)
            } else {
                "captured-opaque-etag".into()
            }),
            body: Box::new(Reader {
                inner: std::io::Cursor::new(self.bytes.clone()),
                mode: self.mode,
                dropped: self.dropped.clone(),
            }),
        })
    }
}
fn discovery(b: &ReceiptBinding) -> Result<ObjectDiscovery, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&json!({"Records":[discovery_tests::record()]}))?;
    Ok(discover_object(&body, b, &ctx())?)
}
fn pins() -> Result<CapturePreparation, Box<dyn std::error::Error>> {
    let p = preparation_tests::plan(3)?;
    Ok(CapturePreparation {
        receipt_id: p.receipt_id,
        captured_at: p.original.captured_at,
        prepared_at: p.prepared_at,
        normalizer_sha256: p.normalizer_sha256,
        retention: p.retention,
        event_ids: p.event_ids,
        delivery_id: p.original.delivery_id,
    })
}
fn fresh() -> Result<ReceiptBinding, Box<dyn std::error::Error>> {
    Ok(vector("prepared")?.1)
}
fn changed_grant() -> Result<ReceiptBinding, Box<dyn std::error::Error>> {
    let mut b = fresh()?.0;
    b["authority_revision"] = "revoked-old-grant".into();
    Ok(ReceiptBinding::from_json(&format::canonical(&b, 65536)?)?)
}

#[tokio::test]
async fn exact_version_capture_prepares_on_owned_worker_and_reuses_retained_pins() -> TestResult {
    let raw = preparation_tests::original()?;
    let source = Source::new(raw.clone(), "ok");
    let b = fresh()?;
    let cap = capture_object(&source, discovery(&b)?, &b, ctx()).await?;
    assert_eq!(cap.original_bytes(), raw);
    assert!(source.dropped.load(Ordering::Acquire));
    let d = root()?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let id = s.publish_capture(cap, pins()?, b.clone(), ctx()).await?;
    let r = s.replay(b.clone(), ctx()).await?.ok_or("receipt")?;
    let wire = r.receipt.bytes;
    let old_progress = r.progress.bytes;
    let m: Value = serde_json::from_slice(
        &wire[36..36 + u32::from_be_bytes(wire[8..12].try_into()?) as usize],
    )?;
    assert_eq!(
        m["original"]["discovery_sha256"],
        format::hex(&discovery(&b)?.sha256())
    );
    assert_eq!(m["original"]["etag"], "captured-opaque-etag");
    s.close(ctx()).await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let cap = capture_object(&source, discovery(&b)?, &b, ctx()).await?;
    let mut newer = pins()?;
    newer.receipt_id = Uuid::new_v4();
    newer.normalizer_sha256 = [9; 32];
    newer.event_ids = vec![Uuid::new_v4()];
    newer.prepared_at += chrono::Duration::seconds(1);
    let reused = s.publish_capture(cap, newer, b.clone(), ctx()).await?;
    assert_eq!(reused, id);
    let r = s.replay(b, ctx()).await?.ok_or("receipt")?;
    assert_eq!(r.receipt.bytes, wire);
    assert_eq!(r.progress.bytes, old_progress);
    assert_eq!(s.metrics().replays, 1);
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn fresh_scope_checks_hold_before_open_and_before_publication() -> TestResult {
    let source = Source::new(preparation_tests::original()?, "ok");
    let b = fresh()?;
    assert!(matches!(
        capture_object(&source, discovery(&b)?, &changed_grant()?, ctx()).await,
        Err(CaptureError::Operation(ReceiptError::Scope))
    ));
    assert_eq!(source.calls.load(Ordering::Acquire), 0);
    let cap = capture_object(&source, discovery(&b)?, &b, ctx()).await?;
    let d = root()?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    assert!(matches!(
        s.publish_capture(cap, pins()?, changed_grant()?, ctx())
            .await,
        Err(ReceiptError::Scope)
    ));
    assert!(s.inspect(b, ctx()).await?.is_none());
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn denied_missing_restore_throttled_outage_and_bad_headers_keep_source_responsibility()
-> TestResult {
    let b = fresh()?;
    for mode in [
        "denied",
        "missing",
        "restore",
        "throttled",
        "outage",
        "wrong_version",
        "large_header",
        "read_error",
    ] {
        let source = Source::new(preparation_tests::original()?, mode);
        let error = capture_object(&source, discovery(&b)?, &b, ctx())
            .await
            .err()
            .ok_or("error")?;
        match mode {
            "denied" => assert!(matches!(
                error,
                CaptureError::Source(CaptureFailure::Denied)
            )),
            "missing" => assert!(matches!(
                error,
                CaptureError::Source(CaptureFailure::MissingVersion)
            )),
            "restore" => assert!(matches!(
                error,
                CaptureError::Source(CaptureFailure::RestorePending)
            )),
            "throttled" => assert!(matches!(
                error,
                CaptureError::Source(CaptureFailure::Throttled)
            )),
            "outage" => assert!(matches!(
                error,
                CaptureError::Source(CaptureFailure::Unavailable)
            )),
            "wrong_version" => assert!(matches!(error, CaptureError::VersionMismatch)),
            "large_header" => assert!(matches!(
                error,
                CaptureError::Source(CaptureFailure::Malformed)
            )),
            _ => assert!(matches!(
                error,
                CaptureError::Read(std::io::ErrorKind::ConnectionReset)
            )),
        }
    }
    Ok(())
}

#[tokio::test]
async fn actual_capture_byte_cap_and_eof_override_declared_size() -> TestResult {
    let b = fresh()?;
    for length in [0, MAX_CAPTURE_BYTES, MAX_CAPTURE_BYTES + 1] {
        let source = Source::new(vec![b'x'; length], "ok");
        let result = capture_object(&source, discovery(&b)?, &b, ctx()).await;
        if length == MAX_CAPTURE_BYTES {
            assert_eq!(result?.original_bytes().len(), length);
        } else {
            assert!(matches!(result, Err(CaptureError::Limit)));
        }
        assert!(source.dropped.load(Ordering::Acquire));
    }
    Ok(())
}

#[tokio::test]
async fn open_and_read_deadline_and_live_cancellation_drop_owned_streams() -> TestResult {
    let b = fresh()?;
    for mode in ["open_stall", "stall"] {
        let source = Source::new(preparation_tests::original()?, mode);
        let short = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(10))?;
        assert!(matches!(
            capture_object(&source, discovery(&b)?, &b, short).await,
            Err(CaptureError::Operation(ReceiptError::Timeout))
        ));
        if mode == "stall" {
            assert!(source.dropped.load(Ordering::Acquire));
        }
    }
    let source = Source::new(preparation_tests::original()?, "stall");
    let token = CancellationToken::new();
    let context = ExtensionContext::new(token.clone(), Duration::from_secs(5))?;
    let result = tokio::join!(
        capture_object(&source, discovery(&b)?, &b, context),
        async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            token.cancel();
        }
    );
    assert!(matches!(
        result.0,
        Err(CaptureError::Operation(ReceiptError::Cancelled))
    ));
    assert!(source.dropped.load(Ordering::Acquire));
    Ok(())
}

#[tokio::test]
async fn changed_bytes_or_object_identity_never_replaces_a_retained_receipt() -> TestResult {
    let b = fresh()?;
    let raw = preparation_tests::original()?;
    let source = Source::new(raw.clone(), "ok");
    let d = root()?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let cap = capture_object(&source, discovery(&b)?, &b, ctx()).await?;
    let initial = s.publish_capture(cap, pins()?, b.clone(), ctx()).await?;
    let source = Source::new(b"changed bytes at the same version".to_vec(), "ok");
    let cap = capture_object(&source, discovery(&b)?, &b, ctx()).await?;
    assert!(matches!(
        s.publish_capture(cap, pins()?, b.clone(), ctx()).await,
        Err(ReceiptError::IdentityConflict)
    ));
    let mut r = discovery_tests::record();
    r["s3"]["object"]["versionId"] = "different-object-version".into();
    let notice = serde_json::to_vec(&json!({"Records":[r]}))?;
    let next = discover_object(&notice, &b, &ctx())?;
    let source = Source::new(raw.clone(), "ok");
    let cap = capture_object(&source, next, &b, ctx()).await?;
    assert!(matches!(
        s.publish_capture(cap, pins()?, b.clone(), ctx()).await,
        Err(ReceiptError::Occupied)
    ));
    let stored = s.inspect(b, ctx()).await?.ok_or("receipt")?;
    assert_eq!(stored.info, initial);
    assert_eq!(stored.original_bytes(), raw);
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn malformed_capture_quarantines_and_bad_preflight_does_not_queue_mutation() -> TestResult {
    let b = fresh()?;
    let source = Source::new(b"invalid gzip original".to_vec(), "ok");
    let d = root()?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let cap = capture_object(&source, discovery(&b)?, &b, ctx()).await?;
    let mut p = pins()?;
    p.event_ids = vec![Uuid::nil(); 1025];
    assert!(s.publish_capture(cap, p, b.clone(), ctx()).await.is_err());
    assert!(s.inspect(b.clone(), ctx()).await?.is_none());
    let cap = capture_object(&source, discovery(&b)?, &b, ctx()).await?;
    let info = s.publish_capture(cap, pins()?, b.clone(), ctx()).await?;
    assert_eq!(info.prepared_count, 0);
    let r = s.replay(b, ctx()).await?.ok_or("receipt")?;
    assert_eq!(r.receipt.original_bytes(), b"invalid gzip original");
    assert_eq!(
        r.receipt.metadata["object_reasons"],
        json!(["invalid_compression"])
    );
    s.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn lost_capture_publication_caller_keeps_physical_owner_and_bounds_cancelled_queue()
-> TestResult {
    let b = fresh()?;
    let source = Source::new(preparation_tests::original()?, "ok");
    let cap = capture_object(&source, discovery(&b)?, &b, ctx()).await?;
    let queued_cap = capture_object(&source, discovery(&b)?, &b, ctx()).await?;
    let d = root()?;
    let mut cfg = config(&d)?;
    let (notify, entered) = tokio::sync::oneshot::channel();
    let notify = std::sync::Mutex::new(Some(notify));
    let (release, gate) = std::sync::mpsc::sync_channel::<()>(1);
    let gate = std::sync::Mutex::new(gate);
    cfg.hook = Some(Arc::new(move |stage| {
        if stage == Stage::ControlDirectorySynced
            && let Some(n) = notify.lock().map_err(|_| ReceiptError::Closed)?.take()
        {
            let _ = n.send(());
            let _ = gate
                .lock()
                .map_err(|_| ReceiptError::Closed)?
                .recv_timeout(Duration::from_secs(2));
        }
        Ok(())
    }));
    let s = Arc::new(ReceiptStore::open(cfg, owner(), 1, ctx()).await?);
    let worker = s.clone();
    let grant = b.clone();
    let p = pins()?;
    let first = tokio::spawn(async move { worker.publish_capture(cap, p, grant, ctx()).await });
    tokio::time::timeout(Duration::from_secs(1), entered).await??;
    first.abort();
    let _ = first.await;
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    let worker = s.clone();
    let grant = b.clone();
    let p = pins()?;
    let context = ctx();
    let cancel = context.cancellation().clone();
    let queued =
        tokio::spawn(async move { worker.publish_capture(queued_cap, p, grant, context).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while s.metrics().queue_depth != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(matches!(
        s.inspect(b.clone(), ctx()).await,
        Err(ReceiptError::Busy)
    ));
    cancel.cancel();
    assert!(matches!(queued.await?, Err(ReceiptError::Cancelled)));
    assert_eq!(s.metrics().queue_capacity, 1);
    assert!(matches!(
        ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await,
        Err(ReceiptError::Locked)
    ));
    let _ = release.try_send(());
    let s = Arc::try_unwrap(s).map_err(|_| "shared handle")?;
    s.close(ctx()).await?;
    let s = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let r = s.replay(b, ctx()).await?.ok_or("committed")?;
    assert_eq!(r.receipt.original_bytes(), source.bytes.as_ref());
    assert_eq!(r.remaining(), 2);
    assert_eq!(r.progress.revision(), 0);
    s.close(ctx()).await?;
    Ok(())
}
