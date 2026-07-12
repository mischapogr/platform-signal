use super::*;
use signal_protocol::audit::{Action, Actor, AuditAcknowledgement, AuditRecord, ConfigurationKind};
use std::{
    cell::Cell,
    task::{Context, Poll, Waker},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
};
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
pub(super) fn record() -> Result<PreparedAudit, signal_protocol::audit::AuditError> {
    AuditRecord {
        schema_version: 1,
        record_id: uuid::Uuid::new_v4(),
        producer_id: uuid::Uuid::new_v4(),
        sequence: 1,
        timestamp: chrono::Utc::now(),
        actor: Actor::System {},
        action: Action::ConfigurationActivation {
            configuration: ConfigurationKind::Runtime,
            revision_sha256: "a".repeat(64),
        },
    }
    .prepare()
}
pub(super) struct Task(pub(super) Option<JoinHandle<TestResult>>);
impl Drop for Task {
    fn drop(&mut self) {
        if let Some(t) = &self.0 {
            t.abort();
        }
    }
}
impl Task {
    async fn finish(mut self) -> TestResult {
        tokio::time::timeout(
            Duration::from_secs(3),
            self.0.as_mut().ok_or("missing peer")?,
        )
        .await???;
        self.0.take();
        Ok(())
    }
    async fn stop(mut self) -> TestResult {
        let t = self.0.take().ok_or("missing peer")?;
        t.abort();
        assert!(t.await.is_err_and(|e| e.is_cancelled()));
        Ok(())
    }
}
async fn peer(
    mode: &'static str,
    record: &PreparedAudit,
) -> Result<(String, Task, oneshot::Receiver<()>), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/v1/audit/records", listener.local_addr()?);
    let expected = record.body().to_vec();
    let mut ack = AuditAcknowledgement::for_prepared(record);
    if mode == "stale" {
        ack.sequence += 1;
    }
    let ack = ack.to_json()?;
    let (began, seen) = oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut stream, _) = listener.accept().await?;
            let mut bytes = Vec::new(); let mut block = [0u8; 1024];
            let (headers, length, offset) = loop {
                let n = stream.read(&mut block).await?;
                if n == 0 || n > 8192 - bytes.len() { return Err("bounded request missing".into()); }
                bytes.extend_from_slice(&block[..n]);
                if let Some(end) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&bytes[..end])?.to_ascii_lowercase();
                    let length = headers.lines().find_map(|l| l.strip_prefix("content-length: ")).ok_or("length")?.parse::<usize>()?;
                    if length > signal_protocol::audit::RECORD_BYTES { return Err("request oversized".into()); }
                    break (headers, length, end + 4);
                }
            };
            while bytes.len() < offset + length {
                let n = stream.read(&mut block).await?;
                if n == 0 || n > 8192 - bytes.len() { return Err("body missing".into()); }
                bytes.extend_from_slice(&block[..n]);
            }
            assert!(headers.starts_with("post /v1/audit/records http/1.1\r\n"));
            assert!(headers.contains("authorization: bearer synthetic-audit-only"));
            assert_eq!(&bytes[offset..offset+length], expected);
            let status = match mode { "permission" => 403, "throttle" => 429, "unavailable" => 503, "redirect" => 307, _ => 200 };
            let body: &[u8] = match mode { "malformed" => b"{", "empty" => b"", "status-only" => b"ok", _ => &ack };
            if mode == "lost" { began.send(()).map_err(|_| "caller gone")?; return Ok(()); }
            let reply = if mode == "chunked-large" {
                let mut reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n401\r\n".to_vec();
                reply.extend_from_slice(&vec![b' '; ACK_BYTES + 1]);
                reply.extend_from_slice(b"\r\n0\r\n\r\n");
                reply
            } else {
                let length = if mode == "declared-large" { ACK_BYTES + 1 } else if mode == "partial" { body.len() + 10 } else { body.len() };
                let headers = format!("HTTP/1.1 {status} Synthetic\r\nContent-Length: {length}\r\nLocation: http://127.0.0.1:1/forbidden\r\nConnection: close\r\n\r\n");
                let mut reply = headers.into_bytes(); reply.extend_from_slice(body); reply
            };
            // Complete bounded write precedes a client's deliberate header rejection.
            stream.write_all(&reply).await.map_err(|e| format!("{mode}: fixture reply write: {e}"))?;
            began.send(()).map_err(|_| "caller gone")?;
            if mode == "partial" { std::future::pending::<()>().await; }
            close_after_reply(&mut stream).await?;
            Ok(())
        }).await?
    });
    Ok((endpoint, Task(Some(task)), seen))
}
pub(super) async fn close_after_reply(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> TestResult {
    if let Err(e) = stream.shutdown().await
        && !matches!(
            e.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::NotConnected
        )
    {
        return Err(e.into());
    }
    Ok(())
}
pub(super) async fn retire() -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(2);
    while OWNER.depth() != 0 {
        if Instant::now() >= deadline {
            return Err("physical audit owner did not retire".into());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}
#[test]
fn private_configuration_requires_restricted_transport_and_finite_credentials() -> TestResult {
    for endpoint in [
        "http://localhost:1",
        "http://192.0.2.1:1",
        "http://127.0.0.1:0",
        "https://127.0.0.1:1",
        "http://u:p@127.0.0.1:1",
        "http://127.0.0.1:1/?token=x",
        "http://127.0.0.1:1/#x",
        "http://127.0.0.1:1/v1/events/batch",
    ] {
        assert!(
            HttpAuditSink::for_loopback_simulation(endpoint, "synthetic", Duration::from_secs(1))
                .is_err(),
            "unsafe endpoint admitted"
        );
    }
    for token in [
        String::new(),
        "x".repeat(4097),
        "synthetic\r\nsecret".into(),
    ] {
        assert!(
            HttpAuditSink::for_loopback_simulation(
                "http://127.0.0.1:1",
                &token,
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
    for timeout in [Duration::ZERO, Duration::from_secs(86401)] {
        assert!(
            HttpAuditSink::for_loopback_simulation("http://127.0.0.1:1", "synthetic", timeout)
                .is_err()
        );
    }
    assert!(
        HttpAuditSink::from_private_tls(
            "http://127.0.0.1:1",
            "synthetic",
            Duration::from_secs(1),
            b"{}"
        )
        .is_err()
    );
    assert!(
        HttpAuditSink::from_private_tls(
            "https://127.0.0.1:1",
            "synthetic",
            Duration::from_secs(1),
            b"{}"
        )
        .is_err()
    );
    assert!(
        HttpAuditSink::for_loopback_simulation(
            "http://[::1]:12345",
            "synthetic",
            Duration::from_secs(1)
        )
        .is_ok()
    );
    assert_eq!(
        ConfigurationError.to_string(),
        "invalid restricted audit transport configuration"
    );
    Ok(())
}
#[tokio::test]
async fn actual_http_and_mutual_tls_replay_failures_cancel_keep_bounded_ownership() -> TestResult {
    let canonical = record()?;
    let mut original = canonical.body().to_vec();
    original.extend_from_slice(b" \n");
    let record = PreparedAudit::from_original(&original)?;
    assert_ne!(record.sha256(), canonical.sha256());
    for mode in [
        "valid",
        "valid",
        "lost",
        "stale",
        "permission",
        "throttle",
        "unavailable",
        "redirect",
        "malformed",
        "empty",
        "status-only",
        "declared-large",
        "chunked-large",
        "partial",
    ] {
        let (endpoint, task, seen) = peer(mode, &record).await?;
        let sink = HttpAuditSink::for_loopback_simulation(
            &endpoint,
            "synthetic-audit-only",
            Duration::from_secs(1),
        )?;
        let budget = Duration::from_secs(2);
        let result = sink
            .append(&record, std::time::Instant::now() + budget)
            .await;
        tokio::time::timeout(Duration::from_secs(1), seen).await??;
        assert_eq!(
            result,
            if mode == "valid" {
                Ok(())
            } else {
                Err(AppendError::Uncertain)
            },
            "wrong outcome: {mode}"
        );
        if mode == "partial" {
            task.stop().await?;
        } else {
            task.finish().await?;
        }
        retire().await?;
        assert_eq!(sink.metrics().capacity, 1);
        assert_eq!(sink.metrics().depth, 0);
    }
    // A caller abort signals the retained operation; replacement never creates
    // an unowned task/worker, and the same immutable record remains reusable.
    let (endpoint, task, seen) = peer("partial", &record).await?;
    let sink = std::sync::Arc::new(HttpAuditSink::for_loopback_simulation(
        &endpoint,
        "synthetic-audit-only",
        Duration::from_secs(1),
    )?);
    let audit = std::sync::Arc::new(record);
    let (caller_sink, caller_record) = (sink.clone(), audit.clone());
    let caller = tokio::spawn(async move {
        caller_sink
            .append(
                &caller_record,
                std::time::Instant::now() + Duration::from_secs(2),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), seen).await??;
    assert_eq!(sink.metrics().depth, 1);
    assert_eq!(
        sink.append(&audit, std::time::Instant::now() + Duration::from_secs(1))
            .await,
        Err(AppendError::Busy)
    );
    let uncertain = sink.metrics().uncertain;
    caller.abort();
    assert!(caller.await.is_err_and(|e| e.is_cancelled()));
    task.stop().await?;
    retire().await?;
    assert_eq!(sink.metrics().uncertain, uncertain + 1);
    assert!(sink.metrics().rejected >= 1);
    let (endpoint, task, seen) = peer("valid", &audit).await?;
    let sink = HttpAuditSink::for_loopback_simulation(
        &endpoint,
        "synthetic-audit-only",
        Duration::from_secs(1),
    )?;
    assert_eq!(
        sink.append(&audit, std::time::Instant::now() + Duration::from_secs(1))
            .await,
        Ok(())
    );
    seen.await?;
    task.finish().await?;
    retire().await?;
    super::tls_tests::qualify_mutual_tls().await?;
    Ok(())
}
#[tokio::test]
async fn expired_ready_and_cancelled_calls_do_not_renew_original_clock() -> TestResult {
    use std::future::Future;
    for during_poll in [false, true] {
        let ctx = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(500))?;
        let ready = Cell::new(false);
        let polls = Cell::new(0);
        let work = std::future::poll_fn(|_| {
            polls.set(polls.get() + 1);
            if !ready.get() {
                return Poll::Pending;
            }
            if during_poll {
                std::thread::sleep(
                    ctx.deadline().saturating_duration_since(Instant::now())
                        + Duration::from_millis(5),
                );
            }
            Poll::Ready(Ok(()))
        });
        let future = before_deadline(&ctx, work);
        tokio::pin!(future);
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        ready.set(true);
        if !during_poll {
            std::thread::sleep(
                ctx.deadline().saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
        }
        assert_eq!(future.await, Err(WorkerError::Timeout));
        assert_eq!(polls.get(), if during_poll { 2 } else { 1 });
    }
    let token = CancellationToken::new();
    let ctx = ExtensionContext::new(token.clone(), Duration::from_secs(1))?;
    token.cancel();
    let polls = Cell::new(0);
    assert!(
        before_deadline(
            &ctx,
            std::future::poll_fn(|_| {
                polls.set(polls.get() + 1);
                Poll::Ready(Ok(()))
            })
        )
        .await
        .is_err()
    );
    assert_eq!(polls.get(), 0);
    Ok(())
}
