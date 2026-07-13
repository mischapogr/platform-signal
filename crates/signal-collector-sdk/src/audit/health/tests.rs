use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn snapshot(held: bool) -> AuditReceiverHealth {
    AuditReceiverHealth {
        schema_version: 1,
        held,
        records: 3,
        bytes: 2000,
        record_capacity: 8,
        byte_capacity: 65_536,
        physical_depth: 1,
        physical_capacity: 1,
        physical_rejected: 2,
        rejected: 3,
        uncertain: 4,
        append_http_depth: 1,
        append_http_capacity: 1,
        append_http_rejected: 5,
        health_http_rejected: 6,
    }
}
struct Task(Option<JoinHandle<TestResult>>);
impl Drop for Task {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
impl Task {
    async fn finish(mut self) -> TestResult {
        tokio::time::timeout(
            Duration::from_secs(4),
            self.0.as_mut().ok_or("peer missing")?,
        )
        .await???;
        self.0.take();
        Ok(())
    }
    async fn stop(mut self) -> TestResult {
        let task = self.0.take().ok_or("peer missing")?;
        task.abort();
        assert!(task.await.is_err_and(|error| error.is_cancelled()));
        Ok(())
    }
}
async fn retire() -> TestResult {
    tokio::time::timeout(Duration::from_secs(3), async {
        while OWNER.depth() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}
async fn peer(
    mode: &'static str,
) -> Result<(String, Task, oneshot::Receiver<()>), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}/v1/audit/health", listener.local_addr()?);
    let (sent, seen) = oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(4), async {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            let mut block = [0u8; 1024];
            loop {
                let count = stream.read(&mut block).await?;
                if count == 0 || count > 4096 - request.len() { return Err("bounded request missing".into()); }
                request.extend_from_slice(&block[..count]);
                if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") { break; }
            }
            let headers = std::str::from_utf8(&request)?.to_ascii_lowercase();
            assert!(headers.starts_with("get /v1/audit/health http/1.1\r\n"));
            assert!(headers.contains("authorization: bearer synthetic-health-only\r\n"));
            assert!(headers.contains("cache-control: no-store\r\n"));
            assert!(headers.contains("pragma: no-cache\r\n"));
            sent.send(()).map_err(|_| "caller missing")?;
            if mode == "stall" { std::future::pending::<()>().await; }
            let held = matches!(mode, "held" | "healthy-held");
            let valid = snapshot(held).to_json()?;
            let body = match mode {
                "malformed" => b"{".to_vec(),
                "array" => b"[]".to_vec(),
                "unknown" => String::from_utf8(valid.clone())?.replacen("{", "{\"private_actor\":\"canary\",", 1).into_bytes(),
                "duplicate" => String::from_utf8(valid.clone())?.replacen("\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1", 1).into_bytes(),
                "busy" => b"{\"error\":\"busy\"}".to_vec(),
                _ => valid,
            };
            let status = match mode { "held" | "held-healthy" | "busy" => 503, "permission" => 403, "throttle" => 429, "redirect" => 307, _ => 200 };
            let content_type = match mode { "wrong-type" => "Content-Type: text/plain\r\n", "duplicate-type" => "Content-Type: application/json\r\nContent-Type: application/json\r\n", _ => "Content-Type: application/json\r\n" };
            let cache = match mode { "missing-cache" => "", "duplicate-cache" => "Cache-Control: no-store\r\nCache-Control: no-store\r\n", "cached" => "Cache-Control: max-age=60\r\n", _ => "Cache-Control: no-store\r\n" };
            let mut reply = if mode == "chunked-large" {
                let mut reply = format!("HTTP/1.1 200 OK\r\n{content_type}{cache}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n401\r\n").into_bytes();
                reply.extend_from_slice(&vec![b' '; HEALTH_BYTES + 1]);
                reply.extend_from_slice(b"\r\n0\r\n\r\n");
                reply
            } else {
                let length = match mode { "declared-large" => HEALTH_BYTES + 1, "partial" => body.len() + 10, _ => body.len() };
                let mut reply = format!("HTTP/1.1 {status} Synthetic\r\n{content_type}{cache}Content-Length: {length}\r\nLocation: http://127.0.0.1:1/forbidden\r\nConnection: close\r\n\r\n").into_bytes();
                reply.extend_from_slice(&body);
                reply
            };
            stream.write_all(&reply).await?;
            reply.clear();
            if mode == "partial" { std::future::pending::<()>().await; }
            super::super::tests::close_after_reply(&mut stream).await?;
            Ok(())
        }).await?
    });
    Ok((endpoint, Task(Some(task)), seen))
}
fn probe(endpoint: &str) -> Result<HttpHealthProbe, ConfigurationError> {
    HttpHealthProbe::for_loopback_simulation(
        endpoint,
        "synthetic-health-only",
        Duration::from_secs(1),
    )
}
#[test]
fn configuration_requires_own_fixed_role_and_explicit_private_transport() -> TestResult {
    for endpoint in [
        "http://localhost:1",
        "http://192.0.2.1:1",
        "https://127.0.0.1:1",
        "http://127.0.0.1:0",
        "http://u:p@127.0.0.1:1",
        "http://127.0.0.1:1/v1/audit/records",
        "http://127.0.0.1:1/?x=1",
        "http://127.0.0.1:1/#x",
    ] {
        assert!(probe(endpoint).is_err());
    }
    assert!(probe("http://[::1]:12345").is_ok());
    assert!(
        HttpHealthProbe::from_private_tls(
            "http://127.0.0.1:1",
            "synthetic",
            Duration::from_secs(1),
            b"{}"
        )
        .is_err()
    );
    assert!(
        HttpHealthProbe::from_private_tls(
            "https://127.0.0.1:1",
            "synthetic",
            Duration::from_secs(1),
            b"{}"
        )
        .is_err()
    );
    for credential in [String::new(), "x".repeat(4097), "x\r\ncanary".into()] {
        assert!(
            HttpHealthProbe::for_loopback_simulation(
                "http://127.0.0.1:1",
                &credential,
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
    assert_eq!(
        ProbeError::Unavailable.to_string(),
        "current authenticated audit health is unavailable"
    );
    Ok(())
}
#[tokio::test]
async fn actual_http_observes_current_busy_and_held_but_rejects_untrusted_replies() -> TestResult {
    let _serial = SERIAL.lock().await;
    for mode in [
        "valid",
        "held",
        "healthy-held",
        "held-healthy",
        "busy",
        "permission",
        "throttle",
        "redirect",
        "malformed",
        "array",
        "unknown",
        "duplicate",
        "wrong-type",
        "duplicate-type",
        "missing-cache",
        "duplicate-cache",
        "cached",
        "declared-large",
        "chunked-large",
        "partial",
    ] {
        let (endpoint, task, seen) = peer(mode).await?;
        let probe = probe(&endpoint)?;
        let started = Instant::now();
        let budget = if mode == "partial" {
            Duration::from_millis(350)
        } else {
            Duration::from_secs(2)
        };
        let result = probe
            .observe(ExtensionContext::new(CancellationToken::new(), budget)?)
            .await;
        seen.await?;
        if matches!(mode, "valid" | "held") {
            let observation = result?;
            assert_eq!(observation.snapshot, snapshot(mode == "held"));
            assert!(
                observation.received_at >= started && observation.received_at <= Instant::now()
            );
            // Busy fields are observed facts, not an automatic readiness decision.
            assert_eq!(observation.snapshot.physical_depth, 1);
        } else {
            assert!(
                matches!(result, Err(ProbeError::Unavailable)),
                "mode {mode} unexpectedly observed"
            );
        }
        if mode == "partial" {
            task.stop().await?;
        } else {
            task.finish().await?;
        }
        retire().await?;
        assert_eq!(probe.metrics().capacity, 1);
        assert_eq!(probe.metrics().depth, 0);
    }
    Ok(())
}
#[tokio::test]
async fn original_clock_cancellation_and_drop_never_renew_or_dispatch_expired_probe() -> TestResult
{
    let _serial = SERIAL.lock().await;
    let (endpoint, peer_task, seen) = peer("stall").await?;
    let probe = std::sync::Arc::new(probe(&endpoint)?);
    let cancel = CancellationToken::new();
    let context = ExtensionContext::new(cancel.clone(), Duration::from_secs(2))?;
    let caller_probe = probe.clone();
    let mut caller = tokio::spawn(async move { caller_probe.observe(context).await });
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(2), seen).await??;
    assert_eq!(probe.metrics().depth, 1);
    assert!(matches!(
        probe
            .observe(ExtensionContext::new(
                CancellationToken::new(),
                Duration::from_secs(1)
            )?)
            .await,
        Err(ProbeError::Busy)
    ));
    cancel.cancel();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), &mut caller).await??,
        Err(ProbeError::Unavailable)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    retire().await?;
    peer_task.stop().await?;

    let (endpoint, peer_task, seen) = peer("stall").await?;
    let probe = std::sync::Arc::new(self::probe(&endpoint)?);
    let context = ExtensionContext::new(CancellationToken::new(), Duration::from_secs(2))?;
    let caller_probe = probe.clone();
    let caller = tokio::spawn(async move { caller_probe.observe(context).await });
    tokio::time::timeout(Duration::from_secs(2), seen).await??;
    let failed = probe.metrics().failed;
    caller.abort();
    assert!(caller.await.is_err_and(|error| error.is_cancelled()));
    retire().await?;
    assert!(probe.metrics().failed > failed);
    peer_task.stop().await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let probe = self::probe(&endpoint)?;
    let cancel = CancellationToken::new();
    let context = ExtensionContext::new(cancel.clone(), Duration::from_secs(1))?;
    cancel.cancel();
    assert!(matches!(
        probe.observe(context).await,
        Err(ProbeError::Unavailable)
    ));
    let context = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(20))?;
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(matches!(
        probe.observe(context).await,
        Err(ProbeError::Unavailable)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(probe.metrics().depth, 0);
    Ok(())
}

#[tokio::test]
async fn actual_mutual_tls_validates_health_origin_identity_and_credential() -> TestResult {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let _serial = SERIAL.lock().await;
    let directory = tempfile::tempdir()?;
    crate::test_tls::pki(directory.path()).map_err(|_| "synthetic PKI unavailable")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(
        directory.path().join("original.pem"),
    )?)?;
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from_pem_file(
                directory.path().join("server.pem"),
            )?],
            PrivateKeyDer::from_pem_file(directory.path().join("server.key"))?,
        )?;
    server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    server.send_tls13_tickets = 0;
    for mode in [
        "wrong-root",
        "foreign-client",
        "wrong-credential",
        "held",
        "valid",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("https://127.0.0.1:{}", listener.local_addr()?.port());
        let observed = Arc::new(AtomicUsize::new(0));
        let seen = observed.clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server.clone()));
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(4), async move {
                let (stream, _) = listener.accept().await?;
                let Ok(mut stream) = acceptor.accept(stream).await else { return Ok(()); };
                let mut bytes = Vec::new();
                let mut block = [0u8; 1024];
                loop {
                    let count = stream.read(&mut block).await?;
                    if count == 0 || count > 4096 - bytes.len() { return Err("bounded TLS request missing".into()); }
                    bytes.extend_from_slice(&block[..count]);
                    if bytes.windows(4).any(|part| part == b"\r\n\r\n") { break; }
                }
                let headers = std::str::from_utf8(&bytes)?.to_ascii_lowercase();
                assert!(headers.starts_with("get /v1/audit/health http/1.1\r\n"));
                let authenticated = headers.contains("authorization: bearer synthetic-health-only\r\n");
                assert_eq!(authenticated, mode != "wrong-credential");
                if authenticated { seen.fetch_add(1, Ordering::Relaxed); }
                let status = if !authenticated { 403 } else if mode == "held" { 503 } else { 200 };
                let body = snapshot(mode == "held").to_json()?;
                let mut reply = format!("HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
                reply.extend_from_slice(&body);
                stream.write_all(&reply).await?;
                super::super::tests::close_after_reply(&mut stream).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            }).await?
        });
        let task = Task(Some(task));
        let material = crate::test_tls::material(
            directory.path(),
            if mode == "foreign-client" {
                "foreign-client"
            } else {
                "client"
            },
            if mode == "wrong-root" {
                "foreign"
            } else {
                "original"
            },
        )
        .map_err(|_| "synthetic TLS material unavailable")?;
        let client = HttpHealthProbe::from_private_tls(
            &endpoint,
            if mode == "wrong-credential" {
                "synthetic-denied"
            } else {
                "synthetic-health-only"
            },
            Duration::from_secs(1),
            &material,
        )?;
        let result = client
            .observe(ExtensionContext::new(
                CancellationToken::new(),
                Duration::from_secs(2),
            )?)
            .await;
        if matches!(mode, "held" | "valid") {
            assert_eq!(result?.snapshot, snapshot(mode == "held"));
        } else {
            assert!(matches!(result, Err(ProbeError::Unavailable)));
        }
        task.finish().await?;
        retire().await?;
        assert_eq!(
            observed.load(Ordering::Relaxed),
            usize::from(matches!(mode, "held" | "valid"))
        );
    }
    Ok(())
}
