use super::*;
use signal_protocol::audit::{Action, Actor, AuditRecord, ConfigurationKind};
use std::{fs, net::SocketAddr, os::unix::fs::PermissionsExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
use uuid::Uuid;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const APPEND_A: &str = "synthetic-receiver-producer-a";
const APPEND_B: &str = "synthetic-receiver-producer-b";
const HEALTH: &str = "synthetic-receiver-health-only";
fn record(producer: Uuid, sequence: u64) -> Result<PreparedAudit> {
    Ok(AuditRecord {
        schema_version: 1,
        record_id: Uuid::new_v4(),
        producer_id: producer,
        sequence,
        timestamp: chrono::Utc::now(),
        actor: Actor::System {},
        action: Action::ConfigurationActivation {
            configuration: ConfigurationKind::Rules,
            revision_sha256: "a".repeat(64),
        },
    }
    .prepare()?)
}
fn ctx() -> Result<ExtensionContext> {
    Ok(ExtensionContext::new(
        CancellationToken::new(),
        Duration::from_secs(5),
    )?)
}
fn credential(value: &str) -> Result<axum::http::HeaderValue> {
    Ok(axum::http::HeaderValue::from_str(&format!(
        "Bearer {value}"
    ))?)
}
struct Fixture {
    directory: tempfile::TempDir,
    host: Host,
    producers: [Uuid; 2],
    append: SocketAddr,
    health: SocketAddr,
    cancellation: CancellationToken,
    tasks: JoinSet<std::result::Result<(), server::ServerError>>,
    client: reqwest::Client,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.host.stop();
        self.cancellation.cancel();
        self.tasks.abort_all();
    }
}
impl Fixture {
    async fn new(records: usize, request_timeout: Duration) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let producers = [Uuid::new_v4(), Uuid::new_v4()];
        let receiver = AuditReceiver::open(
            directory.path(),
            OpenMode::Initialize,
            signal_collector_sdk::audit::receiver::ReceiverLimits {
                max_bytes: 1024 * 1024,
                max_records: records,
                max_producers: 2,
            },
            &producers,
            ctx()?,
        )
        .await?;
        let host = Host {
            receiver: Arc::new(receiver),
            producers: Arc::new(vec![
                Enrollment {
                    id: producers[0],
                    credential: credential(APPEND_A)?,
                },
                Enrollment {
                    id: producers[1],
                    credential: credential(APPEND_B)?,
                },
            ]),
            health_credential: credential(HEALTH)?,
            append_operations: Arc::new(Semaphore::new(1)),
            health_operations: Arc::new(Semaphore::new(2)),
            append_rejected: Arc::new(AtomicU64::new(0)),
            health_rejected: Arc::new(AtomicU64::new(0)),
            request_timeout,
        };
        let append = TcpListener::bind("127.0.0.1:0").await?;
        let health = TcpListener::bind("127.0.0.1:0").await?;
        let addresses = (append.local_addr()?, health.local_addr()?);
        let cancellation = CancellationToken::new();
        let (append_router, health_router) = routers(&host);
        let mut tasks = JoinSet::new();
        for (listener, router) in [(append, append_router), (health, health_router)] {
            let stop = host.clone();
            let cancel = cancellation.clone();
            let state = TransportState::independent(cancel.clone(), Duration::from_secs(1), false)?;
            tasks.spawn(server::serve_transport_router(
                listener,
                state,
                router,
                server::ServerLimits {
                    max_connections: 8,
                    connection_timeout: Duration::from_secs(2),
                    shutdown_timeout: Duration::from_secs(1),
                },
                Arc::new(Semaphore::new(8)),
                None,
                (move || stop.stop(), async move { cancel.cancelled().await }),
            ));
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()?;
        Ok(Self {
            directory,
            host,
            producers,
            append: addresses.0,
            health: addresses.1,
            cancellation,
            tasks,
            client,
        })
    }
    async fn post(&self, credential: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let response = self
            .client
            .post(format!("http://{}/v1/audit/records", self.append))
            .bearer_auth(credential)
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .await?;
        let status = response.status().as_u16();
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let mut response = response;
        let mut bytes = Vec::with_capacity(ACK_BYTES);
        while let Some(chunk) = response.chunk().await? {
            assert!(chunk.len() <= ACK_BYTES - bytes.len());
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    }
    async fn snapshot(&self, credential: &str) -> Result<(u16, serde_json::Value)> {
        let response = self
            .client
            .get(format!("http://{}/v1/audit/health", self.health))
            .bearer_auth(credential)
            .send()
            .await?;
        let status = response.status().as_u16();
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let bytes = response.bytes().await?;
        assert!(bytes.len() <= ACK_BYTES);
        Ok((status, serde_json::from_slice(&bytes)?))
    }
    async fn raw(&self, address: SocketAddr, request: &[u8]) -> Result<Vec<u8>> {
        Ok(tokio::time::timeout(Duration::from_secs(3), async {
            let mut socket = tokio::net::TcpStream::connect(address).await?;
            socket.write_all(request).await?;
            let mut bytes = Vec::with_capacity(2048);
            socket.take(2049).read_to_end(&mut bytes).await?;
            assert!(bytes.len() <= 2048);
            Ok::<_, std::io::Error>(bytes)
        })
        .await??)
    }
    async fn finish(&mut self) -> Result {
        self.host.stop();
        self.cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(result) = self.tasks.join_next().await {
                result??;
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .await??;
        Ok(())
    }
}

#[tokio::test]
async fn exact_http_receipts_preserve_original_interleaved_bytes_and_full_retries() -> Result {
    let _serial = SERIAL.lock().await;
    let mut fixture = Fixture::new(2, Duration::from_secs(1)).await?;
    let a = record(fixture.producers[0], 1)?;
    let original = format!(" \n{} \n", std::str::from_utf8(a.body())?);
    let a = PreparedAudit::from_original(original.as_bytes())?;
    let b = record(fixture.producers[1], 1)?;
    for (token, r) in [(APPEND_A, &a), (APPEND_B, &b), (APPEND_A, &a)] {
        let (status, ack) = fixture.post(token, r.body()).await?;
        assert_eq!(status, 200);
        r.verify_acknowledgement(&ack)?;
    }
    let next = record(fixture.producers[0], 2)?;
    assert_eq!(fixture.post(APPEND_A, next.body()).await?.0, 507);
    let (status, snapshot) = fixture.snapshot(HEALTH).await?;
    assert_eq!(status, 200);
    assert_eq!(snapshot["records"], 2);
    assert_eq!(snapshot["record_capacity"], 2);
    let journal = fs::read(fixture.directory.path().join("journal"))?;
    assert!(journal.windows(a.body().len()).any(|w| w == a.body()));
    assert!(journal.windows(b.body().len()).any(|w| w == b.body()));
    let summary = snapshot.to_string();
    for secret in [
        APPEND_A.to_owned(),
        APPEND_B.to_owned(),
        HEALTH.to_owned(),
        fixture.producers[0].to_string(),
        fixture.directory.path().display().to_string(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    ] {
        assert!(!summary.contains(&secret));
    }
    fixture.finish().await
}
#[tokio::test]
async fn fixed_enrollment_and_separate_health_credentials_deny_without_journal_effect() -> Result {
    let _serial = SERIAL.lock().await;
    let mut fixture = Fixture::new(8, Duration::from_secs(1)).await?;
    let b = record(fixture.producers[1], 1)?;
    for token in [
        HEALTH,
        "normal-api-token-canary",
        "unknown-token-canary",
        APPEND_A,
    ] {
        assert_eq!(fixture.post(token, b.body()).await?.0, 403);
    }
    for token in [APPEND_A, APPEND_B, "normal-api-token-canary"] {
        assert_eq!(fixture.snapshot(token).await?.0, 403);
    }
    for (method, path) in [
        ("GET", "/v1/audit/records"),
        ("POST", "/v1/audit/records?producer=forged"),
        ("POST", "/v1/events"),
        ("DELETE", "/v1/audit/records"),
        ("GET", "/readyz"),
    ] {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {APPEND_A}\r\nContent-Length: 0\r\n\r\n"
        );
        let response = fixture.raw(fixture.append, request.as_bytes()).await?;
        assert!(response.starts_with(b"HTTP/1.1 403"));
    }
    let duplicate = format!(
        "POST /v1/audit/records HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {APPEND_B}\r\nAuthorization: Bearer {HEALTH}\r\nContent-Length: 0\r\n\r\n"
    );
    assert!(
        fixture
            .raw(fixture.append, duplicate.as_bytes())
            .await?
            .starts_with(b"HTTP/1.1 403")
    );
    assert_eq!(fixture.host.receiver.health().records, 0);
    assert_eq!(
        fs::metadata(fixture.directory.path().join("journal"))?.len(),
        0
    );
    fixture.finish().await
}
#[tokio::test]
async fn actual_eof_limits_trailers_malformed_and_conflicting_records_never_append() -> Result {
    let _serial = SERIAL.lock().await;
    let mut fixture = Fixture::new(8, Duration::from_secs(1)).await?;
    assert_eq!(
        fixture
            .post(APPEND_A, &vec![b' '; RECORD_BYTES + 1])
            .await?
            .0,
        400
    );
    for payload in [
        b"null".as_slice(),
        b"{\"raw\":\"private-canary\"}".as_slice(),
    ] {
        assert_eq!(fixture.post(APPEND_A, payload).await?.0, 400);
    }
    let header = format!(
        "POST /v1/audit/records HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {APPEND_A}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    let oversized = format!(
        "{header}{:x}\r\n{}\r\n0\r\n\r\n",
        RECORD_BYTES + 1,
        " ".repeat(RECORD_BYTES + 1)
    );
    assert!(
        fixture
            .raw(fixture.append, oversized.as_bytes())
            .await?
            .starts_with(b"HTTP/1.1 400")
    );
    let r = record(fixture.producers[0], 1)?;
    let trailers = format!(
        "{header}{:x}\r\n{}\r\n0\r\nX-Forged-Proof: private-canary\r\n\r\n",
        r.body().len(),
        std::str::from_utf8(r.body())?
    );
    assert!(
        fixture
            .raw(fixture.append, trailers.as_bytes())
            .await?
            .starts_with(b"HTTP/1.1 400")
    );
    assert_eq!(fixture.host.receiver.health().records, 0);
    assert_eq!(fixture.post(APPEND_A, r.body()).await?.0, 200);
    let conflict = record(fixture.producers[0], 1)?;
    assert_eq!(fixture.post(APPEND_A, conflict.body()).await?.0, 409);
    assert_eq!(fixture.host.receiver.health().records, 1);
    fixture.finish().await
}
#[tokio::test]
async fn occupied_append_body_keeps_health_independent_and_original_timeout_releases_socket()
-> Result {
    let _serial = SERIAL.lock().await;
    let mut fixture = Fixture::new(8, Duration::from_millis(1500)).await?;
    let mut socket = tokio::net::TcpStream::connect(fixture.append).await?;
    let request = format!(
        "POST /v1/audit/records HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {APPEND_A}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n"
    );
    tokio::time::timeout(Duration::from_secs(1), socket.write_all(request.as_bytes())).await??;
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.host.append_operations.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let (status, snapshot) = fixture.snapshot(HEALTH).await?;
    assert_eq!(status, 200);
    assert_eq!(snapshot["append_http_depth"], 1);
    assert_eq!(snapshot["records"], 0);
    let r = record(fixture.producers[0], 1)?;
    assert_eq!(fixture.post(APPEND_A, r.body()).await?.0, 503);
    let mut reply = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        socket.take(2048).read_to_end(&mut reply),
    )
    .await??;
    assert!(reply.starts_with(b"HTTP/1.1 503"));
    assert_eq!(fixture.host.append_operations.available_permits(), 1);
    assert_eq!(fixture.host.receiver.health().records, 0);
    assert_eq!(fixture.post(APPEND_A, r.body()).await?.0, 200);
    fixture.finish().await
}
#[tokio::test]
async fn observed_history_corruption_holds_receiver_and_health_reports_failure() -> Result {
    let _serial = SERIAL.lock().await;
    let mut fixture = Fixture::new(8, Duration::from_secs(1)).await?;
    let r = record(fixture.producers[0], 1)?;
    assert_eq!(fixture.post(APPEND_A, r.body()).await?.0, 200);
    let path = fixture.directory.path().join("journal");
    let mut bytes = fs::read(&path)?;
    bytes[80] ^= 1;
    fs::write(path, bytes)?;
    assert_eq!(fixture.post(APPEND_A, r.body()).await?.0, 503);
    let (status, snapshot) = fixture.snapshot(HEALTH).await?;
    assert_eq!(status, 503);
    assert_eq!(snapshot["held"], true);
    fixture.finish().await
}
#[tokio::test]
async fn original_expired_or_cancelled_context_never_polls_late_work() -> Result {
    let context = ctx()?;
    context.cancellation().cancel();
    let polled = AtomicU64::new(0);
    assert!(
        within(&context, async {
            polled.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .await
        .is_err()
    );
    let context = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(5))?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(
        within(&context, async {
            polled.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .await
        .is_err()
    );
    assert_eq!(polled.load(Ordering::Relaxed), 0);
    Ok(())
}
fn profile() -> serde_json::Value {
    serde_json::json!({"schema_version":1,"directory":"/tmp/receiver-generic-fixture",
        "append":{"listen":"127.0.0.1:18080","tls_config":"/tmp/append-private.json","max_connections":8},
        "health":{"listen":"127.0.0.1:18081","tls_config":"/tmp/health-private.json","max_connections":4},
        "producers":[{"producer_id":Uuid::new_v4(),"credential_env":"AUDIT_APPEND_A"}],
        "health_credential_env":"AUDIT_HEALTH_ONLY","max_bytes":1048576,"max_records":8,
        "request_timeout_ms":1000,"header_timeout_ms":1000,"connection_timeout_ms":2000,"shutdown_timeout_ms":1000})
}
#[test]
fn strict_capture_rejects_ambiguous_profile_duplicates_overlap_and_ordinary_token_fallback()
-> Result {
    let p = profile();
    let captured =
        config::Wire::parse(&p.to_string())?.capture(|name| Ok(format!("synthetic-{name}")))?;
    assert_eq!(captured.producers.len(), 1);
    let mut cases = Vec::new();
    for (field, value) in [
        ("schema_version", serde_json::json!(2)),
        ("directory", serde_json::json!("relative")),
        ("request_timeout_ms", serde_json::json!(0)),
        (
            "health_credential_env",
            serde_json::json!("SIGNAL_API_TOKEN"),
        ),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut changed = p.clone();
        changed[field] = value;
        cases.push(changed.to_string());
    }
    let mut changed = p.clone();
    changed["health"] = changed["append"].clone();
    cases.push(changed.to_string());
    let mut changed = p.clone();
    changed["producers"] = serde_json::json!([changed["producers"][0], changed["producers"][0]]);
    cases.push(changed.to_string());
    let mut changed = p.clone();
    changed["producers"][0]["credential_env"] = serde_json::json!("AUDIT_HEALTH_ONLY");
    cases.push(changed.to_string());
    let mut changed = p.clone();
    changed["append"]["max_connections"] = serde_json::json!(65);
    cases.push(changed.to_string());
    let mut changed = p.clone();
    changed["producers"][0]["producer_id"] = serde_json::json!(Uuid::nil());
    cases.push(changed.to_string());
    cases.push(p.to_string().replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    ));
    let mut changed = p.clone();
    changed["append"] = serde_json::json!(["127.0.0.1:18080", "/tmp/append-private.json", 8]);
    cases.push(changed.to_string());
    let mut changed = p.clone();
    changed["health"] = serde_json::json!(["127.0.0.1:18081", "/tmp/health-private.json", 4]);
    cases.push(changed.to_string());
    let mut changed = p.clone();
    changed["producers"][0] =
        serde_json::json!([p["producers"][0]["producer_id"], "AUDIT_APPEND_A"]);
    cases.push(changed.to_string());
    cases.push(
        serde_json::json!([
            1,
            p["directory"],
            p["append"],
            p["health"],
            p["producers"],
            "AUDIT_HEALTH_ONLY",
            1048576,
            8,
            1000,
            1000,
            2000,
            1000
        ])
        .to_string(),
    );
    for text in cases {
        let result = config::Wire::parse(&text)
            .and_then(|wire| wire.capture(|name| Ok(format!("synthetic-secret-canary-{name}"))));
        let error = match result {
            Ok(_) => return Err("accepted invalid private receiver profile".into()),
            Err(error) => error,
        };
        assert!(!format!("{error} {error:?}").contains("synthetic-secret-canary"));
    }
    assert!(
        config::Wire::parse(&p.to_string())?
            .capture(|_| Ok("same-cross-role-secret".into()))
            .is_err()
    );
    assert!(
        config::Wire::parse(&p.to_string())?
            .capture(|_| Err(HostError::Invalid))
            .is_err()
    );
    Ok(())
}
