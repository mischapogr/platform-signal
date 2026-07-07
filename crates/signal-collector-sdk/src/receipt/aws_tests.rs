use super::*;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
    time::SystemTime,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[path = "../../../../tests/support/aws_signature.rs"]
mod signature;
const ACCESS_A: &str = "AKIASYNTHETIC0001";
const ACCESS_B: &str = "AKIASYNTHETIC0002";
const SECRET: &str = "synthetic-signing-secret-never-use-in-aws";
const TOKEN: &str = "synthetic-session-token-never-log";
struct Credentials {
    calls: AtomicUsize,
    mode: &'static str,
}
#[crate::extension]
impl AwsCredentialsProvider for Credentials {
    async fn credentials(&self, _: &ExtensionContext) -> Result<SigningCredentials, SourceFailure> {
        let n = self.calls.fetch_add(1, Ordering::AcqRel);
        match self.mode {
            "deny" => Err(SourceFailure::Denied),
            "stall" => std::future::pending().await,
            _ => SigningCredentials::new(
                if n == 0 { ACCESS_A } else { ACCESS_B },
                SECRET,
                Some(TOKEN),
                (self.mode == "expired").then(|| SystemTime::now() - Duration::from_secs(1)),
            ),
        }
    }
}
fn credentials(mode: &'static str) -> Arc<Credentials> {
    Arc::new(Credentials {
        calls: AtomicUsize::new(0),
        mode,
    })
}
struct Wire {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
impl Wire {
    fn verifies(&self, access: &str, service: &str) -> bool {
        signature::verify(
            &self.method,
            &self.target,
            &self.headers,
            &self.body,
            access,
            SECRET,
            service,
            if service == "sqs" {
                "us-east-1"
            } else {
                "eu-central-1"
            },
        )
    }
}
struct Endpoint {
    url: String,
    task: Option<tokio::task::JoinHandle<WireResult>>,
}
type WireResult = Result<Vec<Wire>, Box<dyn std::error::Error + Send + Sync>>;
impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Endpoint {
    async fn start(replies: Vec<Vec<u8>>) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let mut captures = Vec::new();
            for reply in replies {
                let (mut socket, _) = listener.accept().await?;
                let (h, body) = http_publisher_tests::request(&mut socket).await?;
                let mut lines = h.lines();
                let mut first = lines.next().ok_or("request line")?.split_ascii_whitespace();
                let method = first.next().ok_or("method")?.into();
                let target = first.next().ok_or("target")?.into();
                let headers = lines
                    .filter_map(|line| {
                        line.split_once(':')
                            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
                    })
                    .collect();
                captures.push(Wire {
                    method,
                    target,
                    headers,
                    body,
                });
                // A cap rejection can close before the full response is sent.
                let _ = socket.write_all(&reply).await;
                let _ = socket.shutdown().await;
            }
            Ok(captures)
        });
        Ok(Self {
            url,
            task: Some(task),
        })
    }
    async fn finish(mut self) -> Result<Vec<Wire>, Box<dyn std::error::Error>> {
        let mut task = self.task.take().ok_or("task")?;
        match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
            Ok(v) => v?.map_err(|_| "endpoint failure".into()),
            Err(e) => {
                task.abort();
                let _ = task.await;
                Err(e.into())
            }
        }
    }
}
fn reply(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}
fn client(url: &str, c: Arc<Credentials>) -> Result<AwsSourceClient, SourceFailure> {
    AwsSourceClient::new(
        AwsSourceConfig::new(
            "arn:aws:sqs:us-east-1:111122223333:fixture",
            &format!("{url}/111122223333/fixture"),
            "eu-central-1",
            url,
            30,
            true,
        )?,
        c,
        Duration::from_secs(1),
    )
}
fn binding() -> Result<ReceiptBinding, Box<dyn std::error::Error>> {
    Ok(vector("prepared")?.1)
}
fn discovery(
    b: &ReceiptBinding,
    key: Option<&str>,
) -> Result<ObjectDiscovery, Box<dyn std::error::Error>> {
    let mut record = discovery_tests::record();
    record["s3"]["bucket"]["name"] = b.0["bucket"].clone();
    if let Some(key) = key {
        record["s3"]["object"]["key"] = key.into();
    }
    Ok(discover_object(
        &serde_json::to_vec(&json!({"Records":[record]}))?,
        b,
        &ctx(),
    )?)
}
#[test]
fn credentials_endpoints_and_queue_scope_are_bounded_before_io() -> TestResult {
    for (access, secret, token) in [
        ("", SECRET, None),
        (ACCESS_A, "short", None),
        (ACCESS_A, SECRET, Some("secret\n")),
    ] {
        assert!(SigningCredentials::new(access, secret, token, None).is_err());
    }
    for url in [
        "http://example.invalid",
        "http://localhost",
        "https://user:pass@example.invalid",
        "https://example.invalid/?secret=1",
        "https://example.invalid/#fragment",
    ] {
        assert!(client(url, credentials("ok")).is_err());
    }
    assert!(
        AwsSourceConfig::new(
            "arn:aws:sqs:eu-central-1:111122223333:fixture-queue",
            "https://sqs.eu-central-1.amazonaws.com/111122223333/another",
            "eu-central-1",
            "https://s3.eu-central-1.amazonaws.com",
            30,
            false
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn independent_witness_matches_published_aws_get_object_signature_vector() {
    // Published test credentials/vector, never operational credentials:
    // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
    let headers = BTreeMap::from([
        ("host".into(), "examplebucket.s3.amazonaws.com".into()),
        ("range".into(), "bytes=0-9".into()),
        ("x-amz-date".into(), "20130524T000000Z".into()),
        ("x-amz-content-sha256".into(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()),
        ("authorization".into(), "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41".into()),
    ]);
    assert!(signature::verify(
        "GET",
        "/test.txt",
        &headers,
        b"",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "s3",
        "us-east-1"
    ));
}

#[tokio::test]
async fn s3_reserved_utf8_repeated_slashes_and_version_bytes_use_aws_encoding() -> TestResult {
    let original = preparation_tests::original()?;
    let version = "v +/%?";
    let ep = Endpoint::start(vec![reply(
        200,
        &format!("x-amz-version-id: {version}\r\n"),
        &original,
    )])
    .await?;
    let src = client(&ep.url, credentials("ok"))?;
    let b = binding()?;
    let mut record = discovery_tests::record();
    record["s3"]["object"]["key"] =
        "AWSLogs%2Ffixture%2F%21%27%28%29%2A%2B%3A%3B%3D%40%3F%23%25%5C%2F%2Ftail%2F".into();
    record["s3"]["object"]["versionId"] = version.into();
    let d = discover_object(
        &serde_json::to_vec(&json!({"Records":[record]}))?,
        &b,
        &ctx(),
    )?;
    let cap = capture_object(&src, d, &b, ctx()).await?;
    assert_eq!(cap.original_bytes(), original);
    let w = ep.finish().await?.pop().ok_or("wire")?;
    assert!(w.verifies(ACCESS_A, "s3"));
    assert_eq!(
        w.target,
        "/fixture-source-evidence/AWSLogs/fixture/%21%27%28%29%2A%2B%3A%3B%3D%40%3F%23%25%5C//tail/?versionId=v%20%2B%2F%25%3F"
    );
    Ok(())
}
#[tokio::test]
async fn actual_signed_receive_rotates_credentials_and_independent_witness_rejects_tampering()
-> TestResult {
    let body = serde_json::to_vec(
        &json!({"Messages":[{"MessageId":"fixture-message-001", "ReceiptHandle":"opaque-handle", "Body":"{}"}]}),
    )?;
    let ep = Endpoint::start(vec![reply(200, "", &body), reply(200, "", b"{}")]).await?;
    let c = credentials("ok");
    let src = client(&ep.url, c.clone())?;
    let d = src.receive(&binding()?, &ctx()).await?.ok_or("delivery")?;
    assert_eq!(d.message_id(), "fixture-message-001");
    assert_eq!(d.body(), b"{}");
    assert!(src.receive(&binding()?, &ctx()).await?.is_none());
    let endpoint_url = ep.url.clone();
    let mut requests = ep.finish().await?;
    for (n, w) in requests.iter().enumerate() {
        assert!(w.verifies(if n == 0 { ACCESS_A } else { ACCESS_B }, "sqs"));
        assert_eq!(w.target, "/");
        assert_eq!(w.headers["x-amz-target"], "AmazonSQS.ReceiveMessage");
        assert!(w.headers["x-amz-security-token"] == TOKEN);
        let b: Value = serde_json::from_slice(&w.body)?;
        assert_eq!(
            b["QueueUrl"],
            format!("{}/111122223333/fixture", endpoint_url)
        );
        assert_eq!(b["MaxNumberOfMessages"], 1);
        assert_eq!(b["WaitTimeSeconds"], 0);
    }
    requests[0].body.push(b' ');
    assert!(!requests[0].verifies(ACCESS_A, "sqs"));
    assert_eq!(c.calls.load(Ordering::Acquire), 2);
    Ok(())
}
#[tokio::test]
async fn queue_failures_and_malformed_success_never_become_empty_collection() -> TestResult {
    let many = json!({"Messages":[{},{}]});
    let oversized = json!({"Messages":[{"MessageId":"i", "ReceiptHandle":"h", "Body":"a".repeat(MAX_DISCOVERY_BYTES+1)}]});
    let cases = vec![
        (403, b"{}".to_vec(), SourceFailure::Denied),
        (429, b"{}".to_vec(), SourceFailure::Throttled),
        (
            400,
            br#"{"__type":"com.amazonaws.sqs#RequestThrottled"}"#.to_vec(),
            SourceFailure::Throttled,
        ),
        (503, b"{}".to_vec(), SourceFailure::Unavailable),
        (
            200,
            br#"{"__type":"Error"}"#.to_vec(),
            SourceFailure::Malformed,
        ),
        (
            200,
            br#"{"Messages":null}"#.to_vec(),
            SourceFailure::Malformed,
        ),
        (
            200,
            br#"{"Messages":[],"Messages":[]}"#.to_vec(),
            SourceFailure::Malformed,
        ),
        (200, serde_json::to_vec(&many)?, SourceFailure::Malformed),
        (
            200,
            serde_json::to_vec(&oversized)?,
            SourceFailure::Malformed,
        ),
        (
            200,
            vec![b' '; 2 * 1024 * 1024 + 1],
            SourceFailure::Malformed,
        ),
    ];
    let ep = Endpoint::start(
        cases
            .iter()
            .map(|(status, bytes, _)| reply(*status, "", bytes))
            .collect(),
    )
    .await?;
    let src = client(&ep.url, credentials("ok"))?;
    for (_, _, expected) in cases {
        assert!(
            matches!(src.receive(&binding()?, &ctx()).await, Err(e) if std::mem::discriminant(&e) == std::mem::discriminant(&expected))
        );
    }
    assert_eq!(ep.finish().await?.len(), 10);
    Ok(())
}
#[tokio::test]
async fn source_get_keeps_exact_encoded_key_version_owner_and_original_bytes() -> TestResult {
    let original = preparation_tests::original()?;
    let ep = Endpoint::start(vec![reply(
        200,
        "x-amz-version-id: fixture-version-001\r\netag: opaque-etag\r\n",
        &original,
    )])
    .await?;
    let src = client(&ep.url, credentials("ok"))?;
    let b = binding()?;
    let cap = capture_object(&src, discovery(&b, None)?, &b, ctx()).await?;
    assert_eq!(cap.original_bytes(), original);
    let w = ep.finish().await?.pop().ok_or("wire")?;
    assert!(w.verifies(ACCESS_A, "s3"));
    assert_eq!(
        w.target,
        "/fixture-source-evidence/AWSLogs/fixture/caf%C3%A9%20%2B%20%25.json.gz?versionId=fixture-version-001"
    );
    assert_eq!(w.headers["x-amz-expected-bucket-owner"], "111122223333");
    Ok(())
}
#[tokio::test]
async fn source_get_errors_version_mismatch_and_lossy_paths_hold_without_rewrite() -> TestResult {
    let cases = vec![
        (
            403,
            "<Error><Code>InvalidObjectState</Code></Error>",
            CaptureFailure::RestorePending,
        ),
        (
            503,
            "<Error><Code>SlowDown</Code></Error>",
            CaptureFailure::Throttled,
        ),
        (403, "", CaptureFailure::Denied),
        (404, "", CaptureFailure::MissingVersion),
        (500, "", CaptureFailure::Unavailable),
    ];
    let ep = Endpoint::start(
        cases
            .iter()
            .map(|(s, b, _)| reply(*s, "", b.as_bytes()))
            .collect(),
    )
    .await?;
    let c = credentials("ok");
    let src = client(&ep.url, c.clone())?;
    let b = binding()?;
    for (_, _, expected) in cases {
        assert!(
            matches!(src.open(&discovery(&b, None)?, &ctx()).await, Err(e) if std::mem::discriminant(&e)==std::mem::discriminant(&expected))
        );
    }
    let before = c.calls.load(Ordering::Acquire);
    for key in [
        "AWSLogs%2Ffixture%2Fa%09b",
        "AWSLogs%2Ffixture%2Fa%0Ab",
        "AWSLogs%2Ffixture%2Fa%0Db",
        "AWSLogs%2Ffixture%2F..%2Fa",
    ] {
        assert!(matches!(
            src.open(&discovery(&b, Some(key))?, &ctx()).await,
            Err(CaptureFailure::Malformed)
        ));
    }
    for bucket in [".", "..", "a\tb", "a\nb", "a\rb"] {
        let mut v = b.0.clone();
        v["bucket"] = bucket.into();
        let b = ReceiptBinding::from_json(&format::canonical(&v, 65536)?)?;
        assert!(matches!(
            src.open(&discovery(&b, None)?, &ctx()).await,
            Err(CaptureFailure::Malformed)
        ));
    }
    assert_eq!(before, c.calls.load(Ordering::Acquire));
    assert_eq!(ep.finish().await?.len(), 5);
    let ep = Endpoint::start(vec![reply(
        200,
        "x-amz-version-id: another-version\r\n",
        b"not-read",
    )])
    .await?;
    let src = client(&ep.url, credentials("ok"))?;
    assert!(matches!(
        capture_object(&src, discovery(&b, None)?, &b, ctx()).await,
        Err(CaptureError::VersionMismatch)
    ));
    ep.finish().await?;
    Ok(())
}
#[tokio::test]
async fn credential_denial_expiry_scope_and_cancel_stop_before_network() -> TestResult {
    let b = binding()?;
    for mode in ["deny", "expired"] {
        let c = credentials(mode);
        let src = client("http://127.0.0.1:9", c.clone())?;
        assert!(matches!(
            src.receive(&b, &ctx()).await,
            Err(SourceFailure::Denied)
        ));
        assert_eq!(c.calls.load(Ordering::Acquire), 1);
    }
    let c = credentials("ok");
    let src = client("http://127.0.0.1:9", c.clone())?;
    let mut v = b.0.clone();
    v["queue_owner"] = "999900001111".into();
    assert!(matches!(
        src.receive(
            &ReceiptBinding::from_json(&format::canonical(&v, 65536)?)?,
            &ctx()
        )
        .await,
        Err(SourceFailure::Denied)
    ));
    assert_eq!(c.calls.load(Ordering::Acquire), 0);
    let context = ctx();
    context.cancellation().cancel();
    assert!(matches!(
        src.receive(&b, &context).await,
        Err(SourceFailure::Unavailable)
    ));
    assert_eq!(c.calls.load(Ordering::Acquire), 0);
    let c = credentials("stall");
    let src = client("http://127.0.0.1:9", c)?;
    let context = ExtensionContext::new(CancellationToken::new(), Duration::from_millis(25))?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), src.receive(&b, &context)).await?,
        Err(SourceFailure::Unavailable)
    ));
    Ok(())
}

#[tokio::test]
async fn delete_requires_durable_ticket_scope_and_only_empty_200_confirms() -> TestResult {
    let d = root()?;
    let store = ReceiptStore::open(config(&d)?, owner(), 1, ctx()).await?;
    let (wire, b) = ack_tests::pure(false)?;
    store.publish(wire, b.clone(), ctx()).await?;
    let ep = Endpoint::start(vec![
        reply(200, "", b"{}"),
        reply(200, "", b""),
        reply(200, "", &vec![b' '; 65537]),
    ])
    .await?;
    let c = credentials("ok");
    let src = client(&ep.url, c.clone())?;
    for (n, expected) in [
        SourceAckState::Uncertain,
        SourceAckState::Confirmed,
        SourceAckState::Uncertain,
    ]
    .into_iter()
    .enumerate()
    {
        let p = store
            .replay(b.clone(), ctx())
            .await?
            .ok_or("receipt")?
            .progress;
        let grant = ReceiptRecoveryGrant::from_trusted_checkpoint(
            b.clone(),
            p.checksum(),
            "trusted-live-current".into(),
        )?;
        let (ticket, p) = match store
            .acknowledge(
                b.clone(),
                p,
                grant,
                ReceiptAckUpdate::BeginProcessLocal {
                    delivery: SourceDelivery::new(
                        Uuid::from_u128(n as u128 + 1),
                        "delivery".into(),
                        "ephemeral-current-handle".into(),
                    )?,
                    observed_at: "2026-10-07T12:00:02.000000000Z".into(),
                },
                ctx(),
            )
            .await?
        {
            ReceiptAckCommit::Intent { ticket, progress } => (ticket, progress),
            _ => return Err("intent".into()),
        };
        assert!(ticket.binding() == &b);
        if n == 0 {
            let mut changed = b.0.clone();
            changed["authority_revision"] = "revoked".into();
            let changed = ReceiptBinding::from_json(&format::canonical(&changed, 65536)?)?;
            assert!(matches!(
                src.delete(&changed, &ticket, &ctx()).await,
                Err(SourceFailure::Denied)
            ));
            assert_eq!(c.calls.load(Ordering::Acquire), 0);
        }
        let outcome = if n == 2 {
            assert!(matches!(
                src.delete(&b, &ticket, &ctx()).await,
                Err(SourceFailure::Malformed)
            ));
            SourceAckOutcome::uncertain()
        } else {
            src.delete(&b, &ticket, &ctx()).await?
        };
        let grant = ReceiptRecoveryGrant::from_trusted_checkpoint(
            b.clone(),
            p.checksum(),
            "trusted-live-current".into(),
        )?;
        let p = match store
            .acknowledge(
                b.clone(),
                p,
                grant,
                ReceiptAckUpdate::Finish {
                    ticket,
                    outcome,
                    observed_at: "2026-10-07T12:00:02.000000000Z".into(),
                },
                ctx(),
            )
            .await?
        {
            ReceiptAckCommit::Settled(p) => p,
            _ => return Err("settled".into()),
        };
        assert_eq!(p.source_ack_state(), expected);
    }
    for w in ep.finish().await? {
        assert!(w.verifies(
            if w.headers["authorization"].contains(ACCESS_A) {
                ACCESS_A
            } else {
                ACCESS_B
            },
            "sqs"
        ));
        assert_eq!(w.headers["x-amz-target"], "AmazonSQS.DeleteMessage");
        let v: Value = serde_json::from_slice(&w.body)?;
        assert!(v["ReceiptHandle"] == "ephemeral-current-handle");
    }
    for path in std::fs::read_dir(d.path())? {
        assert!(
            !std::fs::read(path?.path())?
                .windows(24)
                .any(|s| s == b"ephemeral-current-handle")
        );
    }
    store.close(ctx()).await?;
    Ok(())
}

#[tokio::test]
async fn chunked_caps_and_redirects_hold_without_forwarding_credentials() -> TestResult {
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let mut chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    let chunk = vec![b'a'; 65536];
    for _ in 0..33 {
        chunked.extend_from_slice(b"10000\r\n");
        chunked.extend_from_slice(&chunk);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let redirect = reply(
        302,
        &format!("Location: http://{}/foreign\r\n", target.local_addr()?),
        b"",
    );
    let declared=b"HTTP/1.1 200 OK\r\nContent-Length: 9000000\r\nx-amz-version-id: fixture-version-001\r\nConnection: close\r\n\r\n".to_vec();
    let ep = Endpoint::start(vec![chunked, redirect, declared]).await?;
    let src = client(&ep.url, credentials("ok"))?;
    let b = binding()?;
    assert!(matches!(
        src.receive(&b, &ctx()).await,
        Err(SourceFailure::Malformed)
    ));
    assert!(matches!(
        src.receive(&b, &ctx()).await,
        Err(SourceFailure::Unavailable)
    ));
    assert!(matches!(
        src.open(&discovery(&b, None)?, &ctx()).await,
        Err(CaptureFailure::Malformed)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
    assert_eq!(ep.finish().await?.len(), 3);
    Ok(())
}

#[tokio::test]
async fn cancellation_during_actual_chunked_read_closes_owned_connection() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let (started, observed) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) =
            tokio::time::timeout(Duration::from_secs(1), listener.accept()).await??;
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            http_publisher_tests::request(&mut socket),
        )
        .await??;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await?;
        let _ = started.send(());
        let mut byte = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte)).await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(n)
    });
    let token = CancellationToken::new();
    let context = ExtensionContext::new(token.clone(), Duration::from_secs(3))?;
    let src = client(&url, credentials("ok"))?;
    let b = binding()?;
    let (result, notice) = tokio::join!(src.receive(&b, &context), async {
        observed.await?;
        token.cancel();
        Ok::<_, tokio::sync::oneshot::error::RecvError>(())
    });
    notice?;
    assert!(matches!(result, Err(SourceFailure::Unavailable)));
    assert!(matches!(server.await, Ok(Ok(0))));
    Ok(())
}
