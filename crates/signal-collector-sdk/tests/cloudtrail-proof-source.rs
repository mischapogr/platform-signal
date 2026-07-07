#![cfg(feature = "aws-source")]
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use signal_collector_sdk::{
    ExtensionContext,
    cloudtrail::proof::{aws::*, *},
    receipt::{AwsCredentialsProvider, SigningCredentials, SourceFailure},
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;
#[path = "../../../tests/support/aws_signature.rs"]
mod signature;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ACCESS_A: &str = "AKIASYNTHETIC0001";
const ACCESS_B: &str = "AKIASYNTHETIC0002";
const SECRET: &str = "synthetic-signing-secret-never-use-in-aws";
struct Credentials {
    calls: AtomicUsize,
    deny: bool,
}
#[signal_collector_sdk::extension]
impl AwsCredentialsProvider for Credentials {
    async fn credentials(&self, _: &ExtensionContext) -> Result<SigningCredentials, SourceFailure> {
        let n = self.calls.fetch_add(1, Ordering::AcqRel);
        if self.deny {
            return Err(SourceFailure::Denied);
        }
        SigningCredentials::new(
            if n == 0 { ACCESS_A } else { ACCESS_B },
            SECRET,
            Some("synthetic-session-token"),
            None,
        )
    }
}
fn credentials(deny: bool) -> Arc<Credentials> {
    Arc::new(Credentials {
        calls: AtomicUsize::new(0),
        deny,
    })
}
fn time(value: &str) -> TestResult<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}
fn context(milliseconds: u64) -> TestResult<ExtensionContext> {
    Ok(ExtensionContext::new(
        CancellationToken::new(),
        Duration::from_millis(milliseconds),
    )?)
}
fn native() -> Value {
    json!({"PublicKeyList":[{"Fingerprint":"0123456789abcdef0123456789abcdef", "Value":STANDARD.encode(include_bytes!("proof-fixtures/synthetic-public.der")), "ValidityStartTime":1767225600.0, "ValidityEndTime":1798761600.125}]})
}
fn source(endpoint: &str, c: Arc<Credentials>) -> TestResult<RegionalKeySource> {
    Ok(RegionalKeySource::new(
        "eu-central-1",
        endpoint,
        true,
        c,
        Duration::from_secs(1),
    )?)
}
struct Wire {
    request_line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
struct Endpoint {
    url: String,
    task: Option<tokio::task::JoinHandle<Result<Vec<Wire>, &'static str>>>,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Endpoint {
    async fn start(replies: Vec<Vec<u8>>, stall: bool) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let mut captured = Vec::new();
            for reply in replies {
                let (mut socket, _) = listener.accept().await.map_err(|_| "accept")?;
                let mut raw = Vec::new();
                let header_end = loop {
                    let mut byte = [0u8; 1];
                    socket.read_exact(&mut byte).await.map_err(|_| "header")?;
                    raw.push(byte[0]);
                    if raw.len() > 32768 {
                        return Err("header cap");
                    }
                    if raw.ends_with(b"\r\n\r\n") {
                        break raw.len();
                    }
                };
                let text = std::str::from_utf8(&raw[..header_end]).map_err(|_| "header utf8")?;
                let mut lines = text.lines();
                let request_line = lines.next().ok_or("request line")?.to_owned();
                if !request_line.starts_with("POST ") && !request_line.starts_with("GET ") {
                    return Err("request line");
                }
                let headers: BTreeMap<_, _> = lines
                    .filter_map(|s| s.split_once(':'))
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().into()))
                    .collect();
                let n = headers
                    .get("content-length")
                    .and_then(|v: &String| v.parse::<usize>().ok())
                    .filter(|n| *n <= 32768)
                    .or_else(|| request_line.starts_with("GET ").then_some(0))
                    .ok_or("body cap")?;
                let mut body = vec![0; n];
                socket.read_exact(&mut body).await.map_err(|_| "body")?;
                captured.push(Wire {
                    request_line,
                    headers,
                    body,
                });
                let _ = socket.write_all(&reply).await;
                if stall {
                    std::future::pending::<()>().await;
                }
                let _ = socket.shutdown().await;
            }
            Ok(captured)
        });
        Ok(Self {
            url,
            task: Some(task),
        })
    }
    async fn finish(mut self) -> TestResult<Vec<Wire>> {
        let result =
            tokio::time::timeout(Duration::from_secs(5), self.task.as_mut().ok_or("task")?).await;
        match result {
            Ok(v) => {
                self.task.take();
                v?.map_err(Into::into)
            }
            Err(error) => {
                let task = self.task.as_mut().ok_or("task")?;
                task.abort();
                let _ = task.await;
                self.task.take();
                Err(error.into())
            }
        }
    }
}
fn reply(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[tokio::test]
async fn actual_signed_key_requests_use_regional_scope_exact_times_and_rotating_credentials()
-> TestResult {
    let body = serde_json::to_vec(&native())?;
    let endpoint = Endpoint::start(vec![reply(200, &body), reply(200, &body)], false).await?;
    let c = credentials(false);
    let client = source(&endpoint.url, c.clone())?;
    let start = time("2026-07-09T18:00:00.125Z")?;
    let end = time("2026-07-09T19:00:00.875Z")?;
    for _ in 0..2 {
        assert_eq!(client.fetch(start, end, &context(5000)?).await?.len(), 1);
    }
    assert_eq!(c.calls.load(Ordering::Acquire), 2);
    assert_eq!(client.metrics().active, 0);
    assert_eq!(client.metrics().capacity, 1);
    let wires = endpoint.finish().await?;
    assert_eq!(wires.len(), 2);
    for (i, wire) in wires.iter().enumerate() {
        assert_eq!(wire.request_line, "POST / HTTP/1.1");
        assert!(signature::verify(
            "POST",
            "/",
            &wire.headers,
            &wire.body,
            if i == 0 { ACCESS_A } else { ACCESS_B },
            SECRET,
            "cloudtrail",
            "eu-central-1"
        ));
        assert_eq!(
            wire.headers.get("x-amz-target").map(String::as_str),
            Some("com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.ListPublicKeys")
        );
        assert_eq!(
            wire.headers.get("content-type").map(String::as_str),
            Some("application/x-amz-json-1.1")
        );
        assert_eq!(
            wire.body,
            format!(
                "{{\"StartTime\":{}.125000000,\"EndTime\":{}.875000000}}",
                start.timestamp(),
                end.timestamp()
            )
            .as_bytes()
        );
    }
    Ok(())
}

#[tokio::test]
async fn key_endpoint_denial_throttling_outage_and_malformed_input_are_explicit_without_retry()
-> TestResult {
    let start = time("2026-07-09T18:00:00Z")?;
    let end = time("2026-07-09T19:00:00Z")?;
    for (status, body, kind) in [
        (
            403,
            b"{\"__type\":\"AccessDeniedException\"}".to_vec(),
            "denied",
        ),
        (
            429,
            b"{\"__type\":\"ThrottlingException\"}".to_vec(),
            "throttled",
        ),
        (503, b"{}".to_vec(), "unavailable"),
        (200, b"not-json".to_vec(), "malformed"),
        (200, vec![b' '; MAX_KEY_RESPONSE_BYTES + 1], "oversized"),
        (
            200,
            serde_json::to_vec(
                &json!({"PublicKeyList":native()["PublicKeyList"],"NextToken":"unexpected-page"}),
            )?,
            "pagination",
        ),
        (
            200,
            serde_json::to_vec(
                &json!({"PublicKeyList":native()["PublicKeyList"],"Error":"invalid-authority"}),
            )?,
            "error-envelope",
        ),
    ] {
        let endpoint = Endpoint::start(vec![reply(status, &body)], false).await?;
        let client = source(&endpoint.url, credentials(false))?;
        let result = client.fetch(start, end, &context(5000)?).await;
        let expected = match kind {
            "denied" => matches!(result, Err(KeySourceError::Source(SourceFailure::Denied))),
            "throttled" => matches!(
                result,
                Err(KeySourceError::Source(SourceFailure::Throttled))
            ),
            "unavailable" => matches!(
                result,
                Err(KeySourceError::Source(SourceFailure::Unavailable))
            ),
            "oversized" => matches!(
                result,
                Err(KeySourceError::Source(SourceFailure::Malformed))
            ),
            "pagination" => matches!(result, Err(KeySourceError::Proof(ProofError::Unsupported))),
            _ => matches!(result, Err(KeySourceError::Proof(ProofError::Malformed))),
        };
        assert!(expected, "{kind}");
        assert_eq!(client.metrics().active, 0);
        assert_eq!(endpoint.finish().await?.len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn bounded_single_request_lease_busy_and_cancellation_release_owned_http_work() -> TestResult
{
    // A valid response header without an EOF body keeps the physical request
    // occupied until the caller cancels. No additional credential call/queue.
    let endpoint = Endpoint::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec()],
        true,
    )
    .await?;
    let c = credentials(false);
    let client = Arc::new(source(&endpoint.url, c.clone())?);
    let start = time("2026-07-09T18:00:00Z")?;
    let end = time("2026-07-09T19:00:00Z")?;
    let ctx = context(5000)?;
    let active_client = client.clone();
    let active_ctx = ctx.clone();
    let task = tokio::spawn(async move { active_client.fetch(start, end, &active_ctx).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while c.calls.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(client.metrics().active, 1);
    assert!(matches!(
        client.fetch(start, end, &context(5000)?).await,
        Err(KeySourceError::Busy)
    ));
    assert_eq!(client.metrics().rejected, 1);
    assert_eq!(c.calls.load(Ordering::Acquire), 1);
    ctx.cancellation().cancel();
    assert!(task.await?.is_err());
    assert_eq!(client.metrics().active, 0);
    Ok(())
}

#[tokio::test]
async fn pre_cancel_credentials_denial_bad_configuration_and_read_timeout_hold_no_lease()
-> TestResult {
    let start = time("2026-07-09T18:00:00Z")?;
    let end = time("2026-07-09T19:00:00Z")?;
    let c = credentials(true);
    let client = source("http://127.0.0.1:9", c.clone())?;
    let ctx = context(1000)?;
    ctx.cancellation().cancel();
    assert!(matches!(
        client.fetch(start, end, &ctx).await,
        Err(KeySourceError::Proof(ProofError::Cancelled))
    ));
    assert_eq!(c.calls.load(Ordering::Acquire), 0);
    assert!(matches!(
        client.fetch(start, end, &context(1000)?).await,
        Err(KeySourceError::Source(SourceFailure::Denied))
    ));
    assert_eq!(client.metrics().active, 0);
    assert!(matches!(
        client.fetch(end, start, &context(1000)?).await,
        Err(KeySourceError::Proof(ProofError::Configuration))
    ));
    assert!(
        RegionalKeySource::new(
            "eu-central-1",
            "http://external.invalid",
            true,
            c.clone(),
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        RegionalKeySource::new(
            "eu-central-1",
            "http://127.0.0.1:9/other",
            true,
            c,
            Duration::from_secs(1)
        )
        .is_err()
    );
    let endpoint = Endpoint::start(
        vec![b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec()],
        true,
    )
    .await?;
    let client = source(&endpoint.url, credentials(false))?;
    assert!(client.fetch(start, end, &context(40)?).await.is_err());
    assert_eq!(client.metrics().active, 0);
    Ok(())
}

#[tokio::test]
async fn unsupported_epoch_and_leap_inputs_are_rejected_before_credentials() -> TestResult {
    let c = credentials(false);
    let client = source("http://127.0.0.1:9", c.clone())?;
    for (start, end) in [
        (
            time("1969-12-31T23:59:59.125Z")?,
            time("1970-01-01T00:00:01Z")?,
        ),
        (time("2016-12-31T23:59:60Z")?, time("2017-01-01T00:00:01Z")?),
        (
            time("2026-01-01T00:00:00Z")?,
            time("2026-04-01T00:00:00.001Z")?,
        ),
    ] {
        assert!(matches!(
            client.fetch(start, end, &context(1000)?).await,
            Err(KeySourceError::Proof(ProofError::Configuration))
        ));
    }
    assert_eq!(c.calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[tokio::test]
async fn cancelling_endpoint_finish_drops_and_closes_its_listener() -> TestResult {
    let endpoint = Endpoint::start(vec![reply(200, b"{}")], false).await?;
    let address = endpoint
        .url
        .strip_prefix("http://")
        .ok_or("address")?
        .to_owned();
    let task = tokio::spawn(async move {
        let _ = endpoint.finish().await;
    });
    tokio::task::yield_now().await;
    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if tokio::net::TcpStream::connect(&address).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

fn proof_scope() -> TestResult<ProofScope> {
    Ok(ProofScope::new(
        "synthetic-evidence",
        "444455556666",
        "111122223333",
        "eu-central-1",
        "eu-west-1",
        "synthetic_trail",
        "AWSLogs/111122223333",
    )?)
}
fn digest_object() -> TestResult<CapturedObject> {
    let native: Value =
        serde_json::from_slice(include_bytes!("proof-fixtures/openssl-digest.json"))?;
    Ok(CapturedObject::new(
        "synthetic-evidence",
        native["digestS3Object"].as_str().ok_or("key")?,
        "pinned/+version",
        "444455556666",
    )?)
}
fn object_source(endpoint: &str, c: Arc<Credentials>) -> TestResult<NativeObjectSource> {
    Ok(NativeObjectSource::new(
        proof_scope()?,
        "eu-west-1",
        endpoint,
        true,
        c,
        Duration::from_secs(1),
    )?)
}
fn native_reply(status: u16, body: &[u8], headers: &str) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn digest_headers() -> String {
    let signature: String = include_bytes!("proof-fixtures/openssl-signature.bin")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "x-amz-version-id: pinned/+version\r\nx-amz-meta-signature: {signature}\r\nx-amz-meta-signature-algorithm: SHA256withRSA\r\n"
    )
}

#[tokio::test]
async fn actual_signed_s3_capture_pins_version_owner_metadata_and_complete_body_before_validation()
-> TestResult {
    let bytes = include_bytes!("proof-fixtures/openssl-digest.json.gz");
    let endpoint =
        Endpoint::start(vec![native_reply(200, bytes, &digest_headers())], false).await?;
    let c = credentials(false);
    let client = object_source(&endpoint.url, c)?;
    let object = digest_object()?;
    let captured = client
        .fetch(&object, NativeObjectKind::Digest, &context(5000)?)
        .await?;
    assert_eq!(captured.object(), &object);
    assert_eq!(captured.bytes(), bytes);
    let keys = trusted_keys_from_response(
        "eu-central-1",
        &serde_json::to_vec(&native())?,
        &context(5000)?,
    )?;
    let proof = validate_digest(
        &proof_scope()?,
        captured.object(),
        captured.bytes(),
        &captured.digest_metadata().ok_or("metadata")?,
        &keys,
        &context(5000)?,
    )?;
    assert!(validate_delivery(proof, &[], &context(5000)?).is_ok());
    let wires = endpoint.finish().await?;
    assert_eq!(wires.len(), 1);
    let wire = &wires[0];
    let target = wire
        .request_line
        .strip_prefix("GET ")
        .and_then(|s| s.strip_suffix(" HTTP/1.1"))
        .ok_or("GET")?;
    assert!(target.ends_with("?versionId=pinned%2F%2Bversion"));
    assert_eq!(
        wire.headers
            .get("x-amz-expected-bucket-owner")
            .map(String::as_str),
        Some("444455556666")
    );
    assert!(signature::verify(
        "GET",
        target,
        &wire.headers,
        &wire.body,
        ACCESS_A,
        SECRET,
        "s3",
        "eu-west-1"
    ));
    assert_eq!(client.metrics().active, 0);
    Ok(())
}

#[tokio::test]
async fn exact_s3_version_metadata_status_and_scope_failures_never_return_capture() -> TestResult {
    let object = digest_object()?;
    let bytes = include_bytes!("proof-fixtures/openssl-digest.json.gz");
    for (status, headers, body, kind) in [
        (
            200,
            digest_headers().replace("pinned/+version", "different"),
            bytes.to_vec(),
            "scope",
        ),
        (
            200,
            digest_headers().replace("x-amz-version-id: pinned/+version\r\n", ""),
            bytes.to_vec(),
            "malformed",
        ),
        (
            200,
            format!("{}x-amz-version-id: pinned/+version\r\n", digest_headers()),
            bytes.to_vec(),
            "malformed",
        ),
        (
            200,
            digest_headers().replace("SHA256withRSA", "SHA1withRSA"),
            bytes.to_vec(),
            "unsupported",
        ),
        (
            200,
            "x-amz-version-id: pinned/+version\r\n".into(),
            bytes.to_vec(),
            "malformed",
        ),
        (
            200,
            format!(
                "{}x-amz-meta-backfill-generation-timestamp: 2026-07-10T00:00:00Z\r\n",
                digest_headers()
            ),
            bytes.to_vec(),
            "scope",
        ),
        (
            403,
            String::new(),
            b"<Error><Code>AccessDenied</Code></Error>".to_vec(),
            "denied",
        ),
        (
            404,
            String::new(),
            b"<Error><Code>NoSuchVersion</Code></Error>".to_vec(),
            "missing",
        ),
        (
            403,
            String::new(),
            b"<Error><Code>InvalidObjectState</Code></Error>".to_vec(),
            "restore",
        ),
        (
            503,
            String::new(),
            b"<Error><Code>SlowDown</Code></Error>".to_vec(),
            "throttled",
        ),
    ] {
        let endpoint = Endpoint::start(vec![native_reply(status, &body, &headers)], false).await?;
        let client = object_source(&endpoint.url, credentials(false))?;
        let result = client
            .fetch(&object, NativeObjectKind::Digest, &context(5000)?)
            .await;
        let expected = match kind {
            "scope" => matches!(result, Err(ObjectSourceError::Proof(ProofError::Scope))),
            "malformed" => matches!(result, Err(ObjectSourceError::Proof(ProofError::Malformed))),
            "unsupported" => matches!(
                result,
                Err(ObjectSourceError::Proof(ProofError::Unsupported))
            ),
            "denied" => matches!(
                result,
                Err(ObjectSourceError::Source(SourceFailure::Denied))
            ),
            "missing" => matches!(result, Err(ObjectSourceError::MissingVersion)),
            "restore" => matches!(result, Err(ObjectSourceError::RestorePending)),
            _ => matches!(
                result,
                Err(ObjectSourceError::Source(SourceFailure::Throttled))
            ),
        };
        assert!(expected, "{kind}");
        assert_eq!(client.metrics().active, 0);
        assert_eq!(endpoint.finish().await?.len(), 1);
    }
    let c = credentials(false);
    let client = object_source("http://127.0.0.1:9", c.clone())?;
    let wrong_owner = CapturedObject::new(
        object.bucket(),
        object.key(),
        object.version(),
        "777788889999",
    )?;
    assert!(matches!(
        client
            .fetch(&wrong_owner, NativeObjectKind::Digest, &context(1000)?)
            .await,
        Err(ObjectSourceError::Proof(ProofError::Scope))
    ));
    assert_eq!(c.calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[tokio::test]
async fn s3_body_limits_incomplete_eof_and_cancellation_release_owned_read() -> TestResult {
    let object = digest_object()?;
    let oversized = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{}\r\n",
        MAX_DIGEST_BYTES + 1,
        digest_headers()
    )
    .into_bytes();
    let incomplete = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n{}\r\nx",
        digest_headers()
    )
    .into_bytes();
    for (wire, kind) in [(oversized, "oversized"), (incomplete, "incomplete")] {
        let endpoint = Endpoint::start(vec![wire], false).await?;
        let client = object_source(&endpoint.url, credentials(false))?;
        let result = client
            .fetch(&object, NativeObjectKind::Digest, &context(5000)?)
            .await;
        assert!(match kind {
            "oversized" => matches!(
                result,
                Err(ObjectSourceError::Source(SourceFailure::Malformed))
            ),
            _ => matches!(
                result,
                Err(ObjectSourceError::Source(SourceFailure::Unavailable))
            ),
        });
        assert_eq!(client.metrics().active, 0);
        endpoint.finish().await?;
    }
    let wire = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n{}\r\n",
        digest_headers()
    )
    .into_bytes();
    let endpoint = Endpoint::start(vec![wire], true).await?;
    let client = object_source(&endpoint.url, credentials(false))?;
    assert!(
        client
            .fetch(&object, NativeObjectKind::Digest, &context(40)?)
            .await
            .is_err()
    );
    assert_eq!(client.metrics().active, 0);
    let ctx = context(1000)?;
    ctx.cancellation().cancel();
    assert!(matches!(
        client.fetch(&object, NativeObjectKind::Digest, &ctx).await,
        Err(ObjectSourceError::Proof(ProofError::Cancelled))
    ));
    Ok(())
}
