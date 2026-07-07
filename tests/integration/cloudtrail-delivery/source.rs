//! Deterministic loopback S3/SQS subset. No SigV4, TLS, IAM or AWS qualification.
use super::*;
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

const SOURCE_TOKEN: &str = "synthetic-source-auth-never-log";
pub struct StateData {
    pub original: Vec<u8>,
    pub notification: String,
    pub handle: String,
    pub receives: u64,
    pub deletes: u64,
    pub opens: u64,
    pub clock: u64,
    pub visible_at: u64,
    pub pending: bool,
    pub fault: &'static str,
}
pub struct LocalSource {
    pub url: String,
    pub state: Arc<Mutex<StateData>>,
    task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    stop: CancellationToken,
}
impl LocalSource {
    pub async fn start(original: Vec<u8>, notification: Value) -> TestResult<Self> {
        let state = Arc::new(Mutex::new(StateData {
            original,
            notification: serde_json::to_string(&notification)?,
            handle: String::new(),
            receives: 0,
            deletes: 0,
            opens: 0,
            clock: 0,
            visible_at: 0,
            pending: true,
            fault: "none",
        }));
        let app = Router::new()
            .route("/object", get(object))
            .route("/queue", post(queue))
            .layer(DefaultBodyLimit::max(1024 * 1024))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(cancel.cancelled_owned())
                .await
        });
        Ok(Self {
            url,
            state,
            task: Some(task),
            stop,
        })
    }
    pub async fn expire(&self) {
        let mut s = self.state.lock().await;
        s.clock = s.visible_at;
    }
    pub async fn close(mut self) -> TestResult<()> {
        self.stop.cancel();
        let mut task = self.task.take().ok_or("source task")?;
        match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
            Ok(result) => result??,
            Err(error) => {
                task.abort();
                let _ = task.await;
                return Err(error.into());
            }
        }
        Ok(())
    }
}
impl Drop for LocalSource {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
fn auth(h: &HeaderMap) -> bool {
    h.get("authorization").and_then(|v| v.to_str().ok())
        == Some("Bearer synthetic-source-auth-never-log")
}
async fn queue(
    State(state): State<Arc<Mutex<StateData>>>,
    h: HeaderMap,
    Json(v): Json<Value>,
) -> Response {
    if !auth(&h) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut s = state.lock().await;
    let action = h
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if s.fault == "queue_throttle" {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if s.fault == "queue_denied" {
        return StatusCode::FORBIDDEN.into_response();
    }
    match action {
        "AmazonSQS.ReceiveMessage" => {
            if v["MaxNumberOfMessages"] != 1 {
                return StatusCode::BAD_REQUEST.into_response();
            }
            if !s.pending || s.clock < s.visible_at {
                return Json(json!({"Messages":[]})).into_response();
            }
            s.receives += 1;
            s.handle = format!("ephemeral-private-handle-{}", s.receives);
            s.visible_at = s.clock + 30;
            Json(json!({"Messages":[{"MessageId":"fixture-message-001",
                "ReceiptHandle":s.handle,"Body":s.notification}]}))
            .into_response()
        }
        "AmazonSQS.DeleteMessage" => {
            s.deletes += 1;
            if s.fault == "delete_uncertain" {
                // Simulate transport/service failure without definite deletion.
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            if v["ReceiptHandle"] == s.handle && s.clock < s.visible_at {
                s.pending = false;
            }
            // An old/expired handle may return 200 while the message survives.
            StatusCode::OK.into_response()
        }
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}
async fn object(State(state): State<Arc<Mutex<StateData>>>, h: HeaderMap, uri: Uri) -> Response {
    if !auth(&h) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(v) =
        serde_urlencoded::from_str::<HashMap<String, String>>(uri.query().unwrap_or_default())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let mut s = state.lock().await;
    s.opens += 1;
    if h.get("x-amz-expected-bucket-owner")
        .and_then(|v| v.to_str().ok())
        != Some("111122223333")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if v.get("bucket").map(String::as_str) != Some("fixture-source-evidence")
        || v.get("key").map(String::as_str) != Some("AWSLogs/fixture/café + %.json.gz")
        || v.get("versionId").map(String::as_str) != Some("fixture-version-001")
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    match s.fault {
        "object_throttle" => return StatusCode::TOO_MANY_REQUESTS.into_response(),
        "object_denied" => return StatusCode::FORBIDDEN.into_response(),
        "object_missing" => return StatusCode::NOT_FOUND.into_response(),
        "object_outage" => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        _ => (),
    }
    let version = if s.fault == "wrong_version" {
        "wrong-version"
    } else {
        "fixture-version-001"
    };
    let bytes = if s.fault == "malformed_object" {
        b"bad gzip".to_vec()
    } else {
        s.original.clone()
    };
    Response::builder()
        .status(200)
        .header("x-amz-version-id", version)
        .header("etag", "local-opaque-etag")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub struct Delivery {
    pub body: Vec<u8>,
    pub id: String,
    pub handle: String,
}
pub struct SourceClient {
    client: reqwest::Client,
    pub url: String,
}
impl SourceClient {
    pub fn new(url: String) -> TestResult<Self> {
        Ok(Self {
            client: client()?,
            url,
        })
    }
    pub async fn receive(&self) -> TestResult<Option<Delivery>> {
        let r = self
            .client
            .post(format!("{}/queue", self.url))
            .bearer_auth(SOURCE_TOKEN)
            .header("x-amz-target", "AmazonSQS.ReceiveMessage")
            .json(&json!({"MaxNumberOfMessages":1,"VisibilityTimeout":30}))
            .send()
            .await?;
        if r.status() != 200 {
            return Err("queue receive held".into());
        }
        let v: Value = serde_json::from_slice(&body(r, 1024 * 1024).await?)?;
        let rows = v["Messages"].as_array().ok_or("messages")?;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.len() != 1 {
            return Err("queue count cap".into());
        }
        let row = &rows[0];
        Ok(Some(Delivery {
            body: row["Body"].as_str().ok_or("body")?.as_bytes().to_vec(),
            id: row["MessageId"].as_str().ok_or("id")?.into(),
            handle: row["ReceiptHandle"].as_str().ok_or("handle")?.into(),
        }))
    }
    pub async fn delete(&self, handle: &str) -> TestResult<SourceAckOutcome> {
        let r = self
            .client
            .post(format!("{}/queue", self.url))
            .bearer_auth(SOURCE_TOKEN)
            .header("x-amz-target", "AmazonSQS.DeleteMessage")
            .json(&json!({"ReceiptHandle":handle}))
            .send()
            .await?;
        let status = r.status().as_u16();
        Ok(SourceAckOutcome::from_sqs_json_response(
            status,
            &body(r, 65536).await?,
        ))
    }
}
#[signal_collector_sdk::extension]
impl CaptureTransport for SourceClient {
    async fn open(
        &self,
        d: &ObjectDiscovery,
        context: &ExtensionContext,
    ) -> Result<CaptureStream, CaptureFailure> {
        context.check().map_err(|_| CaptureFailure::Unavailable)?;
        let r = self
            .client
            .get(format!("{}/object", self.url))
            .bearer_auth(SOURCE_TOKEN)
            .header("x-amz-expected-bucket-owner", d.expected_bucket_owner())
            .query(&[
                ("bucket", d.bucket()),
                ("key", d.key()),
                ("versionId", d.version_id()),
            ])
            .send()
            .await
            .map_err(|_| CaptureFailure::Unavailable)?;
        match r.status().as_u16() {
            200 => (),
            403 => return Err(CaptureFailure::Denied),
            404 => return Err(CaptureFailure::MissingVersion),
            429 => return Err(CaptureFailure::Throttled),
            _ => return Err(CaptureFailure::Unavailable),
        }
        let version_id = r
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| s.len() <= 1024)
            .ok_or(CaptureFailure::Malformed)?
            .to_owned();
        let etag = r
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        // Test adapter buffers one capped HTTP object. SDK streaming read failures
        // are tested separately. No cloud SDK authentication claim is made here.
        let bytes = body(r, MAX_CAPTURE_BYTES)
            .await
            .map_err(|_| CaptureFailure::Malformed)?;
        Ok(CaptureStream {
            version_id,
            etag,
            body: Box::new(std::io::Cursor::new(bytes)),
        })
    }
}
pub fn client() -> TestResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(3))
        .pool_max_idle_per_host(1)
        .build()?)
}
pub async fn body(mut r: reqwest::Response, cap: usize) -> TestResult<Vec<u8>> {
    if r.content_length().is_some_and(|n| n > cap as u64) {
        return Err("HTTP body cap".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = r.chunk().await? {
        if chunk.len() > cap - bytes.len() {
            return Err("HTTP body cap".into());
        }
        bytes.try_reserve_exact(chunk.len())?;
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[signal_collector_sdk::extension]
impl SourceQueue for SourceClient {
    async fn receive(
        &self,
        _binding: &ReceiptBinding,
        _context: &ExtensionContext,
    ) -> Result<Option<QueueDelivery>, SourceFailure> {
        // The test endpoint's queue/configuration is fixed and locally trusted.
        // A production adapter must enforce ARN/owner and use current credentials.
        let delivery = SourceClient::receive(self)
            .await
            .map_err(|_| SourceFailure::Unavailable)?;
        delivery
            .map(|d| {
                QueueDelivery::new(d.body, d.id, d.handle).map_err(|_| SourceFailure::Malformed)
            })
            .transpose()
    }
    async fn delete(
        &self,
        _binding: &ReceiptBinding,
        ticket: &SourceAckTicket,
        _context: &ExtensionContext,
    ) -> Result<SourceAckOutcome, SourceFailure> {
        SourceClient::delete(self, ticket.handle())
            .await
            .map_err(|_| SourceFailure::Unavailable)
    }
}
