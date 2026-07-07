//! Finite independent synthetic source truth. It knows no ingest/WAL/receipt state.
use super::*;
use std::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Truth {
    pub verified_at: String,
    pub interval_start: String,
    pub interval_end: String,
    pub source_enabled: bool,
    pub expected_stream: String,
    pub source_id: String,
    pub collector_id: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub configuration_revision: String,
    pub expected_positions: u32,
    pub captured_positions: Vec<u32>,
    pub last_source_arrival: Option<String>,
    pub observer_blind: bool,
}
impl Truth {
    pub fn quiet(at: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            verified_at: stamp(at),
            interval_start: stamp(at - chrono::TimeDelta::seconds(300)),
            interval_end: stamp(at),
            source_enabled: true,
            expected_stream: "fixture-audit".into(),
            source_id: "fixture-source".into(),
            collector_id: "fixture-collector".into(),
            resource_kind: "fixture-scope".into(),
            resource_id: "fixture-resource".into(),
            configuration_revision: "fixture-config-v1".into(),
            expected_positions: 0,
            captured_positions: vec![],
            last_source_arrival: None,
            observer_blind: false,
        }
    }
}
#[derive(Clone)]
pub enum Fault {
    None,
    Status(u16),
    Malformed,
    Oversized,
    Stall,
}
pub struct Simulator {
    pub url: String,
    truth: Arc<Mutex<Truth>>,
    fault: Arc<Mutex<Fault>>,
    cancel: CancellationToken,
    task: Option<tokio::task::JoinHandle<TestResult>>,
}
impl Simulator {
    pub async fn start(truth: Truth) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/source-state", listener.local_addr()?);
        let truth = Arc::new(Mutex::new(truth));
        let fault = Arc::new(Mutex::new(Fault::None));
        let cancel = CancellationToken::new();
        let (t, f, c) = (truth.clone(), fault.clone(), cancel.clone());
        let task = tokio::spawn(async move {
            // One sequential request handler, at most 128 requests, bounded headers/body/time.
            for _ in 0..128 {
                let mut stream = tokio::select! {biased;_ = c.cancelled()=>return Ok(()),stream=listener.accept()=>stream?.0};
                let mut header = Vec::new();
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    let mut chunk = [0; 512];
                    let n = tokio::select! {biased;_=c.cancelled()=>return Ok(()),_=tokio::time::sleep_until(deadline)=>return Err("source header deadline".into()),n=stream.read(&mut chunk)=>n?};
                    if n == 0 {
                        break;
                    }
                    if n > 4096usize.saturating_sub(header.len()) {
                        return Err("source header capacity".into());
                    }
                    header.extend_from_slice(&chunk[..n]);
                    if header.windows(4).any(|v| v == b"\r\n\r\n") {
                        break;
                    }
                }
                let text = std::str::from_utf8(&header)?;
                let mut authorization = text
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"));
                let authenticated = authorization.next().is_some_and(|(_, value)| {
                    value.trim().split_once(' ').is_some_and(|(scheme, token)| {
                        scheme.eq_ignore_ascii_case("Bearer")
                            && token == "source-probe-private-token"
                    })
                }) && authorization.next().is_none()
                    && text.lines().next() == Some("GET /source-state HTTP/1.1");
                let fault = f.lock().map_err(|_| "source fault lock")?.clone();
                if matches!(fault, Fault::Stall) {
                    tokio::select! {_=c.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_millis(300))=>{}};
                    continue;
                }
                let (status, body) = if !authenticated {
                    (403, Vec::new())
                } else {
                    match fault {
                        Fault::None => (
                            200,
                            serde_json::to_vec(&*t.lock().map_err(|_| "source truth lock")?)?,
                        ),
                        Fault::Status(status) => (status, Vec::new()),
                        Fault::Malformed => (200, b"{malformed".to_vec()),
                        Fault::Oversized => (200, vec![b'x'; 8193]),
                        Fault::Stall => return Err("stall branch".into()),
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status} synthetic\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                tokio::select! {biased;_=c.cancelled()=>return Ok(()),_=tokio::time::sleep_until(deadline)=>return Err("source response deadline".into()),r=async{stream.write_all(response.as_bytes()).await?;stream.write_all(&body).await?;Ok::<(),std::io::Error>(())}=>{let _=r;}}
            }
            Err("source request capacity".into())
        });
        Ok(Self {
            url,
            truth,
            fault,
            cancel,
            task: Some(task),
        })
    }
    pub fn change(&self, truth: Truth) -> TestResult {
        *self.truth.lock().map_err(|_| "truth lock")? = truth;
        Ok(())
    }
    pub fn fault(&self, fault: Fault) -> TestResult {
        *self.fault.lock().map_err(|_| "fault lock")? = fault;
        Ok(())
    }
    pub async fn stop(&mut self) -> TestResult {
        self.cancel.cancel();
        if let Some(task) = self.task.as_mut() {
            match tokio::time::timeout(Duration::from_secs(2), &mut *task).await {
                Ok(result) => {
                    self.task.take();
                    result??;
                }
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    self.task.take();
                    return Err("source shutdown deadline; owned task aborted and joined".into());
                }
            }
        }
        Ok(())
    }
}
impl Drop for Simulator {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
// A thin application adapter computes reports from native simulated source data,
// rather than serving pre-written green SourceCoverage or consulting admission.
pub struct Probe {
    url: String,
    client: reqwest::Client,
}
impl Probe {
    pub fn new(url: &str) -> TestResult<Self> {
        Ok(Self {
            url: url.into(),
            client: support::client()?,
        })
    }
}
#[signal_collector_sdk::extension]
impl CoverageProbe for Probe {
    async fn probe(
        &self,
        request: &ProbeRequest<'_>,
        context: &ExtensionContext,
    ) -> Result<ProbeReport, ProbeFailure> {
        let fetch = async {
            let response = self
                .client
                .get(&self.url)
                .bearer_auth("source-probe-private-token")
                .send()
                .await
                .map_err(|_| ProbeFailure::Unavailable)?;
            match response.status().as_u16() {
                200 => {}
                401 | 403 => return Err(ProbeFailure::Denied),
                429 => return Err(ProbeFailure::Throttled),
                _ => return Err(ProbeFailure::Unavailable),
            };
            let raw = support::body(response, 8192)
                .await
                .map_err(|_| ProbeFailure::Malformed)?;
            let truth: Truth = serde_json::from_slice(&raw).map_err(|_| ProbeFailure::Malformed)?;
            build(truth, request.context_bytes()).map_err(|_| ProbeFailure::Malformed)
        };
        tokio::select! {biased;_=context.cancellation().cancelled()=>Err(ProbeFailure::Unavailable),_=tokio::time::sleep_until(context.deadline())=>Err(ProbeFailure::Unavailable),report=fetch=>report}
    }
}
fn build(truth: Truth, context: &[u8]) -> TestResult<ProbeReport> {
    let trusted: Value = serde_json::from_slice(context)?;
    if truth.expected_positions > 16
        || truth.captured_positions.len() > 16
        || truth.expected_stream != trusted["binding"]["expected_stream"]
        || truth.source_id != trusted["binding"]["source_id"]
        || truth.collector_id != trusted["binding"]["collector_id"]
        || truth.configuration_revision != trusted["binding"]["collection_config_revision"]
        || json!({"kind":truth.resource_kind,"id":truth.resource_id,"attributes":{}})
            != trusted["binding"]["resource_scope"]
        || truth
            .captured_positions
            .iter()
            .any(|p| *p == 0 || *p > truth.expected_positions)
        || truth
            .captured_positions
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != truth.captured_positions.len()
    {
        return Err("native snapshot bound/scope".into());
    }
    let at = chrono::DateTime::parse_from_rfc3339(&truth.verified_at)?.with_timezone(&chrono::Utc);
    let missing: Vec<_> = (1..=truth.expected_positions)
        .filter(|p| !truth.captured_positions.contains(p))
        .collect();
    let continuity = if truth.observer_blind {
        "unknown"
    } else if !missing.is_empty() {
        "failed"
    } else {
        "verified"
    };
    let summary = if !truth.source_enabled || continuity == "failed" {
        "failed"
    } else if truth.observer_blind {
        "unknown"
    } else {
        "verified"
    };
    let gaps = if truth.observer_blind {
        vec![
            json!({"id":"synthetic-blind-interval","start":truth.interval_start,"end":truth.interval_end,"resource_scope":trusted["binding"]["resource_scope"],"reason_code":"observer_unhealthy","recoverability":"unknown","proof_ref":null}),
        ]
    } else {
        missing.iter().map(|p|json!({"id":format!("synthetic-source-position-{p}"),"start":truth.interval_start,"end":truth.interval_end,"resource_scope":trusted["binding"]["resource_scope"],"reason_code":"collection_failure","recoverability":"irrecoverable","proof_ref":format!("fixture://independent-source/missing/{p}")})).collect()
    };
    // Arrival/read time are excluded: only effective source configuration and
    // authenticated synthetic interval/capture truth define verification evidence.
    let proof = json!({"source_id":truth.source_id,"collector_id":truth.collector_id,"resource_kind":truth.resource_kind,"resource_id":truth.resource_id,"configuration_revision":truth.configuration_revision,"source_enabled":truth.source_enabled,"expected_stream":truth.expected_stream,"verified_at":truth.verified_at,
        "start":truth.interval_start,"end":truth.interval_end,"expected_positions":truth.expected_positions,"captured_positions":truth.captured_positions,"observer_blind":truth.observer_blind});
    let digest = signal_coverage::format::hex(&signal_coverage::format::sha256(
        &serde_json::to_vec(&proof)?,
    ));
    let checkpoint = if truth.observer_blind {
        Value::Null
    } else {
        json!({"schema_version":1,"kind":"synthetic-source-capture","milestone":"capture","value":format!("expected={},captured={:?}",truth.expected_positions,truth.captured_positions)})
    };
    let mut report = trusted["binding"].clone();
    let fields = report.as_object_mut().ok_or("binding")?;
    fields.insert("schema_version".into(), 1.into());
    fields.insert("record_id".into(), Uuid::new_v4().to_string().into());
    fields.insert("coverage_start".into(), truth.interval_start.into());
    fields.insert("coverage_end".into(), truth.interval_end.into());
    fields.insert(
        "last_observed_at".into(),
        truth.last_source_arrival.map_or(Value::Null, Value::String),
    );
    fields.insert("last_verified_at".into(), truth.verified_at.into());
    fields.insert(
        "valid_until".into(),
        stamp(at + chrono::TimeDelta::seconds(60)).into(),
    );
    fields.insert("checkpoint".into(), checkpoint);
    fields.insert("validation_status".into(), summary.into());
    fields.insert("validation".into(),json!({"configuration":if truth.source_enabled{"verified"}else{"failed"},"scope":"verified","continuity":continuity,"source_integrity":"unsupported"}));
    fields.insert(
        "gap_summary".into(),
        json!({"total":gaps.len(),"truncated":false}),
    );
    fields.insert("gaps".into(), gaps.into());
    fields.insert("provenance".into(),json!({"observer_id":trusted["observer_id"],"method":"synthetic-independent-capture-survey","proof_refs":[format!("fixture://source-proof/sha256/{digest}")],"observed_at":trusted["at"]}));
    Ok(ProbeReport::new(&serde_json::to_vec(&report)?)?)
}
