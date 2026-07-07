//! Application/test HTTP sink: exact pending bytes and complete returned receipt pins.
use super::*;
use signal_coverage::{Receipt, format::ProfileDefinition};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
pub struct HttpSink {
    pub url: String,
    pub token: String,
    client: reqwest::Client,
    pub lose_response: AtomicBool,
    pending: Mutex<Option<Vec<u8>>>,
    pub calls: AtomicUsize,
    pub correction: Option<Uuid>,
}
impl HttpSink {
    pub fn new(url: &str) -> TestResult<Self> {
        Ok(Self {
            url: url.into(),
            token: support::TOKEN.into(),
            client: support::client()?,
            lose_response: AtomicBool::new(false),
            pending: Mutex::new(None),
            calls: AtomicUsize::new(0),
            correction: None,
        })
    }
    pub fn pending(&self) -> TestResult<Option<Vec<u8>>> {
        Ok(self.pending.lock().map_err(|_| "pending lock")?.clone())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema_version: u16,
    disposition: String,
    receipt: Receipt,
    current_health: String,
}
#[signal_collector_sdk::extension]
impl CoverageReportSink for HttpSink {
    async fn commit(
        &self,
        report: &[u8],
        profile: &CoverageProfile,
        context: &ExtensionContext,
    ) -> Result<ReportCommit, ProbeFailure> {
        context.check().map_err(|_| ProbeFailure::Unavailable)?;
        let validated =
            ValidatedCoverage::parse(report, Some(profile)).map_err(|_| ProbeFailure::Malformed)?;
        let expected_pin = ProfileDefinition::parse(
            &profile
                .definition_bytes()
                .map_err(|_| ProbeFailure::Malformed)?,
        )
        .map_err(|_| ProbeFailure::Malformed)?;
        {
            let mut pending = self.pending.lock().map_err(|_| ProbeFailure::Unavailable)?;
            if let Some(original) = pending.as_ref() {
                if original.as_slice() != report {
                    return Err(ProbeFailure::Malformed);
                }
            } else {
                *pending = Some(report.to_vec());
            }
        }
        let publish = async {
            self.calls.fetch_add(1, Ordering::AcqRel);
            let mut url = format!("{}/v1/coverage/records/{}", self.url, validated.record_id());
            if let Some(id) = self.correction {
                url.push_str(&format!("?correction_of={id}"));
            }
            let response = self
                .client
                .post(url)
                .bearer_auth(&self.token)
                .header("content-type", "application/json")
                .body(report.to_vec())
                .send()
                .await
                .map_err(|_| ProbeFailure::Unavailable)?;
            let status = response.status().as_u16();
            match status {
                200 | 201 => {}
                401 | 403 => return Err(ProbeFailure::Denied),
                429 => return Err(ProbeFailure::Throttled),
                _ => return Err(ProbeFailure::Unavailable),
            };
            // Deliberately discard a physically committed response in the fault case.
            // Pending exact input is retained; no replacement record identity is created.
            if self.lose_response.swap(false, Ordering::AcqRel) {
                return Err(ProbeFailure::Unavailable);
            }
            let raw = support::body(response, 8192)
                .await
                .map_err(|_| ProbeFailure::Malformed)?;
            let reply: Reply = serde_json::from_slice(&raw).map_err(|_| ProbeFailure::Malformed)?;
            let r = &reply.receipt;
            if reply.schema_version != 1
                || reply.current_health != "unknown"
                || r.schema_version != 1
                || r.history_id.is_nil()
                || r.record_id.to_string() != validated.record_id()
                || r.content_sha256
                    != signal_coverage::format::hex(&signal_coverage::format::sha256(report))
                || r.profile_fingerprint
                    != signal_coverage::format::hex(&expected_pin.fingerprint())
                || r.correction_of != self.correction
                || r.sequence
                    .parse::<u64>()
                    .ok()
                    .is_none_or(|n| n == 0 || n.to_string() != r.sequence)
                || r.prefix_digest.len() != 64
                || r.authority_revision.is_empty()
            {
                return Err(ProbeFailure::Malformed);
            }
            let result = match (status, reply.disposition.as_str()) {
                (201, "accepted") => ReportCommit::Accepted,
                (200, "replayed") => ReportCommit::Replayed,
                _ => return Err(ProbeFailure::Malformed),
            };
            context.check().map_err(|_| ProbeFailure::Unavailable)?;
            self.pending
                .lock()
                .map_err(|_| ProbeFailure::Unavailable)?
                .take();
            Ok(result)
        };
        tokio::select! {biased;_=context.cancellation().cancelled()=>Err(ProbeFailure::Unavailable),_=tokio::time::sleep_until(context.deadline())=>Err(ProbeFailure::Unavailable),result=publish=>result}
    }
}
pub struct Original(pub Vec<u8>);
#[signal_collector_sdk::extension]
impl CoverageProbe for Original {
    async fn probe(
        &self,
        _: &ProbeRequest<'_>,
        _: &ExtensionContext,
    ) -> Result<ProbeReport, ProbeFailure> {
        ProbeReport::new(&self.0).map_err(|_| ProbeFailure::Malformed)
    }
}
