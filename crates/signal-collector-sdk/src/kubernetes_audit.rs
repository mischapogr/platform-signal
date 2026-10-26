//! Bounded metadata and admitted-Pod projection. The host owns authenticated
//! source binding, protected originals, coverage, durable pins and transport.
use chrono::{DateTime, Datelike, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use signal_event::{SCHEMA_VERSION, Severity, SignalEvent, Source};
use thiserror::Error;
use uuid::Uuid;

mod state;
pub use state::normalize_state_record;

pub const PROFILE_REVISION: &str = "v1";
pub const MAX_RECORD_BYTES: usize = 256 * 1024;
pub const MAX_JSON_DEPTH: usize = 24;
pub const MAX_JSON_NODES: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum Error {
    #[error("invalid Kubernetes audit profile")]
    Configuration,
    #[error("invalid Kubernetes audit record or pinned context")]
    Record,
    #[error("Kubernetes audit JSON or capacity limit")]
    Decode,
}

/// Trusted bindings, never inferred from record annotations or object names.
pub struct Profile {
    cluster: String,
    policy_revision: String,
}
impl Profile {
    pub fn new(cluster: &str, policy_revision: &str) -> Result<Self, Error> {
        if !identity(cluster) || !identity(policy_revision) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            cluster: cluster.into(),
            policy_revision: policy_revision.into(),
        })
    }
}

/// Projection is not a receipt, coverage proof or durable deduplication decision.
pub struct NormalizedRecord<'a> {
    original: &'a [u8],
    hash: [u8; 32],
    event: SignalEvent,
}
impl NormalizedRecord<'_> {
    pub fn original(&self) -> &[u8] {
        self.original
    }
    pub fn original_sha256(&self) -> &[u8; 32] {
        &self.hash
    }
    pub fn event(&self) -> &SignalEvent {
        &self.event
    }
}
fn identity(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.trim() == s && !s.chars().any(char::is_control)
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| identity(s))
        .ok_or(Error::Record)
}
fn timestamp(v: &Value, key: &str) -> Result<DateTime<Utc>, Error> {
    let t = DateTime::parse_from_rfc3339(text(v, key)?).map_err(|_| Error::Record)?;
    if !(1..=9999).contains(&t.year()) {
        return Err(Error::Record);
    }
    Ok(t.with_timezone(&Utc))
}
fn actor(v: &Value) -> Result<Value, Error> {
    let username = text(v, "username")?;
    let mut actor = json!({"username":username});
    if v.get("uid").is_some() {
        actor["uid"] = json!(text(v, "uid")?);
    }
    Ok(actor)
}

/// Project exactly one native Event. Pin ID and observed_at before first use and
/// reuse them on replay; no durable identity allocation is performed here.
pub fn normalize_record<'a>(
    raw: &'a [u8],
    profile: &Profile,
    id: Uuid,
    observed_at: DateTime<Utc>,
) -> Result<NormalizedRecord<'a>, Error> {
    if id.is_nil() || !(1..=9999).contains(&observed_at.year()) {
        return Err(Error::Record);
    }
    let v = crate::cloudtrail::decode_json(raw, MAX_RECORD_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES)
        .map_err(|_| Error::Decode)?;
    if text(&v, "apiVersion")? != "audit.k8s.io/v1" || text(&v, "kind")? != "Event" {
        return Err(Error::Record);
    }
    let uri = v
        .get("requestURI")
        .and_then(Value::as_str)
        .ok_or(Error::Record)?;
    if !uri.starts_with('/')
        || uri.starts_with("//")
        || uri.len() > 8192
        || uri.contains('#')
        || uri.chars().any(char::is_control)
    {
        return Err(Error::Record);
    }
    // Parse only to classify query flags; the dummy origin is never contacted.
    let url =
        reqwest::Url::parse(&format!("https://audit.invalid{uri}")).map_err(|_| Error::Record)?;
    let dry_run = url.query_pairs().any(|(key, _)| key == "dryRun");
    let audit_id = text(&v, "auditID")?;
    let stage = text(&v, "stage")?;
    let level = text(&v, "level")?;
    let verb = text(&v, "verb")?;
    if ![
        "RequestReceived",
        "ResponseStarted",
        "ResponseComplete",
        "Panic",
    ]
    .contains(&stage)
        || !["Metadata", "Request", "RequestResponse"].contains(&level)
    {
        return Err(Error::Record);
    }
    let received = timestamp(&v, "requestReceivedTimestamp")?;
    let timestamp = timestamp(&v, "stageTimestamp")?;
    if timestamp < received {
        return Err(Error::Record);
    }
    let mut metadata = json!({
        "cluster":profile.cluster,"policy_revision":profile.policy_revision,
        "profile_revision":PROFILE_REVISION,"audit_id":audit_id,
        "stage":stage,"level":level,"verb":verb,"dry_run":dry_run,
        "request_received_at":received,"stage_at":timestamp,
        "user":actor(&v["user"])?
    });
    if let Some(impersonated) = v.get("impersonatedUser") {
        metadata["impersonated_user"] = actor(impersonated)?;
    }
    let mut object = json!({});
    if let Some(native) = v.get("objectRef") {
        if !native.is_object() {
            return Err(Error::Record);
        }
        for key in [
            "resource",
            "namespace",
            "name",
            "uid",
            "apiVersion",
            "resourceVersion",
            "subresource",
            "apiGroup",
        ] {
            if let Some(value) = native.get(key) {
                // Core-group apiGroup and empty subresource/namespace may be encoded explicitly.
                let s = value.as_str().ok_or(Error::Record)?;
                if !(identity(s)
                    || s.is_empty() && ["apiGroup", "subresource", "namespace"].contains(&key))
                {
                    return Err(Error::Record);
                }
                object[key] = json!(s);
            }
        }
    }
    metadata["object"] = object.clone();
    let code = match v.get("responseStatus") {
        None => None,
        Some(status) => {
            if !status.is_object() {
                return Err(Error::Record);
            }
            match status.get("code") {
                None => None,
                Some(code) => Some(
                    code.as_u64()
                        .filter(|c| (100..=599).contains(c))
                        .ok_or(Error::Record)?,
                ),
            }
        }
    };
    if let Some(code) = code {
        metadata["response_code"] = json!(code);
    }
    let outcome = match (stage, code) {
        ("ResponseComplete", Some(200..=299)) => "success",
        ("ResponseComplete" | "ResponseStarted", Some(400..=599)) => "failure",
        _ => "unknown",
    };
    let pod_write = object["resource"] == "pods"
        && object.get("apiGroup").is_none_or(|v| v == "")
        && object.get("subresource").is_none_or(|v| v == "")
        && ["create", "update", "patch"].contains(&verb);
    let mut security = json!({"outcome":outcome});
    if pod_write {
        security["action"] = json!("k8s.workload.write");
        if outcome == "success"
            && level == "RequestResponse"
            && !dry_run
            && let Some(privileged) = admitted_privileged(&v["responseObject"], &object)
        {
            security["privileged"] = json!(privileged);
        }
    }
    let attributes = json!({"kubernetes":metadata,"security":security})
        .as_object()
        .ok_or(Error::Record)?
        .clone();
    let event = SignalEvent {
        schema_version: SCHEMA_VERSION,
        id,
        timestamp,
        observed_at,
        source: Source {
            source_type: "kubernetes.audit".into(),
            name: Some(profile.cluster.clone()),
        },
        severity: Severity::Info,
        message: Some("Kubernetes API audit event".into()),
        attributes,
        resource: None,
        trace_id: None,
        span_id: None,
        tags: vec![],
    };
    event.validate().map_err(|_| Error::Record)?;
    // At most 24 selected strings of 256 bytes, even fully JSON escaped, are
    // below the 64-KiB canonical event budget. No native body is cloned to output.
    Ok(NormalizedRecord {
        original: raw,
        hash: Sha256::digest(raw).into(),
        event,
    })
}

fn admitted_privileged(body: &Value, object: &Value) -> Option<bool> {
    if body["apiVersion"] != "v1" || body["kind"] != "Pod" {
        return None;
    }
    let metadata = &body["metadata"];
    for key in ["name", "namespace"] {
        let expected = text(object, key).ok()?;
        if text(metadata, key).ok()? != expected {
            return None;
        }
    }
    let uid = text(metadata, "uid").ok()?;
    if object.get("uid").is_some_and(|expected| expected != uid) {
        return None;
    }
    let spec = body.get("spec")?.as_object()?;
    let mut privileged = false;
    let mut names = std::collections::BTreeSet::new();
    for key in ["containers", "initContainers", "ephemeralContainers"] {
        let containers = match spec.get(key) {
            None if key != "containers" => continue,
            Some(v) => v.as_array()?,
            _ => return None,
        };
        if key == "containers" && containers.is_empty() {
            return None;
        }
        for container in containers {
            if !names.insert(text(container, "name").ok()?) {
                return None;
            }
            let Some(context) = container.get("securityContext") else {
                continue;
            };
            let context = context.as_object()?;
            if let Some(value) = context.get("privileged") {
                privileged |= value.as_bool()?;
            }
        }
    }
    Some(privileged)
}

#[cfg(test)]
mod tests;
