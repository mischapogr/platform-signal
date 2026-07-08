//! Pure, bounded CloudTrail management-record projection. No I/O, clock, random
//! identities, custody, deduplication or authorization service. The application
//! supplies trusted scope and previously pinned preparation identity. Retain the
//! original outside this helper; a checksum is not source-integrity proof.
use chrono::{DateTime, Datelike, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use signal_event::{Resource, SCHEMA_VERSION, Severity, SignalEvent, Source};
use std::io;
use thiserror::Error;
use uuid::Uuid;

pub const PROFILE_ID: &str = "cloudtrail-management";
pub const PROFILE_REVISION: &str = "v1";
mod object;
pub use object::{CloudTrailObject, ObjectReadError, read_object};
pub const MAX_RECORD_BYTES: usize = 256 * 1024;
pub const MAX_EVENT_BYTES: usize = 64 * 1024;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_JSON_NODES: usize = 16_384;
const MAX_ACCOUNTS: usize = 128;
const MAX_REGIONS: usize = 64;
const REQUIRED: [&str; 9] = [
    "eventVersion",
    "eventID",
    "eventTime",
    "eventSource",
    "eventName",
    "awsRegion",
    "eventType",
    "recipientAccountId",
    "managementEvent",
];

/// Static diagnostics never include native fields or trusted configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum NormalizeError {
    #[error("invalid CloudTrail profile configuration")]
    InvalidConfiguration,
    #[error("invalid pinned preparation context")]
    InvalidContext,
    #[error("native record byte limit exceeded")]
    RecordBytesExceeded,
    #[error("native JSON depth limit exceeded")]
    JsonDepthExceeded,
    #[error("native JSON node limit exceeded")]
    JsonNodesExceeded,
    #[error("invalid native JSON")]
    InvalidJson,
    #[error("duplicate native JSON key")]
    DuplicateKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Emit,
    EmitIndeterminate,
    QuarantineRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    MissingRequiredNative,
    MalformedRequiredNative,
    UnsupportedNativeVersion,
    UnsupportedEventCategory,
    RecipientRouteNotAuthorized,
    MissingActor,
    UnsupportedOperation,
    MissingOrUnsupportedMfa,
    UnsupportedActorMfa,
    UnknownOperationOutcome,
    PreparedEventBytesExceeded,
}

/// Trusted application configuration, not a grant inferred from native claims.
/// Construction validates finite count/string budgets before cloning. Full
/// queue/bucket/tenant authorization remains the application's responsibility.
#[derive(Debug)]
pub struct CloudTrailProfile {
    name: String,
    accounts: Vec<String>,
    regions: Vec<String>,
}
impl CloudTrailProfile {
    pub fn new(name: &str, accounts: &[&str], regions: &[&str]) -> Result<Self, NormalizeError> {
        if name.trim().is_empty()
            || name.len() > 128
            || accounts.is_empty()
            || accounts.len() > MAX_ACCOUNTS
            || regions.is_empty()
            || regions.len() > MAX_REGIONS
            || accounts.iter().any(|a| !account(a))
            || regions.iter().any(|r| {
                r.is_empty()
                    || r.len() > 64
                    || !r
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            || accounts
                .iter()
                .enumerate()
                .any(|(i, a)| accounts[..i].contains(a))
            || regions
                .iter()
                .enumerate()
                .any(|(i, r)| regions[..i].contains(r))
        {
            return Err(NormalizeError::InvalidConfiguration);
        }
        Ok(Self {
            name: name.into(),
            accounts: accounts.iter().map(|s| (*s).into()).collect(),
            regions: regions.iter().map(|s| (*s).into()).collect(),
        })
    }
}

/// The caller pins these values once before publishing. This helper never
/// generates IDs or uses the current clock. Ordinal is within the 1,024-record
/// object design; it does not attest to parsing a complete object.
#[derive(Clone, Copy, Debug)]
pub struct PreparationIdentity {
    event_id: Uuid,
    receipt_id: Uuid,
    observed_at: DateTime<Utc>,
    ordinal: u32,
}
impl PreparationIdentity {
    pub fn new(
        event_id: Uuid,
        receipt_id: Uuid,
        observed_at: DateTime<Utc>,
        ordinal: u32,
    ) -> Result<Self, NormalizeError> {
        if event_id.is_nil()
            || receipt_id.is_nil()
            || ordinal >= 1024
            || !(1..=9999).contains(&observed_at.year())
            || observed_at.timestamp_subsec_nanos() >= 1_000_000_000
        {
            return Err(NormalizeError::InvalidContext);
        }
        Ok(Self {
            event_id,
            receipt_id,
            observed_at,
            ordinal,
        })
    }
}

/// One candidate, not a durable source receipt. Exact native bytes are borrowed;
/// canonical bytes and IDs are immutable through this API. Multiple retained
/// results and caller copies require a separately bounded owner/queue.
#[derive(Debug)]
pub struct NormalizedRecord<'a> {
    original: &'a [u8],
    hash: [u8; 32],
    disposition: Disposition,
    reasons: Vec<Reason>,
    event: Option<SignalEvent>,
    bytes: Option<Vec<u8>>,
}
impl NormalizedRecord<'_> {
    pub fn original(&self) -> &[u8] {
        self.original
    }
    pub fn original_sha256(&self) -> &[u8; 32] {
        &self.hash
    }
    pub fn disposition(&self) -> Disposition {
        self.disposition
    }
    pub fn reason_codes(&self) -> &[Reason] {
        &self.reasons
    }
    pub fn event(&self) -> Option<&SignalEvent> {
        self.event.as_ref()
    }
    pub fn prepared_bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
}

/// Parse exactly one decoded native JSON record, not a gzip object or SQS
/// notification. Invalid JSON is an object-level poison error for the future
/// caller; field/scope rejections retain this record with an explicit disposition.
pub fn normalize_record<'a>(
    raw: &'a [u8],
    profile: &CloudTrailProfile,
    pin: PreparationIdentity,
) -> Result<NormalizedRecord<'a>, NormalizeError> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(NormalizeError::RecordBytesExceeded);
    }
    let native = decode_json(raw, MAX_RECORD_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES)?;
    let hash: [u8; 32] = Sha256::digest(raw).into();
    let rejected = |reason| NormalizedRecord {
        original: raw,
        hash,
        disposition: Disposition::QuarantineRecord,
        reasons: vec![reason],
        event: None,
        bytes: None,
    };
    let Some(obj) = native.as_object() else {
        return Ok(rejected(Reason::MissingRequiredNative));
    };
    if REQUIRED.iter().any(|k| !obj.contains_key(*k)) {
        return Ok(rejected(Reason::MissingRequiredNative));
    }
    if REQUIRED[..8]
        .iter()
        .any(|k| obj[*k].as_str().is_none_or(str::is_empty))
    {
        return Ok(rejected(Reason::MalformedRequiredNative));
    }
    let s = |key: &str| obj.get(key).and_then(Value::as_str).unwrap_or("");
    if !canonical_uuid(s("eventID")) {
        return Ok(rejected(Reason::MalformedRequiredNative));
    }
    let Some(timestamp) = timestamp(s("eventTime")) else {
        return Ok(rejected(Reason::MalformedRequiredNative));
    };
    if !version(s("eventVersion")) {
        return Ok(rejected(Reason::UnsupportedNativeVersion));
    }
    if obj["managementEvent"] != Value::Bool(true)
        || obj
            .get("eventCategory")
            .is_some_and(|v| v.as_str() != Some("Management"))
    {
        return Ok(rejected(Reason::UnsupportedEventCategory));
    }
    if !matches!(s("eventType"), "AwsApiCall" | "AwsConsoleSignIn")
        || !account(s("recipientAccountId"))
    {
        return Ok(rejected(Reason::MalformedRequiredNative));
    }
    if !profile
        .accounts
        .iter()
        .any(|a| a == s("recipientAccountId"))
        || !profile.regions.iter().any(|r| r == s("awsRegion"))
    {
        return Ok(rejected(Reason::RecipientRouteNotAuthorized));
    }
    let mut cloud = Map::new();
    for (name, key) in [
        ("event_id", "eventID"),
        ("event_source", "eventSource"),
        ("event_name", "eventName"),
        ("event_version", "eventVersion"),
        ("event_type", "eventType"),
        ("recipient_account_id", "recipientAccountId"),
        ("region", "awsRegion"),
    ] {
        cloud.insert(name.into(), Value::String(s(key).into()));
    }
    cloud.insert("record_ordinal".into(), Value::from(pin.ordinal));
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    cloud.insert("record_sha256".into(), Value::String(hex));
    let mut security = Map::new();
    // Three reasons maximum: missing actor, unsupported MFA, unknown outcome.
    let mut reasons = Vec::with_capacity(3);
    let identity = obj.get("userIdentity").and_then(Value::as_object);
    let actor = identity
        .and_then(|i| i.get("type"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    if let Some(actor) = actor {
        security.insert("actor_kind".into(), Value::String(actor.into()));
    } else {
        reasons.push(Reason::MissingActor);
    }
    if let Some(a) = identity
        .and_then(|i| i.get("accountId"))
        .and_then(Value::as_str)
    {
        cloud.insert("actor_account_id".into(), Value::String(a.into()));
    }
    if let Some(ip) = obj.get("sourceIPAddress").and_then(Value::as_str) {
        cloud.insert("source_ip_address".into(), Value::String(ip.into()));
    }
    let mapping = mapping(&native, s("eventSource"), s("eventName"), s("eventType"));
    if let Some((action, control)) = mapping {
        security.insert("action".into(), Value::String(action.into()));
        if let Some(control) = control {
            security.insert("control".into(), Value::String(control.into()));
        }
        if action == "identity.console_login" {
            if matches!(actor, Some("Root" | "IAMUser")) {
                match field(&native, &["additionalEventData", "MFAUsed"]).and_then(Value::as_str) {
                    Some("Yes") => {
                        security.insert("mfa_used".into(), Value::Bool(true));
                    }
                    Some("No") => {
                        security.insert("mfa_used".into(), Value::Bool(false));
                    }
                    _ => reasons.push(Reason::MissingOrUnsupportedMfa),
                }
            } else {
                reasons.push(Reason::UnsupportedActorMfa);
            }
        }
        if let Some(result) = outcome(&native, action == "identity.console_login") {
            security.insert("outcome".into(), Value::String(result.into()));
        } else {
            reasons.push(Reason::UnknownOperationOutcome);
        }
    } else {
        reasons.push(Reason::UnsupportedOperation);
    }
    let attributes = serde_json::json!({"security": security, "aws": {"cloudtrail": cloud},
        "evidence_ref": format!("receipt://{}/record/{}", pin.receipt_id, pin.ordinal),
        "normalizer": {"id": PROFILE_ID, "revision": PROFILE_REVISION}});
    let Value::Object(attributes) = attributes else {
        return Err(NormalizeError::InvalidContext);
    };
    let event = SignalEvent {
        schema_version: SCHEMA_VERSION,
        id: pin.event_id,
        timestamp,
        observed_at: pin.observed_at,
        source: Source {
            source_type: "cloudtrail".into(),
            name: Some(profile.name.clone()),
        },
        severity: Severity::Info,
        message: Some(format!(
            "CloudTrail {}/{}",
            s("eventSource"),
            s("eventName")
        )),
        attributes,
        resource: Some(Resource {
            kind: "aws_account".into(),
            id: s("recipientAccountId").into(),
            account_id: Some(s("recipientAccountId").into()),
            region: Some(s("awsRegion").into()),
        }),
        trace_id: None,
        span_id: None,
        tags: vec![],
    };
    if event.validate().is_err() {
        return Ok(rejected(Reason::MalformedRequiredNative));
    }
    let mut writer = EventWriter(Vec::new());
    if serde_json::to_writer(&mut writer, &event).is_err() {
        return Ok(rejected(Reason::PreparedEventBytesExceeded));
    }
    Ok(NormalizedRecord {
        original: raw,
        hash,
        disposition: if reasons.is_empty() {
            Disposition::Emit
        } else {
            Disposition::EmitIndeterminate
        },
        reasons,
        event: Some(event),
        bytes: Some(writer.0),
    })
}

struct EventWriter(Vec<u8>);
impl io::Write for EventWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > MAX_EVENT_BYTES - self.0.len() {
            return Err(io::Error::other("canonical event byte limit"));
        }
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn account(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())
}
fn canonical_uuid(s: &str) -> bool {
    s.len() == 36 && Uuid::parse_str(s).is_ok_and(|id| !id.is_nil() && id.to_string() == s)
}
fn version(s: &str) -> bool {
    let Some((major, minor)) = s.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
        && major.parse::<u32>() == Ok(1)
        && minor.parse::<u32>().is_ok_and(|n| n >= 6)
}
fn timestamp(s: &str) -> Option<DateTime<Utc>> {
    let bytes = s.as_bytes();
    if !(20..=30).contains(&bytes.len()) || bytes.last() != Some(&b'Z') {
        return None;
    }
    for (i, &b) in bytes[..19].iter().enumerate() {
        let wanted = match i {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            _ => None,
        };
        if wanted.map_or(!b.is_ascii_digit(), |w| b != w) {
            return None;
        }
    }
    if bytes.len() > 20
        && (bytes[19] != b'.'
            || bytes.len() < 22
            || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return None;
    }
    // Chrono accepts leap-second encodings; this profile uses normal calendar seconds.
    if &bytes[17..19] == b"60" || &bytes[..4] == b"0000" {
        return None;
    }
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}
fn field<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(v, |v, key| v.as_object()?.get(*key))
}
fn mapping(
    v: &Value,
    service: &str,
    name: &str,
    kind: &str,
) -> Option<(&'static str, Option<&'static str>)> {
    let api = kind == "AwsApiCall";
    match (service, name) {
        ("ec2.amazonaws.com", "DescribeInstances") if api => Some(("resource.activity", None)),
        ("cloudtrail.amazonaws.com", "StopLogging") if api => Some(("audit.stop", None)),
        ("cloudtrail.amazonaws.com", "DeleteTrail") if api => Some(("audit.delete", None)),
        ("signin.amazonaws.com", "ConsoleLogin") if kind == "AwsConsoleSignIn" => {
            Some(("identity.console_login", None))
        }
        ("guardduty.amazonaws.com", "UpdateDetector")
            if api && field(v, &["requestParameters", "enable"]) == Some(&Value::Bool(false)) =>
        {
            Some(("control.disable", Some("guardduty")))
        }
        ("guardduty.amazonaws.com", "DeleteDetector") if api => {
            Some(("control.disable", Some("guardduty")))
        }
        ("securityhub.amazonaws.com", "DisableSecurityHub") if api => {
            Some(("control.disable", Some("securityhub")))
        }
        ("config.amazonaws.com", "StopConfigurationRecorder") if api => {
            Some(("control.disable", Some("config")))
        }
        _ => None,
    }
}
fn outcome(v: &Value, console: bool) -> Option<&'static str> {
    let fields = [
        v.get("errorCode"),
        v.get("errorMessage"),
        field(v, &["responseElements", "errorCode"]),
        field(v, &["responseElements", "errorMessage"]),
    ];
    let malformed = fields
        .iter()
        .flatten()
        .any(|v| v.as_str().is_none_or(str::is_empty));
    let code = fields[0]
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
        || fields[2]
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
    let message = fields[1]
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
        || fields[3]
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
    if malformed {
        return None;
    }
    if console {
        match field(v, &["responseElements", "ConsoleLogin"]).and_then(Value::as_str) {
            Some("Success") if !code && !message => Some("success"),
            Some("Failure") => Some("failure"),
            _ => None,
        }
    } else if code {
        Some("failure")
    } else if !message
        && v.get("responseElements")
            .is_some_and(|r| r.is_null() || r.is_object())
    {
        Some("success")
    } else {
        None
    }
}

/// Strict bounded decoder. Every container/key/value is charged before allocation,
/// with no size_hint-driven reserve or arbitrary_precision object conversion.
// Shared strict decoder: bounds are checked before each child allocation.
// Direct object decoding preserves serde arbitrary_precision marker keys literally.
pub(crate) fn decode_json(
    raw: &[u8],
    bytes: usize,
    depth: usize,
    nodes: usize,
) -> Result<Value, NormalizeError> {
    if raw.len() > bytes {
        return Err(NormalizeError::RecordBytesExceeded);
    }
    std::str::from_utf8(raw).map_err(|_| NormalizeError::InvalidJson)?;
    Guard {
        bytes: raw,
        at: 0,
        nodes: 0,
        max_depth: depth,
        max_nodes: nodes,
    }
    .decode()
}

struct Guard<'a> {
    bytes: &'a [u8],
    at: usize,
    nodes: usize,
    max_depth: usize,
    max_nodes: usize,
}
impl Guard<'_> {
    fn decode(mut self) -> Result<Value, NormalizeError> {
        let value = self.value(0)?;
        self.ws();
        if self.at != self.bytes.len() {
            return Err(NormalizeError::InvalidJson);
        }
        Ok(value)
    }
    fn ws(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.at += 1;
        }
    }
    fn byte(&mut self, wanted: u8) -> Result<(), NormalizeError> {
        self.ws();
        if self.bytes.get(self.at) != Some(&wanted) {
            return Err(NormalizeError::InvalidJson);
        }
        self.at += 1;
        Ok(())
    }
    fn node(&mut self) -> Result<(), NormalizeError> {
        if self.nodes == self.max_nodes {
            return Err(NormalizeError::JsonNodesExceeded);
        }
        self.nodes += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String, NormalizeError> {
        self.ws();
        let start = self.at;
        self.byte(b'"')?;
        while let Some(&b) = self.bytes.get(self.at) {
            self.at += 1;
            if b == b'"' {
                return serde_json::from_slice(&self.bytes[start..self.at])
                    .map_err(|_| NormalizeError::InvalidJson);
            }
            if b == b'\\' {
                if self.at == self.bytes.len() {
                    return Err(NormalizeError::InvalidJson);
                }
                self.at += 1;
            } else if b < 32 {
                return Err(NormalizeError::InvalidJson);
            }
        }
        Err(NormalizeError::InvalidJson)
    }
    fn value(&mut self, depth: usize) -> Result<Value, NormalizeError> {
        self.ws();
        self.node()?;
        match self.bytes.get(self.at).copied() {
            Some(b'{') => {
                if depth == self.max_depth {
                    return Err(NormalizeError::JsonDepthExceeded);
                }
                self.at += 1;
                self.ws();
                let mut object = Map::new();
                if self.bytes.get(self.at) == Some(&b'}') {
                    self.at += 1;
                    return Ok(Value::Object(object));
                }
                loop {
                    self.node()?;
                    let key = self.string()?;
                    if object.contains_key(&key) {
                        return Err(NormalizeError::DuplicateKey);
                    }
                    self.byte(b':')?;
                    let value = self.value(depth + 1)?;
                    object.insert(key, value);
                    self.ws();
                    match self.bytes.get(self.at) {
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(Value::Object(object));
                        }
                        Some(b',') => self.at += 1,
                        _ => return Err(NormalizeError::InvalidJson),
                    }
                }
            }
            Some(b'[') => {
                if depth == self.max_depth {
                    return Err(NormalizeError::JsonDepthExceeded);
                }
                self.at += 1;
                self.ws();
                let mut items = Vec::new();
                if self.bytes.get(self.at) == Some(&b']') {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.bytes.get(self.at) {
                        Some(b']') => {
                            self.at += 1;
                            return Ok(Value::Array(items));
                        }
                        Some(b',') => self.at += 1,
                        _ => return Err(NormalizeError::InvalidJson),
                    }
                }
            }
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't' | b'f' | b'n') => {
                let (literal, value): (&[u8], Value) = match self.bytes[self.at] {
                    b't' => (b"true", Value::Bool(true)),
                    b'f' => (b"false", Value::Bool(false)),
                    _ => (b"null", Value::Null),
                };
                if !self.bytes[self.at..].starts_with(literal) {
                    return Err(NormalizeError::InvalidJson);
                }
                self.at += literal.len();
                Ok(value)
            }
            Some(b'-' | b'0'..=b'9') => {
                let start = self.at;
                while self
                    .bytes
                    .get(self.at)
                    .is_some_and(|b| matches!(b, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
                {
                    self.at += 1;
                }
                let raw = &self.bytes[start..self.at];
                let number: serde_json::Number =
                    serde_json::from_slice(raw).map_err(|_| NormalizeError::InvalidJson)?;
                if raw.iter().any(|b| matches!(b, b'.' | b'e' | b'E'))
                    && !number.as_f64().is_some_and(f64::is_finite)
                {
                    return Err(NormalizeError::InvalidJson);
                }
                Ok(Value::Number(number))
            }
            _ => Err(NormalizeError::InvalidJson),
        }
    }
}
