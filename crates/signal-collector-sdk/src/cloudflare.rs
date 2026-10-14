//! Selected Logpush http_requests projection on shared bounded object decoding.
//! Caller-owned route identity and coverage configuration never come from rows.
use crate::{ExtensionContext, source_object};
use chrono::{DateTime, Datelike, Utc};
use serde_json::Value;
use signal_event::{IngestEvent, SignalEvent};
use std::{net::IpAddr, ops::Range};
use thiserror::Error;
use uuid::Uuid;
pub const PROFILE_ID: &str = "cloudflare-http-requests";
pub const PROFILE_REVISION: &str = "v1";
pub const FIELDS: [&str; 5] = [
    "RayID",
    "EdgeStartTimestamp",
    "ClientIP",
    "ClientRequestMethod",
    "EdgeResponseStatus",
];
pub const MAX_RECORD_BYTES: usize = 65536;
pub const MAX_RECORDS: usize = 1024;
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid Cloudflare profile or pinned preparation context")]
    InvalidConfiguration,
    #[error("invalid selected Logpush record")]
    InvalidRecord,
    #[error("Logpush record/object/count/prepared bytes limit")]
    Limits,
    #[error(transparent)]
    Decode(#[from] source_object::DecodeError),
}
pub struct HttpRequestsProfile {
    name: String,
    account_id: String,
    zone_id: String,
    sample_rate_ppm: u32,
    filtered: bool,
}
fn id(v: &str) -> bool {
    v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit())
}
impl HttpRequestsProfile {
    /// Private job/route configuration, not an authorization capability. This
    /// exact profile requires RFC3339 timestamps and the five declared fields.
    pub fn new(
        name: &str,
        account_id: &str,
        zone_id: &str,
        sample_rate_ppm: u32,
        filtered: bool,
    ) -> Result<Self, Error> {
        if name.is_empty()
            || name.len() > 128
            || name.trim() != name
            || name.chars().any(char::is_control)
            || !id(account_id)
            || !id(zone_id)
            || sample_rate_ppm == 0
            || sample_rate_ppm > 1_000_000
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            name: name.into(),
            account_id: account_id.into(),
            zone_id: zone_id.into(),
            sample_rate_ppm,
            filtered,
        })
    }
}
pub struct Preparation {
    event_id: Uuid,
    receipt_id: Uuid,
    ordinal: u32,
    observed_at: DateTime<Utc>,
}
impl Preparation {
    pub fn new(
        event_id: Uuid,
        receipt_id: Uuid,
        ordinal: u32,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, Error> {
        if event_id.is_nil()
            || receipt_id.is_nil()
            || ordinal >= MAX_RECORDS as u32
            || !(1..=9999).contains(&observed_at.year())
            || observed_at.timestamp_subsec_nanos() >= 1_000_000_000
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            event_id,
            receipt_id,
            ordinal,
            observed_at,
        })
    }
}
/// Parse exactly the pinned five-field profile. Extra headers/cookies/URI fields
/// fail rather than leaking into prepared events. Original bytes remain outside
/// this pure projection; their custody/replay and route verification are separate.
pub fn normalize_record(
    raw: &[u8],
    profile: &HttpRequestsProfile,
    pin: Preparation,
) -> Result<SignalEvent, Error> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(Error::Limits);
    }
    let v = crate::cloudtrail::decode_json(raw, MAX_RECORD_BYTES, 16, 16384)
        .map_err(|_| Error::InvalidRecord)?;
    let o = v.as_object().ok_or(Error::InvalidRecord)?;
    if o.len() != FIELDS.len() || FIELDS.iter().any(|k| !o.contains_key(*k)) {
        return Err(Error::InvalidRecord);
    }
    let text = |key: &str| o[key].as_str().ok_or(Error::InvalidRecord);
    let ray = text("RayID")?;
    if ray.is_empty() || ray.len() > 128 || ray.trim() != ray || ray.chars().any(char::is_control) {
        return Err(Error::InvalidRecord);
    }
    let timestamp = DateTime::parse_from_rfc3339(text("EdgeStartTimestamp")?)
        .map_err(|_| Error::InvalidRecord)?
        .with_timezone(&Utc);
    let ip: IpAddr = text("ClientIP")?
        .parse()
        .map_err(|_| Error::InvalidRecord)?;
    let method = text("ClientRequestMethod")?;
    if method.is_empty()
        || method.len() > 32
        || !method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return Err(Error::InvalidRecord);
    }
    let status = o["EdgeResponseStatus"]
        .as_u64()
        .filter(|n| *n == 0 || (100..=599).contains(n))
        .ok_or(Error::InvalidRecord)?;
    let severity = if status >= 500 {
        "error"
    } else if status >= 400 {
        "warn"
    } else {
        "info"
    };
    let input:IngestEvent=serde_json::from_value(serde_json::json!({"timestamp":timestamp,
        "source":{"type":"cloudflare.logpush","name":profile.name},"severity":severity,"message":"Cloudflare HTTP request observed",
        "resource":{"kind":"cloudflare-zone","id":profile.zone_id,"account_id":profile.account_id},
        "attributes":{"cloudflare":{"dataset":"http_requests","ray_id":ray,"client_ip":ip.to_string(),"method":method,"edge_response_status":status},
            "source_receipt":{"id":pin.receipt_id,"ordinal":pin.ordinal},
            "normalizer":{"id":PROFILE_ID,"revision":PROFILE_REVISION},
            "coverage":{"sample_rate_ppm":profile.sample_rate_ppm,"filtered":profile.filtered,"completeness":"not_assessed","scope_basis":"configured_object_route"}}
    })).map_err(|_|Error::InvalidRecord)?;
    let mut event = input
        .normalize(pin.observed_at)
        .map_err(|_| Error::InvalidRecord)?;
    event.id = pin.event_id;
    Ok(event)
}
/// Entire validated single-member gzip NDJSON capture, retaining exact decoded
/// spans and original digest. Invalid JSON/record poisons the complete object;
/// no valid prefix is published by this reader. Caller publication stays separate.
pub struct LogpushObject {
    decoded: source_object::DecodedObject,
    records: Vec<Range<usize>>,
}
impl LogpushObject {
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
    pub fn record(&self, index: usize) -> Option<&[u8]> {
        self.records
            .get(index)
            .map(|r| &self.decoded.bytes()[r.clone()])
    }
    pub fn original_sha256(&self) -> &[u8; 32] {
        self.decoded.original_sha256()
    }
}
pub fn read_object(original: &[u8], ctx: &ExtensionContext) -> Result<LogpushObject, Error> {
    let decoded = source_object::decode_gzip(original, ctx)?;
    let bytes = decoded.bytes();
    let mut records = Vec::new();
    let mut start = 0;
    for (index, b) in bytes.iter().enumerate() {
        if index % 65536 == 0 {
            source_object::check(ctx)?;
        }
        if *b == b'\n' {
            line(bytes, start, index, &mut records)?;
            start = index + 1;
        } else if index - start >= MAX_RECORD_BYTES {
            return Err(Error::Limits);
        }
    }
    if start < bytes.len() {
        line(bytes, start, bytes.len(), &mut records)?;
    }
    if records.is_empty() {
        return Err(Error::InvalidRecord);
    }
    source_object::check(ctx)?;
    Ok(LogpushObject { decoded, records })
}
fn line(
    bytes: &[u8],
    start: usize,
    mut end: usize,
    records: &mut Vec<Range<usize>>,
) -> Result<(), Error> {
    if end > start && bytes[end - 1] == b'\r' {
        end -= 1;
    }
    if end == start || end - start > MAX_RECORD_BYTES || records.len() >= MAX_RECORDS {
        return Err(Error::Limits);
    }
    let v: Value = crate::cloudtrail::decode_json(&bytes[start..end], MAX_RECORD_BYTES, 16, 16384)
        .map_err(|_| Error::InvalidRecord)?;
    if !v.is_object() {
        return Err(Error::InvalidRecord);
    }
    records.push(start..end);
    Ok(())
}

/// Fully prepared finite object. The original and pinned observed time/receipt
/// identity must remain durable in the private adapter; this is not a source ACK.
pub struct PreparedObject {
    original: LogpushObject,
    events: Vec<SignalEvent>,
}
impl PreparedObject {
    pub fn original(&self) -> &LogpushObject {
        &self.original
    }
    pub fn events(&self) -> &[SignalEvent] {
        &self.events
    }
}
pub fn prepare_object(
    original: &[u8],
    profile: &HttpRequestsProfile,
    receipt_id: Uuid,
    observed_at: DateTime<Utc>,
    ctx: &ExtensionContext,
) -> Result<PreparedObject, Error> {
    use sha2::{Digest, Sha256};
    if receipt_id.is_nil() {
        return Err(Error::InvalidConfiguration);
    }
    let object = read_object(original, ctx)?;
    let mut events = Vec::new();
    let mut prepared_bytes = 0usize;
    for ordinal in 0..object.record_count() {
        source_object::check(ctx)?;
        let mut hash = Sha256::new();
        hash.update(b"PLATFORM::SIGNAL/cloudflare-http-requests/v1\0");
        for part in [&profile.name, &profile.account_id, &profile.zone_id] {
            hash.update((part.len() as u32).to_le_bytes());
            hash.update(part.as_bytes());
        }
        hash.update(profile.sample_rate_ppm.to_le_bytes());
        hash.update([u8::from(profile.filtered)]);
        hash.update(receipt_id.as_bytes());
        hash.update(object.original_sha256());
        hash.update((ordinal as u32).to_le_bytes());
        hash.update(observed_at.to_rfc3339().as_bytes());
        let digest = hash.finalize();
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 15) | 0x80;
        bytes[8] = (bytes[8] & 63) | 0x80;
        let pin = Preparation::new(
            Uuid::from_bytes(bytes),
            receipt_id,
            ordinal as u32,
            observed_at,
        )?;
        let event = normalize_record(
            object.record(ordinal).ok_or(Error::InvalidRecord)?,
            profile,
            pin,
        )?;
        let bytes = serde_json::to_vec(&event).map_err(|_| Error::InvalidRecord)?;
        prepared_bytes = prepared_bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= 8 * 1024 * 1024)
            .ok_or(Error::Limits)?;
        events.push(event);
    }
    source_object::check(ctx)?;
    Ok(PreparedObject {
        original: object,
        events,
    })
}
