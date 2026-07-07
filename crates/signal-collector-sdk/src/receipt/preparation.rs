use super::*;
use crate::cloudtrail::{self, CloudTrailProfile, ObjectReadError, PreparationIdentity};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Trusted bounded in-memory capture identity, never inferred authority from
/// object content. No wire serialization or credentials; receipt v1 is the output.
pub struct OriginalCapture {
    pub bucket: String,
    pub key: String,
    pub version_id: String,
    pub etag: Option<String>,
    pub captured_at: DateTime<Utc>,
    pub discovery_sha256: [u8; 32],
    pub delivery_id: String,
}
pub struct ReceiptRetention {
    pub retain_until: DateTime<Utc>,
    pub source_replay_until: DateTime<Utc>,
    pub recovery_budget_seconds: u32,
}
/// Caller pins IDs, times, full binding and code fingerprint once. No random
/// identity, clock or policy selection in this mechanism. IDs map native ordinals
/// including quarantined entries; only actual emitted IDs enter receipt frames.
pub struct ReceiptPreparation {
    pub receipt_id: Uuid,
    pub binding: ReceiptBinding,
    pub original: OriginalCapture,
    pub prepared_at: DateTime<Utc>,
    pub normalizer_sha256: [u8; 32],
    pub retention: ReceiptRetention,
    pub event_ids: Vec<Uuid>,
}
#[derive(Debug, Error)]
pub enum PreparationError {
    #[error(transparent)]
    Receipt(#[from] ReceiptError),
    #[error(transparent)]
    Native(#[from] cloudtrail::NormalizeError),
    #[error(transparent)]
    Source(#[from] ObjectReadError),
}
fn invalid() -> PreparationError {
    ReceiptError::Invalid("preparation pins").into()
}
fn at(t: &DateTime<Utc>) -> Result<String, PreparationError> {
    let text = t.format("%Y-%m-%dT%H:%M:%S.%9fZ").to_string();
    format::time(&text.clone().into())?;
    Ok(text)
}
pub(super) fn validate_plan_bounds(plan: &ReceiptPreparation) -> Result<(), PreparationError> {
    if plan.receipt_id.is_nil()
        || plan.event_ids.len() > 1024
        || plan.event_ids.iter().any(Uuid::is_nil)
        || plan
            .event_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != plan.event_ids.len()
        || plan.original.bucket.is_empty()
        || plan.original.bucket.len() > 63
        || plan.original.key.is_empty()
        || plan.original.key.len() > 1024
        || plan.original.version_id.is_empty()
        || plan.original.version_id.len() > 1024
        || plan
            .original
            .etag
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 1024)
        || plan.original.delivery_id.is_empty()
        || plan.original.delivery_id.len() > 128
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn receipt_error(e: PreparationError) -> ReceiptError {
    match e {
        PreparationError::Receipt(e) => e,
        PreparationError::Source(ObjectReadError::Cancelled) => ReceiptError::Cancelled,
        PreparationError::Source(ObjectReadError::Timeout) => ReceiptError::Timeout,
        _ => ReceiptError::Invalid("object preparation"),
    }
}
fn base(
    plan: &ReceiptPreparation,
    original: &[u8],
    ctx: &ExtensionContext,
) -> Result<Value, PreparationError> {
    check(ctx)?;
    if original.is_empty() || original.len() > 8 * 1024 * 1024 {
        return Err(ObjectReadError::CaptureLimit.into());
    }
    validate_plan_bounds(plan)?;
    let mut hash = Sha256::new();
    for chunk in original.chunks(65536) {
        check(ctx)?;
        hash.update(chunk);
    }
    let sha: [u8; 32] = hash.finalize().into();
    let m = serde_json::json!({"schema_version":1,"receipt_id":plan.receipt_id.to_string(),"binding":plan.binding.0,
        "original":{"bucket":plan.original.bucket,"key":plan.original.key,"version_id":plan.original.version_id,"etag":plan.original.etag,
            "compression":"gzip","length":original.len(),"sha256":format::hex(&sha),"decoded_length":0,"captured_at":at(&plan.original.captured_at)?,
            "discovery_sha256":format::hex(&plan.original.discovery_sha256),"delivery_id":plan.original.delivery_id,"reference_count":1},
        "prepared_at":at(&plan.prepared_at)?,"normalizer_sha256":format::hex(&plan.normalizer_sha256),
        "retention":{"retain_until":at(&plan.retention.retain_until)?,"source_replay_until":at(&plan.retention.source_replay_until)?,"recovery_budget_seconds":plan.retention.recovery_budget_seconds},
        "object_disposition":"quarantine_object","object_reasons":["unsupported_object"],"records":[]});
    format::metadata(&m)?;
    check(ctx)?;
    Ok(m)
}
fn profile(binding: &ReceiptBinding) -> Result<CloudTrailProfile, PreparationError> {
    let list = |key: &str| -> Result<Vec<&str>, PreparationError> {
        binding.0[key]
            .as_array()
            .ok_or_else(invalid)?
            .iter()
            .map(|v| v.as_str().ok_or_else(invalid))
            .collect()
    };
    Ok(CloudTrailProfile::new(
        cloudtrail::PROFILE_ID,
        &list("recipient_accounts")?,
        &list("regions")?,
    )?)
}
/// Validate entire compressed/native object, normalize all ordinals, build one
/// exact v1 receipt, then execute its existing decoder before returning bytes.
/// Poison objects yield bounded original-only quarantine; timeout/cancel or
/// unavailable bounded capture return errors and retain source responsibility.
/// Synchronous CPU work belongs on a single owned blocking worker.
pub fn prepare_receipt(
    original: &[u8],
    plan: ReceiptPreparation,
    ctx: &ExtensionContext,
) -> Result<Vec<u8>, PreparationError> {
    let mut m = base(&plan, original, ctx)?;
    let object = match cloudtrail::read_object(original, ctx) {
        Ok(object) => object,
        Err(e) => {
            let reason = match e {
                ObjectReadError::InvalidCompression => "invalid_compression",
                ObjectReadError::InvalidObjectJson => "invalid_object_json",
                ObjectReadError::ObjectLimitsExceeded => "object_limits_exceeded",
                ObjectReadError::UnsupportedObject => "unsupported_object",
                ObjectReadError::EmptyRecords => "empty_records",
                e => return Err(e.into()),
            };
            m["object_reasons"] = serde_json::json!([reason]);
            return encode(m, original, &[], 0, ctx);
        }
    };
    if plan.event_ids.len() != object.record_count() {
        return Err(invalid());
    }
    m["original"]["decoded_length"] = object.decoded_length().into();
    m["object_disposition"] = "prepared".into();
    m["object_reasons"] = serde_json::json!([]);
    let profile = profile(&plan.binding)?;
    let mut records = Vec::new();
    let mut frames = Vec::new();
    let mut count = 0usize;
    let mut total = 0usize;
    for i in 0..object.record_count() {
        check(ctx)?;
        let raw = object.record(i).ok_or_else(invalid)?;
        let span = object.span(i).ok_or_else(invalid)?;
        let pin = PreparationIdentity::new(
            plan.event_ids[i],
            plan.receipt_id,
            plan.prepared_at,
            i as u32,
        )?;
        let record = cloudtrail::normalize_record(raw, &profile, pin)?;
        let native = cloudtrail::decode_json(
            raw,
            cloudtrail::MAX_RECORD_BYTES,
            cloudtrail::MAX_JSON_DEPTH,
            cloudtrail::MAX_JSON_NODES,
        )?;
        let native_id = native["eventID"].as_str().and_then(|s| {
            Uuid::parse_str(s)
                .ok()
                .filter(|id| !id.is_nil() && id.to_string() == s)
        });
        let mut descriptor = serde_json::json!({"ordinal":i,"start":span.start,"length":span.len(),"sha256":format::hex(record.original_sha256()),
            "native_event_id":native_id.map(|id|id.to_string()),"disposition":record.disposition(),"reasons":record.reason_codes(),
            "prepared_index":null,"prepared_id":null,"prepared_sha256":null});
        if let Some(bytes) = record.prepared_bytes() {
            let next = total.checked_add(bytes.len()).ok_or_else(invalid)?;
            if next > 16 * 1024 * 1024 {
                m["object_disposition"] = "quarantine_object".into();
                m["object_reasons"] = serde_json::json!(["object_limits_exceeded"]);
                m["records"] = serde_json::json!([]);
                return encode(m, original, &[], 0, ctx);
            }
            let hash: [u8; 32] = Sha256::digest(bytes).into();
            let needed = frames
                .len()
                .checked_add(52 + bytes.len())
                .ok_or_else(invalid)?;
            if needed > frames.capacity() {
                let capacity = (frames.capacity().max(65536) * 2)
                    .min(16 * 1024 * 1024 + 65536)
                    .max(needed);
                frames
                    .try_reserve_exact(capacity - frames.len())
                    .map_err(|_| ReceiptError::Quota)?;
            }
            descriptor["prepared_index"] = count.into();
            descriptor["prepared_id"] = plan.event_ids[i].to_string().into();
            descriptor["prepared_sha256"] = format::hex(&hash).into();
            frames.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            frames.extend_from_slice(plan.event_ids[i].as_bytes());
            frames.extend_from_slice(&hash);
            frames.extend_from_slice(bytes);
            total = next;
            count += 1;
        }
        records.push(descriptor);
    }
    m["records"] = records.into();
    check(ctx)?;
    encode(m, original, &frames, count, ctx)
}
fn encode(
    m: Value,
    original: &[u8],
    frames: &[u8],
    count: usize,
    ctx: &ExtensionContext,
) -> Result<Vec<u8>, PreparationError> {
    check(ctx)?;
    let metadata = format::canonical(&m, 1024 * 1024)?;
    let total = frames.len().checked_sub(count * 52).ok_or_else(invalid)?;
    let size = 36usize
        .checked_add(metadata.len())
        .and_then(|n| n.checked_add(original.len()))
        .and_then(|n| n.checked_add(frames.len()))
        .and_then(|n| n.checked_add(32))
        .ok_or_else(invalid)?;
    if size > MAX_RECEIPT_BYTES {
        return Err(ReceiptError::Quota.into());
    }
    let mut wire = Vec::new();
    wire.try_reserve_exact(size)
        .map_err(|_| ReceiptError::Quota)?;
    wire.extend_from_slice(b"SIGSRC01");
    wire.extend_from_slice(&(metadata.len() as u32).to_be_bytes());
    wire.extend_from_slice(&(original.len() as u64).to_be_bytes());
    wire.extend_from_slice(&(count as u64).to_be_bytes());
    wire.extend_from_slice(&(total as u64).to_be_bytes());
    for bytes in [&metadata[..], original, frames] {
        for chunk in bytes.chunks(65536) {
            check(ctx)?;
            wire.extend_from_slice(chunk);
        }
    }
    let mut hash = Sha256::new();
    for chunk in wire.chunks(65536) {
        check(ctx)?;
        hash.update(chunk);
    }
    wire.extend_from_slice(&hash.finalize());
    let verified = format::decode(wire, ctx)?;
    check(ctx)?;
    Ok(verified.bytes)
}
