use super::*;

/// Validation after payload removal checks only retained control syntax/pins.
/// Its current history MUST be authenticated independently before store opening.
pub(super) fn decode(
    bytes: Vec<u8>,
    owner: Uuid,
    generation: u64,
) -> Result<ReceiptProgress, ReceiptError> {
    let p = progress::parse(bytes, owner, generation)?;
    let v = &p.value;
    let keys = "schema_version receipt_id receipt_sha256 binding retention prepared_count owner_id owner_generation revision previous_sha256 verified_prefix prefix_sha256 attempt custody ack retirement";
    if v.as_object()
        .is_none_or(|v| v.len() != keys.split_whitespace().count())
        || !keys.split_whitespace().all(|k| v.get(k).is_some())
        || v["schema_version"] != 1
        || !matches!(
            v["retirement"]["state"].as_str(),
            Some("intent" | "complete")
        )
        || p.revision()
            < if v["retirement"]["state"] == "intent" {
                4
            } else {
                5
            }
    {
        return Err(ReceiptError::Retirement);
    }
    format::uuid(&v["receipt_id"])?;
    for key in ["receipt_sha256", "previous_sha256", "prefix_sha256"] {
        format::hash(&v[key])?;
    }
    format::validate_binding(&v["binding"])?;
    if v["binding"]["custody_mode"] != "process_local"
        || v["prepared_count"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > 1024)
        || v["verified_prefix"] != v["prepared_count"]
        || v["custody"]
            != serde_json::json!({"status":"local_only","witness_id":null,"receipt_sha256":null,"retain_until":null})
        || v["attempt"]
            != serde_json::json!({"kind":"none","start":0,"count":0,"accepted":0,"response_sha256":null})
        || v["ack"]["state"] != "confirmed"
    {
        return Err(ReceiptError::Retirement);
    }
    let a = &v["ack"];
    if a.as_object().is_none_or(|a| a.len() != 4)
        || !["state", "attempt_id", "delivery_id", "observed_at"]
            .iter()
            .all(|k| a.get(k).is_some())
        || a["delivery_id"]
            .as_str()
            .is_none_or(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
    {
        return Err(ReceiptError::Retirement);
    }
    format::uuid(&a["attempt_id"])?;
    let retirement = &v["retirement"];
    if retirement.as_object().is_none_or(|v| v.len() != 2) {
        return Err(ReceiptError::Retirement);
    }
    let at = format::time(&retirement["observed_at"])?;
    let retention = &v["retention"];
    if retention.as_object().is_none_or(|v| v.len() != 3)
        || ![
            "retain_until",
            "source_replay_until",
            "recovery_budget_seconds",
        ]
        .iter()
        .all(|k| retention.get(k).is_some())
        || retention["recovery_budget_seconds"]
            .as_u64()
            .is_none_or(|n| n == 0 || n > u32::MAX as u64)
        || at < format::time(&retention["retain_until"])?
        || at < format::time(&a["observed_at"])?
    {
        return Err(ReceiptError::Retirement);
    }
    format::time(&retention["source_replay_until"])?;
    Ok(p)
}
pub(super) fn verify_receipt(p: &ReceiptProgress, r: &StoredReceipt) -> Result<(), ReceiptError> {
    ack::validate(&p.value, r)?;
    if p.value["receipt_id"] != r.info.id.to_string()
        || p.value["receipt_sha256"] != format::hex(&r.info.checksum)
        || p.value["binding"] != r.metadata["binding"]
        || p.value["retention"] != r.metadata["retention"]
        || p.value["prepared_count"].as_u64() != Some(r.info.prepared_count as u64)
        || p.value["prefix_sha256"]
            != format::hex(&progress::prefix_hash(r, r.info.prepared_count)?)
        || r.metadata["object_disposition"] != "prepared"
        || r.metadata["records"].as_array().is_none_or(|records| {
            records
                .iter()
                .any(|r| r["disposition"] == "quarantine_record")
        })
    {
        return Err(ReceiptError::Retirement);
    }
    Ok(())
}
pub(super) fn replacement(
    old: &ReceiptProgress,
    at: String,
    complete: bool,
    owner: Uuid,
    generation: u64,
) -> Result<ReceiptProgress, ReceiptError> {
    let observed = format::time(&Value::String(at.clone()))?;
    if old.value["retirement"]["state"] != if complete { "intent" } else { "active" }
        || old.value["ack"]["state"] != "confirmed"
        || old.verified_prefix() as u64
            != old.value["prepared_count"]
                .as_u64()
                .ok_or(ReceiptError::Retirement)?
        || observed < format::time(&old.value["retention"]["retain_until"])?
        || observed < format::time(&old.value["ack"]["observed_at"])?
        || (complete && observed < format::time(&old.value["retirement"]["observed_at"])?)
    {
        return Err(ReceiptError::Retirement);
    }
    let mut v = old.value.clone();
    v["revision"] = old
        .revision()
        .checked_add(1)
        .ok_or(ReceiptError::Retirement)?
        .into();
    v["previous_sha256"] = format::hex(&old.checksum()).into();
    v["attempt"] =
        serde_json::json!({"kind":"none","start":0,"count":0,"accepted":0,"response_sha256":null});
    v["retirement"] =
        serde_json::json!({"state":if complete {"complete"} else {"intent"},"observed_at":at});
    decode(progress::encode(&v)?, owner, generation)
}
pub(super) fn owner_replacement(
    old: &ReceiptProgress,
    new_owner: Uuid,
    generation: u64,
) -> Result<ReceiptProgress, ReceiptError> {
    if new_owner.is_nil() || old.value["owner_id"] == new_owner.to_string() {
        return Err(ReceiptError::Configuration);
    }
    let mut v = old.value.clone();
    v["owner_id"] = new_owner.to_string().into();
    v["owner_generation"] = generation.into();
    v["revision"] = old
        .revision()
        .checked_add(1)
        .ok_or(ReceiptError::Retirement)?
        .into();
    v["previous_sha256"] = format::hex(&old.checksum()).into();
    decode(progress::encode(&v)?, new_owner, generation)
}
