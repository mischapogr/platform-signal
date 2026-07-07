use super::*;
use sha2::{Digest, Sha256};
use signal_protocol::{IngestResponse, verify_admission_response};

const CONTROL_LIMIT: usize = 8 * 1024 * 1024;
pub(super) const RESPONSE_LIMIT: usize = 64 * 1024;

/// Exact store-issued compare-and-swap token, not client-declared progress.
/// Clone size is bounded by the frozen control budget. A checksum is not authority.
#[derive(Clone)]
pub struct ReceiptProgress {
    pub(super) bytes: Vec<u8>,
    pub(super) value: Value,
}
impl ReceiptProgress {
    pub fn source_ack_state(&self) -> SourceAckState {
        // Every store-issued control decodes and validates the frozen ACK enum.
        match self.value["ack"]["state"].as_str() {
            Some("intent") => SourceAckState::Intent,
            Some("uncertain") => SourceAckState::Uncertain,
            Some("confirmed") => SourceAckState::Confirmed,
            _ => SourceAckState::NotRequested,
        }
    }
    /// Read-only syntax check for bounded application reconciliation after payload
    /// removal. This does not acquire a lock, attest history or authorize mutation.
    /// Authenticate continuity independently, then open_reconciled rechecks it.
    pub fn inspect_retirement_control(
        bytes: &[u8],
        owner: Uuid,
        generation: u64,
    ) -> Result<Self, ReceiptError> {
        if bytes.len() > CONTROL_LIMIT {
            return Err(ReceiptError::Invalid("control bytes"));
        }
        super::retirement::decode(bytes.to_vec(), owner, generation)
    }
    pub fn revision(&self) -> u64 {
        // Decoding establishes unsigned revision; Value indexing does not panic.
        self.value["revision"].as_u64().unwrap_or_default()
    }
    pub fn verified_prefix(&self) -> usize {
        self.value["verified_prefix"].as_u64().unwrap_or_default() as usize
    }
    pub fn checksum(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes[..self.bytes.len() - 32]).into()
    }
}
/// Input carries the actual response body, never a claimed accepted count/hash.
/// Malformed responses reject without mutation. Record an uncertain attempt after
/// a missing/malformed response if desired, then replay the same suffix.
pub enum ReceiptAttempt {
    Response { status: u16, body: Vec<u8> },
    Uncertain,
    Permanent,
}
/// Owns at most one bounded receipt and control. Events returned are exact pinned
/// bytes starting at the durable verified prefix, not reserialized current events.
pub struct ReceiptReplay {
    pub(super) receipt: StoredReceipt,
    pub(super) progress: ReceiptProgress,
}
impl ReceiptReplay {
    pub fn receipt(&self) -> &StoredReceipt {
        &self.receipt
    }
    pub fn progress(&self) -> &ReceiptProgress {
        &self.progress
    }
    pub fn remaining(&self) -> usize {
        self.receipt.info.prepared_count - self.progress.verified_prefix()
    }
    pub fn suffix_bytes(&self, offset: usize) -> Option<&[u8]> {
        self.progress
            .verified_prefix()
            .checked_add(offset)
            .and_then(|i| self.receipt.prepared_bytes(i))
    }
}
fn invalid(what: &'static str) -> ReceiptError {
    ReceiptError::Invalid(what)
}
fn number(v: &Value) -> Result<u64, ReceiptError> {
    v.as_u64().ok_or_else(|| invalid("progress integer"))
}
fn digest(v: &Value) -> Result<(), ReceiptError> {
    let s = v.as_str().ok_or_else(|| invalid("progress hash"))?;
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("progress hash"));
    }
    Ok(())
}
pub(super) fn prefix_hash(r: &StoredReceipt, prefix: usize) -> Result<[u8; 32], ReceiptError> {
    if prefix > r.info.prepared_count {
        return Err(invalid("verified prefix"));
    }
    let mut h = Sha256::new();
    h.update(b"SIGPRF01");
    h.update(r.info.checksum);
    h.update((prefix as u32).to_be_bytes());
    for range in r.events.iter().take(prefix) {
        // Frozen frame: length4, UUID16, digest32 precede exact event bytes.
        h.update(&r.bytes[range.start - 48..range.start]);
    }
    Ok(h.finalize().into())
}
pub(super) fn encode(value: &Value) -> Result<Vec<u8>, ReceiptError> {
    let json = format::canonical(value, CONTROL_LIMIT - 44)?;
    let mut raw = b"SIGSCP01".to_vec();
    raw.extend_from_slice(&(json.len() as u32).to_be_bytes());
    raw.extend_from_slice(&json);
    raw.extend_from_slice(&Sha256::digest(&raw));
    Ok(raw)
}
pub(super) fn parse(
    bytes: Vec<u8>,
    owner: Uuid,
    generation: u64,
) -> Result<ReceiptProgress, ReceiptError> {
    if owner.is_nil() || generation == 0 {
        return Err(ReceiptError::Owner);
    }
    if !(44..=CONTROL_LIMIT).contains(&bytes.len()) || bytes[..8] != *b"SIGSCP01" {
        return Err(invalid("control frame"));
    }
    let length = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| invalid("control length"))?,
    ) as usize;
    if length.checked_add(44) != Some(bytes.len())
        || bytes[bytes.len() - 32..] != Sha256::digest(&bytes[..bytes.len() - 32])[..]
    {
        return Err(invalid("control checksum/length"));
    }
    let value = format::json(&bytes[12..bytes.len() - 32], CONTROL_LIMIT - 44, 16, 65536)?;
    if format::uuid(&value["owner_id"])? != owner
        || number(&value["owner_generation"])? != generation
    {
        return Err(ReceiptError::Owner);
    }
    Ok(ReceiptProgress { bytes, value })
}

pub(super) fn decode(
    bytes: Vec<u8>,
    r: &StoredReceipt,
    owner: Uuid,
    generation: u64,
) -> Result<ReceiptProgress, ReceiptError> {
    let ReceiptProgress { bytes, value } = parse(bytes, owner, generation)?;
    if value["retirement"]["state"] != "active" {
        let p = super::retirement::decode(bytes, owner, generation)?;
        super::retirement::verify_receipt(&p, r)?;
        return Ok(p);
    }
    if value["custody"]["status"] != "local_only" || value["retirement"]["state"] != "active" {
        return Err(ReceiptError::UnsupportedProgress);
    }
    ack::validate(&value, r)?;
    let revision = number(&value["revision"])?;
    if revision == 0 {
        format::verify_initial(&bytes, r, owner, generation)?;
        return Ok(ReceiptProgress { bytes, value });
    }
    digest(&value["previous_sha256"])?;
    let prefix = number(&value["verified_prefix"])?;
    if prefix > r.info.prepared_count as u64 {
        return Err(invalid("verified prefix"));
    }
    let attempt = &value["attempt"];
    let start = number(&attempt["start"])?;
    let count = number(&attempt["count"])?;
    let accepted = number(&attempt["accepted"])?;
    let none = attempt["kind"] == "none";
    if revision == 1
        && value["ack"]["state"] != "not_requested"
        && (value["ack"]["state"] != "intent" || !none || prefix != 0)
    {
        return Err(invalid("first ACK transition"));
    }
    // ACK-only mutations also clear the admission attempt. Only a handover with
    // no ACK has the generation/predecessor exception used below.
    let handover = none && value["ack"]["state"] == "not_requested";
    if none {
        if (handover && generation <= 1)
            || start != 0
            || count != 0
            || accepted != 0
            || !attempt["response_sha256"].is_null()
            || (revision == 1 && prefix != 0)
        {
            return Err(invalid("empty admission attempt"));
        }
    } else {
        if count == 0
            || start > prefix
            || start
                .checked_add(count)
                .is_none_or(|end| end > r.info.prepared_count as u64)
            || accepted > count
            || start.checked_add(accepted) != Some(prefix)
        {
            return Err(invalid("attempt range"));
        }
        match attempt["kind"].as_str() {
            Some("verified") => digest(&attempt["response_sha256"])?,
            Some("uncertain" | "permanent")
                if accepted == 0 && attempt["response_sha256"].is_null() => {}
            _ => return Err(invalid("attempt outcome")),
        }
    }
    // Compare every immutable and unsupported control field, including unknown
    // keys, against the complete initial pin set. This slice changes only these
    // fields; custody/retirement remain local/active and ACK has its frozen shape.
    let initial = format::initial(r, owner, generation)?;
    if revision == 1
        && !handover
        && (start != 0
            || value["previous_sha256"]
                != format::hex(&Sha256::digest(&initial[..initial.len() - 32])))
    {
        return Err(invalid("first progress predecessor"));
    }
    let mut expected = format::json(
        &initial[12..initial.len() - 32],
        CONTROL_LIMIT - 44,
        16,
        65536,
    )?;
    for key in [
        "revision",
        "previous_sha256",
        "verified_prefix",
        "attempt",
        "ack",
    ] {
        expected[key] = value[key].clone();
    }
    expected["prefix_sha256"] = Value::String(format::hex(&prefix_hash(r, prefix as usize)?));
    if value != expected {
        return Err(ReceiptError::UnsupportedProgress);
    }
    // Ensure attempt has exactly its frozen fields, not arbitrary extra data.
    let keys = attempt
        .as_object()
        .ok_or_else(|| invalid("attempt object"))?;
    if keys.len() != 5
        || !["kind", "start", "count", "accepted", "response_sha256"]
            .iter()
            .all(|k| keys.contains_key(*k))
    {
        return Err(invalid("attempt fields"));
    }
    Ok(ReceiptProgress { bytes, value })
}
pub(super) fn replacement(
    r: &StoredReceipt,
    old: &ReceiptProgress,
    count: u32,
    outcome: ReceiptAttempt,
    owner: Uuid,
    generation: u64,
) -> Result<ReceiptProgress, ReceiptError> {
    let start = old.verified_prefix();
    if count == 0
        || start
            .checked_add(count as usize)
            .is_none_or(|end| end > r.info.prepared_count)
    {
        return Err(invalid("send range"));
    }
    let (kind, accepted, hash) = match outcome {
        ReceiptAttempt::Response { status, body } => {
            if body.len() > RESPONSE_LIMIT {
                return Err(ReceiptError::InvalidResponse);
            }
            crate::cloudtrail::decode_json(&body, RESPONSE_LIMIT, 16, 8192)
                .map_err(|_| ReceiptError::InvalidResponse)?;
            let response: IngestResponse =
                serde_json::from_slice(&body).map_err(|_| ReceiptError::InvalidResponse)?;
            let ids = r.events[start..start + count as usize]
                .iter()
                .map(|range| {
                    Uuid::from_slice(&r.bytes[range.start - 48..range.start - 32])
                        .map_err(|_| invalid("frame UUID"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let verified = verify_admission_response(status, response, &ids)
                .map_err(|_| ReceiptError::InvalidResponse)?;
            (
                "verified",
                verified.accepted,
                Some(format::hex(&Sha256::digest(&body))),
            )
        }
        ReceiptAttempt::Uncertain => ("uncertain", 0, None),
        ReceiptAttempt::Permanent => ("permanent", 0, None),
    };
    let prefix = start + accepted;
    let mut p = old.value.clone();
    p["revision"] = old
        .revision()
        .checked_add(1)
        .ok_or_else(|| invalid("revision overflow"))?
        .into();
    p["previous_sha256"] = format::hex(&old.checksum()).into();
    p["verified_prefix"] = prefix.into();
    p["prefix_sha256"] = format::hex(&prefix_hash(r, prefix)?).into();
    p["attempt"] = serde_json::json!({"kind":kind,"start":start,"count":count,"accepted":accepted,"response_sha256":hash});
    decode(encode(&p)?, r, owner, generation)
}

/// Trusted application's independently reconciled current checkpoint, supplied
/// afresh for one handover. Never infer it from the copied control file or producer
/// attributes. Construction validates bounds, not witness authenticity: the
/// application owns authentication/history reconciliation outside this library.
/// There is deliberately no Deserialize implementation or persisted permission bit.
pub struct ReceiptRecoveryGrant {
    pub(super) binding: ReceiptBinding,
    pub(super) control_checksum: [u8; 32],
    _authority_revision: String,
}
impl ReceiptRecoveryGrant {
    pub fn from_trusted_checkpoint(
        binding: ReceiptBinding,
        control_checksum: [u8; 32],
        authority_revision: String,
    ) -> Result<Self, ReceiptError> {
        if authority_revision.is_empty() || authority_revision.len() > 128 {
            return Err(ReceiptError::Configuration);
        }
        Ok(Self {
            binding,
            control_checksum,
            _authority_revision: authority_revision,
        })
    }
}
pub(super) fn owner_replacement(
    r: &StoredReceipt,
    old: &ReceiptProgress,
    new_owner: Uuid,
    generation: u64,
) -> Result<ReceiptProgress, ReceiptError> {
    if new_owner.is_nil() || old.value["owner_id"] == new_owner.to_string() {
        return Err(ReceiptError::Configuration);
    }
    let mut p = old.value.clone();
    p["owner_id"] = new_owner.to_string().into();
    p["owner_generation"] = generation.into();
    p["revision"] = old
        .revision()
        .checked_add(1)
        .ok_or_else(|| invalid("revision overflow"))?
        .into();
    p["previous_sha256"] = format::hex(&old.checksum()).into();
    p["attempt"] =
        serde_json::json!({"kind":"none","start":0,"count":0,"accepted":0,"response_sha256":null});
    decode(encode(&p)?, r, new_owner, generation)
}
