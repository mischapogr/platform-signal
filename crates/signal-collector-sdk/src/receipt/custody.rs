//! Independently signed complete-receipt custody. A signature authenticates the
//! configured archive assertion, not AWS source completeness or archive isolation.
//! No signer, credentials, archive I/O or producer-selected trust is provided.
use super::*;
use chrono::{DateTime, Utc};
use ring::signature;
use sha2::{Digest, Sha256};

pub const MAX_CUSTODY_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_CUSTODY_ATTESTATION_BYTES: usize = 2048;
pub const MAX_CUSTODY_WITNESS_BYTES: usize =
    8 + 4 + MAX_CUSTODY_MANIFEST_BYTES + 4 + MAX_CUSTODY_ATTESTATION_BYTES + 64;
const MAGIC: &[u8; 8] = b"SIGCUS01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyPurpose {
    Prepared,
    Quarantine,
}
impl CustodyPurpose {
    fn name(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Quarantine => "quarantine",
        }
    }
}
/// Host-configured independent authority. Construction checks shape, not whether
/// the host authorized this key/revision or independently isolated the archive.
pub struct CustodyAuthority {
    id: String,
    key_revision: String,
    key: [u8; 32],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}
impl CustodyAuthority {
    pub fn new(
        id: &str,
        key_revision: &str,
        key: [u8; 32],
        valid_from: &str,
        valid_until: &str,
    ) -> Result<Self, ReceiptError> {
        if !bounded_text(id, 128) || !bounded_text(key_revision, 128) || key == [0; 32] {
            return Err(ReceiptError::Custody);
        }
        let start = time(valid_from)?;
        let end = time(valid_until)?;
        if start >= end {
            return Err(ReceiptError::Custody);
        }
        Ok(Self {
            id: id.into(),
            key_revision: key_revision.into(),
            key,
            start,
            end,
        })
    }
}
/// One caller-generated challenge and explicit trusted purpose, not a producer
/// permission field. UTC clock authority belongs to the authenticated host.
pub struct CustodyChallenge {
    nonce: Uuid,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    purpose: CustodyPurpose,
}
impl CustodyChallenge {
    pub fn new(
        nonce: Uuid,
        requested_at: &str,
        expires_at: &str,
        purpose: CustodyPurpose,
    ) -> Result<Self, ReceiptError> {
        let start = time(requested_at)?;
        let end = time(expires_at)?;
        if nonce.is_nil() || start >= end || end - start > chrono::Duration::seconds(60) {
            return Err(ReceiptError::Custody);
        }
        Ok(Self {
            nonce,
            start,
            end,
            purpose,
        })
    }
    pub fn nonce(&self) -> Uuid {
        self.nonce
    }
}
/// Inputs from an independently owned archive after actual durable publication.
/// This helper only constructs data; it neither writes nor grants custody.
pub struct CustodyArchiveIdentity<'a> {
    pub id: &'a str,
    pub version: &'a str,
    pub authority_id: &'a str,
    pub committed_at: &'a str,
    pub retain_until: &'a str,
    pub purpose: CustodyPurpose,
}
/// Build the stable manifest once. Preserve these exact bytes/identity/time on
/// replay; a fresh challenge is signed separately and cannot renew commit time.
pub fn prepare_custody_manifest(
    receipt: &StoredReceipt,
    archive: &CustodyArchiveIdentity<'_>,
    ctx: &ExtensionContext,
) -> Result<Vec<u8>, ReceiptError> {
    check(ctx)?;
    if !bounded_text(archive.id, 512)
        || !bounded_text(archive.version, 512)
        || archive.version == "null"
        || !bounded_text(archive.authority_id, 128)
    {
        return Err(ReceiptError::Custody);
    }
    if archive.purpose != purpose(receipt)? {
        return Err(ReceiptError::Custody);
    }
    let committed = time(archive.committed_at)?;
    let retention = time(archive.retain_until)?;
    if committed < format::time(&receipt.metadata["prepared_at"])?
        || retention < required_until(receipt)?
        || retention <= committed
    {
        return Err(ReceiptError::Custody);
    }
    if !matches!(
        receipt.metadata["binding"]["custody_mode"].as_str(),
        Some("independent_durable" | "protected_replay")
    ) {
        return Err(ReceiptError::Custody);
    }
    let manifest = serde_json::json!({
        "schema_version":1,"receipt_id":receipt.info.id.to_string(),
        "receipt_sha256":format::hex(&receipt.info.checksum),"framed_sha256":format::hex(&framed_hash(receipt,ctx)?),
        "binding":receipt.metadata["binding"],"original":receipt.metadata["original"],"retention":receipt.metadata["retention"],
        "archive_id":archive.id,"archive_version":archive.version,"authority_id":archive.authority_id,
        "mode":receipt.metadata["binding"]["custody_mode"],"purpose":archive.purpose.name(),
        "committed_at":archive.committed_at,"retain_until":archive.retain_until,
    });
    let bytes = format::canonical(&manifest, MAX_CUSTODY_MANIFEST_BYTES)?;
    check(ctx)?;
    Ok(bytes)
}
/// Only the configured independent signature verifier constructs this token.
/// No Deserialize, Clone, boolean setter or persistent authorization is provided.
pub struct VerifiedCustody {
    receipt: [u8; 32],
    witness_id: String,
    retain_until: String,
    committed_at: String,
    observed_at: String,
    purpose: CustodyPurpose,
    deadline: tokio::time::Instant,
}
impl VerifiedCustody {
    pub fn witness_id(&self) -> &str {
        &self.witness_id
    }
    pub fn committed_at(&self) -> &str {
        &self.committed_at
    }
    pub fn retain_until(&self) -> &str {
        &self.retain_until
    }
    pub(super) fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
    pub(super) fn current(
        &self,
        receipt: &StoredReceipt,
        observed_at: &str,
    ) -> Result<(), ReceiptError> {
        if self.receipt != receipt.info.checksum
            || self.observed_at != observed_at
            || self.purpose != purpose(receipt)?
            || tokio::time::Instant::now() >= self.deadline
        {
            return Err(ReceiptError::Custody);
        }
        Ok(())
    }
    pub(super) fn matches_control(&self, control: &Value) -> Result<(), ReceiptError> {
        if control["status"] != "verified_independent"
            || control["witness_id"] != self.witness_id
            || control["receipt_sha256"] != format::hex(&self.receipt)
            || control["retain_until"] != self.retain_until
        {
            return Err(ReceiptError::Custody);
        }
        Ok(())
    }
    pub(super) fn control(&self) -> Value {
        serde_json::json!({"status":"verified_independent","witness_id":self.witness_id,"receipt_sha256":format::hex(&self.receipt),"retain_until":self.retain_until})
    }
}
/// Verify the complete bounded SIGCUS01 frame: magic, u32be manifest length,
/// exact manifest JSON, u32be attestation length, exact attestation JSON, and
/// Ed25519 signature64 over every preceding byte. Both JSON objects are strict;
/// the stable witness identity is SHA256 of the exact immutable manifest bytes.
/// `observed_at` is the trusted host's current UTC time, not a producer timestamp.
pub fn verify_custody_witness(
    receipt: &StoredReceipt,
    witness: &[u8],
    authority: &CustodyAuthority,
    challenge: &CustodyChallenge,
    observed_at: &str,
    ctx: &ExtensionContext,
) -> Result<VerifiedCustody, ReceiptError> {
    check(ctx)?;
    let started = tokio::time::Instant::now();
    if witness.len() < 80 || witness.len() > MAX_CUSTODY_WITNESS_BYTES || witness[..8] != *MAGIC {
        return Err(ReceiptError::Custody);
    }
    let manifest_length = u32::from_be_bytes(
        witness[8..12]
            .try_into()
            .map_err(|_| ReceiptError::Custody)?,
    ) as usize;
    if manifest_length == 0 || manifest_length > MAX_CUSTODY_MANIFEST_BYTES {
        return Err(ReceiptError::Custody);
    }
    let manifest_end = 12 + manifest_length;
    let length_bytes = witness
        .get(manifest_end..manifest_end + 4)
        .ok_or(ReceiptError::Custody)?;
    let attestation_length =
        u32::from_be_bytes(length_bytes.try_into().map_err(|_| ReceiptError::Custody)?) as usize;
    if attestation_length == 0 || attestation_length > MAX_CUSTODY_ATTESTATION_BYTES {
        return Err(ReceiptError::Custody);
    }
    let signed_end = manifest_end + 4 + attestation_length;
    if signed_end + 64 != witness.len() {
        return Err(ReceiptError::Custody);
    }
    let at = time(observed_at)?;
    if at < challenge.start || at > challenge.end || at < authority.start || at > authority.end {
        return Err(ReceiptError::Custody);
    }
    signature::UnparsedPublicKey::new(&signature::ED25519, authority.key)
        .verify(&witness[..signed_end], &witness[signed_end..])
        .map_err(|_| ReceiptError::Custody)?;
    check(ctx)?;
    let manifest_bytes = &witness[12..manifest_end];
    let manifest = format::json(manifest_bytes, MAX_CUSTODY_MANIFEST_BYTES, 16, 8192)?;
    let attestation = format::json(
        &witness[manifest_end + 4..signed_end],
        MAX_CUSTODY_ATTESTATION_BYTES,
        4,
        128,
    )?;
    fields(
        &manifest,
        "schema_version receipt_id receipt_sha256 framed_sha256 binding original retention archive_id archive_version authority_id mode purpose committed_at retain_until",
    )?;
    fields(
        &attestation,
        "schema_version authority_id key_revision manifest_sha256 challenge verified_at",
    )?;
    if format::canonical(&manifest, MAX_CUSTODY_MANIFEST_BYTES)? != manifest_bytes {
        return Err(ReceiptError::Custody);
    }
    let manifest_hash: [u8; 32] = Sha256::digest(manifest_bytes).into();
    let verified = format::time(&attestation["verified_at"])?;
    if manifest["schema_version"] != 1
        || attestation["schema_version"] != 1
        || manifest["authority_id"] != authority.id
        || attestation["authority_id"] != authority.id
        || attestation["key_revision"] != authority.key_revision
        || attestation["challenge"] != challenge.nonce.to_string()
        || attestation["manifest_sha256"] != format::hex(&manifest_hash)
        || verified < challenge.start
        || verified > at
        || verified < authority.start
        || verified >= authority.end
    {
        return Err(ReceiptError::Custody);
    }
    if manifest["receipt_id"] != receipt.info.id.to_string()
        || manifest["receipt_sha256"] != format::hex(&receipt.info.checksum)
        || manifest["framed_sha256"] != format::hex(&framed_hash(receipt, ctx)?)
        || manifest["binding"] != receipt.metadata["binding"]
        || manifest["original"] != receipt.metadata["original"]
        || manifest["retention"] != receipt.metadata["retention"]
        || manifest["mode"] != receipt.metadata["binding"]["custody_mode"]
        || !matches!(
            manifest["mode"].as_str(),
            Some("independent_durable" | "protected_replay")
        )
        || manifest["purpose"] != challenge.purpose.name()
        || challenge.purpose != purpose(receipt)?
    {
        return Err(ReceiptError::Custody);
    }
    let archive_id = manifest["archive_id"]
        .as_str()
        .ok_or(ReceiptError::Custody)?;
    let archive_version = manifest["archive_version"]
        .as_str()
        .ok_or(ReceiptError::Custody)?;
    if !bounded_text(archive_id, 512)
        || !bounded_text(archive_version, 512)
        || archive_version == "null"
    {
        return Err(ReceiptError::Custody);
    }
    let committed = format::time(&manifest["committed_at"])?;
    let retained = format::time(&manifest["retain_until"])?;
    if committed < format::time(&receipt.metadata["prepared_at"])?
        || committed > verified
        || retained < required_until(receipt)?
        || retained <= at
    {
        return Err(ReceiptError::Custody);
    }
    let remaining = (challenge.end.min(authority.end).min(retained) - at)
        .to_std()
        .map_err(|_| ReceiptError::Custody)?;
    if remaining.is_zero() {
        return Err(ReceiptError::Custody);
    }
    let deadline = (started + remaining).min(ctx.deadline());
    if tokio::time::Instant::now() >= deadline {
        return Err(ReceiptError::Custody);
    }
    check(ctx)?;
    Ok(VerifiedCustody {
        receipt: receipt.info.checksum,
        witness_id: format!("sha256:{}", format::hex(&manifest_hash)),
        retain_until: manifest["retain_until"]
            .as_str()
            .ok_or(ReceiptError::Custody)?
            .into(),
        committed_at: manifest["committed_at"]
            .as_str()
            .ok_or(ReceiptError::Custody)?
            .into(),
        observed_at: observed_at.into(),
        purpose: challenge.purpose,
        deadline,
    })
}
pub(super) fn validate_control(
    control: &Value,
    receipt: &StoredReceipt,
) -> Result<(), ReceiptError> {
    validate_control_pins(
        control,
        &receipt.metadata["binding"],
        &receipt.metadata["retention"],
        &Value::String(format::hex(&receipt.info.checksum)),
    )
}
// Retired receipts retain authenticated control history after local payload
// reclaim. This checks syntax/pins only, never a fresh signature or permission.
pub(super) fn validate_control_pins(
    control: &Value,
    binding: &Value,
    retention: &Value,
    receipt_sha256: &Value,
) -> Result<(), ReceiptError> {
    fields(control, "status witness_id receipt_sha256 retain_until")?;
    match control["status"].as_str() {
        Some("local_only")
            if control["witness_id"].is_null()
                && control["receipt_sha256"].is_null()
                && control["retain_until"].is_null() =>
        {
            Ok(())
        }
        Some("verified_independent") => {
            let id = control["witness_id"]
                .as_str()
                .and_then(|s| s.strip_prefix("sha256:"))
                .ok_or(ReceiptError::Custody)?;
            format::hash(&Value::String(id.into()))?;
            if !matches!(
                binding["custody_mode"].as_str(),
                Some("independent_durable" | "protected_replay")
            ) || control["receipt_sha256"] != *receipt_sha256
                || format::time(&control["retain_until"])?
                    < required_until_pins(binding, retention)?
            {
                return Err(ReceiptError::Custody);
            }
            Ok(())
        }
        _ => Err(ReceiptError::Custody),
    }
}
pub(super) fn replacement(
    receipt: &StoredReceipt,
    old: &ReceiptProgress,
    verified: VerifiedCustody,
    observed_at: &str,
    owner: Uuid,
    generation: u64,
) -> Result<ReceiptProgress, ReceiptError> {
    verified.current(receipt, observed_at)?;
    if old.value["custody"]["status"] == "verified_independent" {
        // Reverification neither changes identity nor renews original manifest.
        verified.matches_control(&old.value["custody"])?;
        return Ok(old.clone());
    }
    if old.value["custody"]["status"] != "local_only"
        || old.value["ack"]["state"] != "not_requested"
    {
        return Err(ReceiptError::Custody);
    }
    let mut value = old.value.clone();
    value["revision"] = old
        .revision()
        .checked_add(1)
        .ok_or(ReceiptError::Custody)?
        .into();
    value["previous_sha256"] = format::hex(&old.checksum()).into();
    value["attempt"] =
        serde_json::json!({"kind":"none","start":0,"count":0,"accepted":0,"response_sha256":null});
    value["custody"] = verified.control();
    progress::decode(progress::encode(&value)?, receipt, owner, generation)
}
fn purpose(receipt: &StoredReceipt) -> Result<CustodyPurpose, ReceiptError> {
    let records = receipt.metadata["records"]
        .as_array()
        .ok_or(ReceiptError::Custody)?;
    Ok(
        if receipt.metadata["object_disposition"] == "prepared"
            && receipt.info.prepared_count > 0
            && records.iter().all(|record| {
                matches!(
                    record["disposition"].as_str(),
                    Some("emit" | "emit_indeterminate")
                )
            })
        {
            CustodyPurpose::Prepared
        } else {
            CustodyPurpose::Quarantine
        },
    )
}
fn fields(value: &Value, names: &str) -> Result<(), ReceiptError> {
    if value
        .as_object()
        .is_none_or(|map| map.len() != names.split_whitespace().count())
        || !names
            .split_whitespace()
            .all(|name| value.get(name).is_some())
    {
        return Err(ReceiptError::Custody);
    }
    Ok(())
}
fn bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn time(value: &str) -> Result<DateTime<Utc>, ReceiptError> {
    if value.len() != 30 {
        return Err(ReceiptError::Custody);
    }
    format::time(&Value::String(value.into()))
}
fn framed_hash(receipt: &StoredReceipt, ctx: &ExtensionContext) -> Result<[u8; 32], ReceiptError> {
    let mut hash = Sha256::new();
    for chunk in receipt.bytes.chunks(65536) {
        check(ctx)?;
        hash.update(chunk);
    }
    check(ctx)?;
    Ok(hash.finalize().into())
}

fn required_until(receipt: &StoredReceipt) -> Result<DateTime<Utc>, ReceiptError> {
    required_until_pins(&receipt.metadata["binding"], &receipt.metadata["retention"])
}
fn required_until_pins(binding: &Value, retention: &Value) -> Result<DateTime<Utc>, ReceiptError> {
    let retained = format::time(&retention["retain_until"])?;
    Ok(if binding["custody_mode"] == "protected_replay" {
        retained.max(format::time(&retention["source_replay_until"])?)
    } else {
        retained
    })
}
