//! Native CloudTrail byte proofs. Call synchronous functions on an owned bounded
//! blocking worker. No network, credentials, clock-based freshness, collection
//! completeness or archive custody is inferred here. Constructors accept trusted
//! host configuration; parsing a key response does not authenticate its provider.
use super::decode_json;
use crate::ExtensionContext;
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Datelike, Utc};
use flate2::bufread::GzDecoder;
use ring::signature;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use thiserror::Error;

pub const MAX_DIGEST_BYTES: usize = 1024 * 1024;
pub const MAX_LOG_COMPRESSED_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_LOG_DECODED_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DELIVERY_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_LOG_FILES: usize = 1024;
pub const MAX_CHAIN_LENGTH: usize = 64;
pub const MAX_KEY_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_KEYS: usize = 64;
const MAX_KEY_BYTES: usize = 4096;
#[cfg(feature = "aws-source")]
#[path = "proof_aws.rs"]
pub mod aws;

/// Static errors never include source content, paths, signatures or credentials.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum ProofError {
    #[error("invalid trusted proof configuration")]
    Configuration,
    #[error("native proof exceeds finite bounds")]
    Limit,
    #[error("malformed native proof")]
    Malformed,
    #[error("unsupported native proof algorithm or pagination")]
    Unsupported,
    #[error("source proof scope does not match trusted capture")]
    Scope,
    #[error("no unique applicable trusted regional key")]
    Key,
    #[error("source signature validation failed")]
    Signature,
    #[error("invalid compressed source")]
    Compression,
    #[error("referenced source content does not match")]
    Content,
    #[error("native chain link does not match retained evidence")]
    Link,
    #[error("proof operation cancelled")]
    Cancelled,
    #[error("proof deadline expired")]
    Timeout,
}

/// Host-authorized trail routing. Creation checks shape/bounds, not permissions.
/// `root` includes optional prefix, AWSLogs, optional organization, and account.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofScope {
    bucket: String,
    owner: String,
    account: String,
    region: String,
    home_region: String,
    trail: String,
    root: String,
}
impl ProofScope {
    pub fn new(
        bucket: &str,
        owner: &str,
        account: &str,
        region: &str,
        home_region: &str,
        trail: &str,
        root: &str,
    ) -> Result<Self, ProofError> {
        if !bucket_name(bucket)
            || !super::account(owner)
            || !super::account(account)
            || !region_name(region)
            || !region_name(home_region)
            || !token(trail, 128)
            || root.len() > 512
            || !object_key(root)
            || !root.ends_with(&format!("/{account}"))
            || !root.split('/').any(|part| part == "AWSLogs")
        {
            return Err(ProofError::Configuration);
        }
        Ok(Self {
            bucket: bucket.into(),
            owner: owner.into(),
            account: account.into(),
            region: region.into(),
            home_region: home_region.into(),
            trail: trail.into(),
            root: root.into(),
        })
    }
    fn validate(&self) -> Result<(), ProofError> {
        Self::new(
            &self.bucket,
            &self.owner,
            &self.account,
            &self.region,
            &self.home_region,
            &self.trail,
            &self.root,
        )
        .map(|_| ())
    }
    fn digest_key(&self, end: DateTime<Utc>, backfill: bool) -> String {
        format!(
            "{}/CloudTrail-Digest/{}/{}/{}_CloudTrail-Digest_{}_{}_{}_{}{}.json.gz",
            self.root,
            self.region,
            end.format("%Y/%m/%d"),
            self.account,
            self.region,
            self.trail,
            self.home_region,
            end.format("%Y%m%dT%H%M%SZ"),
            if backfill { "_backfill" } else { "" }
        )
    }
    fn log_key(&self, key: &str) -> bool {
        object_key(key)
            && key.starts_with(&format!("{}/CloudTrail/{}/", self.root, self.region))
            && key.ends_with(".json.gz")
    }
}

/// Exact version/owner from an authenticated object provider. Shape alone does
/// not authenticate these claims. No latest-version fallback is supported.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedObject {
    bucket: String,
    key: String,
    version: String,
    owner: String,
}
impl CapturedObject {
    pub fn new(bucket: &str, key: &str, version: &str, owner: &str) -> Result<Self, ProofError> {
        if !bucket_name(bucket)
            || !object_key(key)
            || !text(version, 1024)
            || version == "null"
            || !super::account(owner)
        {
            return Err(ProofError::Configuration);
        }
        Ok(Self {
            bucket: bucket.into(),
            key: key.into(),
            version: version.into(),
            owner: owner.into(),
        })
    }
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    fn validate(&self) -> Result<(), ProofError> {
        Self::new(&self.bucket, &self.key, &self.version, &self.owner).map(|_| ())
    }
}

/// Native metadata from the trusted captured object response. Backfill key
/// selection uses generation time, not the historic digest interval end.
pub struct DigestMetadata<'a> {
    pub signature_hex: &'a str,
    pub signature_algorithm: &'a str,
    pub backfill_generated_at: Option<DateTime<Utc>>,
}

/// Region-scoped keys obtained independently of digest content. This type is
/// not deserializable and never accepts keys embedded in a native digest.
pub struct TrustedRegionalKey {
    region: String,
    fingerprint: String,
    der: Vec<u8>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}
impl TrustedRegionalKey {
    pub fn new(
        region: &str,
        fingerprint: &str,
        der: &[u8],
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Self, ProofError> {
        if !region_name(region)
            || !hex_shape(fingerprint, 32)
            || der.is_empty()
            || der.len() > MAX_KEY_BYTES
            || !valid_time(start)
            || !valid_time(end)
            || start >= end
        {
            return Err(ProofError::Configuration);
        }
        Ok(Self {
            region: region.into(),
            fingerprint: fingerprint.into(),
            der: der.into(),
            start,
            end,
        })
    }
}

/// Decode a complete *authenticated* regional ListPublicKeys response. Finite
/// unsupported NextToken is rejected rather than truncating a key inventory.
/// The caller owns authentication, network timeout and response-byte bounding.
pub fn trusted_keys_from_response(
    region: &str,
    bytes: &[u8],
    ctx: &ExtensionContext,
) -> Result<Vec<TrustedRegionalKey>, ProofError> {
    check(ctx)?;
    if !region_name(region) {
        return Err(ProofError::Configuration);
    }
    let value =
        decode_json(bytes, MAX_KEY_RESPONSE_BYTES, 8, 4096).map_err(|_| ProofError::Malformed)?;
    if !value.is_object()
        || ["__type", "Error", "Code"]
            .iter()
            .any(|key| value.get(key).is_some())
    {
        return Err(ProofError::Malformed);
    }
    if value
        .get("NextToken")
        .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
    {
        return Err(ProofError::Unsupported);
    }
    let rows = value
        .get("PublicKeyList")
        .and_then(Value::as_array)
        .ok_or(ProofError::Malformed)?;
    if rows.is_empty() || rows.len() > MAX_KEYS {
        return Err(ProofError::Limit);
    }
    let mut keys = Vec::with_capacity(rows.len());
    for row in rows {
        check(ctx)?;
        let encoded = string(row, "Value", 5500)?;
        let der = STANDARD
            .decode(encoded)
            .map_err(|_| ProofError::Malformed)?;
        let start = epoch(row.get("ValidityStartTime").ok_or(ProofError::Malformed)?)?;
        let end = epoch(row.get("ValidityEndTime").ok_or(ProofError::Malformed)?)?;
        let key =
            TrustedRegionalKey::new(region, string(row, "Fingerprint", 32)?, &der, start, end)?;
        if keys.iter().any(|prior: &TrustedRegionalKey| {
            prior.fingerprint == key.fingerprint && prior.start == key.start && prior.end == key.end
        }) {
            return Err(ProofError::Key);
        }
        keys.push(key);
    }
    check(ctx)?;
    Ok(keys)
}

#[derive(Debug)]
pub struct ReferencedLog {
    bucket: String,
    key: String,
    hash: [u8; 32],
}
impl ReferencedLog {
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn uncompressed_sha256(&self) -> &[u8; 32] {
        &self.hash
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Previous {
    bucket: String,
    key: String,
    hash: [u8; 32],
    signature: String,
}
/// Authenticated digest only: referenced logs still need complete byte checks.
pub struct ValidatedDigest {
    scope: ProofScope,
    capture: CapturedObject,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    hash: [u8; 32],
    compressed_hash: [u8; 32],
    signature: String,
    previous: Option<Previous>,
    backfill: bool,
    logs: Vec<ReferencedLog>,
    compressed_bytes: usize,
    decoded_bytes: usize,
}
impl ValidatedDigest {
    pub fn capture(&self) -> &CapturedObject {
        &self.capture
    }
    pub fn interval(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        (self.start, self.end)
    }
    pub fn uncompressed_sha256(&self) -> &[u8; 32] {
        &self.hash
    }
    pub fn compressed_sha256(&self) -> &[u8; 32] {
        &self.compressed_hash
    }
    pub fn logs(&self) -> &[ReferencedLog] {
        &self.logs
    }
    pub fn is_backfill(&self) -> bool {
        self.backfill
    }
}

/// Verify one exact native gzip digest. RSA hashes the raw signing message once;
/// the native content hash is of exact uncompressed bytes, never reserialized JSON.
pub fn validate_digest(
    scope: &ProofScope,
    capture: &CapturedObject,
    compressed: &[u8],
    metadata: &DigestMetadata<'_>,
    keys: &[TrustedRegionalKey],
    ctx: &ExtensionContext,
) -> Result<ValidatedDigest, ProofError> {
    check(ctx)?;
    scope.validate()?;
    capture.validate()?;
    if keys.is_empty() || keys.len() > MAX_KEYS {
        return Err(ProofError::Limit);
    }
    if capture.bucket != scope.bucket || capture.owner != scope.owner {
        return Err(ProofError::Scope);
    }
    if metadata.signature_algorithm != "SHA256withRSA" {
        return Err(ProofError::Unsupported);
    }
    let signature = decode_hex(metadata.signature_hex, 256, 1024)?;
    let (decoded, compressed_hash) = decode_digest(compressed, ctx)?;
    let value =
        decode_json(&decoded, MAX_DIGEST_BYTES, 8, 16_384).map_err(|_| ProofError::Malformed)?;
    let start = native_time(string(&value, "digestStartTime", 40)?)?;
    let end_text = string(&value, "digestEndTime", 40)?;
    let end = native_time(end_text)?;
    if start >= end || end - start > chrono::Duration::days(1) {
        return Err(ProofError::Malformed);
    }
    let backfill = capture.key.ends_with("_backfill.json.gz");
    if backfill != metadata.backfill_generated_at.is_some()
        || capture.key != scope.digest_key(end, backfill)
        || string(&value, "awsAccountId", 12)? != scope.account
        || string(&value, "digestS3Bucket", 63)? != capture.bucket
        || string(&value, "digestS3Object", 1024)? != capture.key
    {
        return Err(ProofError::Scope);
    }
    if string(&value, "digestSignatureAlgorithm", 32)? != "SHA256withRSA" {
        return Err(ProofError::Unsupported);
    }
    let fingerprint = string(&value, "digestPublicKeyFingerprint", 32)?;
    if !hex_shape(fingerprint, 32) {
        return Err(ProofError::Malformed);
    }
    let signature_time = metadata.backfill_generated_at.unwrap_or(end);
    if !valid_time(signature_time) || signature_time < end {
        return Err(ProofError::Malformed);
    }
    let mut applicable = keys.iter().filter(|k| {
        k.region == scope.region
            && k.fingerprint == fingerprint
            && k.start <= signature_time
            && signature_time <= k.end
    });
    let key = applicable.next().ok_or(ProofError::Key)?;
    if applicable.next().is_some() {
        return Err(ProofError::Key);
    }
    let previous_fields = [
        "previousDigestS3Bucket",
        "previousDigestS3Object",
        "previousDigestHashValue",
        "previousDigestHashAlgorithm",
        "previousDigestSignature",
    ];
    let nulls = previous_fields
        .iter()
        .filter(|f| value.get(**f).is_some_and(Value::is_null))
        .count();
    let previous = if nulls == previous_fields.len() {
        None
    } else if nulls != 0 {
        return Err(ProofError::Malformed);
    } else {
        if string(&value, "previousDigestHashAlgorithm", 32)? != "SHA-256" {
            return Err(ProofError::Unsupported);
        }
        let bucket = string(&value, "previousDigestS3Bucket", 63)?;
        let key = string(&value, "previousDigestS3Object", 1024)?;
        let previous_signature = string(&value, "previousDigestSignature", 2048)?;
        if !bucket_name(bucket) || !object_key(key) {
            return Err(ProofError::Malformed);
        }
        decode_hex(previous_signature, 256, 1024)?;
        Some(Previous {
            bucket: bucket.into(),
            key: key.into(),
            hash: hash_field(&value, "previousDigestHashValue")?,
            signature: previous_signature.into(),
        })
    };
    let hash: [u8; 32] = Sha256::digest(&decoded).into();
    let message = format!(
        "{end_text}\n{}/{}\n{}\n{}",
        capture.bucket,
        capture.key,
        encode_hex(&hash),
        previous.as_ref().map_or("null", |p| p.signature.as_str())
    );
    check(ctx)?;
    signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &key.der)
        .verify(message.as_bytes(), &signature)
        .map_err(|_| ProofError::Signature)?;
    check(ctx)?;
    let rows = value
        .get("logFiles")
        .and_then(Value::as_array)
        .ok_or(ProofError::Malformed)?;
    if rows.len() > MAX_LOG_FILES {
        return Err(ProofError::Limit);
    }
    event_interval(&value, rows.is_empty())?;
    let mut logs = Vec::with_capacity(rows.len());
    for row in rows {
        check(ctx)?;
        let bucket = string(row, "s3Bucket", 63)?;
        let key = string(row, "s3Object", 1024)?;
        if bucket != scope.bucket || !scope.log_key(key) {
            return Err(ProofError::Scope);
        }
        if string(row, "hashAlgorithm", 32)? != "SHA-256" {
            return Err(ProofError::Unsupported);
        }
        event_interval(row, false)?;
        if logs
            .iter()
            .any(|p: &ReferencedLog| p.bucket == bucket && p.key == key)
        {
            return Err(ProofError::Malformed);
        }
        logs.push(ReferencedLog {
            bucket: bucket.into(),
            key: key.into(),
            hash: hash_field(row, "hashValue")?,
        });
    }
    check(ctx)?;
    Ok(ValidatedDigest {
        scope: scope.clone(),
        capture: capture.clone(),
        start,
        end,
        hash,
        compressed_hash,
        signature: metadata.signature_hex.into(),
        previous,
        backfill,
        logs,
        compressed_bytes: compressed.len(),
        decoded_bytes: decoded.len(),
    })
}

/// Borrowed exact-version bytes from a trusted provider. The validator cannot
/// infer that supplied claims or a provider's response are authenticated.
pub struct LogCapture<'a> {
    pub object: &'a CapturedObject,
    pub compressed: &'a [u8],
}
pub struct ValidatedLog {
    capture: CapturedObject,
    compressed_hash: [u8; 32],
    uncompressed_hash: [u8; 32],
}
impl ValidatedLog {
    pub fn capture(&self) -> &CapturedObject {
        &self.capture
    }
    pub fn compressed_sha256(&self) -> &[u8; 32] {
        &self.compressed_hash
    }
    pub fn uncompressed_sha256(&self) -> &[u8; 32] {
        &self.uncompressed_hash
    }
}
/// Complete referenced-byte evidence, not parsed records or collection coverage.
pub struct ValidatedDelivery {
    digest: ValidatedDigest,
    logs: Vec<ValidatedLog>,
    compressed_bytes: usize,
    decoded_bytes: usize,
}
impl ValidatedDelivery {
    pub fn digest(&self) -> &ValidatedDigest {
        &self.digest
    }
    pub fn logs(&self) -> &[ValidatedLog] {
        &self.logs
    }
    pub fn checkpoint(&self) -> DeliveryCheckpoint {
        DeliveryCheckpoint {
            schema_version: 1,
            scope: self.digest.scope.clone(),
            capture: self.digest.capture.clone(),
            start: self.digest.start,
            end: self.digest.end,
            hash: self.digest.hash,
            signature: self.digest.signature.clone(),
            backfill: self.digest.backfill,
        }
    }
}
/// All references must appear exactly once, including empty digests. Version and
/// owner pins are retained independently of the native log hash (which does not
/// contain S3 version IDs). Streaming hashing is independent of record parsing.
pub fn validate_delivery(
    digest: ValidatedDigest,
    captures: &[LogCapture<'_>],
    ctx: &ExtensionContext,
) -> Result<ValidatedDelivery, ProofError> {
    check(ctx)?;
    if captures.len() != digest.logs.len() || captures.len() > MAX_LOG_FILES {
        return Err(ProofError::Content);
    }
    let mut compressed_bytes = digest.compressed_bytes;
    for capture in captures {
        capture.object.validate()?;
        if capture.compressed.is_empty() || capture.compressed.len() > MAX_LOG_COMPRESSED_BYTES {
            return Err(ProofError::Limit);
        }
        compressed_bytes = compressed_bytes
            .checked_add(capture.compressed.len())
            .ok_or(ProofError::Limit)?;
        if compressed_bytes > MAX_DELIVERY_BYTES {
            return Err(ProofError::Limit);
        }
    }
    let mut decoded_bytes = digest.decoded_bytes;
    let mut logs = Vec::with_capacity(captures.len());
    for reference in &digest.logs {
        check(ctx)?;
        let mut matching = captures
            .iter()
            .filter(|c| c.object.bucket == reference.bucket && c.object.key == reference.key);
        let capture = matching.next().ok_or(ProofError::Content)?;
        if matching.next().is_some() || capture.object.owner != digest.scope.owner {
            return Err(ProofError::Scope);
        }
        let (hash, decoded) =
            hash_log(capture.compressed, MAX_DELIVERY_BYTES - decoded_bytes, ctx)?;
        decoded_bytes = decoded_bytes
            .checked_add(decoded)
            .ok_or(ProofError::Limit)?;
        if hash != reference.hash {
            return Err(ProofError::Content);
        }
        logs.push(ValidatedLog {
            capture: capture.object.clone(),
            compressed_hash: bounded_hash(capture.compressed, ctx)?,
            uncompressed_hash: hash,
        });
    }
    check(ctx)?;
    Ok(ValidatedDelivery {
        digest,
        logs,
        compressed_bytes,
        decoded_bytes,
    })
}

/// Restore only from an independently authorized retained checkpoint. Shape and
/// checksums alone do not authenticate a checkpoint or prevent backup rollback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeliveryCheckpoint {
    schema_version: u8,
    scope: ProofScope,
    capture: CapturedObject,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    hash: [u8; 32],
    signature: String,
    backfill: bool,
}
impl DeliveryCheckpoint {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProofError> {
        serde_json::to_vec(self).map_err(|_| ProofError::Malformed)
    }
    pub fn from_trusted_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        decode_json(bytes, 8192, 8, 512).map_err(|_| ProofError::Malformed)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: u8,
            scope: ProofScope,
            capture: CapturedObject,
            start: DateTime<Utc>,
            end: DateTime<Utc>,
            hash: [u8; 32],
            signature: String,
            backfill: bool,
        }
        let wire: Wire = serde_json::from_slice(bytes).map_err(|_| ProofError::Malformed)?;
        let checkpoint = Self {
            schema_version: wire.schema_version,
            scope: wire.scope,
            capture: wire.capture,
            start: wire.start,
            end: wire.end,
            hash: wire.hash,
            signature: wire.signature,
            backfill: wire.backfill,
        };
        checkpoint.scope.validate()?;
        checkpoint.capture.validate()?;
        if checkpoint.schema_version != 1
            || !valid_time(checkpoint.start)
            || !valid_time(checkpoint.end)
            || checkpoint.start >= checkpoint.end
            || checkpoint.end - checkpoint.start > chrono::Duration::days(1)
            || checkpoint.capture.bucket != checkpoint.scope.bucket
            || checkpoint.capture.owner != checkpoint.scope.owner
            || checkpoint.capture.key
                != checkpoint
                    .scope
                    .digest_key(checkpoint.end, checkpoint.backfill)
        {
            return Err(ProofError::Scope);
        }
        decode_hex(&checkpoint.signature, 256, 1024)?;
        Ok(checkpoint)
    }
    pub fn capture(&self) -> &CapturedObject {
        &self.capture
    }
    pub fn end(&self) -> DateTime<Utc> {
        self.end
    }
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ChainClassification {
    Bootstrap,
    Unanchored,
    TemporalGap,
    AnchoredContinuous,
    BackfillOnly,
}
/// No API/configuration coverage, verification age or complete source scope is
/// implied. Caller must retain original classification/history, not replace an
/// earlier gap with a later redelivery/bootstrap assertion.
pub struct ChainEvidence {
    classification: ChainClassification,
    interval: (DateTime<Utc>, DateTime<Utc>),
    checkpoint: Option<DeliveryCheckpoint>,
}
impl ChainEvidence {
    pub fn classification(&self) -> ChainClassification {
        self.classification
    }
    pub fn interval(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        self.interval
    }
    pub fn checkpoint(&self) -> Option<&DeliveryCheckpoint> {
        self.checkpoint.as_ref()
    }
}
/// Ordered retained evidence, exact links and bounded aggregate work. Backfill
/// proves its own referenced bytes only and never advances regular continuity.
pub fn validate_chain(
    anchor: Option<&DeliveryCheckpoint>,
    deliveries: &[&ValidatedDelivery],
    ctx: &ExtensionContext,
) -> Result<ChainEvidence, ProofError> {
    check(ctx)?;
    if deliveries.is_empty() || deliveries.len() > MAX_CHAIN_LENGTH {
        return Err(ProofError::Limit);
    }
    let first = &deliveries[0].digest;
    let mut compressed_bytes = 0usize;
    let mut decoded_bytes = 0usize;
    for delivery in deliveries {
        check(ctx)?;
        compressed_bytes = compressed_bytes
            .checked_add(delivery.compressed_bytes)
            .ok_or(ProofError::Limit)?;
        decoded_bytes = decoded_bytes
            .checked_add(delivery.decoded_bytes)
            .ok_or(ProofError::Limit)?;
        if compressed_bytes > MAX_DELIVERY_BYTES || decoded_bytes > MAX_DELIVERY_BYTES {
            return Err(ProofError::Limit);
        }
        if delivery.digest.scope != first.scope {
            return Err(ProofError::Scope);
        }
    }
    if deliveries.iter().any(|d| d.digest.backfill) {
        if deliveries.len() != 1 || !first.backfill {
            return Err(ProofError::Unsupported);
        }
        return Ok(ChainEvidence {
            classification: ChainClassification::BackfillOnly,
            interval: (first.start, first.end),
            checkpoint: None,
        });
    }
    let mut classification = if anchor.is_some() {
        ChainClassification::AnchoredContinuous
    } else if first.previous.is_none() {
        ChainClassification::Bootstrap
    } else {
        ChainClassification::Unanchored
    };
    let mut previous = anchor.cloned();
    for delivery in deliveries {
        check(ctx)?;
        let digest = &delivery.digest;
        if let Some(prior) = &previous {
            if prior.backfill || prior.scope != digest.scope {
                return Err(ProofError::Scope);
            }
            let link = digest.previous.as_ref().ok_or(ProofError::Link)?;
            if link.bucket != prior.capture.bucket
                || link.key != prior.capture.key
                || link.hash != prior.hash
                || link.signature != prior.signature
            {
                return Err(ProofError::Link);
            }
            if digest.start != prior.end {
                classification = ChainClassification::TemporalGap;
            }
            if digest.end <= prior.end {
                return Err(ProofError::Link);
            }
        }
        previous = Some(delivery.checkpoint());
    }
    check(ctx)?;
    let end = previous.as_ref().ok_or(ProofError::Link)?.end;
    Ok(ChainEvidence {
        classification,
        interval: (first.start, end),
        checkpoint: previous,
    })
}

fn check(ctx: &ExtensionContext) -> Result<(), ProofError> {
    if ctx.cancellation().is_cancelled() {
        return Err(ProofError::Cancelled);
    }
    if tokio::time::Instant::now() >= ctx.deadline() {
        return Err(ProofError::Timeout);
    }
    Ok(())
}
fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn token(value: &str, max: usize) -> bool {
    text(value, max)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn region_name(value: &str) -> bool {
    text(value, 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn bucket_name(value: &str) -> bool {
    (3..=63).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
}
fn object_key(value: &str) -> bool {
    text(value, 1024)
        && !value.starts_with('/')
        && value
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}
fn valid_time(value: DateTime<Utc>) -> bool {
    (1..=9999).contains(&value.year()) && value.timestamp_subsec_nanos() < 1_000_000_000
}
fn native_time(value: &str) -> Result<DateTime<Utc>, ProofError> {
    if !value.ends_with('Z') {
        return Err(ProofError::Malformed);
    }
    let time = DateTime::parse_from_rfc3339(value)
        .map_err(|_| ProofError::Malformed)?
        .with_timezone(&Utc);
    if !valid_time(time) {
        return Err(ProofError::Malformed);
    }
    Ok(time)
}
fn epoch(value: &Value) -> Result<DateTime<Utc>, ProofError> {
    // Parse the exact JSON decimal, including fractional API timestamps. No
    // floating point rounding may widen a key validity interval.
    let number = value.as_number().ok_or(ProofError::Malformed)?.to_string();
    if number.len() > 40 || number.starts_with('-') {
        return Err(ProofError::Malformed);
    }
    let (whole, fractional) = number.split_once('.').unwrap_or((&number, ""));
    if !whole.bytes().all(|b| b.is_ascii_digit())
        || fractional.len() > 9
        || !fractional.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ProofError::Unsupported);
    }
    let seconds = whole.parse::<i64>().map_err(|_| ProofError::Malformed)?;
    let nanos = if fractional.is_empty() {
        0
    } else {
        fractional
            .parse::<u32>()
            .map_err(|_| ProofError::Malformed)?
            * 10u32.pow(9 - fractional.len() as u32)
    };
    DateTime::from_timestamp(seconds, nanos)
        .filter(|v| valid_time(*v))
        .ok_or(ProofError::Malformed)
}
fn string<'a>(value: &'a Value, field: &str, max: usize) -> Result<&'a str, ProofError> {
    let text_value = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ProofError::Malformed)?;
    if !text(text_value, max) {
        return Err(ProofError::Malformed);
    }
    Ok(text_value)
}
fn event_interval(value: &Value, empty: bool) -> Result<(), ProofError> {
    if empty {
        if value.get("oldestEventTime").is_none_or(|v| !v.is_null())
            || value.get("newestEventTime").is_none_or(|v| !v.is_null())
        {
            return Err(ProofError::Malformed);
        }
    } else if native_time(string(value, "oldestEventTime", 40)?)?
        > native_time(string(value, "newestEventTime", 40)?)?
    {
        return Err(ProofError::Malformed);
    }
    Ok(())
}
fn hex_shape(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode_hex(value: &str, min: usize, max: usize) -> Result<Vec<u8>, ProofError> {
    if value.len() < min * 2
        || value.len() > max * 2
        || !value.len().is_multiple_of(2)
        || !hex_shape(value, value.len())
    {
        return Err(ProofError::Malformed);
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        bytes.push((nibble(pair[0]) << 4) | nibble(pair[1]));
    }
    Ok(bytes)
}
fn hash_field(value: &Value, field: &str) -> Result<[u8; 32], ProofError> {
    decode_hex(string(value, field, 64)?, 32, 32)?
        .try_into()
        .map_err(|_| ProofError::Malformed)
}
fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(value.len() * 2);
    for byte in value {
        text.push(char::from(HEX[(byte >> 4) as usize]));
        text.push(char::from(HEX[(byte & 15) as usize]));
    }
    text
}
fn bounded_hash(bytes: &[u8], ctx: &ExtensionContext) -> Result<[u8; 32], ProofError> {
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(65536) {
        check(ctx)?;
        hash.update(chunk);
    }
    check(ctx)?;
    Ok(hash.finalize().into())
}
fn decode_digest(
    compressed: &[u8],
    ctx: &ExtensionContext,
) -> Result<(Vec<u8>, [u8; 32]), ProofError> {
    if compressed.is_empty() || compressed.len() > MAX_DIGEST_BYTES {
        return Err(ProofError::Limit);
    }
    let hash = bounded_hash(compressed, ctx)?;
    let mut gzip = GzDecoder::new(compressed);
    let mut decoded = Vec::new();
    let mut chunk = [0; 65536];
    loop {
        check(ctx)?;
        let n = gzip.read(&mut chunk).map_err(|_| ProofError::Compression)?;
        if n == 0 {
            break;
        }
        if decoded.len() + n > MAX_DIGEST_BYTES {
            return Err(ProofError::Limit);
        }
        if decoded.capacity() < decoded.len() + n {
            let capacity = (decoded.capacity().max(65536) * 2)
                .min(MAX_DIGEST_BYTES)
                .max(decoded.len() + n);
            decoded
                .try_reserve_exact(capacity - decoded.len())
                .map_err(|_| ProofError::Limit)?;
        }
        decoded.extend_from_slice(&chunk[..n]);
    }
    if !gzip.into_inner().is_empty() {
        return Err(ProofError::Compression);
    }
    check(ctx)?;
    Ok((decoded, hash))
}
fn hash_log(
    compressed: &[u8],
    remaining: usize,
    ctx: &ExtensionContext,
) -> Result<([u8; 32], usize), ProofError> {
    let mut gzip = GzDecoder::new(compressed);
    let mut hash = Sha256::new();
    let mut decoded = 0usize;
    let mut chunk = [0; 65536];
    loop {
        check(ctx)?;
        let n = gzip.read(&mut chunk).map_err(|_| ProofError::Compression)?;
        if n == 0 {
            break;
        }
        decoded = decoded.checked_add(n).ok_or(ProofError::Limit)?;
        if decoded > MAX_LOG_DECODED_BYTES || decoded > remaining {
            return Err(ProofError::Limit);
        }
        hash.update(&chunk[..n]);
    }
    if !gzip.into_inner().is_empty() {
        return Err(ProofError::Compression);
    }
    check(ctx)?;
    Ok((hash.finalize().into(), decoded))
}

#[cfg(test)]
#[path = "proof_tests.rs"]
mod tests;
