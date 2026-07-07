use super::{ReceiptBinding, ReceiptError, check};
use crate::{ExtensionContext, cloudtrail};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MAX_DISCOVERY_BYTES: usize = 256 * 1024;
pub const MAX_DISCOVERY_REFERENCES: usize = 16;

/// Static diagnostics never include the notification, object key or credentials.
/// A rejection retains source responsibility; it is never an empty completion.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("notification exceeds bounded discovery budget")]
    Limit,
    #[error("invalid direct S3 notification")]
    Malformed,
    #[error("notification kind or version is unsupported")]
    Unsupported,
    #[error("multi-reference delivery requires independent message custody")]
    MultipleReferences,
    #[error("notification object is outside current trusted source scope")]
    Scope,
    #[error("discovery requires a non-null retrievable version")]
    VersionRequired,
    #[error(transparent)]
    Operation(#[from] ReceiptError),
}

/// One fully validated reference, not an access grant or a continuity checkpoint.
/// Its digest binds exact discovery bytes but is not a signature. In-memory only.
pub struct ObjectDiscovery {
    bucket: String,
    key: String,
    version_id: String,
    etag: Option<String>,
    size: Option<u64>,
    sha256: [u8; 32],
    binding: ReceiptBinding,
}
impl ObjectDiscovery {
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn version_id(&self) -> &str {
        &self.version_id
    }
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }
    /// Diagnostic only. Capture must independently enforce its actual byte cap.
    pub fn declared_size(&self) -> Option<u64> {
        self.size
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub fn binding(&self) -> &ReceiptBinding {
        &self.binding
    }
}
fn text(v: &Value, cap: usize) -> Result<&str, DiscoveryError> {
    v.as_str()
        .filter(|s| !s.is_empty() && s.len() <= cap)
        .ok_or(DiscoveryError::Malformed)
}
fn form_key(raw: &str) -> Result<String, DiscoveryError> {
    // At most three encoded bytes per decoded byte. Decode exactly once; '%' in
    // the result stays literal, not a second decoding opportunity.
    if raw.is_empty() || raw.len() > 3072 {
        return Err(DiscoveryError::Limit);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(raw.len().min(1024))
        .map_err(|_| DiscoveryError::Limit)?;
    let mut i = 0usize;
    let input = raw.as_bytes();
    while i < input.len() {
        if out.len() == 1024 {
            return Err(DiscoveryError::Limit);
        }
        let b = match input[i] {
            b'+' => b' ',
            b'%' => {
                let pair = input.get(i + 1..i + 3).ok_or(DiscoveryError::Malformed)?;
                let h = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                };
                i += 2;
                h(pair[0]).ok_or(DiscoveryError::Malformed)? * 16
                    + h(pair[1]).ok_or(DiscoveryError::Malformed)?
            }
            b => b,
        };
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| DiscoveryError::Malformed)
}
fn supported_version(s: &str) -> bool {
    let Some((major, minor)) = s.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|c| c.is_ascii_digit())
        && minor.bytes().all(|c| c.is_ascii_digit())
        && major.parse::<u32>().ok() == Some(2)
        && minor.parse::<u32>().ok().is_some_and(|n| n >= 1)
}

/// Validate all references before exposing the single supported object. The
/// 16-reference bound limits parser work, not successful multi-object capacity.
/// Caller authenticates and refreshes full binding separately for fetch/replay/
/// ACK. Native ownerIdentity, recipient fields, URLs and hashes grant no access.
pub fn discover_object(
    body: &[u8],
    binding: &ReceiptBinding,
    ctx: &ExtensionContext,
) -> Result<ObjectDiscovery, DiscoveryError> {
    check(ctx)?;
    if body.len() > MAX_DISCOVERY_BYTES {
        return Err(DiscoveryError::Limit);
    }
    let value = cloudtrail::decode_json(body, MAX_DISCOVERY_BYTES, 16, 16_384)
        .map_err(|_| DiscoveryError::Malformed)?;
    check(ctx)?;
    let root = value.as_object().ok_or(DiscoveryError::Malformed)?;
    let records = root
        .get("Records")
        .and_then(Value::as_array)
        .ok_or(DiscoveryError::Unsupported)?;
    if records.is_empty() {
        return Err(DiscoveryError::Unsupported);
    }
    if records.len() > MAX_DISCOVERY_REFERENCES {
        return Err(DiscoveryError::Limit);
    }
    let mut discovered = None;
    for record in records {
        check(ctx)?;
        if !record.is_object() {
            return Err(DiscoveryError::Malformed);
        }
        if !supported_version(text(&record["eventVersion"], 32)?)
            || record["eventSource"] != "aws:s3"
            || !matches!(
                record["eventName"].as_str(),
                Some(
                    "ObjectCreated:Put"
                        | "ObjectCreated:Post"
                        | "ObjectCreated:Copy"
                        | "ObjectCreated:CompleteMultipartUpload"
                )
            )
        {
            return Err(DiscoveryError::Unsupported);
        }
        let bucket = text(&record["s3"]["bucket"]["name"], 63)?;
        let key = form_key(text(&record["s3"]["object"]["key"], 3072)?)?;
        let version = record["s3"]["object"]["versionId"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 1024 && *s != "null")
            .ok_or(DiscoveryError::VersionRequired)?;
        let prefix = binding.0["key_prefix"]
            .as_str()
            .ok_or(DiscoveryError::Scope)?;
        if binding.0["bucket"] != bucket || !key.starts_with(prefix) {
            return Err(DiscoveryError::Scope);
        }
        let object = &record["s3"]["object"];
        let etag = match object.get("eTag") {
            Some(v) if !v.is_null() => Some(text(v, 1024)?.to_owned()),
            _ => None,
        };
        let size = match object.get("size") {
            Some(v) => Some(v.as_u64().ok_or(DiscoveryError::Malformed)?),
            None => None,
        };
        if discovered.is_none() {
            discovered = Some(ObjectDiscovery {
                bucket: bucket.to_owned(),
                key,
                version_id: version.to_owned(),
                etag,
                size,
                sha256: Sha256::digest(body).into(),
                binding: binding.clone(),
            });
        }
    }
    check(ctx)?;
    if records.len() != 1 {
        return Err(DiscoveryError::MultipleReferences);
    }
    discovered.ok_or(DiscoveryError::Malformed)
}
