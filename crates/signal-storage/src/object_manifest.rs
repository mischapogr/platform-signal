//! Finite query-object references and versioned manifests. Validation certifies
//! shape/content binding only; trusted publication/control establishes commitment.
//! These objects never authorize protected-original custody or source ACK.
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const MANIFEST_SCHEMA_VERSION: u16 = 1;
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_MANIFEST_FILES: usize = 128;

#[derive(Clone, Copy, Debug)]
pub struct ManifestLimits {
    pub manifest_bytes: usize,
    pub files: usize,
    pub events: usize,
    pub object_bytes: u64,
    pub batch_object_bytes: u64,
    pub decoded_bytes: u64,
}
impl Default for ManifestLimits {
    fn default() -> Self {
        Self {
            manifest_bytes: 65536,
            files: 128,
            events: 1000,
            object_bytes: 64 * 1024 * 1024,
            batch_object_bytes: 64 * 1024 * 1024,
            decoded_bytes: 256 * 1024 * 1024,
        }
    }
}
impl ManifestLimits {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.manifest_bytes < 128
            || self.manifest_bytes > MAX_MANIFEST_BYTES
            || self.files == 0
            || self.files > MAX_MANIFEST_FILES
            || self.events == 0
            || self.events > 1_000_000
            || self.object_bytes == 0
            || self.object_bytes > 1024 * 1024 * 1024
            || self.batch_object_bytes < self.object_bytes
            || self.batch_object_bytes > 1024 * 1024 * 1024
            || self.decoded_bytes == 0
            || self.decoded_bytes > 4 * 1024 * 1024 * 1024
        {
            return Err(ManifestError::Config);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ManifestError {
    #[error("invalid bounded manifest configuration")]
    Config,
    #[error("invalid query manifest or reference")]
    Invalid,
    #[error("query manifest capacity exceeded")]
    Capacity,
    #[error("query object bytes differ from the pinned reference")]
    Content,
    #[error("query manifest belongs to another stream")]
    Stream,
}

/// Exact server-owned query copy. ETag is a conditional equality guard, not SHA.
/// A missing version requires a nonempty ETag and conditional readback; it does
/// not imply versioned S3 custody. Requests must never fall back to latest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryObjectRef {
    pub key: String,
    pub version: Option<String>,
    pub etag: Option<String>,
    pub bytes: u64,
    pub sha256: [u8; 32],
}
impl QueryObjectRef {
    pub(crate) fn validate(&self, max_bytes: u64) -> Result<(), ManifestError> {
        if !text(&self.key, 512)
            || self.key.contains(['\\', '%', '?', '#'])
            || self.key.starts_with('/')
            || self
                .key
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || self.bytes == 0
            || self.bytes > max_bytes
            || self.version.as_ref().is_some_and(|s| !text(s, 256))
            || self.etag.as_ref().is_some_and(|s| !text(s, 256))
            || (self.version.is_none() && self.etag.is_none())
        {
            return Err(ManifestError::Invalid);
        }
        Ok(())
    }
    pub fn verify_bytes(&self, bytes: &[u8], max_bytes: u64) -> Result<(), ManifestError> {
        self.validate(max_bytes)?;
        if bytes.len() as u64 != self.bytes || sha256(bytes) != self.sha256 {
            return Err(ManifestError::Content);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryFile {
    pub date: String,
    pub hour: u8,
    pub object: QueryObjectRef,
    pub rows: usize,
    /// Bound Arrow/JSON scan input separately from compressed object bytes.
    pub decoded_bytes: u64,
}
impl QueryFile {
    /// Validated UTC hour intersection with [from,to); no event-time assertion.
    /// The publication reader must still check actual Parquet contents/partitions.
    pub fn intersects(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
    ) -> Result<bool, ManifestError> {
        if from.zip(to).is_some_and(|(a, b)| a >= b) {
            return Err(ManifestError::Invalid);
        }
        let date = canonical_date(&self.date)?;
        let time = date
            .and_hms_opt(self.hour.into(), 0, 0)
            .ok_or(ManifestError::Invalid)?;
        let start = Utc.from_utc_datetime(&time);
        let end = start
            .checked_add_signed(Duration::hours(1))
            .ok_or(ManifestError::Invalid)?;
        Ok(from.is_none_or(|lower| end > lower) && to.is_none_or(|upper| start < upper))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousManifest {
    pub object: QueryObjectRef,
    pub first_sequence: u64,
    pub last_sequence: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryManifest {
    pub schema_version: u16,
    pub storage_schema_version: u16,
    pub stream_id: Uuid,
    pub normalizer_revision: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub events: usize,
    pub previous: Option<PreviousManifest>,
    pub files: Vec<QueryFile>,
}
impl QueryManifest {
    pub fn validate(&self, limits: ManifestLimits, stream: Uuid) -> Result<(), ManifestError> {
        limits.validate()?;
        if self.stream_id != stream || stream.is_nil() {
            return Err(ManifestError::Stream);
        }
        let span = self
            .last_sequence
            .checked_sub(self.first_sequence)
            .and_then(|n| n.checked_add(1))
            .ok_or(ManifestError::Invalid)?;
        if self.schema_version != MANIFEST_SCHEMA_VERSION
            || self.storage_schema_version != crate::codec::STORAGE_SCHEMA_VERSION
            || !text(&self.normalizer_revision, 128)
            || self.first_sequence == 0
            || self.events == 0
            || self.events > limits.events
            || self.events as u64 > span
            || self.files.is_empty()
            || self.files.len() > limits.files
            || self.files.len() > self.events
        {
            return Err(ManifestError::Invalid);
        }
        if let Some(previous) = &self.previous {
            previous.object.validate(limits.manifest_bytes as u64)?;
            if previous.first_sequence == 0
                || previous.last_sequence < previous.first_sequence
                || previous.last_sequence >= self.first_sequence
                || previous.object.key != manifest_key(stream, previous.first_sequence)
            {
                return Err(ManifestError::Invalid);
            }
        }
        let mut rows = 0usize;
        let mut compressed = 0u64;
        let mut decoded = 0u64;
        for (index, file) in self.files.iter().enumerate() {
            canonical_date(&file.date)?;
            file.object.validate(limits.object_bytes)?;
            if file.hour >= 24
                || file.rows == 0
                || file.decoded_bytes == 0
                || file.object.key != data_key(stream, &file.date, file.hour, file.object.sha256)
                || self.files[..index]
                    .iter()
                    .any(|old| old.object.key == file.object.key)
            {
                return Err(ManifestError::Invalid);
            }
            rows = rows.checked_add(file.rows).ok_or(ManifestError::Capacity)?;
            compressed = compressed
                .checked_add(file.object.bytes)
                .ok_or(ManifestError::Capacity)?;
            decoded = decoded
                .checked_add(file.decoded_bytes)
                .ok_or(ManifestError::Capacity)?;
            if rows > self.events
                || compressed > limits.batch_object_bytes
                || decoded > limits.decoded_bytes
            {
                return Err(ManifestError::Capacity);
            }
        }
        if rows != self.events {
            return Err(ManifestError::Invalid);
        }
        Ok(())
    }
    pub fn encode(&self, limits: ManifestLimits, stream: Uuid) -> Result<Vec<u8>, ManifestError> {
        self.validate(limits, stream)?;
        let bytes = serde_json::to_vec(self).map_err(|_| ManifestError::Invalid)?;
        if bytes.len() > limits.manifest_bytes {
            return Err(ManifestError::Capacity);
        }
        Ok(bytes)
    }
    /// Trusted control selects the reference/stream; this parses and binds bytes
    /// only. It does not authenticate the control authority or grant commitment.
    pub fn decode_at(
        bytes: &[u8],
        reference: &QueryObjectRef,
        limits: ManifestLimits,
        stream: Uuid,
    ) -> Result<Self, ManifestError> {
        limits.validate()?;
        if bytes.len() > limits.manifest_bytes {
            return Err(ManifestError::Capacity);
        }
        reference.verify_bytes(bytes, limits.manifest_bytes as u64)?;
        let manifest: Self = serde_json::from_slice(bytes).map_err(|_| ManifestError::Invalid)?;
        manifest.validate(limits, stream)?;
        if reference.key != manifest_key(stream, manifest.first_sequence) {
            return Err(ManifestError::Invalid);
        }
        Ok(manifest)
    }
}
fn text(value: &str, cap: usize) -> bool {
    !value.is_empty() && value.len() <= cap && !value.chars().any(char::is_control)
}
fn canonical_date(value: &str) -> Result<NaiveDate, ManifestError> {
    if value.len() != 10 {
        return Err(ManifestError::Invalid);
    }
    let date = NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|_| ManifestError::Invalid)?;
    if date.format("%Y-%m-%d").to_string() != value {
        return Err(ManifestError::Invalid);
    }
    Ok(date)
}
pub fn manifest_key(stream: Uuid, first_sequence: u64) -> String {
    format!("query/{stream}/commits/{first_sequence:020}.json")
}
pub fn data_key(stream: Uuid, date: &str, hour: u8, sha: [u8; 32]) -> String {
    let hex: String = sha.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("query/{stream}/data/date={date}/hour={hour:02}/{hex}.parquet")
}
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(digest(&SHA256, bytes).as_ref());
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> (QueryManifest, ManifestLimits) {
        let stream = Uuid::new_v4();
        let checksum = sha256(b"query-copy");
        (
            QueryManifest {
                schema_version: MANIFEST_SCHEMA_VERSION,
                storage_schema_version: crate::codec::STORAGE_SCHEMA_VERSION,
                stream_id: stream,
                normalizer_revision: "synthetic-normalizer-v1".into(),
                first_sequence: 7,
                last_sequence: 9,
                events: 2,
                previous: None,
                files: vec![QueryFile {
                    date: "2026-07-10".into(),
                    hour: 19,
                    object: QueryObjectRef {
                        key: data_key(stream, "2026-07-10", 19, checksum),
                        version: Some("synthetic-query-v1".into()),
                        etag: None,
                        bytes: 10,
                        sha256: checksum,
                    },
                    rows: 2,
                    decoded_bytes: 100,
                }],
            },
            ManifestLimits::default(),
        )
    }
    fn reference(manifest: &QueryManifest, bytes: &[u8]) -> QueryObjectRef {
        QueryObjectRef {
            key: manifest_key(manifest.stream_id, manifest.first_sequence),
            version: None,
            etag: Some("conditional-v1".into()),
            bytes: bytes.len() as u64,
            sha256: sha256(bytes),
        }
    }
    #[test]
    fn exact_reference_and_strict_versioned_manifest_survive_roundtrip() -> Result<(), ManifestError>
    {
        let (manifest, limits) = sample();
        let bytes = manifest.encode(limits, manifest.stream_id)?;
        let pinned = reference(&manifest, &bytes);
        assert_eq!(
            QueryManifest::decode_at(&bytes, &pinned, limits, manifest.stream_id)?,
            manifest
        );
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert_eq!(
            QueryManifest::decode_at(&changed, &pinned, limits, manifest.stream_id),
            Err(ManifestError::Content)
        );
        let mut wrong_key = pinned.clone();
        wrong_key.key = manifest_key(manifest.stream_id, 8);
        assert_eq!(
            QueryManifest::decode_at(&bytes, &wrong_key, limits, manifest.stream_id),
            Err(ManifestError::Invalid)
        );
        assert_eq!(
            QueryManifest::decode_at(&bytes, &pinned, limits, Uuid::new_v4()),
            Err(ManifestError::Stream)
        );
        for malformed in [
            format!(
                "{{\"unknown\":true,{}",
                &String::from_utf8_lossy(&bytes)[1..]
            ),
            format!(
                "{{\"schema_version\":1,{}",
                &String::from_utf8_lossy(&bytes)[1..]
            ),
        ] {
            let wire = malformed.as_bytes();
            assert_eq!(
                QueryManifest::decode_at(
                    wire,
                    &reference(&manifest, wire),
                    limits,
                    manifest.stream_id
                ),
                Err(ManifestError::Invalid)
            );
        }
        Ok(())
    }
    #[test]
    fn namespace_versions_partitions_and_predecessors_cannot_be_forged() {
        let (manifest, limits) = sample();
        let mut variants = Vec::new();
        let mut value = manifest.clone();
        value.files[0].object.key = "originals/protected.json.gz".into();
        variants.push(value);
        let mut value = manifest.clone();
        value.files[0].object.version = None;
        variants.push(value);
        let mut value = manifest.clone();
        value.files[0].date = "2026-7-10".into();
        variants.push(value);
        let mut value = manifest.clone();
        value.files[0].hour = 24;
        variants.push(value);
        let mut value = manifest.clone();
        value.files[0].object.etag = Some("bad\nheader".into());
        variants.push(value);
        let mut value = manifest.clone();
        value.files.push(value.files[0].clone());
        variants.push(value);
        let mut value = manifest.clone();
        value.storage_schema_version += 1;
        variants.push(value);
        let mut value = manifest.clone();
        value.last_sequence = 6;
        variants.push(value);
        for value in variants {
            assert!(value.validate(limits, manifest.stream_id).is_err());
        }
        let mut value = manifest.clone();
        value.previous = Some(PreviousManifest {
            object: QueryObjectRef {
                key: manifest_key(manifest.stream_id, 1),
                version: Some("previous-v1".into()),
                etag: None,
                bytes: 100,
                sha256: [1; 32],
            },
            first_sequence: 1,
            last_sequence: 6,
        });
        assert!(value.validate(limits, manifest.stream_id).is_ok());
        if let Some(previous) = value.previous.as_mut() {
            previous.last_sequence = 7;
        }
        assert!(value.validate(limits, manifest.stream_id).is_err());
    }
    #[test]
    fn row_byte_and_inventory_caps_reject_whole_manifest() {
        let (manifest, mut limits) = sample();
        limits.events = 1;
        assert!(manifest.validate(limits, manifest.stream_id).is_err());
        limits = ManifestLimits {
            decoded_bytes: 99,
            ..ManifestLimits::default()
        };
        assert_eq!(
            manifest.validate(limits, manifest.stream_id),
            Err(ManifestError::Capacity)
        );
        limits = ManifestLimits {
            manifest_bytes: 128,
            ..ManifestLimits::default()
        };
        assert_eq!(
            manifest.encode(limits, manifest.stream_id),
            Err(ManifestError::Capacity)
        );
        let mut value = manifest.clone();
        value.files[0].rows = 1;
        assert_eq!(
            value.validate(ManifestLimits::default(), value.stream_id),
            Err(ManifestError::Invalid)
        );
        let mut value = manifest.clone();
        value.events = usize::MAX;
        assert!(
            value
                .validate(ManifestLimits::default(), value.stream_id)
                .is_err()
        );
    }
    #[test]
    fn utc_partition_pruning_uses_exclusive_upper_bound_and_never_claims_empty_coverage()
    -> Result<(), ManifestError> {
        let (manifest, _) = sample();
        let file = &manifest.files[0];
        let at = |hour| {
            Utc.with_ymd_and_hms(2026, 7, 10, hour, 0, 0)
                .single()
                .ok_or(ManifestError::Invalid)
        };
        assert!(file.intersects(Some(at(19)?), Some(at(20)?))?);
        assert!(!file.intersects(Some(at(20)?), None)?);
        assert!(!file.intersects(None, Some(at(19)?))?);
        assert!(file.intersects(None, None)?);
        assert!(file.intersects(Some(at(19)?), Some(at(19)?)).is_err());
        Ok(())
    }
}
