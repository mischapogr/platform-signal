//! Wire metadata and fresh confirmation, never a deserializable release permit.
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
pub const WIRE_BYTES: usize = 64 * 1024;
pub const CONFIRM_PATH: &str = "/v1/custody/confirm";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub schema_version: u32,
    pub store_id: Uuid,
    pub generation: Uuid,
    pub tenant: String,
    pub stream: Uuid,
    pub partition_id: Uuid,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectReference {
    pub schema_version: u32,
    pub backend_id: Uuid,
    pub key: String,
    pub version: String,
}
/// Field order matches the already committed control description v1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Description {
    pub schema_version: u32,
    pub id: Uuid,
    pub scope: Scope,
    pub object: ObjectReference,
    pub bytes: u64,
    pub sha256: [u8; 32],
    pub retain_until: DateTime<Utc>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid bounded object custody wire contract")]
pub struct InvalidCustody;
fn text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}
impl Description {
    pub fn validate(&self) -> Result<(), InvalidCustody> {
        if self.schema_version != 1
            || self.id.is_nil()
            || self.scope.schema_version != 1
            || self.scope.store_id.is_nil()
            || self.scope.generation.is_nil()
            || self.scope.stream.is_nil()
            || self.scope.partition_id.is_nil()
            || !text(&self.scope.tenant, 256)
            || self.object.schema_version != 1
            || self.object.backend_id.is_nil()
            || !text(&self.object.key, 512)
            || !text(&self.object.version, 256)
            || matches!(self.object.version.as_str(), "null" | "*")
            || self.object.key.contains(['\\', '%', '?', '#'])
            || self.object.key.starts_with('/')
            || self
                .object
                .key
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
            || self.bytes == 0
            || self.bytes > 64 * 1024 * 1024
            || self.sha256 == [0; 32]
            || !(1..=9999).contains(&self.retain_until.year())
            || self.retain_until.timestamp_subsec_nanos() >= 1_000_000_000
        {
            return Err(InvalidCustody);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32], InvalidCustody> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| InvalidCustody)?;
        if bytes.len() > WIRE_BYTES {
            return Err(InvalidCustody);
        }
        Ok(Sha256::digest(bytes).into())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmRequest {
    pub schema_version: u32,
    pub request_nonce: Uuid,
    pub description: Description,
}
impl ConfirmRequest {
    pub fn validate(&self) -> Result<(), InvalidCustody> {
        if self.schema_version != 1 || self.request_nonce.is_nil() {
            return Err(InvalidCustody);
        }
        self.description.validate()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmation {
    pub schema_version: u32,
    pub request_nonce: Uuid,
    pub description: Description,
    pub description_sha256: [u8; 32],
    pub confirmed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub valid_for_ms: u32,
    pub server_elapsed_ms: u32,
}
impl Confirmation {
    /// Integrity/request binding only. SDK acquires fresh authority over TLS
    /// within its original operation context; saved metadata is never a permit.
    pub fn validate_for(&self, request: &ConfirmRequest) -> Result<(), InvalidCustody> {
        request.validate()?;
        if self.schema_version != 1
            || self.request_nonce != request.request_nonce
            || self.description != request.description
            || self.description_sha256 != request.description.digest()?
            || !(1..=9999).contains(&self.confirmed_at.year())
            || self.confirmed_at.timestamp_subsec_nanos() >= 1_000_000_000
            || self.confirmed_at >= self.description.retain_until
            || self.valid_until <= self.confirmed_at
            || self.valid_until > self.description.retain_until
            || !(1..=9999).contains(&self.valid_until.year())
            || self.valid_until.timestamp_subsec_nanos() >= 1_000_000_000
            || self.valid_for_ms == 0
            || self.valid_for_ms > 5000
            || self.server_elapsed_ms > 5000 - self.valid_for_ms
            || (self.valid_until - self.confirmed_at).num_milliseconds()
                != i64::from(self.valid_for_ms)
        {
            return Err(InvalidCustody);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> ConfirmRequest {
        ConfirmRequest {
            schema_version: 1,
            request_nonce: Uuid::new_v4(),
            description: Description {
                schema_version: 1,
                id: Uuid::from_u128(9),
                scope: Scope {
                    schema_version: 1,
                    store_id: Uuid::from_u128(1),
                    generation: Uuid::from_u128(2),
                    tenant: "synthetic".into(),
                    stream: Uuid::from_u128(3),
                    partition_id: Uuid::from_u128(4),
                },
                object: ObjectReference {
                    schema_version: 1,
                    backend_id: Uuid::from_u128(5),
                    key: "original/body".into(),
                    version: "v1".into(),
                },
                bytes: 4,
                sha256: [7; 32],
                retain_until: Utc::now() + chrono::Duration::hours(1),
            },
        }
    }
    #[test]
    fn confirmation_requires_original_description_digest_nonce_and_finite_validity()
    -> Result<(), InvalidCustody> {
        let request = request();
        let now = Utc::now();
        let confirmation = Confirmation {
            schema_version: 1,
            request_nonce: request.request_nonce,
            description: request.description.clone(),
            description_sha256: request.description.digest()?,
            confirmed_at: now,
            valid_until: now + chrono::Duration::seconds(2),
            valid_for_ms: 2000,
            server_elapsed_ms: 0,
        };
        confirmation.validate_for(&request)?;
        let mut bad = confirmation.clone();
        bad.valid_for_ms = 2001;
        assert!(bad.validate_for(&request).is_err());
        let mut bad = confirmation.clone();
        bad.request_nonce = Uuid::new_v4();
        assert!(bad.validate_for(&request).is_err());
        let mut bad = confirmation.clone();
        bad.description.object.version = "v2".into();
        assert!(bad.validate_for(&request).is_err());
        let mut bad = confirmation.clone();
        bad.description_sha256 = [0; 32];
        assert!(bad.validate_for(&request).is_err());
        let mut bad = confirmation.clone();
        bad.valid_until = bad.confirmed_at;
        assert!(bad.validate_for(&request).is_err());
        let mut bad = confirmation;
        bad.valid_until = bad.description.retain_until + chrono::Duration::seconds(1);
        assert!(bad.validate_for(&request).is_err());
        Ok(())
    }
    #[test]
    fn ambiguous_or_unknown_wire_fields_and_unpinned_objects_reject()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request();
        let mut value = serde_json::to_value(&request)?;
        value["description"]["object"]["authority"] = "producer-selected".into();
        assert!(serde_json::from_value::<ConfirmRequest>(value).is_err());
        let mut d = request.description;
        d.object.version = "null".into();
        assert!(d.validate().is_err());
        d.object.version = "v1".into();
        d.object.key = "original/../body".into();
        assert!(d.validate().is_err());
        assert!(
            serde_json::from_str::<ConfirmRequest>("{\"schema_version\":1,\"schema_version\":1}")
                .is_err()
        );
        Ok(())
    }
}
