//! Exact-version lifecycle metadata only. No provider deletion capability exists.
use crate::{ControlError, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalObjectRef {
    pub schema_version: u32,
    /// Administrator-enrolled physical namespace, shared by all partition aliases.
    pub backend_id: Uuid,
    pub key: String,
    pub version: String,
}
impl CanonicalObjectRef {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 1
            || self.backend_id.is_nil()
            || self.key.is_empty()
            || self.key.len() > 512
            || self.key.capacity() > 512
            || self.version.is_empty()
            || self.version.len() > 256
            || self.version.capacity() > 256
            || self.key.chars().any(char::is_control)
            || self.version.chars().any(char::is_control)
            || self.key.contains(['\\', '%', '?', '#'])
            || self.key.starts_with('/')
            || self
                .key
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
    /// Canonical length-delimited UTF8 tuple; no case or Unicode normalization of keys.
    pub fn identity_bytes(&self) -> Result<Vec<u8>, ControlError> {
        self.validate()?;
        let mut bytes = b"SIGNAL-CONTROL-OBJECT-V1".to_vec();
        bytes.extend_from_slice(self.backend_id.as_bytes());
        bytes.extend_from_slice(&(self.key.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.key.as_bytes());
        bytes.extend_from_slice(&(self.version.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.version.as_bytes());
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<[u8; 32], ControlError> {
        Ok(Sha256::digest(self.identity_bytes()?).into())
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionKind {
    Restore,
    Replay,
    Evidence,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectControlState {
    Retained,
    Released,
    Retired,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPinInput {
    pub schema_version: u32,
    pub id: Uuid,
    pub object: CanonicalObjectRef,
    pub kind: RetentionKind,
    /// Original opaque policy/provenance reference, never credentials or implicit ACK.
    pub reference: Vec<u8>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePinInput {
    pub schema_version: u32,
    pub id: Uuid,
    /// Explicit external retention decision; this mechanism does not invent policy.
    pub reason: Vec<u8>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetirementInput {
    pub schema_version: u32,
    pub id: Uuid,
    pub object: CanonicalObjectRef,
    pub reason: Vec<u8>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectControlResult {
    pub schema_version: u32,
    pub id: Uuid,
    pub reference_sha256: String,
    pub state: ObjectControlState,
    pub request_sha256: String,
}
fn header(version: u32, id: Uuid, bytes: &Vec<u8>) -> Result<(), ControlError> {
    if version != 1
        || id.is_nil()
        || bytes.is_empty()
        || bytes.len() > 4096
        || bytes.capacity() > 4096
    {
        return Err(ControlError::Invalid);
    }
    Ok(())
}
impl RetentionPinInput {
    pub(crate) fn wire(&self, scope: &Scope) -> Result<Vec<u8>, ControlError> {
        scope.validate()?;
        header(self.schema_version, self.id, &self.reference)?;
        self.object.validate()?;
        crate::publication::encode(
            &serde_json::json!({"schema_version":1,"operation":"pin","id":self.id,"object":self.object,"kind":self.kind,"reference":crate::publication::hex(&self.reference)}),
        )
    }
}
impl ReleasePinInput {
    pub(crate) fn wire(&self) -> Result<Vec<u8>, ControlError> {
        header(self.schema_version, self.id, &self.reason)?;
        crate::publication::encode(
            &serde_json::json!({"schema_version":1,"operation":"release","id":self.id,"reason":crate::publication::hex(&self.reason)}),
        )
    }
}
impl RetirementInput {
    pub(crate) fn wire(&self, scope: &Scope) -> Result<Vec<u8>, ControlError> {
        scope.validate()?;
        header(self.schema_version, self.id, &self.reason)?;
        self.object.validate()?;
        crate::publication::encode(
            &serde_json::json!({"schema_version":1,"operation":"retire","id":self.id,"object":self.object,"reason":crate::publication::hex(&self.reason)}),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn object() -> CanonicalObjectRef {
        CanonicalObjectRef {
            schema_version: 1,
            backend_id: Uuid::from_u128(1),
            key: "query/synthetic/object".into(),
            version: "exact-v1".into(),
        }
    }
    #[test]
    fn exact_tuple_preserves_version_and_backend_and_has_unambiguous_framing()
    -> Result<(), ControlError> {
        let one = object();
        let mut two = one.clone();
        two.version = "exact-v2".into();
        assert_ne!(one.digest()?, two.digest()?);
        two = one.clone();
        two.backend_id = Uuid::from_u128(2);
        assert_ne!(one.digest()?, two.digest()?);
        two = one.clone();
        two.key.push('x');
        two.version.remove(0);
        assert_ne!(one.identity_bytes()?, two.identity_bytes()?);
        assert_eq!(&one.identity_bytes()?[24..40], one.backend_id.as_bytes());
        Ok(())
    }
    #[test]
    fn latest_empty_and_ambiguous_paths_or_sparse_allocations_fail_closed() {
        for key in [
            "", "/object", "a//b", "a/../b", "a/./b", "a%2fb", "a\\b", "a?b", "a#b",
        ] {
            let mut reference = object();
            reference.key = key.into();
            assert!(reference.validate().is_err());
        }
        let mut reference = object();
        reference.version.clear();
        assert!(reference.validate().is_err());
        reference = object();
        reference.key.reserve_exact(513);
        assert!(reference.validate().is_err());
    }
    #[test]
    fn unknown_fields_and_unknown_lifecycle_states_are_rejected() {
        assert!(serde_json::from_str::<ObjectControlState>("\"deleted\"").is_err());
        assert!(serde_json::from_str::<ReleasePinInput>(r#"{"schema_version":1,"id":"00000000-0000-0000-0000-000000000001","reason":[1],"override":true}"#).is_err());
    }
}
