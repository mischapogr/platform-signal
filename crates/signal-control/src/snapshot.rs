//! Finite committed-manifest pins. Object I/O and result publication must check expiry.
use crate::{ControlError, ITEMS, MANIFEST_BYTES, REPLY_BYTES, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Duration};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotInput {
    pub schema_version: u32,
    pub id: Uuid,
    /// Exact committed IDs, in caller order; never uncommitted object references.
    pub manifest_ids: Vec<Uuid>,
    pub pin_ms: u32,
}
impl SnapshotInput {
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 1
            || self.id.is_nil()
            || self.manifest_ids.is_empty()
            || self.manifest_ids.len() > ITEMS
            || self.manifest_ids.capacity() > ITEMS
            || !(1..=5000).contains(&self.pin_ms)
            || self.manifest_ids.iter().any(Uuid::is_nil)
            || self.manifest_ids.iter().collect::<BTreeSet<_>>().len() != self.manifest_ids.len()
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedManifest {
    pub schema_version: u32,
    pub id: Uuid,
    /// Original committed bytes, preserved without reserialization.
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}
/// A runtime capability, deliberately not serializable: deserialization cannot renew it.
/// Check immediately before object access and again before returning a query result.
#[derive(Debug)]
pub struct SnapshotPin {
    id: Uuid,
    scope: Scope,
    deadline: tokio::time::Instant,
    manifests: Vec<PinnedManifest>,
}
impl SnapshotPin {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
    pub fn check(&self) -> Result<(), ControlError> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(ControlError::SnapshotExpired);
        }
        Ok(())
    }
    /// Attach this pin's original lifetime to already authenticated query files.
    /// This binds lifetime only: it grants no file/content or tenant authority.
    pub fn bind_query_selection(
        &self,
        mut selection: signal_storage::FileSelection,
    ) -> Result<signal_storage::FileSelection, ControlError> {
        self.check()?;
        selection.restrict_deadline(self.deadline);
        selection
            .check_lifetime()
            .map_err(|_| ControlError::SnapshotExpired)?;
        Ok(selection)
    }
    pub fn manifests(&self) -> Result<&[PinnedManifest], ControlError> {
        self.check()?;
        Ok(&self.manifests)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotReply {
    schema_version: u32,
    id: Uuid,
    scope: Scope,
    remaining_ms: u32,
    manifests: Vec<ManifestReply>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestReply {
    id: Uuid,
    manifest: String,
    sha256: String,
}
fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>, ControlError> {
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() / 2 > maximum {
        return Err(ControlError::Corrupt);
    }
    fn digit(value: u8) -> Result<u8, ControlError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(ControlError::Corrupt),
        }
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(digit(pair[0])? * 16 + digit(pair[1])?))
        .collect()
}
impl SnapshotReply {
    pub(crate) fn catalog_ids(&self) -> Result<Vec<Uuid>, ControlError> {
        if self.manifests.len() > ITEMS {
            return Err(ControlError::Corrupt);
        }
        crate::catalog::validate_ids(self.manifests.iter().map(|item| item.id).collect())
    }
    pub(crate) fn pin(
        self,
        scope: &Scope,
        input: &SnapshotInput,
        started: tokio::time::Instant,
    ) -> Result<SnapshotPin, ControlError> {
        if self.schema_version != 1
            || self.id != input.id
            || &self.scope != scope
            || self.remaining_ms == 0
            || self.remaining_ms > input.pin_ms
            || self.manifests.len() != input.manifest_ids.len()
        {
            return Err(ControlError::Corrupt);
        }
        let deadline = started + Duration::from_millis(u64::from(self.remaining_ms));
        let mut objects = 0_usize;
        let mut bytes = 256_usize;
        let mut manifests = Vec::with_capacity(self.manifests.len());
        for (item, expected) in self.manifests.into_iter().zip(&input.manifest_ids) {
            bytes = bytes
                .checked_add(item.manifest.len() + 512)
                .ok_or(ControlError::Corrupt)?;
            if item.id != *expected || bytes > REPLY_BYTES {
                return Err(ControlError::Corrupt);
            }
            let raw = unhex(&item.manifest, MANIFEST_BYTES)?;
            let hash: [u8; 32] = unhex(&item.sha256, 32)?
                .try_into()
                .map_err(|_| ControlError::Corrupt)?;
            if <[u8; 32]>::from(Sha256::digest(&raw)) != hash {
                return Err(ControlError::Corrupt);
            }
            let manifest: signal_storage::object_manifest::QueryManifest =
                serde_json::from_slice(&raw).map_err(|_| ControlError::Corrupt)?;
            manifest
                .validate(
                    signal_storage::object_manifest::ManifestLimits {
                        manifest_bytes: MANIFEST_BYTES,
                        events: 4096,
                        ..Default::default()
                    },
                    scope.stream,
                )
                .map_err(|_| ControlError::Corrupt)?;
            objects += manifest.files.len() + usize::from(manifest.previous.is_some());
            if objects > ITEMS {
                return Err(ControlError::Full);
            }
            manifests.push(PinnedManifest {
                schema_version: 1,
                id: item.id,
                bytes: raw,
                sha256: hash,
            });
        }
        let pin = SnapshotPin {
            id: self.id,
            scope: self.scope,
            deadline,
            manifests,
        };
        pin.check()?;
        Ok(pin)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_snapshot_requests_reject_empty_duplicate_nil_and_spare_capacity() {
        let mut input = SnapshotInput {
            schema_version: 1,
            id: Uuid::from_u128(1),
            manifest_ids: vec![Uuid::from_u128(2)],
            pin_ms: 5000,
        };
        assert!(input.validate().is_ok());
        input.manifest_ids.push(Uuid::from_u128(2));
        assert!(input.validate().is_err());
        input.manifest_ids = Vec::with_capacity(ITEMS + 1);
        input.manifest_ids.push(Uuid::from_u128(2));
        assert!(input.validate().is_err());
        input.manifest_ids = vec![Uuid::nil()];
        assert!(input.validate().is_err());
        input.manifest_ids = vec![];
        assert!(input.validate().is_err());
        input.manifest_ids = vec![Uuid::from_u128(2)];
        input.pin_ms = 5001;
        assert!(input.validate().is_err());
        input.pin_ms = 0;
        assert!(input.validate().is_err());
    }
    #[test]
    fn corrupt_hex_and_unknown_fields_fail_closed() {
        for raw in ["", "0", "gg", "FF", "0000"] {
            assert!(unhex(raw, 1).is_err());
        }
        assert!(serde_json::from_str::<SnapshotInput>(r#"{"schema_version":1,"id":"00000000-0000-0000-0000-000000000001","manifest_ids":[],"pin_ms":1,"extra":true}"#).is_err());
    }
    #[test]
    fn supported_access_cannot_outlive_fixed_monotonic_pin() {
        let mut pin = SnapshotPin {
            id: Uuid::from_u128(1),
            scope: Scope {
                schema_version: 1,
                store_id: Uuid::from_u128(1),
                generation: Uuid::from_u128(2),
                tenant: "synthetic".into(),
                stream: Uuid::from_u128(3),
                partition_id: Uuid::from_u128(4),
            },
            deadline: tokio::time::Instant::now() + Duration::from_millis(20),
            manifests: vec![],
        };
        assert!(pin.manifests().is_ok());
        pin.deadline = tokio::time::Instant::now();
        assert!(matches!(
            pin.manifests(),
            Err(ControlError::SnapshotExpired)
        ));
    }
}
