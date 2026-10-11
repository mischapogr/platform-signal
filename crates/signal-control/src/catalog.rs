//! Dynamic complete-catalog pins. Discovery is database-owned, never configured IDs.
use crate::{ControlError, ITEMS, Scope, SnapshotInput, SnapshotPin};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

pub fn catalog_schema_identity() -> ([u8; 32], [u8; 32]) {
    (
        crate::schema_identity().0,
        Sha256::digest(include_bytes!(
            "../../../schemas/shared-control/005-catalog.sql"
        ))
        .into(),
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogInput {
    pub schema_version: u32,
    pub id: Uuid,
    pub pin_ms: u32,
}
impl CatalogInput {
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 1 || self.id.is_nil() || !(1..=5000).contains(&self.pin_ms) {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}

/// Nonserializable original database capability; metadata access cannot renew it.
pub struct CatalogPin {
    snapshot: SnapshotPin,
    backend: Uuid,
    head: Option<Uuid>,
    checkpoint: u64,
}
impl CatalogPin {
    pub fn snapshot(&self) -> Result<&SnapshotPin, ControlError> {
        self.snapshot.check()?;
        Ok(&self.snapshot)
    }
    pub fn backend(&self) -> Result<Uuid, ControlError> {
        self.snapshot.check()?;
        Ok(self.backend)
    }
    pub fn head(&self) -> Result<Option<Uuid>, ControlError> {
        self.snapshot.check()?;
        Ok(self.head)
    }
    pub fn checkpoint(&self) -> Result<u64, ControlError> {
        self.snapshot.check()?;
        Ok(self.checkpoint)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatalogReply {
    schema_version: u32,
    backend_id: Uuid,
    head: Option<Uuid>,
    checkpoint: u64,
    snapshot: crate::snapshot::SnapshotReply,
}
impl CatalogReply {
    pub(crate) fn pin(
        self,
        scope: &Scope,
        input: &CatalogInput,
        started: tokio::time::Instant,
    ) -> Result<CatalogPin, ControlError> {
        input.validate()?;
        if self.schema_version != 1
            || self.backend_id.is_nil()
            || self.head.is_some_and(|head| head.is_nil())
            || self.checkpoint > i64::MAX as u64
        {
            return Err(ControlError::Corrupt);
        }
        let ids = self.snapshot.catalog_ids()?;
        let snapshot = self.snapshot.pin(
            scope,
            &SnapshotInput {
                schema_version: 1,
                id: input.id,
                manifest_ids: ids,
                pin_ms: input.pin_ms,
            },
            started,
        )?;
        let mut previous: Option<(
            &crate::PinnedManifest,
            signal_storage::object_manifest::QueryManifest,
        )> = None;
        let mut last_sequence = 0_u64;
        for item in snapshot.manifests()? {
            let manifest: signal_storage::object_manifest::QueryManifest =
                serde_json::from_slice(&item.bytes).map_err(|_| ControlError::Corrupt)?;
            if Some(manifest.first_sequence) != last_sequence.checked_add(1)
                || manifest.last_sequence > i64::MAX as u64
            {
                return Err(ControlError::Corrupt);
            }
            match (&previous, &manifest.previous) {
                (None, None) => {}
                (Some((prior, decoded)), Some(reference))
                    if reference.first_sequence == decoded.first_sequence
                        && reference.last_sequence == decoded.last_sequence
                        && reference.object.sha256 == prior.sha256
                        && reference.object.bytes == prior.bytes.len() as u64 => {}
                _ => return Err(ControlError::Corrupt),
            }
            last_sequence = manifest.last_sequence;
            previous = Some((item, manifest));
        }
        if previous.map(|(item, _)| item.id) != self.head || last_sequence != self.checkpoint {
            return Err(ControlError::Corrupt);
        }
        snapshot.check()?;
        Ok(CatalogPin {
            snapshot,
            backend: self.backend_id,
            head: self.head,
            checkpoint: self.checkpoint,
        })
    }
}

pub(crate) fn validate_ids(ids: Vec<Uuid>) -> Result<Vec<Uuid>, ControlError> {
    if ids.len() > ITEMS
        || ids.iter().any(Uuid::is_nil)
        || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
    {
        return Err(ControlError::Corrupt);
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_request_rejects_invalid_contract_and_identity() {
        let mut input = CatalogInput {
            schema_version: 1,
            id: Uuid::from_u128(1),
            pin_ms: 5000,
        };
        assert!(input.validate().is_ok());
        for duration in [0, 5001] {
            input.pin_ms = duration;
            assert!(input.validate().is_err());
        }
        input.pin_ms = 5000;
        input.id = Uuid::nil();
        assert!(input.validate().is_err());
        input.id = Uuid::from_u128(1);
        input.schema_version = 2;
        assert!(input.validate().is_err());
        assert!(serde_json::from_str::<CatalogInput>(r#"{"schema_version":1,"id":"00000000-0000-0000-0000-000000000001","pin_ms":5000,"manifest_ids":[]}"#).is_err());
    }
    #[test]
    fn discovered_ids_cannot_hide_duplicate_nil_or_over_capacity() {
        assert!(validate_ids(vec![]).is_ok());
        assert!(validate_ids(vec![Uuid::from_u128(1)]).is_ok());
        assert!(validate_ids(vec![Uuid::nil()]).is_err());
        assert!(validate_ids(vec![Uuid::from_u128(1); 2]).is_err());
        assert!(validate_ids((1..=129).map(Uuid::from_u128).collect()).is_err());
    }
}
