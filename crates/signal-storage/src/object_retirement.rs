//! Small's synced query-retirement horizon. No deletion or original custody.
use crate::{
    OperationContext, StorageError, check_context, object_head::validate_reference,
    object_manifest::PreviousManifest, object_retention::RetentionPolicy,
};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Host-reported checkpoint identity, not proof of exclusivity or custody.
/// The stopped host must retain its actual WAL owner throughout retirement.
#[derive(Clone, Copy, Debug)]
pub struct RetirementCheckpoint {
    pub stream_id: Uuid,
    pub checkpoint: u64,
}

pub(crate) const RECORD_BYTES: usize = 4096;

/// Current and interrupted candidate, authenticated by the controller before adoption.
pub(crate) type RetirementControls = (Option<RetirementRecord>, Option<RetirementRecord>);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetirementRecord {
    pub schema_version: u16,
    pub stream_id: Uuid,
    pub backend_id: Uuid,
    pub previous_anchor: Option<PreviousManifest>,
    pub anchor: PreviousManifest,
    pub wal_checkpoint: u64,
    pub assessed_at: DateTime<Utc>,
    pub query_before: DateTime<Utc>,
    pub policy: RetentionPolicy,
}
impl RetirementRecord {
    pub(crate) fn new(
        stream: Uuid,
        backend: Uuid,
        previous: Option<&PreviousManifest>,
        anchor: &PreviousManifest,
        checkpoint: u64,
        now: DateTime<Utc>,
        policy: &RetentionPolicy,
    ) -> Result<Self, StorageError> {
        // Bound all fields before copying caller-owned references.
        policy.validate()?;
        validate_reference(anchor, stream)?;
        if let Some(previous) = previous {
            validate_reference(previous, stream)?;
        }
        let cutoff = now
            .checked_sub_signed(TimeDelta::seconds(policy.query_seconds as i64))
            .ok_or(StorageError::Config("retirement clock range"))?;
        let record = Self {
            schema_version: 1,
            stream_id: stream,
            backend_id: backend,
            previous_anchor: previous.cloned(),
            anchor: anchor.clone(),
            wal_checkpoint: checkpoint,
            assessed_at: now,
            query_before: cutoff,
            policy: policy.clone(),
        };
        record.validate(stream, backend)?;
        Ok(record)
    }
    pub(crate) fn validate(&self, stream: Uuid, backend: Uuid) -> Result<(), StorageError> {
        if self.schema_version != 1
            || stream.is_nil()
            || backend.is_nil()
            || self.stream_id != stream
            || self.backend_id != backend
        {
            return Err(StorageError::StreamMismatch);
        }
        self.policy.validate()?;
        validate_reference(&self.anchor, stream)?;
        if let Some(previous) = &self.previous_anchor {
            validate_reference(previous, stream)?;
            if previous.last_sequence >= self.anchor.first_sequence {
                return Err(StorageError::Corrupt("retirement anchor transition"));
            }
        }
        if self.anchor.last_sequence > self.wal_checkpoint
            || self
                .assessed_at
                .checked_sub_signed(TimeDelta::seconds(self.policy.query_seconds as i64))
                != Some(self.query_before)
        {
            return Err(StorageError::Corrupt("retirement horizon"));
        }
        Ok(())
    }
    pub(crate) fn encode(&self, context: &OperationContext) -> Result<Vec<u8>, StorageError> {
        check_context(Some(context))?;
        self.validate(self.stream_id, self.backend_id)?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| StorageError::Corrupt("retirement record"))?;
        if bytes.len() > RECORD_BYTES {
            return Err(StorageError::Full);
        }
        check_context(Some(context))?;
        Ok(bytes)
    }
    pub(crate) fn decode(
        bytes: &[u8],
        stream: Uuid,
        backend: Uuid,
        context: &OperationContext,
    ) -> Result<Self, StorageError> {
        check_context(Some(context))?;
        if bytes.len() > RECORD_BYTES {
            return Err(StorageError::Full);
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|_| StorageError::Corrupt("retirement record"))?;
        record.validate(stream, backend)?;
        check_context(Some(context))?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests;
