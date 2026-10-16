//! Exact shared-state framing. These values are data, never a live lease grant.
use super::*;
use signal_control::{
    ControlError, MultiEventStateEnvelope, PriorStateProvenance, ProducerEnrollment,
    RevisionedState, Scope, StateReadResult,
};
use signal_storage::StoredEvent;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum SharedError {
    #[error(transparent)]
    Native(#[from] Error),
    #[error(transparent)]
    Control(#[from] ControlError),
}
/// Owner-selected state identity. A restored generation needs an explicit
/// validated migration; this helper never rewrites original scope or outputs.
pub struct SharedBinding {
    pub producer: ProducerEnrollment,
    pub key: String,
    pub rule_revision: [u8; 32],
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema_version: u16,
    scope: Scope,
    key: String,
    rule_revision: [u8; 32],
    sensor: serde_json::Value,
    canonical_sha256: BTreeMap<Uuid, [u8; 32]>,
}
impl SharedBinding {
    fn validate(&self, engine: &Engine, context: &RuleContext) -> Result<(), SharedError> {
        check(context)?;
        self.producer.scope.validate()?;
        signal_control::StateReadInput {
            key: self.key.clone(),
            expected_head: None,
        }
        .validate()?;
        if self.producer.scope_generation.is_nil()
            || self.producer.startup.is_nil()
            || self.producer.wal_floor > i64::MAX as u64
            || self.producer.wal_floor > engine.floor
            || self.producer.scope.stream != engine.epoch.source_stream
            || self.rule_revision == [0; 32]
        {
            return Err(ControlError::Fenced.into());
        }
        Ok(())
    }
    /// Preserve every original proof/history/outbox reference in one bounded
    /// control envelope. The caller separately supplies retained rows to publish.
    pub fn encode(
        &self,
        engine: &Engine,
        snapshot: &Snapshot,
        context: &RuleContext,
    ) -> Result<(RevisionedState, Detached), SharedError> {
        self.validate(engine, context)?;
        let detached = engine.detach(snapshot, context)?;
        let hashes = serde_json::from_value(
            detached
                .metadata
                .get("canonical_sha256")
                .cloned()
                .ok_or(ControlError::Corrupt)?,
        )
        .map_err(|_| ControlError::Corrupt)?;
        let metadata = Metadata {
            schema_version: 1,
            scope: self.producer.scope.clone(),
            key: self.key.clone(),
            rule_revision: self.rule_revision,
            sensor: detached.metadata.clone(),
            canonical_sha256: hashes,
        };
        let bytes = MultiEventStateEnvelope {
            schema_version: 1,
            scope_generation: self.producer.scope_generation,
            checkpoint: snapshot.record.checkpoint,
            metadata: serde_json::to_value(metadata).map_err(|_| ControlError::Corrupt)?,
            canonical_sequences: detached.canonical_sequences.clone(),
        }
        .encode()?;
        let value = RevisionedState {
            key: self.key.clone(),
            revision: self.rule_revision,
            bytes,
        };
        value.validate()?;
        check(context)?;
        Ok((value, detached))
    }
    fn decode(
        &self,
        engine: &Engine,
        read: &StateReadResult,
        context: &RuleContext,
    ) -> Result<(MultiEventStateEnvelope, Metadata), SharedError> {
        self.validate(engine, context)?;
        if read.schema_version != 1
            || read.partition_id != self.producer.scope.partition_id
            || read.head.is_some_and(|head| head.is_nil())
            || (read.head.is_none() != (read.checkpoint == 0))
        {
            return Err(ControlError::Fenced.into());
        }
        let value = read.state.as_ref().ok_or(ControlError::Unavailable)?;
        value.validate()?;
        if value.key != self.key || value.revision != self.rule_revision {
            return Err(ControlError::Conflict.into());
        }
        let envelope: MultiEventStateEnvelope =
            serde_json::from_slice(&value.bytes).map_err(|_| ControlError::Corrupt)?;
        envelope.encode()?;
        if envelope.checkpoint != read.checkpoint
            || envelope.scope_generation != self.producer.scope_generation
        {
            return Err(ControlError::Fenced.into());
        }
        let metadata: Metadata =
            serde_json::from_value(envelope.metadata.clone()).map_err(|_| ControlError::Corrupt)?;
        if metadata.schema_version != 1
            || metadata.scope != self.producer.scope
            || metadata.key != self.key
            || metadata.rule_revision != self.rule_revision
            || serde_json::to_value(&metadata.canonical_sha256)
                .map_err(|_| ControlError::Corrupt)?
                != metadata
                    .sensor
                    .get("canonical_sha256")
                    .cloned()
                    .ok_or(ControlError::Corrupt)?
        {
            return Err(ControlError::Fenced.into());
        }
        check(context)?;
        Ok((envelope, metadata))
    }
    /// References for bounded catalog/object recovery; they grant no read access.
    pub fn references(
        &self,
        engine: &Engine,
        read: &StateReadResult,
        context: &RuleContext,
    ) -> Result<BTreeMap<Uuid, u64>, SharedError> {
        Ok(self.decode(engine, read, context)?.0.canonical_sequences)
    }
    /// Restore exact fenced bytes and independently recovered originals. This
    /// does not confirm a candidate or renew independent observer authority.
    pub fn restore(
        &self,
        engine: &Engine,
        read: &StateReadResult,
        rows: &[StoredEvent],
        context: &RuleContext,
    ) -> Result<(Snapshot, PriorStateProvenance), SharedError> {
        let (envelope, metadata) = self.decode(engine, read, context)?;
        let snapshot = engine.hydrate(
            &metadata.sensor,
            &envelope.canonical_sequences,
            rows,
            context,
        )?;
        if snapshot.record.checkpoint != read.checkpoint {
            return Err(ControlError::Conflict.into());
        }
        let value = read.state.as_ref().ok_or(ControlError::Unavailable)?;
        let prior = PriorStateProvenance {
            schema_version: 1,
            key: self.key.clone(),
            checkpoint: read.checkpoint,
            revision: self.rule_revision,
            value_sha256: Sha256::digest(&value.bytes).into(),
            scope_generation: envelope.scope_generation,
        };
        check(context)?;
        Ok((snapshot, prior))
    }
}
