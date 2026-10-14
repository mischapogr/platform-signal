//! Source-bound WINDOW metadata hydration for the Standard host.
//! These data/provenance helpers confer neither admission nor publication authority.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_control::{
    ControlError, MultiEventStateEnvelope, PriorStateProvenance, ProducerEnrollment,
    RevisionedState, StateReadResult,
};
use signal_rules::window::{Policy, State};
use signal_storage::StoredEvent;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("shared window control evidence refused: {0}")]
    Control(#[from] ControlError),
    #[error("shared window detector evidence refused: {0}")]
    Detector(#[from] signal_rules::window::Error),
}
/// Captured host configuration, not credentials or a live grant.
pub struct SharedWindowBinding {
    pub producer: ProducerEnrollment,
    pub source_binding: [u8; 32],
    pub rule_revision: [u8; 32],
    pub key: String,
}
/// Physical workers remain owned by the host. Recovery uses one original budget.
pub struct SharedWindowRecovery<'a> {
    pub binding: &'a SharedWindowBinding,
    pub control: &'a signal_control::ControlClient,
    pub objects: &'a signal_storage::object_io::ObjectIo,
    pub codec: &'a signal_storage::object_codec::ObjectCodec,
    pub limits: signal_control::CanonicalRecoveryLimits,
}
/// Source data and installed pin IDs, not a new grant or publication capability.
pub struct RecoveredWindow {
    pub state: State,
    pub prior: PriorStateProvenance,
    pub canonical: signal_control::RecoveredCanonicalInputs,
    pub replay_pins: Vec<Uuid>,
}
impl SharedWindowRecovery<'_> {
    /// Missing state refuses recovery. Initializing a new detector is a separate
    /// explicit host decision. Partial/uncertain pin work is never auto-released.
    pub async fn recover(
        &self,
        token: signal_control::LeaseToken,
        policy: &Policy,
        context: signal_control::ControlContext,
    ) -> Result<RecoveredWindow, Error> {
        context.check()?;
        self.binding.validate()?;
        policy.validate()?;
        self.limits.validate()?;
        token.validate()?;
        if token.scope != self.binding.producer.scope {
            return Err(ControlError::Fenced.into());
        }
        let catalog = self
            .control
            .read_catalog_snapshot(
                token.scope.clone(),
                signal_control::CatalogInput {
                    schema_version: 1,
                    id: Uuid::new_v4(),
                    pin_ms: 5000,
                },
                context.clone(),
            )
            .await?;
        let context = context.limited_to(catalog.snapshot()?.deadline());
        let read = self
            .control
            .read_state(
                token.clone(),
                signal_control::StateReadInput {
                    key: self.binding.key.clone(),
                    expected_head: catalog.head()?,
                },
                context.clone(),
            )
            .await?;
        if read.checkpoint != catalog.checkpoint()? {
            return Err(ControlError::Conflict.into());
        }
        let references = self.binding.decode(&read, policy)?.sequences;
        let canonical = signal_control::recover_canonical_inputs_at(
            &catalog,
            self.objects,
            self.codec,
            &references,
            self.limits,
            context.clone(),
        )
        .await?;
        let (state, prior) = self.binding.restore(&read, policy, canonical.rows()?)?;
        let replay_pins = signal_control::retain_window_canonical_inputs(
            self.control,
            token,
            &canonical,
            &self.binding.key,
            self.binding.rule_revision,
            prior.value_sha256,
            context.clone(),
        )
        .await?;
        context.check()?;
        catalog.snapshot()?.check()?;
        Ok(RecoveredWindow {
            state,
            prior,
            canonical,
            replay_pins,
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema_version: u16,
    source_store: Uuid,
    source_partition: Uuid,
    source_tenant: String,
    source_stream: Uuid,
    source_binding: [u8; 32],
    window: serde_json::Value,
    canonical_sha256: BTreeMap<Uuid, [u8; 32]>,
}
struct Decoded<'a> {
    value: &'a RevisionedState,
    scope_generation: Uuid,
    sequences: BTreeMap<Uuid, u64>,
    window: Vec<u8>,
    ids: Vec<Uuid>,
}
struct Budget {
    used: usize,
    limit: usize,
}
impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.used) {
            return Err(std::io::Error::other("shared window byte capacity"));
        }
        self.used += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl SharedWindowBinding {
    fn validate(&self) -> Result<(), Error> {
        self.producer.scope.validate()?;
        if self.producer.scope_generation.is_nil()
            || self.producer.startup.is_nil()
            || self.producer.wal_floor > i64::MAX as u64
            || self.source_binding == [0; 32]
            || self.key.is_empty()
            || self.key.len() > 256
            || self.key.chars().any(char::is_control)
        {
            return Err(ControlError::Invalid.into());
        }
        Ok(())
    }
    /// Supply complete canonical rows for all metadata references. Extra current
    /// rows are allowed here; only referenced identities enter the sequence map.
    pub fn encode(
        &self,
        state: &State,
        policy: &Policy,
        checkpoint: u64,
        rows: &[StoredEvent],
    ) -> Result<RevisionedState, Error> {
        self.validate()?;
        state.validate(policy)?;
        if rows.len() > 4096 || checkpoint == 0 || checkpoint > i64::MAX as u64 {
            return Err(ControlError::Invalid.into());
        }
        let window: serde_json::Value = serde_json::from_slice(&state.encode_metadata(65536)?)
            .map_err(|_| ControlError::Corrupt)?;
        let ids = State::metadata_event_ids(
            &serde_json::to_vec(&window).map_err(|_| ControlError::Corrupt)?,
            policy,
        )?;
        let required = ids.iter().copied().collect::<BTreeSet<_>>();
        let mut sequences = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut positions = BTreeSet::new();
        for row in rows {
            if row.sequence == 0
                || row.sequence > checkpoint
                || !seen.insert(row.event.id)
                || !positions.insert(row.sequence)
            {
                return Err(ControlError::Corrupt.into());
            }
            if required.contains(&row.event.id) {
                sequences.insert(row.event.id, row.sequence);
            }
        }
        if sequences.len() != required.len() {
            return Err(ControlError::Unavailable.into());
        }
        let mut budget = Budget {
            used: 0,
            limit: policy.max_state_bytes,
        };
        for row in rows.iter().filter(|row| required.contains(&row.event.id)) {
            serde_json::to_writer(&mut budget, &row.event).map_err(|_| ControlError::Full)?;
        }
        let events = rows
            .iter()
            .filter(|row| required.contains(&row.event.id))
            .map(|row| row.event.clone())
            .collect::<Vec<_>>();
        State::restore_metadata(
            &serde_json::to_vec(&window).map_err(|_| ControlError::Corrupt)?,
            policy,
            &events,
        )?;
        let hashes = serde_json::from_value(
            window
                .get("canonical_sha256")
                .cloned()
                .ok_or(ControlError::Corrupt)?,
        )
        .map_err(|_| ControlError::Corrupt)?;
        let metadata = serde_json::to_value(Metadata {
            schema_version: 1,
            source_store: self.producer.scope.store_id,
            source_partition: self.producer.scope.partition_id,
            source_tenant: self.producer.scope.tenant.clone(),
            source_stream: self.producer.scope.stream,
            source_binding: self.source_binding,
            window,
            canonical_sha256: hashes,
        })
        .map_err(|_| ControlError::Corrupt)?;
        let bytes = MultiEventStateEnvelope {
            schema_version: 1,
            scope_generation: self.producer.scope_generation,
            checkpoint,
            metadata,
            canonical_sequences: sequences,
        }
        .encode()?;
        let value = RevisionedState {
            key: self.key.clone(),
            revision: self.rule_revision,
            bytes,
        };
        value.validate()?;
        Ok(value)
    }
    /// Restore only a fenced read's complete protected state and original inputs.
    /// The host must independently verify the catalog/object capability and custody.
    fn decode<'a>(&self, read: &'a StateReadResult, policy: &Policy) -> Result<Decoded<'a>, Error> {
        self.validate()?;
        policy.validate()?;
        if read.schema_version != 1
            || read.partition_id != self.producer.scope.partition_id
            || read.checkpoint == 0
            || read.head.is_none()
        {
            return Err(ControlError::Corrupt.into());
        }
        let value = read.state.as_ref().ok_or(ControlError::Unavailable)?;
        value.validate()?;
        if value.key != self.key || value.revision != self.rule_revision {
            return Err(ControlError::Conflict.into());
        }
        let envelope: MultiEventStateEnvelope =
            serde_json::from_slice(&value.bytes).map_err(|_| ControlError::Corrupt)?;
        envelope.encode()?;
        if envelope.scope_generation != self.producer.scope_generation
            || envelope.checkpoint != read.checkpoint
        {
            return Err(ControlError::Fenced.into());
        }
        let metadata: Metadata =
            serde_json::from_value(envelope.metadata).map_err(|_| ControlError::Corrupt)?;
        if metadata.schema_version != 1
            || metadata.source_store != self.producer.scope.store_id
            || metadata.source_partition != self.producer.scope.partition_id
            || metadata.source_tenant != self.producer.scope.tenant
            || metadata.source_stream != self.producer.scope.stream
            || metadata.source_binding != self.source_binding
            || serde_json::to_value(&metadata.canonical_sha256)
                .map_err(|_| ControlError::Corrupt)?
                != metadata
                    .window
                    .get("canonical_sha256")
                    .cloned()
                    .ok_or(ControlError::Corrupt)?
        {
            return Err(ControlError::Fenced.into());
        }
        let window = serde_json::to_vec(&metadata.window).map_err(|_| ControlError::Corrupt)?;
        let ids = State::metadata_event_ids(&window, policy)?;
        if ids.iter().copied().collect::<BTreeSet<_>>()
            != envelope.canonical_sequences.keys().copied().collect()
        {
            return Err(ControlError::Corrupt.into());
        }
        Ok(Decoded {
            value,
            scope_generation: envelope.scope_generation,
            sequences: envelope.canonical_sequences,
            window,
            ids,
        })
    }
    /// Required original IDs for bounded catalog recovery; this list grants no read authority.
    pub fn required_event_ids(
        &self,
        read: &StateReadResult,
        policy: &Policy,
    ) -> Result<Vec<Uuid>, Error> {
        Ok(self.decode(read, policy)?.ids)
    }
    pub fn restore(
        &self,
        read: &StateReadResult,
        policy: &Policy,
        rows: &[StoredEvent],
    ) -> Result<(State, PriorStateProvenance), Error> {
        let decoded = self.decode(read, policy)?;
        if rows.len() != decoded.sequences.len() {
            return Err(ControlError::Unavailable.into());
        }
        let value = decoded.value;
        let window = decoded.window;
        let mut seen = BTreeSet::new();
        let mut positions = BTreeSet::new();
        let mut budget = Budget {
            used: 0,
            limit: policy.max_state_bytes,
        };
        // Charge complete canonical payloads before cloning them for hydration.
        for row in rows {
            if decoded.sequences.get(&row.event.id) != Some(&row.sequence)
                || !seen.insert(row.event.id)
                || !positions.insert(row.sequence)
            {
                return Err(ControlError::Corrupt.into());
            }
            serde_json::to_writer(&mut budget, &row.event).map_err(|_| ControlError::Full)?;
        }
        let events = rows.iter().map(|r| r.event.clone()).collect::<Vec<_>>();
        let state = State::restore_metadata(&window, policy, &events)?;
        let prior = PriorStateProvenance {
            schema_version: 1,
            key: value.key.clone(),
            checkpoint: read.checkpoint,
            revision: value.revision,
            value_sha256: Sha256::digest(&value.bytes).into(),
            scope_generation: decoded.scope_generation,
        };
        Ok((state, prior))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn fixture() -> Result<(SharedWindowBinding, Policy, State, Vec<StoredEvent>)> {
        let binding = SharedWindowBinding {
            producer: ProducerEnrollment {
                scope: signal_control::Scope {
                    schema_version: 1,
                    store_id: Uuid::from_u128(1),
                    generation: Uuid::from_u128(2),
                    tenant: "fixture".into(),
                    stream: Uuid::from_u128(3),
                    partition_id: Uuid::from_u128(4),
                },
                scope_generation: Uuid::from_u128(5),
                startup: Uuid::from_u128(6),
                wal_floor: 0,
            },
            source_binding: [1; 32],
            rule_revision: [2; 32],
            key: "window-fixture".into(),
        };
        let policy = Policy {
            schema_version: 1,
            partition: Uuid::from_u128(4),
            rule_id: "fixture-window".into(),
            revision: "fixture-v1".into(),
            title: "Fixture".into(),
            severity: signal_findings::DetectionSeverity::High,
            threshold: 3,
            window_ms: 60000,
            lateness_ms: 10000,
            ttl_ms: 70000,
            max_keys: 4,
            max_attempts_per_key: 8,
            max_attempts: 32,
            max_outputs: 32,
            max_state_bytes: 65536,
            max_history_assessments: 32,
            max_history_bytes: 262144,
            history_retention_ms: 60000,
        };
        let mut state = State::new(policy.clone())?;
        let mut rows = Vec::new();
        for (sequence, seconds) in [(1, 0), (2, 30), (3, 60)] {
            let at =
                chrono::DateTime::from_timestamp(1791972000 + seconds, 0).ok_or("fixture time")?;
            let input: signal_event::IngestEvent = serde_json::from_value(
                serde_json::json!({"timestamp":at,"source":{"type":"authentication","name":"fixture"},"message":"private body must stay in Parquet","attributes":{"authentication":{"identity_authority":"fixture","principal_id":"fixture","target_id":"fixture","outcome":"failure"},"producer":{"boot_id":"fixture","sequence":sequence}}}),
            )?;
            let mut event = input.normalize(at)?;
            event.id = Uuid::from_u128(sequence);
            state.admit(&event, true)?;
            rows.push(StoredEvent {
                sequence: sequence as u64,
                event,
            });
        }
        state.seal(rows[2].event.timestamp, true)?;
        Ok((binding, policy, state, rows))
    }
    #[test]
    fn shared_metadata_roundtrip_preserves_outcomes_sequences_and_provenance_without_raw_bodies()
    -> Result {
        let (binding, policy, state, rows) = fixture()?;
        let value = binding.encode(&state, &policy, 3, &rows)?;
        assert!(
            !String::from_utf8_lossy(&value.bytes).contains("private body must stay in Parquet")
        );
        let read = StateReadResult {
            schema_version: 1,
            partition_id: binding.producer.scope.partition_id,
            head: Some(Uuid::from_u128(7)),
            checkpoint: 3,
            state: Some(value.clone()),
        };
        assert_eq!(
            binding.required_event_ids(&read, &policy)?,
            rows.iter().map(|r| r.event.id).collect::<Vec<_>>()
        );
        let (restored, prior) = binding.restore(&read, &policy, &rows)?;
        assert_eq!(
            restored.encode_metadata(65536)?,
            state.encode_metadata(65536)?
        );
        assert_eq!(
            prior.value_sha256,
            <[u8; 32]>::from(Sha256::digest(&value.bytes))
        );
        assert_eq!(prior.checkpoint, 3);
        assert_eq!(prior.revision, binding.rule_revision);
        Ok(())
    }
    #[test]
    fn missing_changed_canonical_inputs_or_binding_policy_checkpoint_refuse() -> Result {
        let (mut binding, policy, state, rows) = fixture()?;
        let value = binding.encode(&state, &policy, 3, &rows)?;
        let mut read = StateReadResult {
            schema_version: 1,
            partition_id: binding.producer.scope.partition_id,
            head: Some(Uuid::from_u128(7)),
            checkpoint: 3,
            state: Some(value),
        };
        assert!(binding.restore(&read, &policy, &rows[..2]).is_err());
        let mut changed = rows.clone();
        changed[0].sequence = 99;
        assert!(binding.restore(&read, &policy, &changed).is_err());
        let mut changed = rows.clone();
        changed[0].event.message = Some("changed".into());
        assert!(binding.restore(&read, &policy, &changed).is_err());
        assert!(binding.encode(&state, &policy, 3, &changed).is_err());
        binding.source_binding = [9; 32];
        assert!(binding.restore(&read, &policy, &rows).is_err());
        binding.source_binding = [1; 32];
        let original_store = binding.producer.scope.store_id;
        binding.producer.scope.store_id = Uuid::from_u128(99);
        assert!(binding.restore(&read, &policy, &rows).is_err());
        binding.producer.scope.store_id = original_store;
        let original_tenant = binding.producer.scope.tenant.clone();
        binding.producer.scope.tenant = "foreign".into();
        assert!(binding.restore(&read, &policy, &rows).is_err());
        binding.producer.scope.tenant = original_tenant;
        let mut other = policy.clone();
        other.threshold = 2;
        assert!(binding.restore(&read, &other, &rows).is_err());
        read.checkpoint = 2;
        assert!(binding.restore(&read, &policy, &rows).is_err());
        read.checkpoint = 3;
        read.state = None;
        assert!(matches!(
            binding.restore(&read, &policy, &rows),
            Err(Error::Control(ControlError::Unavailable))
        ));
        Ok(())
    }
}
