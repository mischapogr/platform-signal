//! Original bounded pre-upload multi-event plans. Captured evidence is not authority.
use crate::shared::PublicationDraft;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_control::{
    ControlError, MultiEventFindingClaims, MultiEventPublicationInput, MultiEventStateEnvelope,
    PriorStateProvenance, ProducerEnrollment, Scope,
};
use signal_findings::ScopedFinding;
use signal_storage::StoredEvent;
use std::io::Write;
use uuid::Uuid;
const RETAINED_BYTES: usize = 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Producer {
    scope: Scope,
    scope_generation: Uuid,
    startup: Uuid,
    wal_floor: u64,
}
impl Producer {
    fn enrollment(&self) -> ProducerEnrollment {
        ProducerEnrollment {
            scope: self.scope.clone(),
            scope_generation: self.scope_generation,
            startup: self.startup,
            wal_floor: self.wal_floor,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    sequence: u64,
    event: signal_event::SignalEvent,
}
struct Budget {
    used: usize,
    hash: Sha256,
}
impl Budget {
    fn new() -> Self {
        let mut hash = Sha256::new();
        hash.update(b"PLATFORM::SIGNAL/multi-event-retained/v1\0");
        Self { used: 0, hash }
    }
}
impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > RETAINED_BYTES.saturating_sub(self.used) {
            return Err(std::io::Error::other("retained input capacity"));
        }
        self.used += bytes.len();
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiEventPublicationDraft {
    schema_version: u16,
    draft: PublicationDraft,
    producer: Producer,
    claims: MultiEventFindingClaims,
    state_key: String,
    retained: Vec<Row>,
    retained_sha256: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiEventRecoveryInputs {
    schema_version: u16,
    producer: Producer,
    retained: Vec<Row>,
    retained_sha256: [u8; 32],
}
impl MultiEventRecoveryInputs {
    pub(crate) fn verify(
        &self,
        request: &MultiEventPublicationInput,
        current: &[StoredEvent],
        scope: &Scope,
    ) -> Result<(), ControlError> {
        if self.schema_version != 1
            || &self.producer.scope != scope
            || self.retained.len() > 4096
            || self.retained.capacity() > 4096
        {
            return Err(ControlError::Corrupt);
        }
        let mut budget = Budget::new();
        for row in &self.retained {
            budget
                .write_all(&row.sequence.to_be_bytes())
                .map_err(|_| ControlError::Full)?;
            serde_json::to_writer(&mut budget, &row.event).map_err(|_| ControlError::Full)?;
        }
        if <[u8; 32]>::from(budget.hash.finalize()) != self.retained_sha256 {
            return Err(ControlError::Corrupt);
        }
        let retained = self
            .retained
            .iter()
            .map(|r| StoredEvent {
                sequence: r.sequence,
                event: r.event.clone(),
            })
            .collect::<Vec<_>>();
        request.verify(&self.producer.enrollment(), current, &retained)
    }
}
impl MultiEventPublicationDraft {
    /// The host protects each detector's retained canonical rows independently.
    /// The union preserves original bodies; serialization cannot renew authority.
    pub fn from_state_groups(
        draft: PublicationDraft,
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        primary: &str,
        groups: Vec<signal_control::StateFindingGroup>,
    ) -> Result<Self, ControlError> {
        if groups.is_empty() || groups.len() > 128 || groups.capacity() > 128 {
            return Err(ControlError::Full);
        }
        let mut retained: std::collections::BTreeMap<Uuid, StoredEvent> =
            std::collections::BTreeMap::new();
        let mut memory_budget = Budget::new();
        for group in &groups {
            if group.retained.len() > 4096 || group.retained.capacity() > 4096 {
                return Err(ControlError::Full);
            }
            for row in &group.retained {
                if let Some(old) = retained.get(&row.event.id) {
                    if old.sequence != row.sequence || old.event != row.event {
                        return Err(ControlError::Conflict);
                    }
                } else {
                    if retained.len() >= 4096 {
                        return Err(ControlError::Full);
                    }
                    memory_budget
                        .write_all(&row.sequence.to_be_bytes())
                        .map_err(|_| ControlError::Full)?;
                    serde_json::to_writer(&mut memory_budget, &row.event)
                        .map_err(|_| ControlError::Full)?;
                    retained.insert(row.event.id, row.clone());
                }
            }
        }
        let retained = retained.into_values().collect::<Vec<_>>();
        let budget = Self::retained_budget(&retained, primary)?;
        let claims = MultiEventFindingClaims::from_state_groups(producer, current, groups)?;
        if !claims.state_keys().iter().any(|key| key == primary) {
            return Err(ControlError::Conflict);
        }
        Self::from_claims(draft, producer, current, &retained, primary, claims, budget)
    }
    pub(crate) fn recovery_inputs(&self) -> MultiEventRecoveryInputs {
        MultiEventRecoveryInputs {
            schema_version: 1,
            producer: self.producer.clone(),
            retained: self.retained.clone(),
            retained_sha256: self.retained_sha256,
        }
    }
    /// Host must verify newly admitted inputs and protected prior canonical custody.
    pub fn from_host(
        draft: PublicationDraft,
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        retained: &[StoredEvent],
        prior: Option<PriorStateProvenance>,
        state_key: &str,
        derived: Vec<(u64, ScopedFinding)>,
    ) -> Result<Self, ControlError> {
        let budget = Self::retained_budget(retained, state_key)?;
        let claims =
            MultiEventFindingClaims::from_host(producer, current, retained, prior, derived)?;
        Self::from_claims(
            draft, producer, current, retained, state_key, claims, budget,
        )
    }
    /// New admission remains a host duty; delayed anchors need exact protected prior state.
    pub fn from_retained_anchor_host(
        draft: PublicationDraft,
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        retained: &[StoredEvent],
        prior: Option<PriorStateProvenance>,
        state_key: &str,
        derived: Vec<(u64, ScopedFinding)>,
    ) -> Result<Self, ControlError> {
        let budget = Self::retained_budget(retained, state_key)?;
        let claims = MultiEventFindingClaims::from_retained_anchor_host(
            producer, current, retained, prior, derived,
        )?;
        Self::from_claims(
            draft, producer, current, retained, state_key, claims, budget,
        )
    }
    fn retained_budget(retained: &[StoredEvent], state_key: &str) -> Result<Budget, ControlError> {
        if retained.len() > 4096
            || state_key.is_empty()
            || state_key.len() > 256
            || state_key.chars().any(char::is_control)
        {
            return Err(ControlError::Invalid);
        }
        let mut budget = Budget::new();
        for row in retained {
            budget
                .write_all(&row.sequence.to_be_bytes())
                .map_err(|_| ControlError::Full)?;
            serde_json::to_writer(&mut budget, &row.event).map_err(|_| ControlError::Full)?;
        }
        Ok(budget)
    }
    fn from_claims(
        draft: PublicationDraft,
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        retained: &[StoredEvent],
        state_key: &str,
        claims: MultiEventFindingClaims,
        budget: Budget,
    ) -> Result<Self, ControlError> {
        let result = Self {
            schema_version: 2,
            draft,
            producer: Producer {
                scope: producer.scope.clone(),
                scope_generation: producer.scope_generation,
                startup: producer.startup,
                wal_floor: producer.wal_floor,
            },
            claims,
            state_key: state_key.into(),
            retained_sha256: budget.hash.finalize().into(),
            retained: retained
                .iter()
                .map(|r| Row {
                    sequence: r.sequence,
                    event: r.event.clone(),
                })
                .collect(),
        };
        result.validate(current, &producer.scope)?;
        Ok(result)
    }
    pub(crate) fn render(&self) -> Result<PublicationDraft, ControlError> {
        let mut draft = self.draft.clone();
        for finding in self.claims.findings() {
            if let Some(existing) = draft.findings.iter().find(|f| f.id == finding.id) {
                if existing != finding {
                    return Err(ControlError::Conflict);
                }
            } else {
                if draft.findings.len() >= 128 {
                    return Err(ControlError::Full);
                }
                draft.findings.push(finding.clone());
            }
        }
        Ok(draft)
    }
    pub(crate) fn validate(
        &self,
        current: &[StoredEvent],
        scope: &Scope,
    ) -> Result<(), ControlError> {
        if self.schema_version != 2
            || &self.producer.scope != scope
            || self.retained.len() > 4096
            || self.retained.capacity() > 4096
            || self.state_key.is_empty()
            || self.state_key.len() > 256
            || self.state_key.chars().any(char::is_control)
        {
            return Err(ControlError::Invalid);
        }
        let mut budget = Budget::new();
        for row in &self.retained {
            budget
                .write_all(&row.sequence.to_be_bytes())
                .map_err(|_| ControlError::Full)?;
            serde_json::to_writer(&mut budget, &row.event).map_err(|_| ControlError::Full)?;
        }
        if <[u8; 32]>::from(budget.hash.finalize()) != self.retained_sha256 {
            return Err(ControlError::Corrupt);
        }
        let retained = self
            .retained
            .iter()
            .map(|r| StoredEvent {
                sequence: r.sequence,
                event: r.event.clone(),
            })
            .collect::<Vec<_>>();
        self.claims
            .verify_rows(&self.producer.enrollment(), current, &retained)?;
        let draft = self.render()?;
        draft.validate(current)?;
        for prior in self.claims.priors() {
            if (!self.claims.state_keys().is_empty()
                && !self.claims.state_keys().contains(&prior.key))
                || (self.claims.state_keys().is_empty() && prior.key != self.state_key)
                || prior.revision != draft.rule_revision
                || current.first().map(|r| r.sequence) != prior.checkpoint.checked_add(1)
            {
                return Err(ControlError::Conflict);
            }
        }
        let keys = if self.claims.state_keys().is_empty() {
            vec![self.state_key.as_str()]
        } else {
            if !self.claims.state_keys().contains(&self.state_key)
                || draft.states.len() != self.claims.state_keys().len()
            {
                return Err(ControlError::Conflict);
            }
            self.claims
                .state_keys()
                .iter()
                .map(String::as_str)
                .collect()
        };
        for key in keys {
            let state = draft
                .states
                .iter()
                .find(|s| s.key == key)
                .ok_or(ControlError::Invalid)?;
            let envelope: MultiEventStateEnvelope =
                serde_json::from_slice(&state.bytes).map_err(|_| ControlError::Corrupt)?;
            envelope.encode()?;
            if envelope.scope_generation != self.producer.scope_generation
                || current.last().map(|r| r.sequence) != Some(envelope.checkpoint)
            {
                return Err(ControlError::Fenced);
            }
        }
        Ok(())
    }
    pub(crate) fn attach(
        &self,
        request: signal_control::PublicationInput,
    ) -> Result<MultiEventPublicationInput, ControlError> {
        let result = self.claims.clone().bind(request, &self.state_key)?;
        result.validate(&self.producer.scope)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_control::RevisionedState;
    use signal_findings::{DerivedFinding, DetectionSeverity, Finding};
    use signal_storage::object_manifest::{QueryFile, QueryManifest, QueryObjectRef, data_key};
    use std::collections::BTreeMap;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn fixture() -> Result<(
        ProducerEnrollment,
        Vec<StoredEvent>,
        PublicationDraft,
        ScopedFinding,
    )> {
        let producer = ProducerEnrollment {
            scope: Scope {
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
        };
        let rows=(1..=3).map(|sequence|{let event=serde_json::from_value(serde_json::json!({"schema_version":1,"id":Uuid::from_u128(sequence),"timestamp":"2026-10-15T00:00:00Z","observed_at":"2026-10-15T00:00:00Z","source":{"type":"fixture"},"severity":"info","message":"fixture","attributes":{},"tags":[]}))?;Ok(StoredEvent{sequence:sequence as u64,event})}).collect::<Result<Vec<_>>>()?;
        let mut finding = Finding::for_event(
            "fixture-window",
            &rows[2].event,
            DetectionSeverity::High,
            "Fixture",
        )?;
        finding.event_ids = rows.iter().map(|r| r.event.id).collect();
        let scoped = DerivedFinding::from_events(
            finding,
            &rows.iter().map(|r| &r.event).collect::<Vec<_>>(),
            true,
        )?
        .into_scoped(producer.scope_generation)?;
        let draft = PublicationDraft {
            schema_version: 1,
            id: Uuid::from_u128(7),
            previous: None,
            rule_revision: [1; 32],
            normalizer_revision: "fixture-v1".into(),
            states: vec![RevisionedState {
                key: "window-fixture".into(),
                revision: [1; 32],
                bytes: MultiEventStateEnvelope {
                    schema_version: 1,
                    scope_generation: producer.scope_generation,
                    checkpoint: 3,
                    metadata: serde_json::json!({"canonical_sha256":{}}),
                    canonical_sequences: BTreeMap::new(),
                }
                .encode()?,
            }],
            findings: vec![],
            work: vec![],
            receipts: vec![],
        };
        Ok((producer, rows, draft, scoped))
    }
    #[test]
    fn multiple_state_draft_preserves_independent_priors_and_original_retained_body_hash() -> Result
    {
        let (producer, rows, mut base, window) = fixture()?;
        let mut sensor_state = base.states[0].clone();
        sensor_state.key = "sensor-fixture".into();
        base.states.push(sensor_state);
        let mut sensor = Finding::for_event(
            "fixture-sensor",
            &rows[2].event,
            DetectionSeverity::High,
            "Sensor fixture",
        )?;
        sensor.event_ids = rows[1..].iter().map(|r| r.event.id).collect();
        let sensor = DerivedFinding::from_events(
            sensor,
            &rows[1..].iter().map(|r| &r.event).collect::<Vec<_>>(),
            true,
        )?
        .into_scoped(producer.scope_generation)?;
        let prior = |key: &str| PriorStateProvenance {
            schema_version: 1,
            key: key.into(),
            checkpoint: 2,
            revision: [1; 32],
            value_sha256: [2; 32],
            scope_generation: producer.scope_generation,
        };
        let draft = MultiEventPublicationDraft::from_state_groups(
            base,
            &producer,
            &rows[2..],
            "window-fixture",
            vec![
                signal_control::StateFindingGroup {
                    state_key: "window-fixture".into(),
                    prior: Some(prior("window-fixture")),
                    retained: rows[..2].to_vec(),
                    derived: vec![(3, window)],
                },
                signal_control::StateFindingGroup {
                    state_key: "sensor-fixture".into(),
                    prior: Some(prior("sensor-fixture")),
                    retained: rows[1..2].to_vec(),
                    derived: vec![(3, sensor)],
                },
            ],
        )?;
        assert_eq!(draft.retained.len(), 2);
        assert_eq!(draft.render()?.states.len(), 2);
        assert_eq!(draft.render()?.findings.len(), 2);
        let encoded = serde_json::to_vec(&draft)?;
        let restored: MultiEventPublicationDraft = serde_json::from_slice(&encoded)?;
        restored.validate(&rows[2..], &producer.scope)?;
        let mut wire = serde_json::to_value(&draft)?;
        wire["retained"][0]["event"]["message"] =
            serde_json::json!("changed body with identical scope");
        let changed: MultiEventPublicationDraft = serde_json::from_value(wire)?;
        assert!(matches!(
            changed.validate(&rows[2..], &producer.scope),
            Err(ControlError::Corrupt)
        ));
        let mut wire = serde_json::to_value(&draft)?;
        wire["claims"]["priors"]["sensor-fixture"]["revision"] = serde_json::json!(vec![9; 32]);
        let changed: MultiEventPublicationDraft = serde_json::from_value(wire)?;
        assert!(changed.validate(&rows[2..], &producer.scope).is_err());
        Ok(())
    }
    #[test]
    fn multi_draft_roundtrip_preserves_original_finding_and_attaches_uploaded_span() -> Result {
        let (producer, rows, base, finding) = fixture()?;
        let draft = MultiEventPublicationDraft::from_host(
            base,
            &producer,
            &rows,
            &[],
            None,
            "window-fixture",
            vec![(3, finding)],
        )?;
        let encoded = serde_json::to_vec(&draft)?;
        let restored: MultiEventPublicationDraft = serde_json::from_slice(&encoded)?;
        restored.validate(&rows, &producer.scope)?;
        assert!(restored.render()? == draft.render()?);
        let rendered = draft.render()?;
        let manifest = QueryManifest {
            schema_version: 1,
            storage_schema_version: 1,
            stream_id: producer.scope.stream,
            normalizer_revision: rendered.normalizer_revision.clone(),
            first_sequence: 1,
            last_sequence: 3,
            events: 3,
            previous: None,
            files: vec![QueryFile {
                date: "2026-10-15".into(),
                hour: 0,
                object: QueryObjectRef {
                    key: data_key(producer.scope.stream, "2026-10-15", 0, [1; 32]),
                    version: Some("fixture-v1".into()),
                    etag: None,
                    bytes: 1024,
                    sha256: [1; 32],
                },
                rows: 3,
                decoded_bytes: 4096,
            }],
        };
        let request = signal_control::PublicationInput {
            schema_version: 1,
            id: rendered.id,
            previous: rendered.previous,
            first_sequence: 1,
            last_sequence: 3,
            manifest: serde_json::to_vec(&manifest)?,
            rule_revision: rendered.rule_revision,
            normalizer_revision: rendered.normalizer_revision,
            states: rendered.states,
            findings: rendered.findings,
            work: rendered.work,
            receipts: rendered.receipts,
        };
        let input = restored.attach(request.clone())?;
        assert_eq!(input.publication().findings, request.findings);
        input.validate(&producer.scope)?;
        let mut other = producer.scope.clone();
        other.tenant = "foreign".into();
        assert!(restored.validate(&rows, &other).is_err());
        Ok(())
    }
    #[test]
    fn captured_retained_bytes_and_current_rows_are_rechecked_before_upload() -> Result {
        let (mut producer, rows, mut base, finding) = fixture()?;
        producer.wal_floor = 1;
        base.previous = Some(Uuid::from_u128(8));
        let prior = PriorStateProvenance {
            schema_version: 1,
            key: "window-fixture".into(),
            checkpoint: 1,
            revision: [1; 32],
            value_sha256: [2; 32],
            scope_generation: producer.scope_generation,
        };
        let draft = MultiEventPublicationDraft::from_host(
            base,
            &producer,
            &rows[1..],
            &rows[..1],
            Some(prior),
            "window-fixture",
            vec![(3, finding)],
        )?;
        draft.validate(&rows[1..], &producer.scope)?;
        let mut bad_prior = serde_json::to_value(&draft)?;
        bad_prior["claims"]["prior"]["key"] = serde_json::json!("wrong-state-key");
        let bad_prior: MultiEventPublicationDraft = serde_json::from_value(bad_prior)?;
        assert!(bad_prior.validate(&rows[1..], &producer.scope).is_err());
        let mut changed = serde_json::to_value(&draft)?;
        changed["retained"][0]["event"]["message"] = serde_json::json!("changed");
        let changed: MultiEventPublicationDraft = serde_json::from_value(changed)?;
        assert!(changed.validate(&rows[1..], &producer.scope).is_err());
        let mut current = rows[1..].to_vec();
        current[0].event.id = Uuid::from_u128(99);
        assert!(draft.validate(&current, &producer.scope).is_err());
        let mut changed = draft;
        changed.draft.states[0].bytes = b"{}".to_vec();
        assert!(changed.validate(&rows[1..], &producer.scope).is_err());
        Ok(())
    }
}
