//! Version2 host evidence for a future fenced multi-event publication routine.
//! This format cannot be submitted through the frozen single-event publisher.
use crate::{ControlError, FindingInput, ITEM_BYTES, ProducerEnrollment, Scope};
use serde::{Deserialize, Serialize};
use signal_findings::{DerivedFinding, ScopedFinding};
use signal_storage::StoredEvent;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// Bounded metadata for recovering a multi-event detector at a protected
/// checkpoint. It records provenance; it cannot authorize canonical inputs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiEventStateEnvelope {
    pub schema_version: u16,
    pub scope_generation: Uuid,
    pub checkpoint: u64,
    pub metadata: serde_json::Value,
    pub canonical_sequences: BTreeMap<Uuid, u64>,
}
impl MultiEventStateEnvelope {
    fn validate(&self, generation: Uuid, checkpoint: u64) -> Result<(), ControlError> {
        if self.schema_version != 1
            || generation.is_nil()
            || self.scope_generation != generation
            || self.checkpoint != checkpoint
            || checkpoint == 0
            || checkpoint > i64::MAX as u64
            || self.canonical_sequences.len() > 4096
        {
            return Err(ControlError::Invalid);
        }
        let hashes = self
            .metadata
            .get("canonical_sha256")
            .and_then(serde_json::Value::as_object)
            .ok_or(ControlError::Invalid)?;
        if hashes.len() != self.canonical_sequences.len() {
            return Err(ControlError::Corrupt);
        }
        for (id, sequence) in &self.canonical_sequences {
            if id.is_nil() || *sequence == 0 || *sequence > checkpoint {
                return Err(ControlError::Invalid);
            }
            let hash = hashes.get(&id.to_string()).ok_or(ControlError::Corrupt)?;
            let bytes = hash
                .as_array()
                .filter(|bytes| bytes.len() == 32)
                .ok_or(ControlError::Corrupt)?;
            if bytes
                .iter()
                .any(|byte| byte.as_u64().is_none_or(|byte| byte > 255))
            {
                return Err(ControlError::Corrupt);
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, ControlError> {
        self.validate(self.scope_generation, self.checkpoint)?;
        let bytes = crate::publication::encode(self)?;
        if bytes.len() > ITEM_BYTES {
            return Err(ControlError::Full);
        }
        Ok(bytes)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorStateProvenance {
    pub schema_version: u16,
    pub key: String,
    pub checkpoint: u64,
    pub revision: [u8; 32],
    pub value_sha256: [u8; 32],
    pub scope_generation: Uuid,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reference {
    event_id: Uuid,
    sequence: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fact {
    id: Uuid,
    anchor_sequence: u64,
    references: Vec<Reference>,
    source: Option<String>,
    account: Option<String>,
    resource: Option<String>,
    binding_digest: String,
}

/// Validate stored selectors against original finding bytes. Database ownership,
/// content hashes and publication provenance must be checked by the caller.
pub(crate) fn validate_stored_fact(
    bytes: &[u8],
    finding_bytes: &[u8],
    generation: Uuid,
) -> Result<(), ControlError> {
    if bytes.is_empty()
        || bytes.len() > 131072
        || finding_bytes.len() > ITEM_BYTES
        || generation.is_nil()
    {
        return Err(ControlError::Corrupt);
    }
    let fact: Fact = serde_json::from_slice(bytes).map_err(|_| ControlError::Corrupt)?;
    let finding: signal_findings::Finding =
        serde_json::from_slice(finding_bytes).map_err(|_| ControlError::Corrupt)?;
    finding.validate().map_err(|_| ControlError::Corrupt)?;
    if fact.id.is_nil()
        || fact.id != finding.id
        || fact.anchor_sequence == 0
        || fact.anchor_sequence > i64::MAX as u64
        || fact.references.is_empty()
        || fact.references.len() > 1000
        || fact.binding_digest.len() != 64
        || !fact
            .binding_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || [&fact.source, &fact.account, &fact.resource]
            .iter()
            .any(|value| {
                value.as_ref().is_some_and(|s| {
                    s.len() > 256 || s.trim().is_empty() || s.chars().any(char::is_control)
                })
            })
    {
        return Err(ControlError::Corrupt);
    }
    let ids = fact
        .references
        .iter()
        .map(|r| r.event_id)
        .collect::<Vec<_>>();
    if ids != finding.event_ids
        || ids.iter().any(Uuid::is_nil)
        || ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len()
        || fact
            .references
            .iter()
            .map(|r| r.sequence)
            .collect::<BTreeSet<_>>()
            .len()
            != ids.len()
        || fact
            .references
            .iter()
            .any(|r| r.sequence == 0 || r.sequence > i64::MAX as u64)
        || !fact
            .references
            .iter()
            .any(|r| r.sequence == fact.anchor_sequence)
        || finding.attributes.get("signal.scope.v1")
            != Some(
                &serde_json::json!({"schema_version":1,"generation":generation,"binding_digest":fact.binding_digest,"source":fact.source,"account":fact.account,"resource":fact.resource}),
            )
    {
        return Err(ControlError::Corrupt);
    }
    Ok(())
}

fn index_inputs<'a>(
    current: &'a [StoredEvent],
    retained: &'a [StoredEvent],
    retries: bool,
) -> Result<BTreeMap<Uuid, &'a StoredEvent>, ControlError> {
    let mut inputs: BTreeMap<Uuid, &StoredEvent> = BTreeMap::new();
    for row in current {
        if let Some(old) = inputs.get(&row.event.id) {
            if !retries || old.event != row.event {
                return Err(ControlError::Conflict);
            }
        } else {
            inputs.insert(row.event.id, row);
        }
    }
    let mut retained_ids = BTreeSet::new();
    for row in retained {
        if !retained_ids.insert(row.event.id) {
            return Err(ControlError::Conflict);
        }
        if let Some(old) = inputs.get(&row.event.id)
            && (!retries || old.event != row.event)
        {
            return Err(ControlError::Conflict);
        }
        inputs.insert(row.event.id, row);
    }
    Ok(inputs)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiEventFindingClaims {
    schema_version: u16,
    scope: Scope,
    scope_generation: Uuid,
    startup: Uuid,
    wal_floor: u64,
    prior: Option<PriorStateProvenance>,
    facts: Vec<Fact>,
    findings: Vec<FindingInput>,
}
impl MultiEventFindingClaims {
    pub fn findings(&self) -> &[FindingInput] {
        &self.findings
    }
    pub fn prior(&self) -> Option<&PriorStateProvenance> {
        self.prior.as_ref()
    }
    /// The host must establish native admission for all NEW inputs and verify
    /// protected prior state and retained canonical objects for older inputs.
    /// Provenance/checksums remain evidence, never credentials or a commit permit.
    pub fn from_host(
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        retained: &[StoredEvent],
        prior: Option<PriorStateProvenance>,
        derived: Vec<(u64, ScopedFinding)>,
    ) -> Result<Self, ControlError> {
        Self::from_host_version(producer, current, retained, prior, derived, 2)
    }
    /// Host-verified retained anchors may close after a later WAL batch seals.
    /// Every old anchor must be protected by the exact prior state, not a new grant.
    pub fn from_retained_anchor_host(
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        retained: &[StoredEvent],
        prior: Option<PriorStateProvenance>,
        derived: Vec<(u64, ScopedFinding)>,
    ) -> Result<Self, ControlError> {
        Self::from_host_version(producer, current, retained, prior, derived, 3)
    }
    fn from_host_version(
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        retained: &[StoredEvent],
        prior: Option<PriorStateProvenance>,
        derived: Vec<(u64, ScopedFinding)>,
        version: u16,
    ) -> Result<Self, ControlError> {
        producer.scope.validate()?;
        if producer.scope_generation.is_nil()
            || producer.startup.is_nil()
            || producer.wal_floor > i64::MAX as u64
            || current.is_empty()
            || current.len() > 4096
            || retained.len() > 4096
            || derived.len() > 128
            || derived.capacity() > 128
        {
            return Err(ControlError::Invalid);
        }
        let first = current[0].sequence;
        let last = current[current.len() - 1].sequence;
        if first == 0
            || last > i64::MAX as u64
            || last.checked_sub(first).and_then(|n| n.checked_add(1)) != Some(current.len() as u64)
        {
            return Err(ControlError::Invalid);
        }
        let mut sequences = BTreeSet::new();
        for (index, row) in current.iter().enumerate() {
            row.event.validate().map_err(|_| ControlError::Corrupt)?;
            if row.sequence != first + index as u64 {
                return Err(ControlError::Conflict);
            }
            sequences.insert(row.sequence);
        }
        if let Some(old) = &prior
            && (old.schema_version != 1
                || old.key.is_empty()
                || old.key.len() > 256
                || old.key.chars().any(char::is_control)
                || old.scope_generation != producer.scope_generation
                || old.checkpoint >= first)
        {
            return Err(ControlError::Fenced);
        }
        for row in retained {
            row.event.validate().map_err(|_| ControlError::Corrupt)?;
            if row.sequence == 0
                || prior
                    .as_ref()
                    .is_none_or(|old| row.sequence > old.checkpoint)
                || !sequences.insert(row.sequence)
            {
                return Err(ControlError::Conflict);
            }
        }
        let inputs = index_inputs(current, retained, version == 3)?;
        let mut facts = Vec::new();
        let mut findings = Vec::new();
        let mut identities = BTreeSet::new();
        let mut references_total = 0usize;
        for (anchor, payload) in derived {
            if payload.generation() != producer.scope_generation
                || (anchor < first
                    && (version != 3 || prior.as_ref().is_none_or(|old| anchor > old.checkpoint)))
                || anchor > last
                || anchor <= producer.wal_floor
            {
                return Err(ControlError::Fenced);
            }
            let finding = payload.finding();
            if !identities.insert(finding.id) {
                return Err(ControlError::Conflict);
            }
            references_total = references_total
                .checked_add(finding.event_ids.len())
                .ok_or(ControlError::Full)?;
            if references_total > 4096 {
                return Err(ControlError::Full);
            }
            let mut references = Vec::new();
            let mut events = Vec::new();
            let mut has_anchor = false;
            for id in &finding.event_ids {
                let row = inputs.get(id).ok_or(ControlError::Corrupt)?;
                if row.sequence <= producer.wal_floor
                    && prior
                        .as_ref()
                        .is_none_or(|old| row.sequence > old.checkpoint)
                {
                    return Err(ControlError::Fenced);
                }
                has_anchor |= row.sequence == anchor;
                references.push(Reference {
                    event_id: *id,
                    sequence: row.sequence,
                });
                events.push(&row.event);
            }
            if !has_anchor {
                return Err(ControlError::Corrupt);
            }
            let mut base = finding.clone();
            base.attributes.remove("signal.scope.v1");
            let reconstructed = DerivedFinding::from_events(base, &events, true)
                .map_err(|_| ControlError::Corrupt)?
                .into_scoped(producer.scope_generation)
                .map_err(|_| ControlError::Fenced)?;
            if reconstructed.finding() != finding {
                return Err(ControlError::Corrupt);
            }
            let selectors = payload.facts();
            facts.push(Fact {
                id: finding.id,
                anchor_sequence: anchor,
                references,
                source: selectors.source.map(str::to_owned),
                account: selectors.account.map(str::to_owned),
                resource: selectors.resource.map(str::to_owned),
                binding_digest: payload.binding_digest().into(),
            });
            let input = FindingInput {
                id: finding.id,
                bytes: crate::publication::encode(finding)?,
            };
            if input.bytes.len() > ITEM_BYTES {
                return Err(ControlError::Full);
            }
            input.validate()?;
            findings.push(input);
        }
        let result = Self {
            schema_version: version,
            scope: producer.scope.clone(),
            scope_generation: producer.scope_generation,
            startup: producer.startup,
            wal_floor: producer.wal_floor,
            prior,
            facts,
            findings,
        };
        result.encode()?;
        Ok(result)
    }
    pub fn validate(&self, scope: &Scope) -> Result<(), ControlError> {
        scope.validate()?;
        if &self.scope != scope
            || !matches!(self.schema_version, 2 | 3)
            || self.scope_generation.is_nil()
            || self.startup.is_nil()
            || self.wal_floor > i64::MAX as u64
        {
            return Err(ControlError::Fenced);
        }
        if self.facts.len() > 128
            || self.facts.capacity() > 128
            || self.findings.len() != self.facts.len()
            || self.findings.capacity() > 128
        {
            return Err(ControlError::Full);
        }
        if let Some(old) = &self.prior
            && (old.schema_version != 1
                || old.key.is_empty()
                || old.key.len() > 256
                || old.key.capacity() > 256
                || old.key.chars().any(char::is_control)
                || old.checkpoint > i64::MAX as u64
                || old.scope_generation != self.scope_generation)
        {
            return Err(ControlError::Fenced);
        }
        let mut identities = BTreeSet::new();
        let mut total = 0usize;
        for fact in &self.facts {
            if fact.id.is_nil()
                || !identities.insert(fact.id)
                || fact.anchor_sequence <= self.wal_floor
                || fact.anchor_sequence > i64::MAX as u64
                || fact.references.is_empty()
                || fact.references.len() > 1000
                || fact.binding_digest.len() != 64
                || !fact
                    .binding_digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || [&fact.source, &fact.account, &fact.resource]
                    .iter()
                    .any(|s| {
                        s.as_ref().is_some_and(|s| {
                            s.len() > 256 || s.trim().is_empty() || s.chars().any(char::is_control)
                        })
                    })
            {
                return Err(ControlError::Invalid);
            }
            total = total
                .checked_add(fact.references.len())
                .ok_or(ControlError::Full)?;
            if total > 4096 {
                return Err(ControlError::Full);
            }
            let input = self
                .findings
                .iter()
                .find(|f| f.id == fact.id)
                .ok_or(ControlError::Corrupt)?;
            input.validate()?;
            let finding: signal_findings::Finding =
                serde_json::from_slice(&input.bytes).map_err(|_| ControlError::Corrupt)?;
            finding.validate().map_err(|_| ControlError::Corrupt)?;
            let refs = fact
                .references
                .iter()
                .map(|r| r.event_id)
                .collect::<Vec<_>>();
            let expected = serde_json::json!({"schema_version":1,"generation":self.scope_generation,"binding_digest":fact.binding_digest,
                "source":fact.source,"account":fact.account,"resource":fact.resource});
            if finding.id != fact.id
                || finding.event_ids != refs
                || refs.iter().copied().collect::<BTreeSet<_>>().len() != refs.len()
                || refs.iter().any(Uuid::is_nil)
                || finding.attributes.get("signal.scope.v1") != Some(&expected)
                || !fact
                    .references
                    .iter()
                    .any(|r| r.sequence == fact.anchor_sequence)
                || fact
                    .references
                    .iter()
                    .map(|r| r.sequence)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != fact.references.len()
            {
                return Err(ControlError::Corrupt);
            }
            for reference in &fact.references {
                if reference.sequence == 0
                    || reference.sequence > i64::MAX as u64
                    || (reference.sequence <= self.wal_floor
                        && self
                            .prior
                            .as_ref()
                            .is_none_or(|old| reference.sequence > old.checkpoint))
                {
                    return Err(ControlError::Fenced);
                }
            }
        }
        Ok(())
    }
    /// Reconstruct stored host evidence without renewing its enrollment or
    /// authentication. The original captured producer and canonical inputs are
    /// required; a fresh publication must still verify current DB authority.
    pub fn verify_rows(
        &self,
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        retained: &[StoredEvent],
    ) -> Result<(), ControlError> {
        self.validate(&producer.scope)?;
        if self.scope_generation != producer.scope_generation
            || self.startup != producer.startup
            || self.wal_floor != producer.wal_floor
        {
            return Err(ControlError::Fenced);
        }
        let inputs = index_inputs(current, retained, self.schema_version == 3)?;
        let mut derived = Vec::with_capacity(self.facts.len());
        for fact in &self.facts {
            let input = self
                .findings
                .iter()
                .find(|f| f.id == fact.id)
                .ok_or(ControlError::Corrupt)?;
            let mut finding: signal_findings::Finding =
                serde_json::from_slice(&input.bytes).map_err(|_| ControlError::Corrupt)?;
            finding.attributes.remove("signal.scope.v1");
            let mut events = Vec::new();
            for reference in &fact.references {
                let row = inputs
                    .get(&reference.event_id)
                    .ok_or(ControlError::Corrupt)?;
                if row.sequence != reference.sequence {
                    return Err(ControlError::Corrupt);
                }
                events.push(&row.event);
            }
            let payload = DerivedFinding::from_events(finding, &events, true)
                .map_err(|_| ControlError::Corrupt)?
                .into_scoped(self.scope_generation)
                .map_err(|_| ControlError::Fenced)?;
            derived.push((fact.anchor_sequence, payload));
        }
        let expected = Self::from_host_version(
            producer,
            current,
            retained,
            self.prior.clone(),
            derived,
            self.schema_version,
        )?;
        if crate::publication::encode(&expected)? != crate::publication::encode(self)? {
            return Err(ControlError::Corrupt);
        }
        Ok(())
    }
    pub fn bind(
        self,
        mut publication: crate::PublicationInput,
        state_key: &str,
    ) -> Result<MultiEventPublicationInput, ControlError> {
        self.validate(&self.scope)?;
        let state = publication
            .states
            .iter()
            .find(|s| s.key == state_key)
            .ok_or(ControlError::Invalid)?;
        if state.revision != publication.rule_revision {
            return Err(ControlError::Conflict);
        }
        if let Some(prior) = &self.prior
            && (prior.key != state_key
                || prior.revision != publication.rule_revision
                || prior.checkpoint.checked_add(1) != Some(publication.first_sequence))
        {
            return Err(ControlError::Conflict);
        }
        for fact in &self.facts {
            if (fact.anchor_sequence < publication.first_sequence
                && (self.schema_version != 3
                    || self
                        .prior
                        .as_ref()
                        .is_none_or(|old| fact.anchor_sequence > old.checkpoint)))
                || fact.anchor_sequence > publication.last_sequence
            {
                return Err(ControlError::Invalid);
            }
            for reference in &fact.references {
                if !(publication.first_sequence..=publication.last_sequence)
                    .contains(&reference.sequence)
                    && self
                        .prior
                        .as_ref()
                        .is_none_or(|old| reference.sequence > old.checkpoint)
                {
                    return Err(ControlError::Fenced);
                }
            }
        }
        for finding in &self.findings {
            if let Some(old) = publication.findings.iter().find(|f| f.id == finding.id) {
                if old != finding {
                    return Err(ControlError::Conflict);
                }
            } else {
                publication.findings.push(finding.clone());
            }
        }
        publication.validate(&self.scope)?;
        Ok(MultiEventPublicationInput {
            schema_version: 2,
            publication,
            claims: self,
            state_key: state_key.to_owned(),
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, ControlError> {
        self.validate(&self.scope)?;

        let bytes = crate::publication::encode(self)?;
        if bytes.len() > 131072 {
            return Err(ControlError::Full);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiEventPublicationInput {
    schema_version: u16,
    publication: crate::PublicationInput,
    claims: MultiEventFindingClaims,
    state_key: String,
}
impl MultiEventPublicationInput {
    pub fn publication(&self) -> &crate::PublicationInput {
        &self.publication
    }
    pub fn validate(&self, scope: &Scope) -> Result<(), ControlError> {
        self.sql_parts(scope).map(|_| ())
    }
    pub(crate) fn sql_parts(
        &self,
        scope: &Scope,
    ) -> Result<(crate::PublicationInput, Vec<u8>), ControlError> {
        if &self.claims.scope != scope {
            return Err(ControlError::Fenced);
        }
        self.encode_sql_publication()?;
        Ok((self.publication.clone(), self.encode_sql_claims()?))
    }
    /// Original publication wire bytes paired with `encode_sql_claims`.
    /// Host evidence and current database authority must still be verified.
    pub fn encode_sql_publication(&self) -> Result<Vec<u8>, ControlError> {
        self.encode_sql_claims()?;
        let state = self
            .publication
            .states
            .iter()
            .find(|s| s.key == self.state_key)
            .ok_or(ControlError::Invalid)?;
        let envelope: MultiEventStateEnvelope =
            serde_json::from_slice(&state.bytes).map_err(|_| ControlError::Invalid)?;
        envelope.validate(self.claims.scope_generation, self.publication.last_sequence)?;
        self.publication.wire(&self.claims.scope)
    }

    /// Encode only the companion SQL claims. Finding bytes and partition scope
    /// travel in the original publication and fenced token respectively.
    /// This does not verify host evidence or grant submission authority.
    pub fn encode_sql_claims(&self) -> Result<Vec<u8>, ControlError> {
        if self.schema_version != 2 {
            return Err(ControlError::Invalid);
        }
        self.claims.validate(&self.claims.scope)?;
        let expected = self
            .claims
            .clone()
            .bind(self.publication.clone(), &self.state_key)?;
        if crate::publication::encode(&expected)? != crate::publication::encode(self)? {
            return Err(ControlError::Corrupt);
        }
        let prior = self.claims.prior.as_ref().map(|prior| {
            serde_json::json!({
                "schema_version": prior.schema_version,
                "key": prior.key,
                "checkpoint": prior.checkpoint,
                "revision": crate::publication::hex(&prior.revision),
                "value_sha256": crate::publication::hex(&prior.value_sha256),
                "scope_generation": prior.scope_generation,
            })
        });
        let bytes = crate::publication::encode(&serde_json::json!({
            "schema_version": self.claims.schema_version,
            "scope_generation": self.claims.scope_generation,
            "startup": self.claims.startup,
            "wal_floor": self.claims.wal_floor,
            "prior": prior,
            "facts": self.claims.facts,
            "state_key": self.state_key,
        }))?;
        if bytes.len() > 131072 {
            return Err(ControlError::Full);
        }
        Ok(bytes)
    }

    pub fn verify(
        &self,
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        retained: &[StoredEvent],
    ) -> Result<(), ControlError> {
        if self.schema_version != 2 {
            return Err(ControlError::Invalid);
        }
        if current.first().map(|r| r.sequence) != Some(self.publication.first_sequence)
            || current.last().map(|r| r.sequence) != Some(self.publication.last_sequence)
        {
            return Err(ControlError::Conflict);
        }
        self.claims.verify_rows(producer, current, retained)?;
        let expected = self
            .claims
            .clone()
            .bind(self.publication.clone(), &self.state_key)?;
        if crate::publication::encode(&expected)? != crate::publication::encode(self)? {
            return Err(ControlError::Corrupt);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_findings::{DetectionSeverity, Finding};
    #[test]
    fn state_envelope_requires_exact_bounded_hash_sequence_inventory() -> Result<(), ControlError> {
        let id = Uuid::from_u128(1);
        let mut envelope = MultiEventStateEnvelope {
            schema_version: 1,
            scope_generation: Uuid::from_u128(2),
            checkpoint: 3,
            metadata: serde_json::json!({"canonical_sha256":{id.to_string():vec![0;32]}}),
            canonical_sequences: BTreeMap::from([(id, 2)]),
        };
        envelope.encode()?;
        envelope.canonical_sequences.insert(id, 4);
        assert!(envelope.encode().is_err());
        envelope.canonical_sequences.insert(id, 2);
        envelope.metadata["canonical_sha256"][id.to_string()] = serde_json::json!([0]);
        assert!(envelope.encode().is_err());
        envelope.metadata["canonical_sha256"][id.to_string()] = serde_json::json!(vec![256; 32]);
        assert!(envelope.encode().is_err());
        envelope.metadata["canonical_sha256"][id.to_string()] = serde_json::json!(vec![0; 32]);
        envelope.metadata["canonical_sha256"][Uuid::from_u128(9).to_string()] =
            serde_json::json!(vec![0; 32]);
        assert!(envelope.encode().is_err());
        Ok(())
    }
    fn fixture() -> Result<(ProducerEnrollment, Vec<StoredEvent>), ControlError> {
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
        let rows=(1..=3).map(|sequence| {
            let event=serde_json::from_value(serde_json::json!({"schema_version":1,"id":Uuid::from_u128(sequence),"timestamp":"2026-10-15T00:00:00Z","observed_at":"2026-10-15T00:00:00Z","source":{"type":"fixture"},"resource":{"kind":"host","id":"fixture","account_id":"fixture"},"severity":"info","message":"fixture","attributes":{},"tags":[]})).map_err(|_|ControlError::Invalid)?;
            Ok(StoredEvent {sequence:sequence as u64,event})
        }).collect::<Result<Vec<_>,ControlError>>()?;
        Ok((producer, rows))
    }
    fn finding(
        producer: &ProducerEnrollment,
        rows: &[StoredEvent],
    ) -> Result<ScopedFinding, ControlError> {
        let mut base = Finding::for_event(
            "window-fixture",
            &rows[0].event,
            DetectionSeverity::Medium,
            "Fixture",
        )
        .map_err(|_| ControlError::Invalid)?;
        base.event_ids = rows.iter().map(|r| r.event.id).collect();
        let events = rows.iter().map(|r| &r.event).collect::<Vec<_>>();
        DerivedFinding::from_events(base, &events, true)
            .map_err(|_| ControlError::Invalid)?
            .into_scoped(producer.scope_generation)
            .map_err(|_| ControlError::Invalid)
    }
    #[test]
    fn retry_index_preserves_first_sequence_and_rejects_changed_bodies() -> Result<(), ControlError>
    {
        let (_, rows) = fixture()?;
        let mut retry = rows[0].clone();
        retry.sequence = 4;
        let current = [rows[0].clone(), retry.clone()];
        assert_eq!(
            index_inputs(&current, &[], true)?[&retry.event.id].sequence,
            1
        );
        assert!(matches!(
            index_inputs(&current, &[], false),
            Err(ControlError::Conflict)
        ));
        assert_eq!(
            index_inputs(&[retry.clone()], &rows[..1], true)?[&retry.event.id].sequence,
            1
        );
        assert!(matches!(
            index_inputs(&[retry.clone()], &rows[..1], false),
            Err(ControlError::Conflict)
        ));
        retry.event.message = Some("changed".into());
        assert!(matches!(
            index_inputs(&[retry.clone()], &rows[..1], true),
            Err(ControlError::Conflict)
        ));
        assert!(matches!(
            index_inputs(&[rows[0].clone(), retry], &[], true),
            Err(ControlError::Conflict)
        ));
        assert!(matches!(
            index_inputs(&[], &[rows[0].clone(), rows[0].clone()], true),
            Err(ControlError::Conflict)
        ));
        Ok(())
    }
    #[test]
    fn retained_anchor_version_requires_exact_prior_and_preserves_version2_refusal()
    -> Result<(), ControlError> {
        let (producer, rows) = fixture()?;
        let prior = PriorStateProvenance {
            schema_version: 1,
            key: "window".into(),
            checkpoint: 2,
            revision: [1; 32],
            value_sha256: [2; 32],
            scope_generation: producer.scope_generation,
        };
        let payload = finding(&producer, &rows[..2])?;
        assert!(matches!(
            MultiEventFindingClaims::from_host(
                &producer,
                &rows[2..],
                &rows[..2],
                Some(prior.clone()),
                vec![(2, finding(&producer, &rows[..2])?)]
            ),
            Err(ControlError::Fenced)
        ));
        let claims = MultiEventFindingClaims::from_retained_anchor_host(
            &producer,
            &rows[2..],
            &rows[..2],
            Some(prior.clone()),
            vec![(2, finding(&producer, &rows[..2])?)],
        )?;
        claims.verify_rows(&producer, &rows[2..], &rows[..2])?;
        let wire: serde_json::Value =
            serde_json::from_slice(&claims.encode()?).map_err(|_| ControlError::Corrupt)?;
        assert_eq!(wire["schema_version"], 3);
        let retry = StoredEvent {
            sequence: 3,
            event: rows[0].event.clone(),
        };
        let retries = [retry];
        let repeated = MultiEventFindingClaims::from_retained_anchor_host(
            &producer,
            &retries,
            &rows[..2],
            Some(prior.clone()),
            vec![(2, finding(&producer, &rows[..2])?)],
        )?;
        repeated.verify_rows(&producer, &retries, &rows[..2])?;
        let repeated_wire: serde_json::Value =
            serde_json::from_slice(&repeated.encode()?).map_err(|_| ControlError::Corrupt)?;
        assert_eq!(repeated_wire["facts"], wire["facts"]);
        assert_eq!(repeated_wire["findings"], wire["findings"]);
        assert!(
            MultiEventFindingClaims::from_retained_anchor_host(
                &producer,
                &rows[2..],
                &rows[..2],
                None,
                vec![(2, finding(&producer, &rows[..2])?)]
            )
            .is_err()
        );
        let mut old_floor = producer.clone();
        old_floor.wal_floor = 2;
        assert!(matches!(
            MultiEventFindingClaims::from_retained_anchor_host(
                &old_floor,
                &rows[2..],
                &rows[..2],
                Some(prior),
                vec![(2, payload)]
            ),
            Err(ControlError::Fenced)
        ));
        Ok(())
    }
    #[test]
    fn version2_binds_all_current_references_and_refuses_missing_or_foreign_scope()
    -> Result<(), ControlError> {
        let (producer, rows) = fixture()?;
        let claims = MultiEventFindingClaims::from_host(
            &producer,
            &rows,
            &[],
            None,
            vec![(3, finding(&producer, &rows)?)],
        )?;
        let wire: serde_json::Value =
            serde_json::from_slice(&claims.encode()?).map_err(|_| ControlError::Corrupt)?;
        assert_eq!(wire["schema_version"], 2);
        assert_eq!(
            wire["facts"][0]["references"].as_array().map(Vec::len),
            Some(3)
        );
        assert!(
            MultiEventFindingClaims::from_host(
                &producer,
                &rows[..2],
                &[],
                None,
                vec![(2, finding(&producer, &rows)?)]
            )
            .is_err()
        );
        let mut foreign = rows.clone();
        foreign[1]
            .event
            .resource
            .as_mut()
            .ok_or(ControlError::Invalid)?
            .account_id = Some("foreign".into());
        assert!(
            MultiEventFindingClaims::from_host(
                &producer,
                &foreign,
                &[],
                None,
                vec![(3, finding(&producer, &rows)?)]
            )
            .is_err()
        );
        let mut reversed = rows.clone();
        reversed.reverse();
        assert!(
            MultiEventFindingClaims::from_host(
                &producer,
                &reversed,
                &[],
                None,
                vec![(3, finding(&producer, &rows)?)]
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn stored_fact_matches_original_scope_and_complete_ordered_references()
    -> Result<(), ControlError> {
        let (producer, rows) = fixture()?;
        let claims = MultiEventFindingClaims::from_host(
            &producer,
            &rows,
            &[],
            None,
            vec![(3, finding(&producer, &rows)?)],
        )?;
        let bytes = serde_json::to_vec(&claims.facts[0]).map_err(|_| ControlError::Corrupt)?;
        validate_stored_fact(&bytes, &claims.findings[0].bytes, producer.scope_generation)?;
        let original: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| ControlError::Corrupt)?;
        for (field, value) in [
            ("source", serde_json::json!("foreign")),
            ("anchor_sequence", serde_json::json!(99)),
            ("references", serde_json::json!([])),
            ("id", serde_json::json!(Uuid::from_u128(99))),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(
                validate_stored_fact(
                    &serde_json::to_vec(&changed).map_err(|_| ControlError::Corrupt)?,
                    &claims.findings[0].bytes,
                    producer.scope_generation
                )
                .is_err()
            );
        }
        assert!(
            validate_stored_fact(&bytes, &claims.findings[0].bytes, Uuid::from_u128(99)).is_err()
        );
        Ok(())
    }
    #[test]
    fn deserialized_claims_reverify_original_scope_sequences_and_reserved_metadata()
    -> Result<(), ControlError> {
        let (producer, rows) = fixture()?;
        let claims = MultiEventFindingClaims::from_host(
            &producer,
            &rows,
            &[],
            None,
            vec![(3, finding(&producer, &rows)?)],
        )?;
        let bytes = claims.encode()?;
        let restored: MultiEventFindingClaims =
            serde_json::from_slice(&bytes).map_err(|_| ControlError::Corrupt)?;
        restored.verify_rows(&producer, &rows, &[])?;
        let raw: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| ControlError::Corrupt)?;
        for (field, value) in [
            ("anchor_sequence", serde_json::json!(1)),
            ("binding_digest", serde_json::json!("00".repeat(32))),
            ("references", serde_json::json!([])),
            ("source", serde_json::json!("foreign")),
        ] {
            let mut changed = raw.clone();
            changed["facts"][0][field] = value;
            let changed: MultiEventFindingClaims =
                serde_json::from_value(changed).map_err(|_| ControlError::Corrupt)?;
            // A different current anchor can be structurally valid but must not
            // silently alter a future publication's exact captured request.
            if field != "anchor_sequence" {
                assert!(changed.verify_rows(&producer, &rows, &[]).is_err());
            }
        }
        let mut other = producer.clone();
        other.startup = Uuid::from_u128(99);
        assert!(restored.verify_rows(&other, &rows, &[]).is_err());
        let mut missing = rows.clone();
        missing[1].event.id = Uuid::from_u128(99);
        assert!(restored.verify_rows(&producer, &missing, &[]).is_err());
        Ok(())
    }

    #[test]
    fn publication_attachment_requires_state_revision_and_exact_source_span()
    -> Result<(), ControlError> {
        use signal_storage::object_manifest::{QueryFile, QueryManifest, QueryObjectRef, data_key};
        let (producer, rows) = fixture()?;
        let claims = MultiEventFindingClaims::from_host(
            &producer,
            &rows,
            &[],
            None,
            vec![(3, finding(&producer, &rows)?)],
        )?;
        let manifest = QueryManifest {
            schema_version: 1,
            storage_schema_version: 1,
            stream_id: producer.scope.stream,
            normalizer_revision: "fixture-v1".into(),
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
                    etag: Some("fixture".into()),
                    bytes: 1024,
                    sha256: [1; 32],
                },
                rows: 3,
                decoded_bytes: 4096,
            }],
        };
        let publication = crate::PublicationInput {
            schema_version: 1,
            id: Uuid::from_u128(10),
            previous: None,
            first_sequence: 1,
            last_sequence: 3,
            manifest: serde_json::to_vec(&manifest).map_err(|_| ControlError::Invalid)?,
            rule_revision: [1; 32],
            normalizer_revision: "fixture-v1".into(),
            states: vec![crate::RevisionedState {
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
        let bound = claims.clone().bind(publication.clone(), "window-fixture")?;
        bound.verify(&producer, &rows, &[])?;
        bound.encode_sql_publication()?;
        let mut wrong_state = bound.clone();
        wrong_state.publication.states[0].bytes = b"{}".to_vec();
        assert!(wrong_state.encode_sql_publication().is_err());
        assert_eq!(bound.publication.findings.len(), 1);
        let sql: serde_json::Value = serde_json::from_slice(&bound.encode_sql_claims()?)
            .map_err(|_| ControlError::Corrupt)?;
        assert_eq!(sql.as_object().map(serde_json::Map::len), Some(7));
        assert_eq!(sql["state_key"], "window-fixture");
        assert_eq!(sql["prior"], serde_json::Value::Null);
        assert_eq!(sql["facts"][0]["references"][2]["sequence"], 3);
        assert!(sql.get("findings").is_none());
        let mut corrupt = bound.clone();
        corrupt.state_key = "absent".into();
        assert!(corrupt.encode_sql_claims().is_err());
        let mut replay = bound.clone();
        replay.claims.prior = Some(PriorStateProvenance {
            schema_version: 1,
            key: "window-fixture".into(),
            checkpoint: 0,
            revision: [1; 32],
            value_sha256: [2; 32],
            scope_generation: producer.scope_generation,
        });
        let replay_sql: serde_json::Value = serde_json::from_slice(&replay.encode_sql_claims()?)
            .map_err(|_| ControlError::Corrupt)?;
        assert_eq!(replay_sql["prior"]["revision"], "01".repeat(32));
        assert_eq!(replay_sql["prior"]["value_sha256"], "02".repeat(32));
        let mut missing = publication.clone();
        missing.states.clear();
        assert!(claims.clone().bind(missing, "window-fixture").is_err());
        let mut wrong = publication;
        wrong.states[0].revision = [9; 32];
        assert!(claims.bind(wrong, "window-fixture").is_err());
        assert!(bound.verify(&producer, &rows[..2], &[]).is_err());
        let encoded = crate::publication::encode(&bound)?;
        let decoded: MultiEventPublicationInput =
            serde_json::from_slice(&encoded).map_err(|_| ControlError::Corrupt)?;
        decoded.verify(&producer, &rows, &[])?;
        Ok(())
    }

    #[test]
    fn older_inputs_need_prior_generation_checkpoint_and_complete_evidence()
    -> Result<(), ControlError> {
        let (mut producer, rows) = fixture()?;
        producer.wal_floor = 2;
        let prior = PriorStateProvenance {
            schema_version: 1,
            key: "window-fixture".into(),
            checkpoint: 2,
            revision: [1; 32],
            value_sha256: [2; 32],
            scope_generation: producer.scope_generation,
        };
        assert!(
            MultiEventFindingClaims::from_host(
                &producer,
                &rows[2..],
                &rows[..2],
                None,
                vec![(3, finding(&producer, &rows)?)]
            )
            .is_err()
        );
        MultiEventFindingClaims::from_host(
            &producer,
            &rows[2..],
            &rows[..2],
            Some(prior.clone()),
            vec![(3, finding(&producer, &rows)?)],
        )?;
        let mut changed = prior.clone();
        changed.scope_generation = Uuid::from_u128(99);
        assert!(
            MultiEventFindingClaims::from_host(
                &producer,
                &rows[2..],
                &rows[..2],
                Some(changed),
                vec![(3, finding(&producer, &rows)?)]
            )
            .is_err()
        );
        let mut changed = prior;
        changed.checkpoint = 1;
        assert!(
            MultiEventFindingClaims::from_host(
                &producer,
                &rows[2..],
                &rows[..2],
                Some(changed),
                vec![(3, finding(&producer, &rows)?)]
            )
            .is_err()
        );
        Ok(())
    }
}
