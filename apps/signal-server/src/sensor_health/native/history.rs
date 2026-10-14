//! Bounded historical assessments. These rows never authorize current health.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    schema_version: u16,
    rule_revision: String,
    pub(super) assessment: Assessment,
    evidence: Vec<Proof>,
    current: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct History {
    schema_version: u16,
    pub(super) entries: Vec<Entry>,
    pub(super) expired: u64,
    pub(super) evicted: u64,
}
impl Default for History {
    fn default() -> Self {
        Self {
            schema_version: 1,
            entries: vec![],
            expired: 0,
            evicted: 0,
        }
    }
}
pub(super) struct Batch<'a> {
    pub assessments: &'a [Assessment],
    pub proofs: &'a [Proof],
    pub fresh: &'a BTreeSet<Uuid>,
    pub trusted: bool,
    pub now: i64,
}
impl History {
    pub fn expire(&mut self, config: &Config, now: i64) -> Result<(), Error> {
        let before = self.entries.len();
        self.entries
            .retain(|e| e.assessment.assessed_at_ms + config.history_retention_ms > now);
        self.expired = self
            .expired
            .checked_add((before - self.entries.len()) as u64)
            .ok_or(Error::Capacity)?;
        Ok(())
    }
    pub fn evict_oldest(&mut self, minimum: usize) -> Result<(), Error> {
        if self.entries.len() <= minimum {
            return Err(Error::Capacity);
        }
        self.entries.remove(0);
        self.evicted = self.evicted.checked_add(1).ok_or(Error::Capacity)?;
        Ok(())
    }
    pub fn validate(
        &self,
        config: &Config,
        verifier: &Verifier,
        checkpoint: u64,
        clock: i64,
        context: &RuleContext,
    ) -> Result<(), Error> {
        if self.schema_version != 1 || self.entries.len() > config.max_history_assessments {
            return Err(Error::Capacity);
        }
        encode(self, config.max_history_bytes)?;
        let mut identities = BTreeSet::new();
        let mut previous = None;
        for entry in &self.entries {
            check(context)?;
            let at = entry.assessment.assessed_at_ms;
            if entry.schema_version != 1
                || entry.rule_revision != config.policy.revision
                || at > clock
                || at + config.history_retention_ms <= clock
                || previous.is_some_and(|old| at < old)
                || entry.evidence.len() > 3
                || (entry.current && entry.evidence.is_empty())
                || entry
                    .evidence
                    .windows(2)
                    .any(|v| v[0].wal_sequence >= v[1].wal_sequence)
                || !identities
                    .insert(Sha256::digest(encode(entry, config.max_history_bytes)?).to_vec())
            {
                return Err(Error::Conflict);
            }
            previous = Some(at);
            let mut ids = BTreeSet::new();
            for proof in &entry.evidence {
                check(context)?;
                validate_proof(config, verifier, proof)?;
                if proof.observation.source_id != entry.assessment.source_id
                    || proof.wal_sequence > checkpoint
                    || !ids.insert(proof.event.id)
                {
                    return Err(Error::Conflict);
                }
            }
            let mut monitor = reconstruct(config, &entry.evidence, at, context)?;
            let fresh = if entry.current {
                BTreeSet::from([entry.assessment.source_id])
            } else {
                BTreeSet::new()
            };
            let expected = assess(&mut monitor, at, &fresh, true)?
                .into_iter()
                .find(|a| a.source_id == entry.assessment.source_id)
                .ok_or(Error::Conflict)?;
            if expected != entry.assessment {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }

    pub fn record(
        &mut self,
        config: &Config,
        batch: Batch<'_>,
        context: &RuleContext,
    ) -> Result<(), Error> {
        self.expire(config, batch.now)?;
        for assessment in batch.assessments {
            check(context)?;
            let current = batch.trusted && batch.fresh.contains(&assessment.source_id);
            if let Some(previous) = self
                .entries
                .iter()
                .rev()
                .find(|e| e.assessment.source_id == assessment.source_id)
            {
                let mut comparable = previous.assessment.clone();
                comparable.assessed_at_ms = assessment.assessed_at_ms;
                if comparable == *assessment && previous.current == current {
                    continue;
                }
            }
            let entry = Entry {
                schema_version: 1,
                rule_revision: config.policy.revision.clone(),
                assessment: assessment.clone(),
                current,
                evidence: batch
                    .proofs
                    .iter()
                    .filter(|p| p.observation.source_id == assessment.source_id)
                    .cloned()
                    .collect(),
            };
            // A single unrepresentable entry refuses the complete transaction;
            // capacity eviction cannot silently discard the newest assessment.
            encode(&entry, config.max_history_bytes)?;
            self.entries.push(entry);
            while self.entries.len() > config.max_history_assessments
                || encode(self, config.max_history_bytes).is_err()
            {
                check(context)?;
                self.evict_oldest(1)?;
            }
        }
        Ok(())
    }
}
