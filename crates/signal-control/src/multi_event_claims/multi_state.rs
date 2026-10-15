//! Version4 per-state host evidence. Database fencing remains mandatory.
use super::*;

/// A detector's own original retained inputs and derived findings. A different
/// detector's prior state cannot substitute for this group's provenance.
pub struct StateFindingGroup {
    pub state_key: String,
    pub prior: Option<PriorStateProvenance>,
    pub retained: Vec<StoredEvent>,
    pub derived: Vec<(u64, ScopedFinding)>,
}
pub(super) fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 256 && !key.chars().any(char::is_control)
}
impl MultiEventFindingClaims {
    /// Native host authenticates new inputs and protects each group's original
    /// retained rows separately. This constructs data, never a database grant.
    pub fn from_state_groups(
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        groups: Vec<StateFindingGroup>,
    ) -> Result<Self, ControlError> {
        if groups.is_empty() || groups.len() > crate::ITEMS || groups.capacity() > crate::ITEMS {
            return Err(ControlError::Full);
        }
        let mut keys = BTreeSet::new();
        let mut priors = BTreeMap::new();
        let mut facts = Vec::with_capacity(crate::ITEMS);
        let mut findings = Vec::with_capacity(crate::ITEMS);
        for group in groups {
            if !valid_key(&group.state_key) || !keys.insert(group.state_key.clone()) {
                return Err(ControlError::Conflict);
            }
            if group.retained.len() > 4096 || group.retained.capacity() > 4096 {
                return Err(ControlError::Full);
            }
            if let Some(prior) = &group.prior {
                if prior.key != group.state_key {
                    return Err(ControlError::Fenced);
                }
                priors.insert(group.state_key.clone(), prior.clone());
            }
            let mut part = Self::from_retained_anchor_host(
                producer,
                current,
                &group.retained,
                group.prior,
                group.derived,
            )?;
            if facts.len() + part.facts.len() > crate::ITEMS {
                return Err(ControlError::Full);
            }
            for fact in &mut part.facts {
                fact.state_key = Some(group.state_key.clone());
            }
            facts.append(&mut part.facts);
            findings.append(&mut part.findings);
        }
        let result = Self {
            schema_version: 4,
            scope: producer.scope.clone(),
            scope_generation: producer.scope_generation,
            startup: producer.startup,
            wal_floor: producer.wal_floor,
            prior: None,
            state_keys: keys.into_iter().collect(),
            priors,
            facts,
            findings,
        };
        result.encode()?;
        Ok(result)
    }
    /// Project one group into the existing version3 validator. The state key is
    /// removed only in this internal projection, never from version4 wire data.
    fn part(&self, key: &str) -> Self {
        let facts = self
            .facts
            .iter()
            .filter(|f| f.state_key.as_deref() == Some(key))
            .map(|f| {
                let mut fact = f.clone();
                fact.state_key = None;
                fact
            })
            .collect::<Vec<_>>();
        let ids = facts.iter().map(|f| f.id).collect::<BTreeSet<_>>();
        Self {
            schema_version: 3,
            scope: self.scope.clone(),
            scope_generation: self.scope_generation,
            startup: self.startup,
            wal_floor: self.wal_floor,
            prior: self.priors.get(key).cloned(),
            state_keys: vec![],
            priors: BTreeMap::new(),
            facts,
            findings: self
                .findings
                .iter()
                .filter(|f| ids.contains(&f.id))
                .cloned()
                .collect(),
        }
    }
    pub(super) fn validate_multiple(&self, scope: &Scope) -> Result<(), ControlError> {
        scope.validate()?;
        if &self.scope != scope
            || self.prior.is_some()
            || self.state_keys.is_empty()
            || self.state_keys.len() > crate::ITEMS
            || self.state_keys.capacity() > crate::ITEMS
            || self
                .state_keys
                .iter()
                .any(|key| !valid_key(key) || key.capacity() > 256)
            || self.state_keys.windows(2).any(|v| v[0] >= v[1])
            || self
                .priors
                .keys()
                .any(|key| self.state_keys.binary_search(key).is_err())
            || self.priors.iter().any(|(key, prior)| &prior.key != key)
        {
            return Err(ControlError::Fenced);
        }
        if self.facts.len() > crate::ITEMS
            || self.facts.capacity() > crate::ITEMS
            || self.findings.len() != self.facts.len()
            || self.findings.capacity() > crate::ITEMS
        {
            return Err(ControlError::Full);
        }
        let mut ids = BTreeSet::new();
        let mut references = 0usize;
        for fact in &self.facts {
            let key = fact.state_key.as_ref().ok_or(ControlError::Invalid)?;
            if !valid_key(key)
                || key.capacity() > 256
                || self.state_keys.binary_search(key).is_err()
                || !ids.insert(fact.id)
            {
                return Err(ControlError::Conflict);
            }
            references = references
                .checked_add(fact.references.len())
                .ok_or(ControlError::Full)?;
            if references > 4096 || fact.references.capacity() > 1000 {
                return Err(ControlError::Full);
            }
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        for key in &self.state_keys {
            self.part(key).validate(scope)?;
        }
        Ok(())
    }
    pub(super) fn verify_multiple(
        &self,
        producer: &ProducerEnrollment,
        current: &[StoredEvent],
        retained: &[StoredEvent],
    ) -> Result<(), ControlError> {
        self.validate_multiple(&producer.scope)?;
        if current.is_empty() || current.len() > 4096 || retained.len() > 4096 {
            return Err(ControlError::Full);
        }
        index_inputs(current, retained, true)?;
        for row in retained {
            row.event.validate().map_err(|_| ControlError::Corrupt)?;
            if row.sequence == 0 || row.sequence >= current[0].sequence {
                return Err(ControlError::Conflict);
            }
        }
        for key in &self.state_keys {
            let part = self.part(key);
            let required = part
                .facts
                .iter()
                .flat_map(|f| f.references.iter().map(|r| r.event_id))
                .collect::<BTreeSet<_>>();
            let selected = retained
                .iter()
                .filter(|r| required.contains(&r.event.id))
                .cloned()
                .collect::<Vec<_>>();
            part.verify_rows(producer, current, &selected)?;
        }
        Ok(())
    }
    pub(super) fn bind_multiple(
        self,
        mut publication: crate::PublicationInput,
        primary: &str,
    ) -> Result<MultiEventPublicationInput, ControlError> {
        self.validate_multiple(&self.scope)?;
        publication.validate(&self.scope)?;
        if !self.state_keys.iter().any(|key| key == primary)
            || publication.states.len() != self.state_keys.len()
            || publication
                .states
                .iter()
                .any(|s| self.state_keys.binary_search(&s.key).is_err())
        {
            return Err(ControlError::Conflict);
        }
        let mut findings = Vec::with_capacity(crate::ITEMS);
        findings.append(&mut publication.findings);
        for finding in &self.findings {
            if let Some(old) = findings.iter().find(|old| old.id == finding.id) {
                if old != finding {
                    return Err(ControlError::Conflict);
                }
            } else {
                if findings.len() == crate::ITEMS {
                    return Err(ControlError::Full);
                }
                findings.push(finding.clone());
            }
        }
        publication.findings = findings;
        for key in &self.state_keys {
            self.part(key).bind(publication.clone(), key)?;
        }
        publication.validate(&self.scope)?;
        Ok(MultiEventPublicationInput {
            schema_version: 2,
            publication,
            claims: self,
            state_key: primary.to_owned(),
        })
    }
}
