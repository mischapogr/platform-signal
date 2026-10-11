//! Canonical host payload and exact retained companion claims, never credentials.
use crate::{ControlError, ProducerEnrollment, PublicationInput, Scope};
use serde::{Deserialize, Serialize};
use signal_findings::ScopedFinding;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Fact {
    id: Uuid,
    event_id: Uuid,
    sequence: u64,
    source: Option<String>,
    account: Option<String>,
    resource: Option<String>,
    binding_digest: String,
}
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Claims {
    schema_version: u32,
    scope_generation: Uuid,
    startup: Uuid,
    wal_floor: u64,
    findings: Vec<Fact>,
}
/// Serializable original-operation evidence for durable recovery. Deserializing
/// it grants no authority: publication freshly checks current enrollment; exact
/// reconciliation requires the original already committed companion claims.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScopedPublicationInput {
    scope: Scope,
    publication: PublicationInput,
    claims: Claims,
}
impl ScopedPublicationInput {
    /// Native authenticated admission and sequence ownership are host duties.
    /// Original unknown findings must use their retained bytes in `publication`;
    /// this method never annotates or upgrades them.
    pub fn from_host(
        mut publication: PublicationInput,
        producer: &ProducerEnrollment,
        derived: Vec<(u64, ScopedFinding)>,
    ) -> Result<Self, ControlError> {
        if derived.len() > 128
            || derived.capacity() > 128
            || publication.findings.len().saturating_add(derived.len()) > 128
        {
            return Err(ControlError::Full);
        }
        let mut facts = Vec::with_capacity(derived.len());
        for (sequence, payload) in derived {
            if payload.generation() != producer.scope_generation {
                return Err(ControlError::Fenced);
            }
            let finding = payload.finding();
            let selectors = payload.facts();
            let event_id = *finding.event_ids.first().ok_or(ControlError::Invalid)?;
            facts.push(Fact {
                id: finding.id,
                event_id,
                sequence,
                source: selectors.source.map(str::to_owned),
                account: selectors.account.map(str::to_owned),
                resource: selectors.resource.map(str::to_owned),
                binding_digest: payload.binding_digest().to_owned(),
            });
            let bytes = crate::publication::encode(finding)?;
            let input = crate::FindingInput {
                id: finding.id,
                bytes,
            };
            input.validate()?;
            publication.findings.push(input);
        }
        let input = Self {
            scope: producer.scope.clone(),
            publication,
            claims: Claims {
                schema_version: 1,
                scope_generation: producer.scope_generation,
                startup: producer.startup,
                wal_floor: producer.wal_floor,
                findings: facts,
            },
        };
        input.wire(&producer.scope)?;
        Ok(input)
    }
    pub fn publication(&self) -> &PublicationInput {
        &self.publication
    }
    pub(crate) fn wire(&self, scope: &Scope) -> Result<Vec<u8>, ControlError> {
        if &self.scope != scope {
            return Err(ControlError::Fenced);
        }
        self.publication.validate(scope)?;
        validate_claims(
            &self.claims,
            &self.publication.findings,
            self.publication.first_sequence,
            self.publication.last_sequence,
        )
    }
}

fn validate_claims(
    c: &Claims,
    findings: &[crate::FindingInput],
    first: u64,
    last: u64,
) -> Result<Vec<u8>, ControlError> {
    if c.schema_version != 1
        || c.scope_generation.is_nil()
        || c.startup.is_nil()
        || c.wal_floor > i64::MAX as u64
        || c.findings.len() > 128
        || c.findings.capacity() > 128
    {
        return Err(ControlError::Invalid);
    }
    let mut ids = std::collections::BTreeSet::new();
    for fact in &c.findings {
        if fact.id.is_nil()
            || fact.event_id.is_nil()
            || !ids.insert(fact.id)
            || fact.sequence <= c.wal_floor
            || fact.sequence < first
            || fact.sequence > last
            || fact.binding_digest.len() != 64
            || fact.binding_digest.capacity() > 64
            || !fact
                .binding_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || [&fact.source, &fact.account, &fact.resource]
                .iter()
                .any(|v| {
                    v.as_ref()
                        .is_some_and(|s| s.len() > 256 || s.capacity() > 256 || s.trim().is_empty())
                })
        {
            return Err(ControlError::Invalid);
        }
        let original = findings
            .iter()
            .find(|f| f.id == fact.id)
            .ok_or(ControlError::Invalid)?;
        let finding: signal_findings::Finding =
            serde_json::from_slice(&original.bytes).map_err(|_| ControlError::Invalid)?;
        finding.validate().map_err(|_| ControlError::Invalid)?;
        let expected = serde_json::json!({"schema_version":1,"generation":c.scope_generation,
                "binding_digest":fact.binding_digest,"source":fact.source,"account":fact.account,"resource":fact.resource});
        if finding.event_ids != [fact.event_id]
            || finding.attributes.get("signal.scope.v1") != Some(&expected)
        {
            return Err(ControlError::Invalid);
        }
    }
    let bytes = crate::publication::encode(c)?;
    if bytes.len() > 131072 {
        return Err(ControlError::Full);
    }
    Ok(bytes)
}
fn verify_rows(
    c: &Claims,
    findings: &[crate::FindingInput],
    rows: &[signal_storage::StoredEvent],
) -> Result<(), ControlError> {
    if rows.is_empty() || rows.len() > 4096 {
        return Err(ControlError::Invalid);
    }
    for fact in &c.findings {
        let row = rows
            .iter()
            .find(|r| r.sequence == fact.sequence)
            .ok_or(ControlError::Corrupt)?;
        if row.event.id != fact.event_id {
            return Err(ControlError::Corrupt);
        }
        let original = findings
            .iter()
            .find(|f| f.id == fact.id)
            .ok_or(ControlError::Corrupt)?;
        let finding: signal_findings::Finding =
            serde_json::from_slice(&original.bytes).map_err(|_| ControlError::Corrupt)?;
        let base = signal_findings::Finding::for_event(
            &finding.rule_id,
            &row.event,
            finding.severity,
            &finding.title,
        )
        .map_err(|_| ControlError::Corrupt)?;
        // Reconstruct solely to verify original content, never to renew its
        // authentication/startup or replace retained finding/claim bytes.
        let expected = signal_findings::DerivedFinding::from_event(base, &row.event, true)
            .map_err(|_| ControlError::Corrupt)?
            .into_scoped(c.scope_generation)
            .map_err(|_| ControlError::Corrupt)?;
        if expected.finding() != &finding {
            return Err(ControlError::Corrupt);
        }
    }
    Ok(())
}

/// Original canonical claims can be synced before any object upload. This
/// serialized evidence neither authenticates events nor renews an enrollment.
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScopedFindingClaims {
    scope: Scope,
    claims: Claims,
    findings: Vec<crate::FindingInput>,
}
impl ScopedFindingClaims {
    pub fn from_host(
        producer: &ProducerEnrollment,
        derived: Vec<(u64, ScopedFinding)>,
    ) -> Result<Self, ControlError> {
        if derived.len() > 128 || derived.capacity() > 128 {
            return Err(ControlError::Full);
        }
        let mut facts = Vec::with_capacity(derived.len());
        let mut findings = Vec::with_capacity(derived.len());
        for (sequence, payload) in derived {
            if payload.generation() != producer.scope_generation {
                return Err(ControlError::Fenced);
            }
            let finding = payload.finding();
            let selectors = payload.facts();
            facts.push(Fact {
                id: finding.id,
                event_id: *finding.event_ids.first().ok_or(ControlError::Invalid)?,
                sequence,
                source: selectors.source.map(str::to_owned),
                account: selectors.account.map(str::to_owned),
                resource: selectors.resource.map(str::to_owned),
                binding_digest: payload.binding_digest().to_owned(),
            });
            findings.push(crate::FindingInput {
                id: finding.id,
                bytes: crate::publication::encode(finding)?,
            });
        }
        let result = Self {
            scope: producer.scope.clone(),
            claims: Claims {
                schema_version: 1,
                scope_generation: producer.scope_generation,
                startup: producer.startup,
                wal_floor: producer.wal_floor,
                findings: facts,
            },
            findings,
        };
        result.validate(&producer.scope)?;
        Ok(result)
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn findings(&self) -> &[crate::FindingInput] {
        &self.findings
    }
    pub fn validate(&self, scope: &Scope) -> Result<(), ControlError> {
        if &self.scope != scope {
            return Err(ControlError::Fenced);
        }
        scope.validate()?;
        if self.findings.len() > 128 || self.findings.capacity() > 128 {
            return Err(ControlError::Full);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut bytes = 0usize;
        for f in &self.findings {
            f.validate()?;
            if !ids.insert(f.id) {
                return Err(ControlError::Invalid);
            }
            bytes += f.bytes.len();
        }
        if bytes > 512 * 1024 || self.findings.len() != self.claims.findings.len() {
            return Err(ControlError::Full);
        }
        validate_claims(&self.claims, &self.findings, 1, i64::MAX as u64)?;
        Ok(())
    }
    pub fn verify_rows(&self, rows: &[signal_storage::StoredEvent]) -> Result<(), ControlError> {
        self.validate(&self.scope)?;
        verify_rows(&self.claims, &self.findings, rows)
    }
    /// Attach exact original bytes to an already verified prepared manifest.
    /// The database still checks independently current authority on submission.
    pub fn attach(
        self,
        mut publication: PublicationInput,
    ) -> Result<ScopedPublicationInput, ControlError> {
        self.validate(&self.scope)?;
        for finding in self.findings {
            if let Some(existing) = publication.findings.iter().find(|f| f.id == finding.id) {
                if existing != &finding {
                    return Err(ControlError::Conflict);
                }
            } else {
                if publication.findings.len() >= 128 {
                    return Err(ControlError::Full);
                }
                publication.findings.push(finding);
            }
        }
        let result = ScopedPublicationInput {
            scope: self.scope,
            publication,
            claims: self.claims,
        };
        result.wire(&result.scope)?;
        Ok(result)
    }
}
impl ScopedPublicationInput {
    pub fn validate(&self, scope: &Scope) -> Result<(), ControlError> {
        self.wire(scope).map(drop)
    }
    pub fn verify_rows(&self, rows: &[signal_storage::StoredEvent]) -> Result<(), ControlError> {
        self.wire(&self.scope)?;
        verify_rows(&self.claims, &self.publication.findings, rows)
    }
}
