//! Host-enrolled exact originals, never caller-supplied scope claims.
use super::Failure;
use sha2::{Digest, Sha256};
use signal_findings::{FindingContext, FindingStore, disposition::FindingReference};
use signal_protocol::access::{Operation, RequestGrant, ScopeFacts};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
pub(super) struct Scope {
    source: Option<String>,
    account: Option<String>,
    resource: Option<String>,
}
impl Scope {
    pub(super) fn from_facts(facts: ScopeFacts<'_>) -> Self {
        Self {
            source: facts.source.map(str::to_owned),
            account: facts.account.map(str::to_owned),
            resource: facts.resource.map(str::to_owned),
        }
    }
    pub(super) fn facts(&self) -> ScopeFacts<'_> {
        ScopeFacts {
            source: self.source.as_deref(),
            account: self.account.as_deref(),
            resource: self.resource.as_deref(),
        }
    }
}

/// Exact canonical store enrollment: authenticated from_event AND complete
/// same-scope from_events derivations, including retained canonical windows.
/// Unknown rows refuse individually; this is never an episode fallback.
pub(super) struct Registry {
    canonical: BTreeMap<Uuid, Arc<FindingStore>>,
    episodes: BTreeMap<Uuid, Arc<super::episode::Provider>>,
}
pub(super) struct Evidence {
    pub(super) finding: signal_findings::Finding,
    pub(super) episode: Option<signal_rules::correlation::Episode>,
}
impl Registry {
    #[cfg(test)]
    pub(super) fn episode_providers(&self) -> Vec<Arc<super::episode::Provider>> {
        self.episodes.values().cloned().collect()
    }
    pub(super) fn enroll_episode(
        &mut self,
        provider: Arc<super::episode::Provider>,
    ) -> Result<(), Failure> {
        if self.canonical.contains_key(&provider.stream())
            || self.episodes.contains_key(&provider.stream())
            || self.episodes.len() >= 16
        {
            return Err(Failure::Invalid);
        }
        self.episodes.insert(provider.stream(), provider);
        Ok(())
    }
    pub(super) async fn evidence(
        &self,
        reference: FindingReference,
        context: &FindingContext,
    ) -> Result<Evidence, Failure> {
        super::check(context)?;
        if let Some(provider) = self.episodes.get(&reference.stream_id) {
            let resolved = provider.resolve(reference, context).await?;
            return Ok(Evidence {
                finding: resolved.finding,
                episode: Some(resolved.episode),
            });
        }
        let original = self
            .canonical
            .get(&reference.stream_id)
            .ok_or(Failure::Unavailable)?
            .resolve_reference(reference, context.clone())
            .await
            .map_err(|_| Failure::Unavailable)?
            .ok_or(Failure::Denied)?;
        if original.canonical_provenance().is_none() {
            return Err(Failure::Unavailable);
        }
        Ok(Evidence {
            finding: original.finding().clone(),
            episode: None,
        })
    }
    pub(super) fn canonical(stream: Uuid, store: Arc<FindingStore>) -> Result<Self, Failure> {
        if stream.is_nil() {
            return Err(Failure::Invalid);
        }
        Ok(Self {
            canonical: BTreeMap::from([(stream, store)]),
            episodes: BTreeMap::new(),
        })
    }
    pub(super) async fn resolve(
        &self,
        references: &[FindingReference],
        context: &FindingContext,
    ) -> Result<Inventory, Failure> {
        if references.is_empty() || references.len() > 32 {
            return Err(Failure::Invalid);
        }
        let mut scopes = Vec::with_capacity(references.len());
        let mut ranges = Vec::with_capacity(references.len());
        let mut leases = Vec::new();
        let mut digest = Sha256::new();
        digest.update(b"PLATFORM::SIGNAL/case-originals/v1\0");
        for reference in references {
            super::check(context)?;
            if let Some(provider) = self.episodes.get(&reference.stream_id) {
                let resolved = provider.resolve(*reference, context).await?;
                digest.update(reference.stream_id.as_bytes());
                digest.update(reference.finding_id.as_bytes());
                digest.update(resolved.finding_sha256);
                digest.update(resolved.original_binding);
                ranges.push(append_scopes(&mut scopes, resolved.scopes)?);
                leases.push(resolved.lease);
                continue;
            }
            let store = self
                .canonical
                .get(&reference.stream_id)
                .ok_or(Failure::Unavailable)?;
            let original = store
                .resolve_reference(*reference, context.clone())
                .await
                .map_err(|_| Failure::Unavailable)?
                .ok_or(Failure::Denied)?;
            let provenance = original
                .canonical_provenance()
                .ok_or(Failure::Unavailable)?;
            // The store verified the complete single canonical scope and original
            // bytes. Reserved finding attributes alone never reach this branch.
            digest.update(reference.stream_id.as_bytes());
            digest.update(reference.finding_id.as_bytes());
            digest.update(original.original_sha256());
            digest.update(provenance.generation().as_bytes());
            digest.update(provenance.binding_digest().as_bytes());
            ranges.push(append_scopes(
                &mut scopes,
                vec![Scope::from_facts(provenance.facts())],
            )?);
        }
        super::check(context)?;
        Ok(Inventory {
            references: references.to_vec(),
            scopes,
            ranges,
            leases,
            digest: digest.finalize().into(),
        })
    }
}
fn append_scopes(
    scopes: &mut Vec<Scope>,
    incoming: Vec<Scope>,
) -> Result<std::ops::Range<usize>, Failure> {
    if incoming.is_empty() || incoming.len() > 1024usize.saturating_sub(scopes.len()) {
        return Err(Failure::Capacity);
    }
    let start = scopes.len();
    scopes.extend(incoming);
    Ok(start..scopes.len())
}

pub(super) struct Inventory {
    pub(super) references: Vec<FindingReference>,
    pub(super) scopes: Vec<Scope>,
    pub(super) digest: [u8; 32],
    pub(super) ranges: Vec<std::ops::Range<usize>>,
    pub(super) leases: Vec<super::episode::CustodyLease>,
}
impl Inventory {
    pub(super) fn bounds(&self) -> Result<Option<(u64, u64)>, Failure> {
        let mut bounds = None;
        for lease in &self.leases {
            lease.check()?;
            bounds = Some(bounds.map_or(
                (lease.not_before, lease.expires_at),
                |(from, until): (u64, u64)| {
                    (from.max(lease.not_before), until.min(lease.expires_at))
                },
            ));
        }
        Ok(bounds)
    }
    pub(super) fn authorize_reference(
        &self,
        grant: &RequestGrant,
        operation: Operation,
        reference: signal_findings::disposition::FindingReference,
    ) -> Result<(), Failure> {
        let at = crate::access::now().ok_or(Failure::Unavailable)?;
        self.bounds()?;
        let range = self
            .references
            .iter()
            .zip(&self.ranges)
            .find(|(r, _)| **r == reference)
            .map(|(_, range)| range.clone())
            .ok_or(Failure::Denied)?;
        let scopes = self
            .scopes
            .get(range)
            .filter(|s| !s.is_empty())
            .ok_or(Failure::Unavailable)?;
        if scopes
            .iter()
            .all(|scope| grant.allows(operation, scope.facts(), at))
        {
            Ok(())
        } else {
            Err(Failure::Denied)
        }
    }
    pub(super) fn authorize(
        &self,
        grant: &RequestGrant,
        operation: Operation,
    ) -> Result<(), Failure> {
        let now = crate::access::now().ok_or(Failure::Unavailable)?;
        self.bounds()?;
        if self.scopes.is_empty()
            || !self.scopes.iter().all(|scope| {
                grant.allows(operation, scope.facts(), now)
                    && grant.allows(Operation::ReadFindings, scope.facts(), now)
            })
        {
            return Err(Failure::Denied);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scopes(count: usize) -> Vec<Scope> {
        (0..count)
            .map(|_| {
                Scope::from_facts(ScopeFacts {
                    source: Some("fixture"),
                    account: None,
                    resource: None,
                })
            })
            .collect()
    }
    #[test]
    fn mixed_canonical_and_episode_ordering_never_exceeds_the_inventory_ceiling() {
        let mut inventory = Vec::new();
        for _ in 0..8 {
            assert!(append_scopes(&mut inventory, scopes(128)).is_ok());
        }
        assert!(matches!(
            append_scopes(&mut inventory, scopes(1)),
            Err(Failure::Capacity)
        ));
        assert_eq!(inventory.len(), 1024);
        let mut reverse = scopes(1);
        for _ in 0..7 {
            assert!(append_scopes(&mut reverse, scopes(128)).is_ok());
        }
        assert!(matches!(
            append_scopes(&mut reverse, scopes(128)),
            Err(Failure::Capacity)
        ));
        assert_eq!(reverse.len(), 897);
        assert_eq!(
            append_scopes(&mut reverse, scopes(127)).ok(),
            Some(897..1024)
        );
    }
}
