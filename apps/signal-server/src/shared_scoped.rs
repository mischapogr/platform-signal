//! Original pre-upload scoped plans. Host authentication is a separate duty.
use crate::shared::PublicationDraft;
use signal_control::{
    ControlError, ProducerEnrollment, Scope, ScopedFindingClaims, ScopedPublicationInput,
};
use signal_findings::ScopedFinding;
use signal_storage::StoredEvent;

#[derive(Clone, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScopedPublicationDraft {
    draft: PublicationDraft,
    claims: ScopedFindingClaims,
}
impl ScopedPublicationDraft {
    /// Before construction the host must establish native authenticated NEW
    /// admission above this producer's original startup WAL floor. Retained
    /// legacy findings use their exact bytes in draft, with no derived claim.
    pub fn from_host(
        draft: PublicationDraft,
        producer: &ProducerEnrollment,
        rows: &[StoredEvent],
        derived: Vec<(u64, ScopedFinding)>,
    ) -> Result<Self, ControlError> {
        let result = Self {
            draft,
            claims: ScopedFindingClaims::from_host(producer, derived)?,
        };
        result.validate(rows, &producer.scope)?;
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
    pub(crate) fn validate(&self, rows: &[StoredEvent], scope: &Scope) -> Result<(), ControlError> {
        self.claims.validate(scope)?;
        self.claims.verify_rows(rows)?;
        self.render()?.validate(rows)
    }
    pub(crate) fn attach(
        &self,
        request: signal_control::PublicationInput,
    ) -> Result<ScopedPublicationInput, ControlError> {
        self.claims.clone().attach(request)
    }
}
