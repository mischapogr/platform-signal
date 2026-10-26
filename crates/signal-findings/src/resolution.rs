//! Exact host-side finding lookup facts. Neither type is a permission or a wire
//! authority. Current provider enrollment and all-contributor grants stay with
//! the consuming authenticated adapter.
use crate::{Finding, disposition::FindingReference};
use signal_protocol::access::ScopeFacts;
use uuid::Uuid;

/// Historical canonical facts from the store's physical scope boundary.
/// An explicitly absent selector is not an invented wildcard grant.
#[derive(Clone)]
pub struct CanonicalProvenance {
    pub(crate) generation: Uuid,
    pub(crate) source: Option<Box<str>>,
    pub(crate) account: Option<Box<str>>,
    pub(crate) resource: Option<Box<str>>,
    pub(crate) binding_digest: Box<str>,
}
impl CanonicalProvenance {
    pub fn generation(&self) -> Uuid {
        self.generation
    }
    pub fn facts(&self) -> ScopeFacts<'_> {
        ScopeFacts {
            source: self.source.as_deref(),
            account: self.account.as_deref(),
            resource: self.resource.as_deref(),
        }
    }
    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }
}
/// Host-only immutable lookup data. No Serialize/Deserialize implementation;
/// callers must authorize before constructing an explicit transport response.
#[derive(Clone)]
pub struct ResolvedFinding {
    pub(crate) reference: FindingReference,
    pub(crate) finding: Finding,
    pub(crate) original_sha256: [u8; 32],
    pub(crate) provenance: Option<CanonicalProvenance>,
}
impl ResolvedFinding {
    pub fn reference(&self) -> FindingReference {
        self.reference
    }
    pub fn finding(&self) -> &Finding {
        &self.finding
    }
    pub fn original_sha256(&self) -> [u8; 32] {
        self.original_sha256
    }
    /// None is unknown provenance, including legacy/pre-activation rows.
    /// Some describes only historical canonical single-scope derivation.
    pub fn canonical_provenance(&self) -> Option<&CanonicalProvenance> {
        self.provenance.as_ref()
    }
}
