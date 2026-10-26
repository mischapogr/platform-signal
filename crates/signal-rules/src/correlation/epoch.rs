use super::binding::BindingView;
use super::*;
pub(super) fn capture_evidence<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<d14::CaptureEvidence>, D::Error> {
    Ok(Some(d14::CaptureEvidence::deserialize(d)?))
}
impl Epoch {
    pub fn new(b: &Binding, p: Vec<Verification>, c: &RuleContext) -> Result<Self, Error> {
        check(c)?;
        if p.len() > b.config.sources.len() {
            return Err(Error::Invalid);
        }
        Self::new_with(
            &BindingView::authentication(b),
            p.into_iter().map(|p| (p, None)).collect(),
            Vec::new(),
            c,
        )
    }
    pub(super) fn valid(&self, b: &Binding, c: &RuleContext) -> Result<(), Error> {
        self.valid_with(&BindingView::authentication(b), c)
    }
    pub(super) fn watermark(&self, b: &Binding) -> Option<DateTime<Utc>> {
        self.watermark_with(&BindingView::authentication(b))
    }
}
impl Epoch {
    pub(super) fn new_with(
        binding: &BindingView<'_>,
        proofs: Vec<(Verification, Option<d14::CaptureEvidence>)>,
        policy_proofs: Vec<d14::PolicyCoverageVerification>,
        context: &RuleContext,
    ) -> Result<Self, Error> {
        check(context)?;
        if proofs.len() > binding.config.sources.len() {
            return Err(Error::Invalid);
        }
        let mut evidence = Vec::new();
        let mut seen = BTreeSet::new();
        let mut bounded = context.clone();
        for (mut p, capture) in proofs {
            if (binding.version() == 1 && capture.is_some())
                || (binding.version() == 2
                    && capture
                        .as_ref()
                        .is_none_or(|c| !c.metadata_only || c.enrollment_sha256 != binding.digest))
            {
                return Err(Error::Unverified);
            }
            if let Some(capture) = &capture {
                p.complete &= capture.execution_continuity && capture.clock_continuity;
            }
            let s = binding
                .config
                .sources
                .iter()
                .find(|s| s.stream == p.stream)
                .ok_or(Error::Unverified)?;
            if !seen.insert(p.stream)
                || p.source_binding != s.binding
                || p.source_config_revision != s.config_revision
                || p.authority_keys_sha256 != binding.config.authority_keys_sha256
                || !identity(&p.verification_reference)
                || !p.authenticated
                || p.verified_at > p.now
                || p.now >= p.verified_until
                || p.coverage_from > p.frontier
                || p.frontier > p.now
            {
                return Err(Error::Unverified);
            }
            let ttl = (p.verified_until - p.now)
                .to_std()
                .map_err(|_| Error::Unverified)?;
            bounded.deadline = bounded.deadline.min(
                tokio::time::Instant::now()
                    .checked_add(ttl)
                    .ok_or(Error::Invalid)?,
            );
            evidence.push(VerificationEvidence {
                stream: p.stream,
                position: p.position,
                source_binding: p.source_binding,
                source_config_revision: p.source_config_revision,
                authority_keys_sha256: p.authority_keys_sha256,
                verification_reference: p.verification_reference,
                verified_at: p.verified_at,
                verified_until: p.verified_until,
                assessed_at: p.now,
                coverage_from: p.coverage_from,
                frontier: p.frontier,
                complete: p.complete,
                runtime: capture,
            });
        }
        let mut policy = Vec::new();
        if let Some(runtime) = binding.runtime_binding() {
            if policy_proofs.len() > runtime.config.policy_authorities.len() {
                return Err(Error::Invalid);
            }
            let mut seen = BTreeSet::new();
            for proof in policy_proofs {
                let e = d14::coverage_evidence(runtime, proof, context)?;
                if !seen.insert(e.authority) {
                    return Err(Error::Conflict);
                }
                let ttl = (e.verified_until - e.assessed_at)
                    .to_std()
                    .map_err(|_| Error::Unverified)?;
                bounded.deadline = bounded.deadline.min(
                    tokio::time::Instant::now()
                        .checked_add(ttl)
                        .ok_or(Error::Invalid)?,
                );
                policy.push(e);
            }
            policy.sort_by_key(|p| p.authority);
        } else if !policy_proofs.is_empty() {
            return Err(Error::Invalid);
        }
        evidence.sort_by_key(|p| p.stream);
        Ok(Self {
            binding: binding.digest,
            evidence,
            context: bounded,
            policy,
        })
    }
    pub(super) fn valid_with(&self, b: &BindingView<'_>, c: &RuleContext) -> Result<(), Error> {
        check(c)?;
        check(&self.context)?;
        if self.binding != b.digest {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    pub(super) fn proof(&self, stream: Uuid) -> Result<&VerificationEvidence, Error> {
        self.evidence
            .iter()
            .find(|e| e.stream == stream)
            .ok_or(Error::Unverified)
    }
    pub(super) fn watermark_with(&self, b: &BindingView<'_>) -> Option<DateTime<Utc>> {
        let mut frontiers = Vec::new();
        for s in &b.config.sources {
            frontiers.push(
                self.proof(s.stream)
                    .ok()?
                    .frontier
                    .checked_sub_signed(TimeDelta::milliseconds(b.config.lateness_ms))?,
            );
        }
        if let Some(runtime) = b.runtime_binding() {
            for a in &runtime.config.policy_authorities {
                frontiers.push(
                    self.policy
                        .iter()
                        .find(|p| p.authority == a.id)?
                        .frontier
                        .checked_sub_signed(TimeDelta::milliseconds(b.config.lateness_ms))?,
                );
            }
        }
        frontiers.into_iter().min()
    }
}
