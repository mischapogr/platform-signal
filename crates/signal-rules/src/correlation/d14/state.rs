//! Runtime observations in the common bounded correlation state. Historical
//! decoding validates data; it never reconstructs fresh source/policy permits.
use super::*;
use crate::correlation::binding::BindingView;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::correlation) struct Retained {
    pub(super) projection: Projection,
    // Explicit absence is the original classification gap, not a request to
    // classify this native operation again on subsequent delivery.
    pub(super) decision: Option<DecisionEvidence>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::correlation) struct RuntimeSeal {
    pub(in crate::correlation) policy: Vec<PolicyCoverageEvidence>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEpisode {
    pub policy_coverage: Vec<PolicyCoverageEvidence>,
    pub decisions: Vec<DecisionEvidence>,
}
pub(in crate::correlation) fn seal_evidence<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RuntimeSeal>, D::Error> {
    Ok(Some(RuntimeSeal::deserialize(d)?))
}
pub(in crate::correlation) fn episode_evidence<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<RuntimeEpisode>, D::Error> {
    Ok(Some(RuntimeEpisode::deserialize(d)?))
}
pub(in crate::correlation) fn historical_watermark(
    b: &RuntimeBinding,
    sources: &[VerificationEvidence],
    policies: &[PolicyCoverageEvidence],
    c: &RuleContext,
) -> Result<DateTime<Utc>, Error> {
    if sources.len() != b.config.sources.len()
        || policies.len() != b.config.policy_authorities.len()
    {
        return Err(Error::Conflict);
    }
    let mut streams = BTreeSet::new();
    let mut authorities = BTreeSet::new();
    let mut frontiers = Vec::new();
    for p in sources {
        historical_proof(b, p)?;
        if !streams.insert(p.stream) {
            return Err(Error::Conflict);
        }
        frontiers.push(p.frontier);
    }
    for p in policies {
        p.validate_historical(b, c)?;
        if !authorities.insert(p.authority) {
            return Err(Error::Conflict);
        }
        frontiers.push(p.frontier);
    }
    frontiers
        .into_iter()
        .min()
        .ok_or(Error::Conflict)?
        .checked_sub_signed(TimeDelta::milliseconds(b.config.lateness_ms))
        .ok_or(Error::Invalid)
}
pub(in crate::correlation) fn retained<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Retained>, D::Error> {
    Ok(Some(Retained::deserialize(d)?))
}
impl Retained {
    pub(in crate::correlation) fn time(&self) -> DateTime<Utc> {
        let ns = self
            .projection
            .operation
            .interval()
            .map_or(self.projection.observed_ns, |i| i.exit_ns);
        // Projection validation bounds these unsigned nanoseconds by i64::MAX.
        DateTime::from_timestamp_nanos(ns as i64)
    }
    pub(in crate::correlation) fn lookback_start(
        &self,
        correlation_ms: i64,
    ) -> Result<DateTime<Utc>, Error> {
        let ns = self
            .projection
            .operation
            .interval()
            .map_or(self.projection.observed_ns, |i| i.entry_ns);
        DateTime::from_timestamp_nanos(ns as i64)
            .checked_sub_signed(TimeDelta::milliseconds(correlation_ms))
            .ok_or(Error::Invalid)
    }
    pub(in crate::correlation) fn process(&self) -> &Process {
        &self.projection.process
    }
}
pub(in crate::correlation) fn historical_proof(
    b: &RuntimeBinding,
    p: &VerificationEvidence,
) -> Result<(), Error> {
    let s = b
        .config
        .sources
        .iter()
        .find(|s| s.stream == p.stream)
        .ok_or(Error::Conflict)?;
    let capture = p.runtime.as_ref().ok_or(Error::Conflict)?;
    if p.source_binding != s.binding
        || p.source_config_revision != s.config_revision
        || p.authority_keys_sha256 != b.config.authority_keys_sha256
        || !identity(&p.verification_reference)
        || p.verified_at > p.assessed_at
        || p.assessed_at >= p.verified_until
        || p.coverage_from > p.frontier
        || p.frontier > p.assessed_at
        || capture.enrollment_sha256 != b.digest
        || !capture.metadata_only
        || (p.complete && (!capture.execution_continuity || !capture.clock_continuity))
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub(in crate::correlation) fn observation(
    b: &RuntimeBinding,
    input: &Input,
    proof: &VerificationEvidence,
    decision: Option<DecisionEvidence>,
    c: &RuleContext,
) -> Result<Observation, Error> {
    historical_proof(b, proof)?;
    if input.binding != b.digest || input.stream != proof.stream {
        return Err(Error::Conflict);
    }
    if let Some(d) = &decision {
        d.validate_historical(b, input, c)?;
    }
    Ok(Observation {
        event: input.event.clone(),
        canonical_sha256: input.canonical_sha256,
        native: Some(NativeId {
            stream: input.stream,
            boot: input.projection.native.capture.to_string(),
            sequence: input.native_sequence(),
        }),
        content_sha256: input.content_sha256,
        key: None,
        success: None,
        verification: proof.clone(),
        admission_watermark: None,
        source_position: 0,
        runtime: Some(Retained {
            projection: input.projection.clone(),
            decision,
        }),
    })
}
pub(in crate::correlation) fn verify_range(o: &Observation) -> Result<(), Error> {
    let p = &o.verification;
    if o.event.timestamp < p.coverage_from || o.event.timestamp > p.frontier {
        return Err(Error::Unverified);
    }
    if let Some(i) = o
        .runtime
        .as_ref()
        .and_then(|r| r.projection.operation.interval())
    {
        let from = p
            .coverage_from
            .timestamp_nanos_opt()
            .ok_or(Error::Unverified)?;
        let through = p.frontier.timestamp_nanos_opt().ok_or(Error::Unverified)?;
        if from < 0 || through < 0 || from as u64 > i.entry_ns || (through as u64) < i.exit_ns {
            return Err(Error::Unverified);
        }
    }
    Ok(())
}
pub(in crate::correlation) fn rebuild(
    b: &RuntimeBinding,
    o: &Observation,
    c: &RuleContext,
) -> Result<Observation, Error> {
    let r = o.runtime.as_ref().ok_or(Error::Conflict)?;
    let input = Input::new(b, o.verification.stream, &o.event, c)?;
    observation(b, &input, &o.verification, r.decision.clone(), c)
}

/// Typed facade over shared state, aliases, positions and interval-aware sealing.
/// Journal composition is in correlation::journal; protected history is pending.
pub struct RuntimeState {
    inner: State,
}
impl RuntimeState {
    pub(in crate::correlation) fn from_inner(inner: State) -> Self {
        Self { inner }
    }
    pub fn new(b: &RuntimeBinding) -> Self {
        Self {
            inner: State::new_with(&BindingView::runtime(b)),
        }
    }
    pub fn metrics(&self, b: &RuntimeBinding) -> Result<Metrics, Error> {
        self.inner.metrics_with(&BindingView::runtime(b))
    }
    pub fn source_positions(&self) -> &[(Uuid, u64)] {
        self.inner.source_positions()
    }
    pub fn episodes(&self) -> &[Episode] {
        self.inner.episodes()
    }
    pub fn original_effect(&self, id: Uuid) -> Option<crate::state_journal::Output> {
        self.inner.original_effect(id)
    }
    pub fn archive_anchor(&self) -> Option<&history::Anchor> {
        self.inner.archive_anchor()
    }
    pub fn watermark(&self) -> Option<DateTime<Utc>> {
        self.inner.watermark()
    }
    pub fn seal(
        &mut self,
        b: &RuntimeBinding,
        epoch: &RuntimeEpoch,
        c: &RuleContext,
    ) -> Result<Seal, Error> {
        self.inner
            .seal_with(&BindingView::runtime(b), &epoch.inner, c)
    }
    pub fn encode(&self, b: &RuntimeBinding, c: &RuleContext) -> Result<Vec<u8>, Error> {
        self.inner.encode_with(&BindingView::runtime(b), c)
    }
    pub fn decode(b: &RuntimeBinding, bytes: &[u8], c: &RuleContext) -> Result<Self, Error> {
        Ok(Self {
            inner: State::decode_with(&BindingView::runtime(b), bytes, c)?,
        })
    }
    pub fn admit(
        &mut self,
        b: &RuntimeBinding,
        input: &Input,
        position: u64,
        epoch: &RuntimeEpoch,
        decision: Option<&CurrentDecision>,
        c: &RuleContext,
    ) -> Result<Admission, Error> {
        self.admit_checked(b, input, position, epoch, decision, None, c)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn admit_checked(
        &mut self,
        b: &RuntimeBinding,
        input: &Input,
        position: u64,
        epoch: &RuntimeEpoch,
        decision: Option<&CurrentDecision>,
        lookup: Option<&history::Lookup<'_>>,
        c: &RuleContext,
    ) -> Result<Admission, Error> {
        // Keep the input's original context, in addition to the common engine's
        // source epoch and any first-admission classification contexts.
        check(&input.original)?;
        if input.binding != b.digest {
            return Err(Error::Conflict);
        }
        self.inner.admit_selected_with(
            &BindingView::runtime(b),
            input.stream,
            position,
            &input.event,
            &epoch.inner,
            lookup,
            decision,
            Some(&input.original),
            c,
        )
    }
}
