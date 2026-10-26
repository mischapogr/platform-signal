use super::binding::BindingView;
use super::d11::late;
use super::*;
// Existing public authentication APIs remain wrappers around the common engine.
impl State {
    pub fn new(b: &Binding) -> Self {
        Self::new_with(&BindingView::authentication(b))
    }
    pub fn metrics(&self, b: &Binding) -> Result<Metrics, Error> {
        self.metrics_with(&BindingView::authentication(b))
    }
    pub fn encode(&self, b: &Binding, c: &RuleContext) -> Result<Vec<u8>, Error> {
        self.encode_with(&BindingView::authentication(b), c)
    }
    pub fn decode(b: &Binding, bytes: &[u8], c: &RuleContext) -> Result<Self, Error> {
        Self::decode_with(&BindingView::authentication(b), bytes, c)
    }
    pub fn admit(
        &mut self,
        b: &Binding,
        stream: Uuid,
        position: u64,
        event: &SignalEvent,
        epoch: &Epoch,
        c: &RuleContext,
    ) -> Result<Admission, Error> {
        self.admit_with(
            &BindingView::authentication(b),
            stream,
            position,
            event,
            epoch,
            c,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn admit_checked(
        &mut self,
        b: &Binding,
        stream: Uuid,
        position: u64,
        event: &SignalEvent,
        epoch: &Epoch,
        lookup: Option<&history::Lookup<'_>>,
        c: &RuleContext,
    ) -> Result<Admission, Error> {
        self.admit_checked_with(
            &BindingView::authentication(b),
            stream,
            position,
            event,
            epoch,
            lookup,
            c,
        )
    }
    pub fn seal(&mut self, b: &Binding, epoch: &Epoch, c: &RuleContext) -> Result<Seal, Error> {
        self.seal_with(&BindingView::authentication(b), epoch, c)
    }
}
impl State {
    pub(super) fn new_with(binding: &BindingView<'_>) -> Self {
        Self {
            schema_version: binding.version(),
            binding: binding.digest,
            observations: vec![],
            aliases: vec![],
            episodes: vec![],
            effects: vec![],
            completions: vec![],
            archive: None,
            positions: binding
                .config
                .sources
                .iter()
                .map(|s| (s.stream, 0))
                .collect(),
            watermark: None,
            last_seal_evidence: vec![],
            degraded_through: None,
            retired_late_inputs: 0,
            runtime_seal: None,
        }
    }
    pub(super) fn metrics_with(&self, b: &BindingView<'_>) -> Result<Metrics, Error> {
        if self.binding != b.digest {
            return Err(Error::Conflict);
        }
        Ok(Metrics {
            retained_events: self.observations.len(),
            event_capacity: b.config.max_events,
            retained_aliases: self.aliases.len(),
            alias_capacity: 256,
            retained_episodes: self.episodes.len(),
            episode_capacity: b.config.max_episodes,
            late_inputs: self
                .retired_late_inputs
                .saturating_add(self.observations.iter().filter(|o| late(o)).count() as u64),
        })
    }
    /// Original immutable bytes; the host must authorize the complete artifact scope.
    pub fn original_effect(&self, id: Uuid) -> Option<crate::state_journal::Output> {
        self.effects
            .iter()
            .find(|e| e.id == id)
            .map(|e| crate::state_journal::Output {
                schema_version: 1,
                id: e.id,
                bytes: e.bytes.clone(),
            })
    }
    pub fn episodes(&self) -> &[Episode] {
        &self.episodes
    }
    /// Contiguous host delivery ordinals, independent of native producer sequence.
    pub fn source_positions(&self) -> &[(Uuid, u64)] {
        &self.positions
    }
    pub fn watermark(&self) -> Option<DateTime<Utc>> {
        self.watermark
    }
    pub(super) fn encode_with(
        &self,
        b: &BindingView<'_>,
        c: &RuleContext,
    ) -> Result<Vec<u8>, Error> {
        self.validate_with(b, c)?;
        codec::encode(self, b.config.max_state_bytes, c)
    }
    pub(super) fn decode_with(
        b: &BindingView<'_>,
        bytes: &[u8],
        c: &RuleContext,
    ) -> Result<Self, Error> {
        check(c)?;
        if bytes.len() > b.config.max_state_bytes {
            return Err(Error::Capacity);
        }
        let state: Self = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        state.validate_with(b, c)?;
        Ok(state)
    }
    pub(super) fn validate_with(&self, b: &BindingView<'_>, c: &RuleContext) -> Result<(), Error> {
        check(c)?;
        if self.schema_version != b.version()
            || self.binding != b.digest
            || self.observations.len() > b.config.max_events
            || self.episodes.len() > b.config.max_episodes
            || self.aliases.len() > 256
            || self.effects.len() != self.episodes.len()
            || self.completions.len() > b.config.max_events
            || self.positions.len() != b.config.sources.len()
        {
            return Err(Error::Conflict);
        }
        if b.runtime_binding().is_some() && self.retired_late_inputs != 0 && self.archive.is_none()
        {
            return Err(Error::Conflict);
        }
        if b.runtime_binding().is_none() && self.runtime_seal.is_some() {
            return Err(Error::Conflict);
        }
        history::validate_metadata_with(b, self, c)?;
        let mut streams = BTreeSet::new();
        for (stream, _) in &self.positions {
            if !streams.insert(*stream) || !b.config.sources.iter().any(|s| s.stream == *stream) {
                return Err(Error::Conflict);
            }
        }
        if let Some(watermark) = self.watermark {
            if self.last_seal_evidence.len() != b.config.sources.len() {
                return Err(Error::Conflict);
            }
            let mut streams = BTreeSet::new();
            for p in &self.last_seal_evidence {
                b.historical_proof(p)?;
                if !streams.insert(p.stream)
                    || self
                        .positions
                        .iter()
                        .find(|(s, _)| *s == p.stream)
                        .is_none_or(|(_, n)| p.position > *n)
                {
                    return Err(Error::Conflict);
                }
            }
            let min = if let Some(runtime) = b.runtime_binding() {
                Some(d14::state::historical_watermark(
                    runtime,
                    &self.last_seal_evidence,
                    &self.runtime_seal.as_ref().ok_or(Error::Conflict)?.policy,
                    c,
                )?)
            } else {
                self.last_seal_evidence
                    .iter()
                    .map(|p| {
                        p.frontier
                            .checked_sub_signed(TimeDelta::milliseconds(b.config.lateness_ms))
                    })
                    .collect::<Option<Vec<_>>>()
                    .ok_or(Error::Invalid)?
                    .into_iter()
                    .min()
            };
            if min != Some(watermark) {
                return Err(Error::Conflict);
            }
        } else if !self.last_seal_evidence.is_empty()
            || self.runtime_seal.is_some()
            || self.degraded_through.is_some()
        {
            return Err(Error::Conflict);
        }
        let mut ids = BTreeSet::new();
        let mut natives = BTreeSet::new();
        for o in &self.observations {
            check(c)?;
            b.historical_proof(&o.verification)?;
            if !ids.insert(o.event.id)
                || o.native
                    .as_ref()
                    .is_some_and(|n| !natives.insert(n.clone()))
            {
                return Err(Error::Conflict);
            }
            let mut rebuilt = b.rebuild(o, c)?;
            d14::state::verify_range(o)?;
            rebuilt.admission_watermark = o.admission_watermark;
            rebuilt.source_position = o.source_position;
            if o.event.timestamp < o.verification.coverage_from
                || o.event.timestamp > o.verification.frontier
                || o.source_position == 0
                || o.source_position > o.verification.position
                || self
                    .positions
                    .iter()
                    .find(|(s, _)| *s == o.verification.stream)
                    .is_none_or(|(_, p)| o.source_position > *p)
                || rebuilt != *o
                || o.admission_watermark
                    .is_some_and(|w| self.watermark.is_none_or(|current| w > current))
            {
                return Err(Error::Conflict);
            }
        }
        let mut alias_ids = BTreeSet::new();
        for a in &self.aliases {
            if !alias_ids.insert(a.id) {
                return Err(Error::Conflict);
            }
            if let Some(original) = self.observations.iter().find(|o| match &a.native {
                Some(n) => o.native.as_ref() == Some(n),
                None => o.event.id == a.original_id,
            }) {
                if original.verification.stream != a.stream
                    || original.content_sha256 != a.content_sha256
                    || original.native != a.native
                    || a.original_id != original.event.id
                    || (original.event.id == a.id
                        && original.canonical_sha256 != a.canonical_sha256)
                {
                    return Err(Error::Conflict);
                }
            } else if a.origin_archive.is_none() || self.archive.is_none() {
                return Err(Error::Conflict);
            }
        }
        if self
            .observations
            .iter()
            .any(|o| !alias_ids.contains(&o.event.id))
        {
            return Err(Error::Conflict);
        }
        b.validate_keys(&self.observations)?;
        let mut episode_ids = BTreeSet::new();
        for e in &self.episodes {
            if !episode_ids.insert(e.id)
                || e.observation_count > self.observations.len()
                || self.watermark.is_none_or(|w| e.sealed_watermark > w)
            {
                return Err(Error::Conflict);
            }
            for p in &e.verification {
                b.historical_proof(p)?;
                if self
                    .positions
                    .iter()
                    .find(|(s, _)| *s == p.stream)
                    .is_none_or(|(_, n)| p.position > *n)
                {
                    return Err(Error::Conflict);
                }
            }
            let observations = &self.observations[..e.observation_count];
            let anchor = observations
                .iter()
                .position(|o| e.originals.last().is_some_and(|x| x.id == o.event.id))
                .ok_or(Error::Conflict)?;
            if b.episode(
                observations,
                anchor,
                e.sealed_watermark,
                &e.verification,
                e.runtime
                    .as_ref()
                    .map_or(&[][..], |r| r.policy_coverage.as_slice()),
                e.coverage_degraded_through,
                c,
            )? != *e
            {
                return Err(Error::Conflict);
            }
        }
        for (episode, effect) in self.episodes.iter().zip(&self.effects) {
            if effect.id != episode.id || codec::encode(episode, 65536, c)? != effect.bytes {
                return Err(Error::Conflict);
            }
        }
        codec::encode(self, b.config.max_state_bytes, c)?;
        Ok(())
    }
    /// Stage on a clone; refusal never changes the caller's accepted state.
    pub(super) fn admit_with(
        &mut self,
        b: &BindingView<'_>,
        stream: Uuid,
        position: u64,
        event: &SignalEvent,
        epoch: &Epoch,
        c: &RuleContext,
    ) -> Result<Admission, Error> {
        self.admit_checked_with(b, stream, position, event, epoch, None, c)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit_checked_with(
        &mut self,
        b: &BindingView<'_>,
        stream: Uuid,
        position: u64,
        event: &SignalEvent,
        epoch: &Epoch,
        lookup: Option<&history::Lookup<'_>>,
        c: &RuleContext,
    ) -> Result<Admission, Error> {
        self.admit_selected_with(b, stream, position, event, epoch, lookup, None, None, c)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit_selected_with(
        &mut self,
        b: &BindingView<'_>,
        stream: Uuid,
        position: u64,
        event: &SignalEvent,
        epoch: &Epoch,
        lookup: Option<&history::Lookup<'_>>,
        decision: Option<&d14::CurrentDecision>,
        original_input: Option<&RuleContext>,
        c: &RuleContext,
    ) -> Result<Admission, Error> {
        epoch.valid_with(b, c)?;
        self.validate_with(b, c)?;
        if position == 0 {
            return Err(Error::Conflict);
        }
        let proof = epoch.proof(stream)?;
        if position > proof.position
            || self
                .last_seal_evidence
                .iter()
                .find(|p| p.stream == stream)
                .is_some_and(|old| proof.frontier < old.frontier)
        {
            return Err(Error::Conflict);
        }
        let mut input = b.observation(stream, event, proof, c)?;
        let cold = history::resolve(b, self, &input, lookup, c)?;
        let mut next = self.clone();
        let frontier = next
            .positions
            .iter_mut()
            .find(|(s, _)| *s == stream)
            .ok_or(Error::Conflict)?;
        if position > frontier.1 && frontier.1.checked_add(1) != Some(position) {
            return Err(Error::Conflict);
        }
        let canonical = self.aliases.iter().find(|o| o.id == event.id);
        let native = input.native.as_ref().and_then(|n| {
            self.observations
                .iter()
                .find(|o| o.native.as_ref() == Some(n))
        });
        if canonical.is_some_and(|o| {
            o.canonical_sha256 != input.canonical_sha256
                || o.stream != stream
                || o.native != input.native
        }) || native.is_some_and(|o| o.content_sha256 != input.content_sha256)
        {
            return Err(Error::Conflict);
        }
        history::consistent_local(self, &input, cold.as_ref())?;
        let original_id = cold
            .as_ref()
            .map(|x| x.original_id)
            .or_else(|| canonical.map(|a| a.original_id))
            .or_else(|| native.map(|o| o.event.id))
            .unwrap_or(event.id);
        let origin_archive = cold
            .as_ref()
            .map(|x| x.origin_archive)
            .or_else(|| canonical.and_then(|a| a.origin_archive))
            .or_else(|| {
                native.and_then(|o| {
                    self.aliases
                        .iter()
                        .find(|a| a.id == o.event.id)
                        .and_then(|a| a.origin_archive)
                })
            });
        let original_effect = cold
            .as_ref()
            .and_then(|x| x.effect.clone())
            .or_else(|| canonical.and_then(|a| a.effect.clone()))
            .or_else(|| {
                self.aliases
                    .iter()
                    .find(|a| a.original_id == original_id)
                    .and_then(|a| a.effect.clone())
            });
        if canonical.is_none() {
            if next.aliases.len() >= 256 {
                return Err(Error::Capacity);
            }
            next.aliases.push(Alias {
                id: event.id,
                original_id,
                origin_archive,
                effect: original_effect,
                lookup: lookup.map(|l| l.retained(c)).transpose()?,
                canonical_sha256: input.canonical_sha256,
                native: input.native.clone(),
                content_sha256: input.content_sha256,
                stream,
            });
        }
        let admission = if canonical.is_some() || native.is_some() || cold.is_some() {
            Admission::Duplicate
        } else {
            d14::state::verify_range(&input)?;
            if let Some(runtime) = b.runtime_binding() {
                if let Some(decision) = decision {
                    let original = d14::Input::new(runtime, stream, event, c)?;
                    input = d14::state::observation(
                        runtime,
                        &original,
                        proof,
                        Some(decision.retained(runtime, &original, c)?),
                        c,
                    )?;
                }
            } else if decision.is_some() {
                return Err(Error::Invalid);
            }
            if position <= frontier.1 {
                return Err(Error::Conflict);
            }
            if next.observations.len() >= b.config.max_events {
                return Err(Error::Capacity);
            }
            input.admission_watermark = self.watermark;
            input.source_position = position;
            let result = if late(&input) {
                Admission::Late
            } else {
                Admission::New
            };
            next.observations.push(input);
            result
        };
        frontier.1 = frontier.1.max(position);
        next.validate_with(b, c)?;
        if admission != Admission::Duplicate
            && let (Some(runtime), Some(decision)) = (b.runtime_binding(), decision)
        {
            decision.retained(runtime, &d14::Input::new(runtime, stream, event, c)?, c)?;
        }
        if let Some(lookup) = lookup {
            lookup.valid(b, c)?;
        }
        if admission != Admission::Duplicate
            && let Some(decision) = decision
        {
            for original in decision.original_contexts() {
                check(original)?;
            }
        }
        epoch.valid_with(b, c)?;
        if let Some(original) = original_input {
            check(original)?;
        }
        check(c)?;
        *self = next;
        Ok(admission)
    }
    pub(super) fn seal_with(
        &mut self,
        b: &BindingView<'_>,
        epoch: &Epoch,
        c: &RuleContext,
    ) -> Result<Seal, Error> {
        epoch.valid_with(b, c)?;
        self.validate_with(b, c)?;
        let Some(watermark) = epoch.watermark_with(b) else {
            return Ok(Seal {
                watermark: self.watermark,
                new_episodes: 0,
                coverage_gap: true,
            });
        };
        for proof in &epoch.evidence {
            if self
                .positions
                .iter()
                .find(|(s, _)| *s == proof.stream)
                .is_none_or(|(_, n)| *n != proof.position)
                || self
                    .last_seal_evidence
                    .iter()
                    .find(|old| old.stream == proof.stream)
                    .is_some_and(|old| {
                        proof.frontier < old.frontier || proof.position < old.position
                    })
            {
                return Err(Error::Conflict);
            }
        }
        if self.watermark.is_some_and(|w| watermark < w) {
            return Err(Error::Conflict);
        }
        let mut next = self.clone();
        let mut count = 0;
        if let Some(old) = &self.runtime_seal {
            for p in &epoch.policy {
                if old
                    .policy
                    .iter()
                    .find(|o| o.authority == p.authority)
                    .is_some_and(|o| p.frontier < o.frontier)
                {
                    return Err(Error::Conflict);
                }
            }
        }
        let incomplete = epoch.evidence.iter().any(|p| !p.complete)
            || epoch.policy.iter().any(|p| !p.complete());
        if incomplete {
            let until = watermark
                .checked_add_signed(TimeDelta::milliseconds(
                    b.config.extra_lookback_ms + b.config.correlation_ms,
                ))
                .ok_or(Error::Invalid)?;
            next.degraded_through = Some(next.degraded_through.map_or(until, |old| old.max(until)));
        }
        let mut coverage_gap = incomplete || next.degraded_through.is_some_and(|t| watermark <= t);
        let mut candidates: Vec<_> = self.observations.iter().enumerate().collect();
        candidates.sort_by(|(_, a), (_, other)| {
            b.time(a)
                .cmp(&b.time(other))
                .then_with(|| a.native.cmp(&other.native))
                .then_with(|| a.event.id.cmp(&other.event.id))
        });
        for (index, o) in candidates {
            check(c)?;
            if b.time(o) > watermark || !b.candidate(o) {
                continue;
            }
            if self
                .completions
                .iter()
                .any(|m| m.canonical_id == o.event.id)
                || self.episodes.iter().any(|e| {
                    e.originals
                        .last()
                        .is_some_and(|original| original.id == o.event.id)
                })
            {
                continue;
            }
            if next.episodes.len() >= b.config.max_episodes {
                return Err(Error::Capacity);
            }
            let e = b.episode(
                &self.observations,
                index,
                watermark,
                &epoch.evidence,
                &epoch.policy,
                next.degraded_through,
                c,
            )?;
            coverage_gap |= e.coverage_gap;
            next.effects.push(Effect {
                id: e.id,
                bytes: codec::encode(&e, 65536, c)?,
            });
            next.episodes.push(e);
            count += 1;
        }
        next.watermark = Some(watermark);
        next.last_seal_evidence = epoch.evidence.clone();
        next.runtime_seal = b.runtime_binding().map(|_| d14::state::RuntimeSeal {
            policy: epoch.policy.clone(),
        });
        next.validate_with(b, c)?;
        epoch.valid_with(b, c)?;
        *self = next;
        Ok(Seal {
            watermark: Some(watermark),
            new_episodes: count,
            coverage_gap,
        })
    }
}
