//! Journal-free bounded transitions for local and fenced shared persistence.
use super::*;
mod shared_binding;
mod shared_metadata;
mod shared_recovery;
pub use shared_binding::{SharedBinding, SharedError};
pub use shared_metadata::Detached;
pub use shared_recovery::{RecoveredSensor, SharedRecovery};

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    schema_version: u16,
    stream: Uuid,
    source_binding: [u8; 32],
    policy_binding: [u8; 32],
    record: Record,
}
impl Snapshot {
    pub fn record(&self) -> &Record {
        &self.record
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Receipt {
    revision: u64,
    checkpoint: u64,
    sha256: [u8; 32],
}
/// Prepared data, never proof of physical publication or a fresh host grant.
/// Cannot deserialize or clone a confirmation ticket into another engine.
pub struct Candidate {
    instance: Uuid,
    ticket: u64,
    base: Option<Receipt>,
    snapshot: Snapshot,
    fresh: BTreeSet<Uuid>,
    now: i64,
    trusted: bool,
    replay: bool,
    original: RuleContext,
}
impl Candidate {
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn expected_revision(&self) -> u64 {
        self.base.map_or(0, |r| r.revision)
    }
    pub fn is_replay(&self) -> bool {
        self.replay
    }
}
/// Native host supplies authenticated admission and a captured source epoch.
/// This engine owns no worker, journal, network client, lease or scheduler.
pub struct Engine {
    pub(super) config: Config,
    verifier: Verifier,
    pub(super) epoch: Epoch,
    pub(super) binding: [u8; 32],
    baseline: u64,
    floor: u64,
    epoch_ms: i64,
    fresh: BTreeSet<Uuid>,
    instance: Uuid,
    ticket: u64,
    highest: Option<Receipt>,
}
impl Engine {
    pub fn new(
        mut config: Config,
        epoch: Epoch,
        current: Option<&Snapshot>,
        context: &RuleContext,
    ) -> Result<Self, Error> {
        check(context)?;
        config.validate()?;
        if epoch.schema_version != 1
            || epoch.source_stream.is_nil()
            || epoch.last_sequence < epoch.checkpoint
            || epoch.last_sequence > i64::MAX as u64
            || epoch.source_binding == [0; 32]
        {
            return Err(Error::Configuration);
        }
        Monitor::new(config.policy.clone(), epoch.now_ms)?;
        config.observer_keys.sort_by_key(|k| k.observer_id);
        let verifier = Verifier::new(config.policy.clone(), config.observer_keys.clone())?;
        let mut digest = Sha256::new();
        digest.update(b"platform-signal/native-sensor-policy/v1\0");
        digest.update(encode(&config, 4 * 1024 * 1024)?);
        digest.update(verifier.enrollment_sha256());
        let mut engine = Self {
            config,
            verifier,
            binding: digest.finalize().into(),
            baseline: epoch.checkpoint,
            floor: epoch.last_sequence,
            epoch_ms: epoch.now_ms,
            epoch,
            fresh: BTreeSet::new(),
            instance: Uuid::new_v4(),
            ticket: 0,
            highest: None,
        };
        if let Some(snapshot) = current {
            engine.recover(snapshot, context)?;
        }
        check(context)?;
        Ok(engine)
    }
    pub fn policy_binding(&self) -> [u8; 32] {
        self.binding
    }
    fn receipt(&self, record: &Record) -> Result<Receipt, Error> {
        Ok(Receipt {
            revision: record.revision,
            checkpoint: record.checkpoint,
            sha256: Sha256::digest(encode(record, self.config.max_record_bytes)?).into(),
        })
    }
    fn validate(&self, snapshot: &Snapshot, context: &RuleContext) -> Result<(), Error> {
        self.decoded(snapshot, context).map(|_| ())
    }
    fn decoded(&self, snapshot: &Snapshot, context: &RuleContext) -> Result<State, Error> {
        check(context)?;
        if snapshot.schema_version != 1
            || snapshot.stream != self.epoch.source_stream
            || snapshot.source_binding != self.epoch.source_binding
            || snapshot.policy_binding != self.binding
        {
            return Err(Error::Conflict);
        }
        let record = &snapshot.record;
        if record.schema_version != 1
            || record.revision == 0
            || record.revision > i64::MAX as u64
            || record.checkpoint < self.baseline
            || record.checkpoint > i64::MAX as u64
            || record.outbox.len() > self.config.max_outputs
        {
            return Err(Error::Conflict);
        }
        let mut ids = BTreeSet::new();
        for output in &record.outbox {
            check(context)?;
            if output.bytes.len() > self.config.max_output_bytes || !ids.insert(output.id) {
                return Err(Error::Capacity);
            }
        }
        encode(record, self.config.max_record_bytes)?;
        decode(&self.config, &self.verifier, record, context)
    }
    pub(super) fn recover(
        &mut self,
        snapshot: &Snapshot,
        context: &RuleContext,
    ) -> Result<(), Error> {
        self.validate_recovery(snapshot, context)?;
        self.highest = Some(self.receipt(&snapshot.record)?);
        Ok(())
    }
    fn validate_recovery(&self, snapshot: &Snapshot, context: &RuleContext) -> Result<(), Error> {
        self.validate(snapshot, context)?;
        if snapshot.record.checkpoint > self.epoch.last_sequence {
            return Err(Error::Conflict);
        }
        let state = decode(&self.config, &self.verifier, &snapshot.record, context)?;
        if Monitor::restore(self.config.policy.clone(), &state.monitor)?.clock_ms() > self.epoch_ms
        {
            return Err(core::Error::Clock.into());
        }
        Ok(())
    }
    pub(super) fn wrap(&self, record: Record, context: &RuleContext) -> Result<Snapshot, Error> {
        let snapshot = Snapshot {
            schema_version: 1,
            stream: self.epoch.source_stream,
            source_binding: self.epoch.source_binding,
            policy_binding: self.binding,
            record,
        };
        self.validate(&snapshot, context)?;
        Ok(snapshot)
    }
    /// Preparation changes no confirmed observer authority. The caller must
    /// persist this candidate under its original lease/deadline before confirm.
    pub async fn prepare(
        &mut self,
        current: Option<&Snapshot>,
        rows: &[SequencedEvent],
        now: i64,
        trusted_current: bool,
        context: RuleContext,
    ) -> Result<Candidate, Error> {
        self.prepare_inner(current, rows, now, trusted_current, 0, context)
            .await
    }
    /// Proposed idle evaluation and retirement of a physically confirmed prefix.
    /// The embedding host must prove original publication before committing it.
    pub async fn prepare_retiring(
        &mut self,
        current: &Snapshot,
        retired: usize,
        now: i64,
        context: RuleContext,
    ) -> Result<Candidate, Error> {
        self.prepare_inner(Some(current), &[], now, true, retired, context)
            .await
    }
    /// Inspect original durable counts and pending bodies without renewing health.
    pub fn inspect(
        &self,
        snapshot: &Snapshot,
        now: i64,
        context: &RuleContext,
    ) -> Result<Completion, Error> {
        self.validate(snapshot, context)?;
        self.completion(
            snapshot.record.clone(),
            now,
            false,
            &BTreeSet::new(),
            context,
        )
    }
    async fn prepare_inner(
        &mut self,
        current: Option<&Snapshot>,
        rows: &[SequencedEvent],
        now: i64,
        trusted_current: bool,
        retired: usize,
        context: RuleContext,
    ) -> Result<Candidate, Error> {
        check(&context)?;
        if rows.len() > 4096 {
            return Err(Error::Capacity);
        }
        if retired > current.map_or(0, |s| s.record.outbox.len()) {
            return Err(Error::Conflict);
        }
        let receipt = match current {
            Some(snapshot) => {
                self.validate(snapshot, &context)?;
                Some(self.receipt(&snapshot.record)?)
            }
            None => None,
        };
        if let Some(previous) = self.highest
            && receipt.is_none_or(|r| {
                r.revision < previous.revision
                    || r.checkpoint < previous.checkpoint
                    || (r.revision == previous.revision && r != previous)
            })
        {
            return Err(Error::Conflict);
        }
        self.highest = receipt;
        self.ticket = self.ticket.checked_add(1).ok_or(Error::Capacity)?;
        let current = current.map(|s| &s.record);
        let checkpoint = current.map_or(self.baseline, |r| r.checkpoint);
        let last = rows.last().map_or(checkpoint, |r| r.sequence);
        if !rows.is_empty() && last <= checkpoint {
            return Ok(Candidate {
                instance: self.instance,
                ticket: self.ticket,
                base: self.highest,
                snapshot: self.wrap(current.ok_or(Error::Conflict)?.clone(), &context)?,
                fresh: self.fresh.clone(),
                now,
                trusted: false,
                replay: true,
                original: context.clone(),
            });
        }
        let mut state = match &current {
            Some(r) => decode(&self.config, &self.verifier, r, &context)?,
            None => State {
                schema_version: 2,
                monitor: Monitor::new(self.config.policy.clone(), now)?.snapshot()?,
                proofs: vec![],
                known: vec![],
                history: history::History::default(),
            },
        };
        let mut monitor = Monitor::restore(self.config.policy.clone(), &state.monitor)?;
        state.history.expire(&self.config, now)?;
        let mut fresh = if trusted_current {
            self.fresh.clone()
        } else {
            BTreeSet::new()
        };
        let mut previous = checkpoint;
        for row in rows.iter().filter(|r| r.sequence > checkpoint) {
            check(&context)?;
            if row.sequence % 16 == 0 {
                tokio::task::yield_now().await;
            }
            if previous.checked_add(1) != Some(row.sequence) {
                return Err(Error::Conflict);
            }
            previous = row.sequence;
            if !row.event.attributes.contains_key(ATTRIBUTE) {
                continue;
            }
            if !trusted_current || row.sequence <= self.floor {
                continue;
            }
            row.event.validate().map_err(|_| Error::Configuration)?;
            encode(&row.event, self.config.max_event_bytes)?;
            let verified = match self.verifier.verify(envelope(&row.event)?, now) {
                Ok(verified) => verified,
                // Admission and physical consumption have separate clocks. A
                // legitimately admitted report may expire in the bounded WAL;
                // consuming it grants no new health or historical finding.
                Err(super::super::Error::Expired) => continue,
                Err(error) => return Err(error.into()),
            };
            if verified.observation().observed_at_ms < self.epoch_ms {
                continue;
            }
            let observation = verified.observation().clone();
            if !self.config.includes(observation.source_id, &row.event) {
                return Err(Error::Conflict);
            }
            if let Some(old) = state.proofs.iter().find(|p| {
                p.observation.source_id == observation.source_id
                    && p.observation.sequence == observation.sequence
            }) {
                if old.payload_sha256 != verified.payload_sha256() || old.event != row.event {
                    return Err(Error::Conflict);
                }
                monitor.observe(observation, now)?;
                continue;
            }
            let proof = Proof {
                schema_version: 1,
                wal_sequence: row.sequence,
                authenticated_after: self.floor,
                epoch_ms: self.epoch_ms,
                event: row.event.clone(),
                observation: observation.clone(),
                payload_sha256: verified.payload_sha256(),
            };
            validate_proof(&self.config, &self.verifier, &proof)?;
            if monitor.observe(observation.clone(), now)? == Admission::Accepted {
                fresh.insert(observation.source_id);
            }
            state.proofs.push(proof);
            state.proofs = required(&monitor, &state.proofs)?;
            if state.proofs.len() > self.config.max_proofs {
                return Err(Error::Capacity);
            }
            state.fit_history(&self.config, 0, &context)?;
        }
        let assessments = assess(&mut monitor, now, &fresh, trusted_current)?;
        let mut outbox = current.map_or_else(Vec::new, |r| r.outbox.clone());
        outbox.drain(..retired);
        for a in &assessments {
            if a.outcome != Outcome::Match {
                continue;
            }
            let id = a.gap_id.ok_or(Error::Conflict)?;
            if state.known.iter().any(|p| p.finding.id == id) {
                continue;
            }
            let evidence: Vec<_> = state
                .proofs
                .iter()
                .filter(|p| p.observation.source_id == a.source_id)
                .cloned()
                .collect();
            let p = Pending {
                schema_version: 1,
                assessment: a.clone(),
                finding: finding(&self.config, a, &evidence)?,
                evidence,
            };
            validate_pending(&self.config, &self.verifier, &p, &context)?;
            if outbox.len() == self.config.max_outputs {
                return Err(Error::Capacity);
            }
            outbox.push(Output {
                schema_version: 1,
                id,
                bytes: encode(&p, self.config.max_output_bytes)?,
            });
            state
                .known
                .retain(|old| old.assessment.source_id != a.source_id);
            state.known.push(p);
            state.fit_history(&self.config, 0, &context)?;
        }
        state.monitor = monitor.snapshot()?;
        state.history.record(
            &self.config,
            history::Batch {
                assessments: &assessments,
                proofs: &state.proofs,
                fresh: &fresh,
                trusted: trusted_current,
                now,
            },
            &context,
        )?;
        state.fit_history(&self.config, 1, &context)?;
        let expected = current.map_or(0, |r| r.revision);
        let next = Record {
            schema_version: 1,
            revision: expected.checked_add(1).ok_or(Error::Conflict)?,
            checkpoint: last,
            state: encode(&state, self.config.max_state_bytes)?,
            outbox,
        };
        check(&context)?;
        Ok(Candidate {
            instance: self.instance,
            ticket: self.ticket,
            base: self.highest,
            snapshot: self.wrap(next, &context)?,
            fresh,
            now,
            trusted: trusted_current,
            replay: false,
            original: context.clone(),
        })
    }
    fn completion(
        &self,
        record: Record,
        now: i64,
        trusted: bool,
        fresh: &BTreeSet<Uuid>,
        context: &RuleContext,
    ) -> Result<Completion, Error> {
        let state = decode(&self.config, &self.verifier, &record, context)?;
        let mut monitor = Monitor::restore(self.config.policy.clone(), &state.monitor)?;
        let assessments = assess(&mut monitor, now, fresh, trusted)?;
        let valid_until_ms = if trusted && assessments.iter().all(|a| a.outcome == Outcome::NoMatch)
        {
            monitor
                .retained_progress()
                .filter_map(|(_, o, _, _)| {
                    o.map(|o| o.observed_at_ms + self.config.policy.observer_freshness_ms)
                })
                .chain(assessments.iter().map(|a| a.deadline_ms))
                .min()
                .unwrap_or(0)
        } else {
            0
        };
        let mut findings = Vec::with_capacity(record.outbox.len());
        for output in &record.outbox {
            let p: Pending =
                serde_json::from_slice(&output.bytes).map_err(|_| Error::Configuration)?;
            findings.push(DerivedFinding::from_events(
                p.finding,
                &p.evidence.iter().map(|e| &e.event).collect::<Vec<_>>(),
                true,
            )?);
        }
        Ok(Completion {
            revision: record.revision,
            published_prefix: record.outbox.len(),
            findings,
            assessments,
            proofs: state.proofs.len(),
            bytes: record.state.len(),
            valid_until_ms,
            history_assessments: state.history.entries.len(),
            history_bytes: encode(&state.history, self.config.max_history_bytes)?.len(),
            history_expired: state.history.expired,
            history_evicted: state.history.evicted,
        })
    }
    /// Proposed findings/metrics only; the host must not report these as
    /// committed health or publication before its physical commit succeeds.
    pub fn preview(
        &self,
        candidate: &Candidate,
        context: &RuleContext,
    ) -> Result<Completion, Error> {
        self.check_ticket(candidate, context)?;
        self.completion(
            candidate.snapshot.record.clone(),
            candidate.now,
            candidate.trusted,
            &candidate.fresh,
            context,
        )
    }
    fn check_ticket(&self, candidate: &Candidate, context: &RuleContext) -> Result<(), Error> {
        check(context)?;
        check(&candidate.original)?;
        if candidate.instance != self.instance
            || candidate.ticket != self.ticket
            || candidate.base != self.highest
        {
            return Err(Error::Conflict);
        }
        // Candidates are private, immutable and non-deserializable. Their
        // snapshot was validated by prepare; completion validates its domain
        // again before returning any confirmed result.
        Ok(())
    }
    /// Caller proves the physical fenced commit; exact confirmed bytes are
    /// mandatory. A lost/late reply never upgrades in-memory observer authority.
    pub fn confirm(
        &mut self,
        candidate: Candidate,
        confirmed: &Record,
        context: &RuleContext,
    ) -> Result<Completion, Error> {
        self.check_ticket(&candidate, context)?;
        if confirmed != &candidate.snapshot.record {
            return Err(Error::Conflict);
        }
        let result = self.preview(&candidate, context)?;
        let receipt = self.receipt(confirmed)?;
        check(context)?;
        self.fresh = candidate.fresh;
        self.highest = Some(receipt);
        Ok(result)
    }
}
