//! Single-writer Standard detector state. Commit/ACK remains owned by SharedRecovery.
use crate::{
    onboarding,
    window::{Configuration, SharedConfiguration},
};
use sha2::{Digest, Sha256};
use signal_control::{
    ControlClient, ControlContext, ControlError, LeaseToken, PriorStateProvenance, RevisionedState,
    StateReadInput, WindowProfile,
};
use signal_findings::{DerivedFinding, ScopedFinding};
use signal_protocol::WindowSinkMetrics;
use signal_rules::window::{Policy, State};
use signal_server::shared_window::{SharedWindowBinding, SharedWindowRecovery};
use signal_storage::{StoredEvent, object_codec::ObjectCodec, object_io::ObjectIo};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error(transparent)]
    Detector(#[from] signal_rules::window::Error),
    #[error(transparent)]
    Recovery(#[from] signal_server::shared_window::Error),
    #[error("Standard Window source coverage unavailable")]
    Coverage,
}
pub(crate) struct Health {
    value: Mutex<WindowSinkMetrics>,
    coverage_until: AtomicI64,
    stopped: AtomicBool,
    pins: AtomicUsize,
    pin_capacity: usize,
}
impl Health {
    pub fn pins(&self) -> (usize, usize) {
        (self.pins.load(Ordering::Acquire), self.pin_capacity)
    }
    pub fn metrics(&self) -> WindowSinkMetrics {
        let mut value = self.value.lock().map(|v| *v).unwrap_or(WindowSinkMetrics {
            closed: true,
            coverage_gap: true,
            ..Default::default()
        });
        value.closed |= self.stopped.load(Ordering::Acquire);
        value.coverage_gap |= value.closed
            || chrono::Utc::now().timestamp_millis() >= self.coverage_until.load(Ordering::Acquire);
        value
    }
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Ok(mut v) = self.value.lock() {
            v.operations = 0;
        }
    }
}
pub(crate) struct Consumer {
    pub binding: SharedWindowBinding,
    pub prior: Option<PriorStateProvenance>,
    pub retained: Vec<StoredEvent>,
    pub health: Arc<Health>,
    policy: Policy,
    state: State,
    host: Arc<onboarding::Host>,
    settings: SharedConfiguration,
    checkpoint: u64,
    replay_pins: Vec<Uuid>,
}
pub(crate) struct Startup<'a> {
    pub configuration: Configuration,
    pub host: Arc<onboarding::Host>,
    pub producer: signal_control::ProducerEnrollment,
    pub revision: [u8; 32],
    pub backend: Uuid,
    pub control: &'a ControlClient,
    pub objects: &'a ObjectIo,
    pub codec: &'a ObjectCodec,
    pub token: LeaseToken,
    pub head: Option<Uuid>,
    pub wal_checkpoint: u64,
    pub context: ControlContext,
}
pub(crate) struct Candidate {
    pub value: RevisionedState,
    pub derived: Vec<(u64, ScopedFinding)>,
    state: State,
    retained: Vec<StoredEvent>,
    prior: PriorStateProvenance,
    coverage_until: i64,
}
struct Budget(usize, usize);
impl Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.1.saturating_sub(self.0) {
            return Err(std::io::Error::other("Window canonical capacity"));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Consumer {
    pub async fn open(input: Startup<'_>) -> Result<Self, Error> {
        input.context.check()?;
        let settings = input
            .configuration
            .shared()
            .cloned()
            .ok_or(ControlError::Invalid)?;
        let policy = input.configuration.policy;
        if policy.partition != input.producer.scope.partition_id {
            return Err(ControlError::Fenced.into());
        }
        let limits = settings.limits(input.backend)?;
        let binding = SharedWindowBinding {
            producer: input.producer,
            source_binding: settings.source_binding(input.host.window_binding()),
            rule_revision: input.revision,
            key: settings.state_key.clone(),
        };
        let read = input
            .control
            .read_window_state(
                input.token.clone(),
                StateReadInput {
                    key: binding.key.clone(),
                    expected_head: input.head,
                },
                WindowProfile {
                    schema_version: 1,
                    scope_generation: binding.producer.scope_generation,
                    history_rows: policy.max_history_assessments,
                    history_bytes: policy.max_history_bytes,
                    retention_ms: policy.history_retention_ms,
                    bootstrap_checkpoint: settings.bootstrap_checkpoint,
                },
                input.context.clone(),
            )
            .await?;
        if read.checkpoint != input.wal_checkpoint {
            return Err(ControlError::Conflict.into());
        }
        let (state, prior, retained, replay_pins) = if read.state.is_some() {
            let recovered = SharedWindowRecovery {
                binding: &binding,
                control: input.control,
                objects: input.objects,
                codec: input.codec,
                limits,
            }
            .recover(input.token.clone(), &policy, input.context.clone())
            .await?;
            if recovered.prior.checkpoint != read.checkpoint {
                return Err(ControlError::Conflict.into());
            }
            let rows = recovered.canonical.rows()?;
            let mut budget = Budget(0, settings.recovery.result_bytes);
            for row in rows {
                serde_json::to_writer(&mut budget, &row.event).map_err(|_| ControlError::Full)?;
            }
            (
                recovered.state,
                Some(recovered.prior),
                rows.to_vec(),
                recovered.replay_pins,
            )
        } else {
            if settings.bootstrap_checkpoint != Some(read.checkpoint) {
                return Err(ControlError::Fenced.into());
            }
            (State::new(policy.clone())?, None, Vec::new(), Vec::new())
        };
        let health = Arc::new(Health {
            value: Mutex::new(WindowSinkMetrics {
                attempt_capacity: policy.max_attempts,
                assessment_capacity: policy.max_outputs,
                byte_capacity: policy.max_state_bytes * 2,
                history_assessment_capacity: policy.max_history_assessments,
                history_byte_capacity: policy.max_history_bytes,
                operation_capacity: 1,
                coverage_gap: true,
                ..Default::default()
            }),
            coverage_until: AtomicI64::new(0),
            stopped: AtomicBool::new(false),
            pins: AtomicUsize::new(replay_pins.len()),
            pin_capacity: settings.recovery.files,
        });
        let result = Self {
            binding,
            prior,
            retained,
            health,
            policy,
            state,
            host: input.host,
            settings,
            checkpoint: read.checkpoint,
            replay_pins,
        };
        if result.prior.is_some() {
            result
                .refresh_history(
                    input.control,
                    input.token.clone(),
                    input.head.ok_or(ControlError::Corrupt)?,
                    input.context.clone(),
                )
                .await?;
        } else {
            result.refresh(0, 0)?;
        }
        Ok(result)
    }
    pub async fn prepare(
        &self,
        rows: &[StoredEvent],
        authenticated_after: u64,
        source_tail: u64,
        context: &ControlContext,
    ) -> Result<Candidate, Error> {
        context.check()?;
        if rows.is_empty()
            || rows.len() > 4096
            || rows.first().map(|r| r.sequence) != self.checkpoint.checked_add(1)
        {
            return Err(ControlError::Conflict.into());
        }
        if let Ok(mut h) = self.health.value.lock() {
            h.operations = 1;
            h.coverage_gap = true;
        }
        let mut state = self.state.clone();
        state.retire_assessments(state.assessments().len())?;
        let coverage = self
            .host
            .snapshot(&signal_rules::RuleContext {
                deadline: context.deadline(),
                cancellation: context.cancellation_token(),
            })
            .await
            .map_err(|_| Error::Coverage)?;
        let interval = coverage.source_interval.filter(|_| {
            coverage.valid_until.is_some_and(|t| t > chrono::Utc::now())
                && coverage
                    .report
                    .detections
                    .iter()
                    .any(|d| d.id == self.policy.rule_id && d.active)
        });
        let mut previous = self.checkpoint;
        for row in rows {
            context.check()?;
            if previous.checked_add(1) != Some(row.sequence) {
                return Err(ControlError::Conflict.into());
            }
            if self.host.includes_event(&row.event) {
                let verified = row.sequence
                    > authenticated_after.max(self.settings.bootstrap_checkpoint.unwrap_or(0))
                    && interval.is_some_and(|(start, end)| {
                        row.event.timestamp >= start && row.event.timestamp <= end
                    });
                state.admit(&row.event, verified)?;
            }
            previous = row.sequence;
        }
        if let Some((start, end)) = interval
            && previous == source_tail
        {
            let watermark = end
                .checked_sub_signed(chrono::TimeDelta::milliseconds(self.policy.lateness_ms))
                .ok_or(ControlError::Invalid)?;
            if state.watermark().is_none_or(|old| watermark >= old) {
                state.seal_covered(start, end)?;
            }
        }
        let metadata = state.encode_metadata(65536)?;
        let ids = State::metadata_event_ids(&metadata, &self.policy)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut inputs: BTreeMap<Uuid, &StoredEvent> = BTreeMap::new();
        for row in self.retained.iter().chain(rows) {
            if let Some(old) = inputs.get(&row.event.id) {
                if old.event != row.event {
                    return Err(ControlError::Conflict.into());
                }
            } else {
                inputs.insert(row.event.id, row);
            }
        }
        if ids.len() > 4096 {
            return Err(ControlError::Full.into());
        }
        let mut retained = Vec::with_capacity(ids.len());
        let mut budget = Budget(0, self.settings.recovery.result_bytes);
        for id in ids {
            let row = inputs.get(&id).ok_or(ControlError::Unavailable)?;
            serde_json::to_writer(&mut budget, &row.event).map_err(|_| ControlError::Full)?;
            retained.push((**row).clone());
        }
        let value = self
            .binding
            .encode(&state, &self.policy, previous, &retained)?;
        let derived = derive_findings(
            &state,
            &self.policy,
            &retained,
            self.binding.producer.scope_generation,
        )?;
        let prior = PriorStateProvenance {
            schema_version: 1,
            key: self.binding.key.clone(),
            checkpoint: previous,
            revision: self.binding.rule_revision,
            value_sha256: Sha256::digest(&value.bytes).into(),
            scope_generation: self.binding.producer.scope_generation,
        };
        context.check()?;
        Ok(Candidate {
            value,
            derived,
            state,
            retained,
            prior,
            coverage_until: if interval.is_some() {
                coverage.valid_until.map_or(0, |t| t.timestamp_millis())
            } else {
                0
            },
        })
    }
    pub fn accept(&mut self, candidate: Candidate, checkpoint: u64) -> Result<(), Error> {
        if candidate.prior.checkpoint != checkpoint {
            return Err(ControlError::Conflict.into());
        }
        self.state = candidate.state;
        self.retained = candidate.retained;
        self.prior = Some(candidate.prior);
        self.checkpoint = checkpoint;
        self.health
            .coverage_until
            .store(candidate.coverage_until, Ordering::Release);
        Ok(())
    }
    /// Only the host's confirmed-idle path may call this. Unknown/partial pins
    /// outside this recovered set remain retained for an explicit later decision.
    pub async fn cleanup(
        &mut self,
        control: &ControlClient,
        token: LeaseToken,
        head: Uuid,
        context: ControlContext,
    ) -> Result<(), Error> {
        if self.replay_pins.is_empty() {
            return Ok(());
        }
        let prior = self.prior.as_ref().ok_or(ControlError::Conflict)?;
        let mut index = 0;
        while index < self.replay_pins.len() {
            context.check()?;
            let input = signal_control::ObsoleteReplayPin {
                id: self.replay_pins[index],
                state_key: self.binding.key.clone(),
                expected_head: head,
                revision: self.binding.rule_revision,
                value_sha256: prior.value_sha256,
            };
            match control
                .release_obsolete_replay_pin(token.clone(), input, context.clone())
                .await
            {
                Ok(result) if result.state == signal_control::ObjectControlState::Released => {
                    self.replay_pins.remove(index);
                }
                Err(ControlError::Fenced) => {
                    index += 1;
                }
                Ok(_) => return Err(ControlError::Corrupt.into()),
                Err(error) => return Err(error.into()),
            }
            self.health
                .pins
                .store(self.replay_pins.len(), Ordering::Release);
        }
        Ok(())
    }
    pub async fn refresh_history(
        &self,
        control: &ControlClient,
        token: LeaseToken,
        head: Uuid,
        context: ControlContext,
    ) -> Result<(), Error> {
        let page = control
            .read_window_history(
                token,
                signal_control::HistoryInput {
                    schema_version: 1,
                    key: self.binding.key.clone(),
                    head,
                    limit: 1,
                    max_bytes: 1048576,
                    cursor: None,
                },
                context,
            )
            .await?;
        let (rows, bytes) = page.usage()?;
        self.refresh(rows, bytes)
    }
    fn refresh(&self, history_rows: usize, history_bytes: usize) -> Result<(), Error> {
        let (attempts, attempt_capacity, assessments, assessment_capacity, rejected, duplicates) =
            self.state.metrics();
        let mut budget = Budget(0, self.policy.max_state_bytes * 2);
        serde_json::to_writer(&mut budget, &self.state).map_err(|_| ControlError::Full)?;
        for row in &self.retained {
            serde_json::to_writer(&mut budget, &row.event).map_err(|_| ControlError::Full)?;
        }
        let bytes = budget.0;
        let mut h = self
            .health
            .value
            .lock()
            .map_err(|_| ControlError::Unavailable)?;
        h.attempts = attempts;
        h.attempt_capacity = attempt_capacity;
        h.assessments = assessments;
        h.assessment_capacity = assessment_capacity;
        h.rejected = rejected;
        h.duplicates = duplicates;
        h.bytes = bytes;
        h.history_assessments = history_rows;
        h.history_bytes = history_bytes;
        h.operations = 0;
        h.indeterminate = self
            .state
            .assessments()
            .iter()
            .filter(|a| a.outcome == signal_rules::window::Outcome::Indeterminate)
            .count();
        h.coverage_gap = self
            .state
            .coverage_gap()
            .is_some_and(|g| g.degraded_through >= chrono::Utc::now());
        Ok(())
    }
}

fn derive_findings(
    state: &State,
    policy: &Policy,
    retained: &[StoredEvent],
    generation: Uuid,
) -> Result<Vec<(u64, ScopedFinding)>, Error> {
    let mut derived: Vec<(u64, ScopedFinding)> = Vec::new();
    let mut positions = BTreeMap::new();
    for assessment in state.assessments() {
        if let Some(finding) = assessment.finding(policy)? {
            let anchor = retained
                .iter()
                .find(|r| {
                    r.event.timestamp == assessment.anchor
                        && assessment.event_ids.contains(&r.event.id)
                })
                .ok_or(ControlError::Corrupt)?
                .sequence;
            let events = assessment.canonical_events().iter().collect::<Vec<_>>();
            let scoped = DerivedFinding::from_events(finding, &events, true)
                .map_err(|_| ControlError::Corrupt)?
                .into_scoped(generation)
                .map_err(|_| ControlError::Fenced)?;
            if let Some(index) = positions.get(&scoped.finding().id).copied() {
                let existing: &(u64, ScopedFinding) = &derived[index];
                if existing.1.finding() != scoped.finding() {
                    return Err(ControlError::Conflict.into());
                }
                continue;
            }
            if derived.len() == 128 {
                return Err(ControlError::Full.into());
            }
            positions.insert(scoped.finding().id, derived.len());
            derived.push((anchor, scoped));
        }
    }
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        Policy {
            schema_version: 1,
            partition: Uuid::from_u128(1),
            rule_id: "fixture-window".into(),
            revision: "fixture-v1".into(),
            title: "fixture".into(),
            severity: signal_findings::DetectionSeverity::Medium,
            threshold: 2,
            window_ms: 60000,
            lateness_ms: 10000,
            ttl_ms: 70000,
            max_keys: 4,
            max_attempts_per_key: 16,
            max_attempts: 32,
            max_outputs: 32,
            max_state_bytes: 65536,
            max_history_assessments: 32,
            max_history_bytes: 262144,
            history_retention_ms: 60000,
        }
    }
    #[test]
    fn same_timestamp_attempts_publish_one_identical_finding()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = policy();
        let mut state = State::new(policy.clone())?;
        let mut rows = Vec::new();
        let at = chrono::DateTime::from_timestamp(1791972000, 0).ok_or("fixture timestamp")?;
        for sequence in 1..=3 {
            let input: signal_event::IngestEvent = serde_json::from_value(
                serde_json::json!({"timestamp":at,"source":{"type":"authentication","name":"fixture"},"message":"fixture","attributes":{"authentication":{"identity_authority":"fixture","principal_id":"fixture","target_id":"fixture","outcome":"failure"},"producer":{"boot_id":"fixture","sequence":sequence}}}),
            )?;
            let mut event = input.normalize(at)?;
            event.id = Uuid::from_u128(u128::from(sequence));
            state.admit(&event, true)?;
            rows.push(StoredEvent { sequence, event });
        }
        state.seal(at, true)?;
        assert!(state.assessments().len() > 1);
        let derived = derive_findings(&state, &policy, &rows, Uuid::from_u128(2))?;
        assert_eq!(derived.len(), 1);
        assert_eq!(derived[0].1.finding().event_ids.len(), 3);
        let producer = signal_control::ProducerEnrollment {
            scope: signal_control::Scope {
                schema_version: 1,
                store_id: Uuid::from_u128(3),
                generation: Uuid::from_u128(4),
                partition_id: policy.partition,
                tenant: "fixture".into(),
                stream: Uuid::from_u128(5),
            },
            scope_generation: Uuid::from_u128(2),
            startup: Uuid::from_u128(6),
            wal_floor: 0,
        };
        signal_control::MultiEventFindingClaims::from_retained_anchor_host(
            &producer,
            &rows,
            &[],
            None,
            derived,
        )?;
        Ok(())
    }
    #[test]
    fn health_never_reports_clean_before_fresh_coverage_or_after_stop() {
        let health = Health {
            value: Mutex::new(WindowSinkMetrics::default()),
            coverage_until: AtomicI64::new(0),
            stopped: AtomicBool::new(false),
            pins: AtomicUsize::new(0),
            pin_capacity: 128,
        };
        assert!(health.metrics().coverage_gap);
        health.coverage_until.store(
            chrono::Utc::now().timestamp_millis() + 60000,
            Ordering::Release,
        );
        assert!(!health.metrics().coverage_gap);
        health.stop();
        assert!(health.metrics().closed && health.metrics().coverage_gap);
    }
}
