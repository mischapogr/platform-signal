//! Optional private window policy; a source-bound atomic outbox precedes WAL ack.
use crate::{
    config::{self, ConfigError, Settings},
    onboarding,
};
use serde::Deserialize;
use signal_buffer::{BufferMetrics, SequencedEvent};
use signal_findings::DerivedFinding;
use signal_protocol::WindowSinkMetrics;
use signal_rules::{
    RuleContext,
    window::{self, Journal, Policy, Snapshot, State},
};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(crate) struct Configuration {
    persistence: Persistence,
    pub policy: Policy,
}
enum Persistence {
    Local(PathBuf),
    Shared(SharedConfiguration),
}
#[derive(Clone, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharedConfiguration {
    pub state_key: String,
    pub bootstrap_checkpoint: Option<u64>,
    pub recovery: RecoveryConfiguration,
}
#[derive(Clone, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryConfiguration {
    pub files: usize,
    pub object_bytes: u64,
    pub decoded_bytes: u64,
    pub scanned_rows: usize,
    pub result_bytes: usize,
}
impl SharedConfiguration {
    pub fn limits(
        &self,
        backend: Uuid,
    ) -> Result<signal_control::CanonicalRecoveryLimits, signal_control::ControlError> {
        let limits = signal_control::CanonicalRecoveryLimits {
            backend,
            files: self.recovery.files,
            object_bytes: self.recovery.object_bytes,
            decoded_bytes: self.recovery.decoded_bytes,
            scanned_rows: self.recovery.scanned_rows,
            result_bytes: self.recovery.result_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }
    #[cfg(any(test, feature = "s3-query"))]
    pub fn source_binding(&self, host: [u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"platform-signal/shared-window-source/v1\0");
        hash.update(host);
        hash.update((self.state_key.len() as u64).to_be_bytes());
        hash.update(self.state_key.as_bytes());
        match self.bootstrap_checkpoint {
            Some(c) => {
                hash.update([1]);
                hash.update(c.to_be_bytes());
            }
            None => hash.update([0]),
        };
        hash.finalize().into()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalDocument {
    schema_version: u16,
    database: PathBuf,
    policy: Policy,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedDocument {
    schema_version: u16,
    shared: SharedConfiguration,
    policy: Policy,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Document {
    Local(LocalDocument),
    Shared(SharedDocument),
}
impl Configuration {
    fn parse(text: &str) -> Result<Self, ConfigError> {
        let document: Document =
            serde_json::from_str(text).map_err(|_| ConfigError::Invalid("window configuration"))?;
        let config = match document {
            Document::Local(local) => {
                if local.schema_version != 1
                    || !local.database.is_absolute()
                    || local.database.as_os_str().len() > 4096
                {
                    return Err(ConfigError::Invalid("window database path/version"));
                }
                Self {
                    persistence: Persistence::Local(local.database),
                    policy: local.policy,
                }
            }
            Document::Shared(shared) => {
                if shared.schema_version != 2
                    || shared.shared.state_key.is_empty()
                    || shared.shared.state_key.len() > 256
                    || shared.shared.state_key.capacity() > 256
                    || shared.shared.state_key.chars().any(char::is_control)
                    || shared
                        .shared
                        .bootstrap_checkpoint
                        .is_some_and(|c| c > i64::MAX as u64)
                {
                    return Err(ConfigError::Invalid("window shared profile/version"));
                }
                Self {
                    persistence: Persistence::Shared(shared.shared),
                    policy: shared.policy,
                }
            }
        };
        config
            .policy
            .validate()
            .map_err(|_| ConfigError::Invalid("window policy"))?;
        if let Some(shared) = config.shared() {
            if shared.recovery.result_bytes > 1048576 {
                return Err(ConfigError::Invalid("shared window retained input limit"));
            }
            // Check resource bounds now; startup supplies and verifies the actual backend.
            shared
                .limits(config.policy.partition)
                .map_err(|_| ConfigError::Invalid("window recovery limits"))?;
        }
        Ok(config)
    }
    pub fn shared(&self) -> Option<&SharedConfiguration> {
        match &self.persistence {
            Persistence::Shared(c) => Some(c),
            Persistence::Local(_) => None,
        }
    }
    pub async fn load(settings: &Settings) -> Result<Option<Self>, ConfigError> {
        let Some(path) = settings.optional("SIGNAL_WINDOW_CONFIG")? else {
            return Ok(None);
        };
        let config = config::read_limited_document(
            path.into(),
            65536,
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
            Self::parse,
        )
        .await?;
        Ok(Some(config))
    }
    pub async fn open(
        self,
        wal: BufferMetrics,
        host: Arc<onboarding::Host>,
    ) -> Result<Detector, window::Error> {
        let Persistence::Local(database) = self.persistence else {
            return Err(window::Error::Configuration);
        };
        let (journal, ready) = Journal::begin_open(
            database,
            self.policy.clone(),
            RuleContext::new(Duration::from_secs(5)),
        )?;
        ready.wait().await?;
        let current = journal
            .load(RuleContext::new(Duration::from_secs(5)))
            .await?;
        if let Some(current) = current.as_ref()
            && (current.source_stream != wal.stream_id
                || current.source_binding != host.window_binding()
                || current.checkpoint < wal.checkpoint
                || current.checkpoint > wal.last_sequence)
        {
            journal
                .shutdown(RuleContext::new(Duration::from_secs(5)))
                .await?;
            return Err(window::Error::Conflict);
        }
        let detector = Detector {
            journal,
            host,
            stream: wal.stream_id,
            baseline: wal.checkpoint,
            health: Mutex::new(WindowSinkMetrics {
                history_assessment_capacity: self.policy.max_history_assessments,
                history_byte_capacity: self.policy.max_history_bytes,
                attempt_capacity: self.policy.max_attempts,
                assessment_capacity: self.policy.max_outputs,
                byte_capacity: self.policy.max_state_bytes * 2,
                ..Default::default()
            }),
            coverage_until: AtomicI64::new(0),
            held: AtomicBool::new(true),
            policy: self.policy,
        };
        if let Some(snapshot) = current {
            detector.refresh(&snapshot)?;
        }
        Ok(detector)
    }
}
pub(crate) struct Detector {
    pub journal: Journal,
    policy: Policy,
    host: Arc<onboarding::Host>,
    stream: Uuid,
    baseline: u64,
    health: Mutex<WindowSinkMetrics>,
    coverage_until: AtomicI64,
    held: AtomicBool,
}
pub(crate) struct Completion {
    pub findings: Vec<DerivedFinding>,
    pub revision: u64,
    pub assessments: usize,
}
struct HealthAttempt<'a> {
    held: &'a AtomicBool,
    completed: bool,
}
impl Drop for HealthAttempt<'_> {
    fn drop(&mut self) {
        self.held.store(!self.completed, Ordering::Release);
    }
}
impl Detector {
    pub async fn acknowledge(
        &self,
        revision: u64,
        assessments: usize,
        context: RuleContext,
    ) -> Result<(), window::Error> {
        let mut attempt = HealthAttempt {
            held: &self.held,
            completed: false,
        };
        let snapshot = self.journal.retire(revision, assessments, context).await?;
        self.refresh(&snapshot)?;
        attempt.completed = true;
        Ok(())
    }
    pub fn metrics(&self) -> WindowSinkMetrics {
        let mut health = self.health.lock().map(|h| *h).unwrap_or(WindowSinkMetrics {
            coverage_gap: true,
            ..Default::default()
        });
        let (depth, capacity, failures) = self.journal.metrics();
        health.operations = depth;
        health.operation_capacity = capacity;
        health.failures = failures;
        health.closed = self.journal.is_closed();
        health.coverage_gap |=
            chrono::Utc::now().timestamp_millis() >= self.coverage_until.load(Ordering::Acquire);
        health.coverage_gap |= self.held.load(Ordering::Acquire);
        health.coverage_gap |= health.closed;
        health
    }
    fn refresh(&self, snapshot: &Snapshot) -> Result<(), window::Error> {
        let (attempts, attempt_capacity, assessments, assessment_capacity, rejected, duplicates) =
            snapshot.state.metrics();
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|_| window::Error::Configuration)?
            .len();
        let gap = snapshot
            .state
            .coverage_gap()
            .is_some_and(|gap| gap.degraded_through >= chrono::Utc::now());
        *self.health.lock().map_err(|_| window::Error::Closed)? = WindowSinkMetrics {
            history_assessments: snapshot.history.assessments,
            history_assessment_capacity: self.policy.max_history_assessments,
            history_bytes: snapshot.history.bytes,
            history_byte_capacity: self.policy.max_history_bytes,
            attempts,
            attempt_capacity,
            assessments,
            assessment_capacity,
            rejected,
            duplicates,
            bytes,
            byte_capacity: self.policy.max_state_bytes * 2,
            coverage_gap: gap,
            indeterminate: snapshot
                .state
                .assessments()
                .iter()
                .filter(|a| a.outcome == window::Outcome::Indeterminate)
                .count(),
            ..Default::default()
        };
        Ok(())
    }
    /// Storage has already verified this immutable WAL batch. On replay, reload
    /// the committed snapshot/outbox before publishing or evaluating any input.
    pub async fn complete(
        &self,
        batch: &[SequencedEvent],
        authenticated_after: u64,
        source_tail: u64,
        context: RuleContext,
    ) -> Result<Completion, crate::pipeline::PipelineError> {
        let mut health_attempt = HealthAttempt {
            held: &self.held,
            completed: false,
        };
        let current = self.journal.load(context.clone()).await?;
        let last = batch.last().ok_or(window::Error::Configuration)?.sequence;
        let checkpoint = current.as_ref().map_or(self.baseline, |s| s.checkpoint);
        let snapshot = if last <= checkpoint {
            current.ok_or(window::Error::Conflict)?
        } else {
            let mut next = current.unwrap_or(Snapshot {
                history: Default::default(),
                schema_version: 1,
                revision: 0,
                checkpoint: self.baseline,
                source_stream: self.stream,
                source_binding: self.host.window_binding(),
                state: State::new(self.policy.clone())?,
                findings: Vec::new(),
            });
            let expected = next.revision;
            let coverage = self
                .host
                .snapshot(&context)
                .await
                .map_err(|_| window::Error::Configuration)?;
            let interval = coverage.source_interval.filter(|_| {
                coverage
                    .valid_until
                    .is_some_and(|end| end > chrono::Utc::now())
                    && coverage
                        .report
                        .detections
                        .iter()
                        .any(|d| d.id == self.policy.rule_id && d.active)
            });
            self.coverage_until.store(
                if interval.is_some() {
                    coverage.valid_until.map_or(0, |end| end.timestamp_millis())
                } else {
                    0
                },
                Ordering::Release,
            );
            let mut previous = checkpoint;
            for row in batch.iter().filter(|r| r.sequence > checkpoint) {
                if previous.checked_add(1) != Some(row.sequence) {
                    return Err(window::Error::Conflict.into());
                }
                if context.cancellation.is_cancelled() {
                    return Err(window::Error::Cancelled.into());
                }
                if Instant::now() >= context.deadline {
                    return Err(window::Error::Timeout.into());
                }
                if self.host.includes_event(&row.event) {
                    let verified = row.sequence > authenticated_after
                        && interval.is_some_and(|(start, end)| {
                            row.event.timestamp >= start && row.event.timestamp <= end
                        });
                    next.state.admit(&row.event, verified)?;
                }
                previous = row.sequence;
            }
            if let Some((start, end)) = interval
                && last == source_tail
            {
                let watermark = end
                    .checked_sub_signed(chrono::TimeDelta::milliseconds(self.policy.lateness_ms))
                    .ok_or(window::Error::Configuration)?;
                if next.state.watermark().is_none_or(|old| watermark >= old) {
                    next.state.seal_covered(start, end)?;
                }
            }
            next.findings = next
                .state
                .assessments()
                .iter()
                .map(|a| a.finding(&self.policy))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .collect();
            next.revision = expected.checked_add(1).ok_or(window::Error::Capacity)?;
            next.checkpoint = last;
            self.journal.commit(expected, next, context).await?
        };
        self.refresh(&snapshot)?;
        let mut published = Vec::new();
        for assessment in snapshot.state.assessments() {
            if let Some(finding) = assessment.finding(&self.policy)? {
                let events = assessment.canonical_events().iter().collect::<Vec<_>>();
                published.push(DerivedFinding::from_events(finding, &events, true)?);
            }
        }
        health_attempt.completed = true;
        Ok(Completion {
            findings: published,
            revision: snapshot.revision,
            assessments: snapshot.state.assessments().len(),
        })
    }
}

#[cfg(test)]
mod configuration_tests {
    use super::*;
    fn policy() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"partition":Uuid::from_u128(1),"rule_id":"fixture-window","revision":"fixture-v1",
            "title":"fixture","severity":"medium","threshold":2,"window_ms":60000,"lateness_ms":10000,"ttl_ms":70000,
            "max_keys":4,"max_attempts_per_key":16,"max_attempts":32,"max_outputs":32,"max_state_bytes":65536,
            "max_history_assessments":32,"max_history_bytes":262144,"history_retention_ms":60000})
    }
    fn shared() -> serde_json::Value {
        serde_json::json!({"schema_version":2,"policy":policy(),"shared":{"state_key":"fixture-window","bootstrap_checkpoint":0,
            "recovery":{"files":128,"object_bytes":67108864,"decoded_bytes":67108864,"scanned_rows":65536,"result_bytes":1048576}}})
    }
    #[test]
    fn local_schema1_preserved_and_shared_schema2_has_no_sqlite_path() -> Result<(), ConfigError> {
        let local = serde_json::json!({"schema_version":1,"database":"/private/fixture.sqlite","policy":policy()});
        let local = Configuration::parse(&local.to_string())?;
        assert!(matches!(local.persistence, Persistence::Local(_)));
        let value = shared();
        let shared = Configuration::parse(&value.to_string())?;
        assert_eq!(
            shared.shared().map(|c| c.bootstrap_checkpoint),
            Some(Some(0))
        );
        for (path, replacement) in [
            ("/schema_version", serde_json::json!(1)),
            ("/shared/recovery/files", serde_json::json!(0)),
            ("/shared/bootstrap_checkpoint", serde_json::json!(-1)),
        ] {
            let mut changed = value.clone();
            *changed
                .pointer_mut(path)
                .ok_or(ConfigError::Invalid("fixture path"))? = replacement;
            assert!(
                Configuration::parse(&changed.to_string()).is_err(),
                "{path}"
            );
        }
        let mut mixed = value;
        mixed["database"] = serde_json::json!("/private/unused.sqlite");
        assert!(Configuration::parse(&mixed.to_string()).is_err());
        Ok(())
    }
    #[test]
    fn shared_source_binding_pins_host_key_and_explicit_bootstrap_boundary()
    -> Result<(), ConfigError> {
        let parsed = Configuration::parse(&shared().to_string())?;
        let original = parsed
            .shared()
            .ok_or(ConfigError::Invalid("fixture profile"))?;
        let hash = original.source_binding([1; 32]);
        assert_eq!(hash, original.clone().source_binding([1; 32]));
        assert_ne!(hash, original.source_binding([2; 32]));
        let mut changed = original.clone();
        changed.bootstrap_checkpoint = Some(1);
        assert_ne!(hash, changed.source_binding([1; 32]));
        changed = original.clone();
        changed.state_key = "another-fixture".into();
        assert_ne!(hash, changed.source_binding([1; 32]));
        Ok(())
    }
}
