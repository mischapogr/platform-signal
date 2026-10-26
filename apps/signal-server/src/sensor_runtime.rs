//! Small runtime owner for the independent observer detector and physical journal.
use crate::config::{self, ConfigError, Settings};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use signal_buffer::{BufferMetrics, SequencedEvent};
use signal_event::SignalEvent;
use signal_protocol::{AdmissionError, SensorHealthSinkMetrics};
use signal_rules::{RuleContext, sensor_health::Outcome, state_journal};
use signal_server::sensor_health::{
    Verifier,
    native::{self, Completion, Epoch, Session},
};
use std::{
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(crate) type Error = native::Error;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    schema_version: u16,
    database: Option<PathBuf>,
    shared: Option<SharedConfiguration>,
    owner_generation: Uuid,
    cadence_ms: u64,
    pub detector: native::Config,
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
        if limits.result_bytes > 1048576 {
            return Err(signal_control::ControlError::Full);
        }
        Ok(limits)
    }
}
impl Configuration {
    pub(crate) fn parse(text: &str) -> Result<Self, ConfigError> {
        let c: Self = serde_json::from_str(text)
            .map_err(|_| ConfigError::Invalid("sensor health configuration"))?;
        c.detector
            .validate()
            .map_err(|_| ConfigError::Invalid("sensor health policy"))?;
        let persistence_valid = match (c.schema_version, &c.database, &c.shared) {
            (1, Some(path), None) => path.is_absolute() && path.as_os_str().len() <= 4096,
            (2, None, Some(shared)) => {
                signal_control::StateReadInput {
                    key: shared.state_key.clone(),
                    expected_head: None,
                }
                .validate()
                .is_ok()
                    && shared
                        .bootstrap_checkpoint
                        .is_none_or(|n| n <= i64::MAX as u64)
                    && shared.limits(Uuid::from_u128(1)).is_ok()
            }
            _ => false,
        };
        if !persistence_valid
            || c.owner_generation.is_nil()
            || c.cadence_ms == 0
            || c.cadence_ms > 60000
            || c.cadence_ms > c.detector.policy.observer_freshness_ms as u64
            || c.cadence_ms > c.detector.policy.heartbeat_ms as u64
        {
            return Err(ConfigError::Invalid("sensor health bounds"));
        }
        Ok(c)
    }
    pub fn cadence(&self) -> Duration {
        Duration::from_millis(self.cadence_ms)
    }
    pub fn shared(&self) -> Option<&SharedConfiguration> {
        self.shared.as_ref()
    }
    pub async fn load(settings: &Settings) -> Result<Option<Self>, ConfigError> {
        let Some(path) = settings.optional("SIGNAL_SENSOR_HEALTH_CONFIG")? else {
            return Ok(None);
        };
        config::read_limited_document(
            path.into(),
            512 * 1024,
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
            Self::parse,
        )
        .await
        .map(Some)
    }
    pub fn source_binding(&self) -> Result<[u8; 32], Error> {
        let verifier = Verifier::new(
            self.detector.policy.clone(),
            self.detector.observer_keys.clone(),
        )?;
        let mut hash = Sha256::new();
        hash.update(b"platform-signal/sensor-owner/v1\0");
        hash.update(self.owner_generation.as_bytes());
        hash.update(
            serde_json::to_vec(&self.detector.source_scopes).map_err(|_| Error::Configuration)?,
        );
        hash.update(verifier.enrollment_sha256());
        if let Some(shared) = &self.shared {
            hash.update(b"platform-signal/shared-sensor-source/v1\0");
            hash.update(serde_json::to_vec(shared).map_err(|_| Error::Configuration)?);
        }
        Ok(hash.finalize().into())
    }
    pub async fn open(self, wal: BufferMetrics) -> Result<Detector, Error> {
        let cadence = self.cadence();
        let verifier = Verifier::new(
            self.detector.policy.clone(),
            self.detector.observer_keys.clone(),
        )?;
        let epoch = Epoch {
            schema_version: 1,
            source_stream: wal.stream_id,
            source_binding: self.source_binding()?,
            checkpoint: wal.checkpoint,
            last_sequence: wal.last_sequence,
            now_ms: chrono::Utc::now().timestamp_millis(),
        };
        let session = Session::open(
            self.detector.clone(),
            self.database.ok_or(Error::Configuration)?,
            epoch,
            RuleContext::new(Duration::from_secs(5)),
        )
        .await?;
        let monitor = session.monitor();
        Ok(Detector {
            session: tokio::sync::Mutex::new(session),
            monitor,
            verifier,
            config: self.detector.clone(),
            cadence,
            next: Mutex::new(Instant::now()),
            health: Mutex::new(SensorHealthSinkMetrics {
                sources: self.detector.policy.expected.len(),
                source_capacity: self.detector.policy.max_sources,
                proof_capacity: self.detector.max_proofs,
                pending_capacity: self.detector.max_outputs,
                history_assessment_capacity: self.detector.max_history_assessments,
                history_byte_capacity: self.detector.max_history_bytes,
                byte_capacity: self.detector.max_state_bytes,
                indeterminate: self.detector.policy.expected.len(),
                coverage_gap: true,
                ..Default::default()
            }),
            valid_until: AtomicI64::new(0),
            held: AtomicBool::new(true),
            rejections: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        })
    }
}
pub(crate) struct Detector {
    session: tokio::sync::Mutex<Session>,
    monitor: state_journal::Monitor,
    verifier: Verifier,
    config: native::Config,
    cadence: Duration,
    next: Mutex<Instant>,
    health: Mutex<SensorHealthSinkMetrics>,
    valid_until: AtomicI64,
    held: AtomicBool,
    rejections: AtomicU64,
    failures: AtomicU64,
}
struct Attempt<'a> {
    owner: &'a Detector,
    complete: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.owner.held.store(true, Ordering::Release);
            self.owner.failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl Detector {
    pub fn validate(&self, event: &SignalEvent) -> Result<(), AdmissionError> {
        self.config
            .validate_event(event, &self.verifier, chrono::Utc::now().timestamp_millis())
            .map_err(|_| {
                self.rejections.fetch_add(1, Ordering::Relaxed);
                AdmissionError::InvalidEvent
            })
    }
    pub fn due(&self) -> bool {
        self.next
            .lock()
            .map(|t| Instant::now() >= *t)
            .unwrap_or(true)
    }
    pub async fn complete(
        &self,
        rows: &[SequencedEvent],
        context: RuleContext,
    ) -> Result<Completion, Error> {
        let mut attempt = Attempt {
            owner: self,
            complete: false,
        };
        let mut session = self
            .session
            .try_lock()
            .map_err(|_| state_journal::Error::Busy)?;
        let result = session
            .complete(rows, chrono::Utc::now().timestamp_millis(), true, context)
            .await?;
        let mut health = self
            .health
            .lock()
            .map_err(|_| state_journal::Error::Closed)?;
        health.history_assessments = result.history_assessments;
        health.history_bytes = result.history_bytes;
        health.history_expired = result.history_expired;
        health.history_evicted = result.history_evicted;
        health.proofs = result.proofs;
        health.bytes = result.bytes;
        health.pending = result.published_prefix;
        health.indeterminate = result
            .assessments
            .iter()
            .filter(|a| a.outcome == Outcome::Indeterminate)
            .count();
        health.coverage_gap = result
            .assessments
            .iter()
            .any(|a| a.outcome != Outcome::NoMatch);
        self.valid_until
            .store(result.valid_until_ms, Ordering::Release);
        *self.next.lock().map_err(|_| state_journal::Error::Closed)? =
            Instant::now() + self.cadence;
        self.held.store(false, Ordering::Release);
        attempt.complete = true;
        Ok(result)
    }
    pub async fn acknowledge(
        &self,
        revision: u64,
        count: usize,
        context: RuleContext,
    ) -> Result<(), Error> {
        let mut attempt = Attempt {
            owner: self,
            complete: false,
        };
        let session = self
            .session
            .try_lock()
            .map_err(|_| state_journal::Error::Busy)?;
        session.acknowledge(revision, count, context).await?;
        self.health
            .lock()
            .map_err(|_| state_journal::Error::Closed)?
            .pending = 0;
        attempt.complete = true;
        Ok(())
    }
    pub fn metrics(&self) -> SensorHealthSinkMetrics {
        let mut h = self
            .health
            .lock()
            .map(|h| *h)
            .unwrap_or(SensorHealthSinkMetrics {
                coverage_gap: true,
                ..Default::default()
            });
        let (depth, capacity, failures) = self.monitor.metrics();
        h.operations = depth;
        h.operation_capacity = capacity;
        h.failures = failures.saturating_add(self.failures.load(Ordering::Relaxed));
        h.rejections = self.rejections.load(Ordering::Relaxed);
        h.closed = self.monitor.is_closed();
        h.coverage_gap |= h.closed
            || self.held.load(Ordering::Acquire)
            || chrono::Utc::now().timestamp_millis() >= self.valid_until.load(Ordering::Acquire);
        h
    }
    pub async fn shutdown(&self, context: RuleContext) -> Result<(), Error> {
        self.held.store(true, Ordering::Release);
        let session = tokio::select! {biased;_=context.cancellation.cancelled()=>return Err(state_journal::Error::Cancelled.into()),r=tokio::time::timeout_at(context.deadline,self.session.lock())=>r.map_err(|_|state_journal::Error::Timeout)?};
        session.shutdown(context).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    pub(crate) fn configuration(database: &std::path::Path) -> Value {
        json!({
            "schema_version": 1, "database": database,
            "owner_generation": Uuid::from_u128(3), "cadence_ms": 10,
            "detector": {
                "schema_version": 1,
                "policy": {
                    "schema_version": 1, "rule_id": "fixture-heartbeat", "revision": "fixture-v1",
                    "heartbeat_ms": 100, "grace_ms": 20, "observer_freshness_ms": 500,
                    "max_sources": 1, "max_state_bytes": 8192,
                    "expected": [{"source_id": Uuid::from_u128(1), "observer_id": Uuid::from_u128(2),
                        "binding": vec![1; 32], "expected_since_ms": 1000, "require_checkpoint": true}]
                },
                "observer_keys": [{"schema_version": 1, "observer_id": Uuid::from_u128(2),
                    "public_key": vec![3; 32]}],
                "source_scopes": [{"schema_version": 1, "source_id": Uuid::from_u128(1),
                    "event_scope": {"schema_version": 1, "source": "fixture", "account": "a", "resource": "r"}}],
                "title": "Fixture telemetry gap", "severity": "high", "max_proofs": 3,
                "max_event_bytes": 16384, "max_state_bytes": 262144,
                "max_record_bytes": 1048576, "max_outputs": 4, "max_output_bytes": 65536,
                "max_history_assessments": 16, "max_history_bytes": 65536, "history_retention_ms": 1000
            }
        })
    }

    #[test]
    fn configuration_refuses_unknown_fields_relative_paths_and_invalid_cadence() -> Result {
        let valid = configuration(std::path::Path::new("/fixture/native.sqlite"));
        Configuration::parse(&valid.to_string())?;
        for (key, value) in [
            ("schema_version", json!(2)),
            ("database", json!("relative.sqlite")),
            ("owner_generation", json!(Uuid::nil())),
            ("cadence_ms", json!(0)),
            ("cadence_ms", json!(101)),
            ("unexpected", json!(true)),
        ] {
            let mut invalid = valid.clone();
            invalid[key] = value;
            assert!(Configuration::parse(&invalid.to_string()).is_err(), "{key}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn configuration_loads_through_the_bounded_document_reader() -> Result {
        let _worker_fixture = config::FILE_WORKER_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sensor.json");
        std::fs::write(
            &path,
            configuration(&dir.path().join("native.sqlite")).to_string(),
        )?;
        let settings = Settings::for_test(
            "schema_version: 1\n",
            &[(
                "SIGNAL_SENSOR_HEALTH_CONFIG",
                path.to_str().ok_or("fixture path")?,
            )],
        )?;
        assert!(Configuration::load(&settings).await?.is_some());
        std::fs::write(path, vec![b' '; 512 * 1024 + 1])?;
        assert!(Configuration::load(&settings).await.is_err());
        Ok(())
    }

    #[test]
    fn shared_configuration_requires_explicit_storage_and_bounded_canonical_recovery() -> Result {
        let local = configuration(std::path::Path::new("/fixture/native.sqlite"));
        let mut shared = local.clone();
        shared
            .as_object_mut()
            .ok_or("configuration object")?
            .remove("database");
        shared["schema_version"] = json!(2);
        shared["shared"] = json!({
            "state_key":"sensor-fixture", "bootstrap_checkpoint":0,
            "recovery":{"files":4,"object_bytes":1048576,"decoded_bytes":1048576,
                "scanned_rows":4096,"result_bytes":1048576}
        });
        assert!(Configuration::parse(&local.to_string())?.shared().is_none());
        let parsed = Configuration::parse(&shared.to_string())?;
        let settings = parsed.shared().ok_or("shared settings")?;
        assert_eq!(settings.bootstrap_checkpoint, Some(0));
        settings.limits(Uuid::from_u128(1))?;
        let binding = parsed.source_binding()?;
        for mode in 0..5 {
            let mut changed = shared.clone();
            match mode {
                0 => changed["shared"]["state_key"] = json!("another-state"),
                1 => changed["shared"]["bootstrap_checkpoint"] = json!(1),
                2 => changed["shared"]["recovery"]["files"] = json!(5),
                3 => changed["owner_generation"] = json!(Uuid::from_u128(4)),
                _ => {
                    changed["detector"]["source_scopes"][0]["event_scope"]["account"] =
                        json!("another-account")
                }
            }
            assert_ne!(
                Configuration::parse(&changed.to_string())?.source_binding()?,
                binding
            );
        }
        for mode in 0..8 {
            let mut invalid = shared.clone();
            match mode {
                0 => invalid["database"] = json!("/fixture/native.sqlite"),
                1 => invalid["schema_version"] = json!(1),
                2 => invalid["shared"]["state_key"] = json!(""),
                3 => invalid["shared"]["bootstrap_checkpoint"] = json!(u64::MAX),
                4 => invalid["shared"]["recovery"]["files"] = json!(129),
                5 => invalid["shared"]["recovery"]["result_bytes"] = json!(1048577),
                6 => invalid["shared"]["recovery"]["extra"] = json!(true),
                _ => invalid
                    .as_object_mut()
                    .ok_or("configuration object")?
                    .remove("shared")
                    .map(|_| ())
                    .ok_or("shared field")?,
            }
            assert!(
                Configuration::parse(&invalid.to_string()).is_err(),
                "mutation {mode}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn idle_runtime_stays_unknown_and_shutdown_releases_the_actual_journal() -> Result {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let text = configuration(&dir.path().join("native.sqlite")).to_string();
        let wal = BufferMetrics {
            stream_id: Uuid::from_u128(4),
            ..Default::default()
        };
        let detector = Configuration::parse(&text)?.open(wal).await?;
        assert!(detector.due());
        assert!(detector.metrics().coverage_gap);
        assert_eq!(detector.metrics().indeterminate, 1);
        let completed = detector
            .complete(&[], RuleContext::new(Duration::from_secs(5)))
            .await?;
        assert!(completed.findings.is_empty());
        assert_eq!(completed.assessments[0].outcome, Outcome::Indeterminate);
        detector
            .acknowledge(
                completed.revision,
                completed.published_prefix,
                RuleContext::new(Duration::from_secs(5)),
            )
            .await?;
        assert!(detector.metrics().coverage_gap);
        assert!(Configuration::parse(&text)?.open(wal).await.is_err());
        detector
            .shutdown(RuleContext::new(Duration::from_secs(5)))
            .await?;
        assert!(detector.metrics().closed);
        let reopened = Configuration::parse(&text)?.open(wal).await?;
        assert!(reopened.metrics().coverage_gap);
        reopened
            .shutdown(RuleContext::new(Duration::from_secs(5)))
            .await?;
        Ok(())
    }
}
