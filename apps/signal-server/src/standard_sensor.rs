//! Standard's single-writer sensor owner; control publication owns commit/ACK.
use crate::sensor_runtime::Configuration;
use sha2::{Digest, Sha256};
use signal_control::{
    ControlClient, ControlContext, ControlError, LeaseToken, PriorStateProvenance,
    ProducerEnrollment, RevisionedState, StateReadInput,
};
use signal_findings::ScopedFinding;
use signal_protocol::{AdmissionError, SensorHealthSinkMetrics};
use signal_rules::{RuleContext, sensor_health::Outcome};
use signal_server::sensor_health::{
    Verifier,
    native::{self, Engine, Epoch, SharedBinding, Snapshot},
};
use signal_storage::{StoredEvent, object_codec::ObjectCodec, object_io::ObjectIo};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
};
use uuid::Uuid;
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error(transparent)]
    Native(#[from] native::Error),
    #[error(transparent)]
    Shared(#[from] native::SharedError),
}
pub(crate) struct Health {
    value: Mutex<SensorHealthSinkMetrics>,
    verifier: Verifier,
    config: native::Config,
    valid_until: AtomicI64,
    closed: AtomicBool,
    rejections: AtomicU64,
    pins: AtomicUsize,
    pin_capacity: usize,
}
impl Health {
    fn refresh(&self, result: &native::Completion) -> Result<(), Error> {
        let mut value = self.value.lock().map_err(|_| ControlError::Unavailable)?;
        value.operations = 0;
        value.proofs = result.proofs;
        value.bytes = result.bytes;
        value.pending = result.published_prefix;
        value.history_assessments = result.history_assessments;
        value.history_bytes = result.history_bytes;
        value.history_expired = result.history_expired;
        value.history_evicted = result.history_evicted;
        value.indeterminate = result
            .assessments
            .iter()
            .filter(|a| a.outcome == Outcome::Indeterminate)
            .count();
        value.coverage_gap = result
            .assessments
            .iter()
            .any(|a| a.outcome != Outcome::NoMatch);
        self.valid_until
            .store(result.valid_until_ms, Ordering::Release);
        Ok(())
    }

    pub fn stop(&self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut value) = self.value.lock() {
            value.operations = 0;
        }
    }
    pub fn validate(&self, event: &signal_event::SignalEvent) -> Result<(), AdmissionError> {
        self.config
            .validate_event(event, &self.verifier, chrono::Utc::now().timestamp_millis())
            .map_err(|_| {
                self.rejections.fetch_add(1, Ordering::Relaxed);
                AdmissionError::InvalidEvent
            })
    }
    pub fn metrics(&self) -> SensorHealthSinkMetrics {
        let mut value = self
            .value
            .lock()
            .map(|v| *v)
            .unwrap_or(SensorHealthSinkMetrics {
                coverage_gap: true,
                ..Default::default()
            });
        value.closed |= self.closed.load(Ordering::Acquire);
        value.coverage_gap |= value.closed
            || chrono::Utc::now().timestamp_millis() >= self.valid_until.load(Ordering::Acquire);
        value.rejections = self.rejections.load(Ordering::Relaxed);
        value
    }
    pub fn pins(&self) -> (usize, usize) {
        (self.pins.load(Ordering::Acquire), self.pin_capacity)
    }
}
pub(crate) struct Consumer {
    pub binding: SharedBinding,
    pub prior: Option<PriorStateProvenance>,
    pub retained: Vec<StoredEvent>,
    pub health: Arc<Health>,
    engine: Engine,
    current: Option<Snapshot>,
    replay_pins: Vec<Uuid>,
    cadence: std::time::Duration,
    next: tokio::time::Instant,
}
pub(crate) struct Startup<'a> {
    pub configuration: Configuration,
    pub producer: ProducerEnrollment,
    pub revision: [u8; 32],
    pub backend: Uuid,
    pub control: &'a ControlClient,
    pub objects: &'a ObjectIo,
    pub codec: &'a ObjectCodec,
    pub token: LeaseToken,
    pub head: Option<Uuid>,
    pub wal: signal_buffer::BufferMetrics,
    pub admission_floor: u64,
    pub context: ControlContext,
}
pub(crate) struct Candidate {
    pub value: RevisionedState,
    pub derived: Vec<(u64, ScopedFinding)>,
    native: native::Candidate,
    retained: Vec<StoredEvent>,
}
fn rules(context: &ControlContext) -> RuleContext {
    RuleContext {
        deadline: context.deadline(),
        cancellation: context.cancellation_token(),
    }
}
impl Consumer {
    pub async fn open(input: Startup<'_>) -> Result<Self, Error> {
        input.context.check()?;
        let config = input.configuration.detector.clone();
        let cadence = input.configuration.cadence();
        let settings = input
            .configuration
            .shared()
            .cloned()
            .ok_or(ControlError::Invalid)?;
        if input.wal.stream_id != input.producer.scope.stream
            || input.producer.wal_floor > input.wal.last_sequence
            || input.admission_floor != input.wal.last_sequence
        {
            return Err(ControlError::Fenced.into());
        }
        let epoch = Epoch {
            schema_version: 1,
            source_stream: input.wal.stream_id,
            source_binding: input.configuration.source_binding()?,
            checkpoint: input.wal.checkpoint,
            last_sequence: input.wal.last_sequence,
            now_ms: chrono::Utc::now().timestamp_millis(),
        };
        let binding = SharedBinding {
            producer: input.producer,
            key: settings.state_key.clone(),
            rule_revision: input.revision,
        };
        let read = input
            .control
            .read_state(
                input.token.clone(),
                StateReadInput {
                    key: binding.key.clone(),
                    expected_head: input.head,
                },
                input.context.clone(),
            )
            .await?;
        if read.checkpoint != input.wal.checkpoint {
            return Err(ControlError::Conflict.into());
        }
        let mut engine = Engine::new(config.clone(), epoch.clone(), None, &rules(&input.context))?;
        let (current, prior, retained, replay_pins) = if read.state.is_some() {
            let recovered = native::SharedRecovery {
                binding: &binding,
                engine: &engine,
                control: input.control,
                objects: input.objects,
                codec: input.codec,
                limits: settings.limits(input.backend)?,
            }
            .recover(input.token, input.context.clone())
            .await?;
            if recovered.prior.checkpoint != read.checkpoint {
                return Err(ControlError::Conflict.into());
            }
            (
                Some(recovered.snapshot),
                Some(recovered.prior),
                recovered.canonical.rows()?.to_vec(),
                recovered.replay_pins,
            )
        } else {
            if settings.bootstrap_checkpoint != Some(read.checkpoint) {
                return Err(ControlError::Fenced.into());
            }
            let candidate = engine
                .prepare(None, &[], epoch.now_ms, true, rules(&input.context))
                .await?;
            let snapshot = candidate.snapshot().clone();
            let (value, detached) = binding.encode(&engine, &snapshot, &rules(&input.context))?;
            if !detached.retained.is_empty() {
                return Err(ControlError::Corrupt.into());
            }
            let confirmed = input
                .control
                .initialize_sensor_state(
                    input.token.clone(),
                    signal_control::SensorBootstrap {
                        head: input.head,
                        checkpoint: read.checkpoint,
                        state: value,
                    },
                    input.context.clone(),
                )
                .await?;
            engine.confirm(candidate, snapshot.record(), &rules(&input.context))?;
            let (snapshot, prior) =
                binding.restore(&engine, &confirmed, &[], &rules(&input.context))?;
            (Some(snapshot), Some(prior), Vec::new(), Vec::new())
        };
        let engine = Engine::new(
            config.clone(),
            epoch,
            current.as_ref(),
            &rules(&input.context),
        )?;
        let health = Arc::new(Health {
            value: Mutex::new(SensorHealthSinkMetrics {
                sources: config.policy.expected.len(),
                source_capacity: config.policy.max_sources,
                proof_capacity: config.max_proofs,
                pending_capacity: config.max_outputs,
                byte_capacity: config.max_state_bytes,
                history_assessment_capacity: config.max_history_assessments,
                history_byte_capacity: config.max_history_bytes,
                operation_capacity: 1,
                indeterminate: config.policy.expected.len(),
                coverage_gap: true,
                ..Default::default()
            }),
            verifier: Verifier::new(config.policy.clone(), config.observer_keys.clone())
                .map_err(native::Error::from)?,
            config,
            valid_until: AtomicI64::new(0),
            closed: AtomicBool::new(false),
            rejections: AtomicU64::new(0),
            pins: AtomicUsize::new(replay_pins.len()),
            pin_capacity: settings.recovery.files,
        });
        if let Some(snapshot) = &current {
            health.refresh(&engine.inspect(
                snapshot,
                chrono::Utc::now().timestamp_millis(),
                &rules(&input.context),
            )?)?;
        }
        input.context.check()?;
        Ok(Self {
            binding,
            prior,
            retained,
            health,
            engine,
            current,
            replay_pins,
            cadence,
            next: tokio::time::Instant::now(),
        })
    }
    pub async fn prepare(
        &mut self,
        rows: &[StoredEvent],
        context: &ControlContext,
    ) -> Result<Candidate, Error> {
        context.check()?;
        if rows.is_empty() || rows.len() > 4096 {
            return Err(ControlError::Invalid.into());
        }
        if let Ok(mut value) = self.health.value.lock() {
            value.operations = 1;
            value.coverage_gap = true;
        }
        let sequenced = rows
            .iter()
            .map(|r| signal_buffer::SequencedEvent {
                sequence: r.sequence,
                event: r.event.clone(),
            })
            .collect::<Vec<_>>();
        let native = self
            .engine
            .prepare(
                self.current.as_ref(),
                &sequenced,
                chrono::Utc::now().timestamp_millis(),
                true,
                rules(context),
            )
            .await?;
        let preview = self.engine.preview(&native, &rules(context))?;
        let (value, detached) =
            self.binding
                .encode(&self.engine, native.snapshot(), &rules(context))?;
        let mut derived = Vec::with_capacity(preview.findings.len());
        for finding in preview.findings {
            let scoped = finding
                .into_scoped(self.binding.producer.scope_generation)
                .map_err(native::Error::from)?;
            let anchor = detached
                .retained
                .iter()
                .find(|r| scoped.finding().event_ids.contains(&r.event.id))
                .ok_or(ControlError::Corrupt)?
                .sequence;
            derived.push((anchor, scoped));
        }
        context.check()?;
        Ok(Candidate {
            value,
            derived,
            native,
            retained: detached.retained,
        })
    }
    pub fn accept(
        &mut self,
        candidate: Candidate,
        checkpoint: u64,
        context: &ControlContext,
    ) -> Result<(), Error> {
        if candidate.native.snapshot().record().checkpoint != checkpoint {
            return Err(ControlError::Conflict.into());
        }
        let snapshot = candidate.native.snapshot().clone();
        let result = self
            .engine
            .confirm(candidate.native, snapshot.record(), &rules(context))?;
        self.prior = Some(PriorStateProvenance {
            schema_version: 1,
            key: self.binding.key.clone(),
            checkpoint,
            revision: self.binding.rule_revision,
            value_sha256: Sha256::digest(&candidate.value.bytes).into(),
            scope_generation: self.binding.producer.scope_generation,
        });
        self.current = Some(snapshot);
        self.retained = candidate.retained;
        self.health.refresh(&result)?;
        self.next = tokio::time::Instant::now() + self.cadence;
        Ok(())
    }
    pub fn due(&self) -> bool {
        self.current.is_some() && tokio::time::Instant::now() >= self.next
    }
    pub fn wait(&self) -> std::time::Duration {
        if self.current.is_none() {
            std::time::Duration::from_secs(1)
        } else {
            self.next
                .saturating_duration_since(tokio::time::Instant::now())
        }
    }
    pub async fn maintain(
        &mut self,
        control: &ControlClient,
        token: LeaseToken,
        head: Option<Uuid>,
        context: ControlContext,
    ) -> Result<(), Error> {
        context.check()?;
        if let Ok(mut value) = self.health.value.lock() {
            value.operations = 1;
            value.coverage_gap = true;
        }
        let current = self.current.as_ref().ok_or(ControlError::Conflict)?;
        let original = self.engine.inspect(
            current,
            chrono::Utc::now().timestamp_millis(),
            &rules(&context),
        )?;
        let mut items = Vec::with_capacity(original.findings.len());
        for finding in original.findings {
            let scoped = finding
                .into_scoped(self.binding.producer.scope_generation)
                .map_err(native::Error::from)?;
            items.push(signal_control::FindingInput {
                id: scoped.finding().id,
                bytes: serde_json::to_vec(scoped.finding()).map_err(|_| ControlError::Invalid)?,
            });
        }
        let known = control
            .known_findings(token.clone(), head, items.clone(), context.clone())
            .await?;
        let retired = items.iter().take_while(|f| known.contains(&f.id)).count();
        let native = self
            .engine
            .prepare_retiring(
                current,
                retired,
                chrono::Utc::now().timestamp_millis(),
                rules(&context),
            )
            .await?;
        let (value, detached) =
            self.binding
                .encode(&self.engine, native.snapshot(), &rules(&context))?;
        let input = signal_control::SensorMaintenance {
            head,
            prior: self.prior.clone().ok_or(ControlError::Conflict)?,
            state: value.clone(),
            retired: items.into_iter().take(retired).collect(),
        };
        let confirmed = control
            .maintain_sensor_state(token, input, context.clone())
            .await?;
        self.accept(
            Candidate {
                value,
                derived: Vec::new(),
                native,
                retained: detached.retained,
            },
            confirmed.checkpoint,
            &context,
        )?;
        Ok(())
    }
    pub async fn cleanup(
        &mut self,
        control: &ControlClient,
        token: LeaseToken,
        head: Uuid,
        context: ControlContext,
    ) -> Result<(), Error> {
        let Some(prior) = &self.prior else {
            return Ok(());
        };
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
                Err(ControlError::Fenced) => index += 1,
                Ok(_) => return Err(ControlError::Corrupt.into()),
                Err(error) => return Err(error.into()),
            }
            self.health
                .pins
                .store(self.replay_pins.len(), Ordering::Release);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use signal_control::{Scope, StateReadResult};
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    #[tokio::test]
    async fn candidate_waits_for_confirmation_and_restart_keeps_original_outbox_unknown() -> Result
    {
        let signer =
            Ed25519KeyPair::from_seed_unchecked(&[17; 32]).map_err(|_| "fixture signer")?;
        let now = chrono::Utc::now().timestamp_millis();
        let mut document = crate::sensor_runtime::tests::configuration(std::path::Path::new(
            "/fixture/native.sqlite",
        ));
        document["detector"]["observer_keys"][0]["public_key"] =
            serde_json::json!(signer.public_key().as_ref());
        document["detector"]["policy"]["observer_freshness_ms"] = serde_json::json!(60000);
        document["detector"]["policy"]["expected"][0]["expected_since_ms"] =
            serde_json::json!(now - 10000);
        let configuration = Configuration::parse(&document.to_string())?;
        let config = configuration.detector.clone();
        let verifier = Verifier::new(config.policy.clone(), config.observer_keys.clone())?;
        let binding = SharedBinding {
            producer: ProducerEnrollment {
                scope: Scope {
                    schema_version: 1,
                    store_id: Uuid::from_u128(20),
                    generation: Uuid::from_u128(21),
                    tenant: "fixture".into(),
                    stream: Uuid::from_u128(1),
                    partition_id: Uuid::from_u128(22),
                },
                scope_generation: Uuid::from_u128(23),
                startup: Uuid::from_u128(24),
                wal_floor: 0,
            },
            key: "sensor-fixture".into(),
            rule_revision: [2; 32],
        };
        let epoch = Epoch {
            schema_version: 1,
            source_stream: binding.producer.scope.stream,
            source_binding: configuration.source_binding()?,
            checkpoint: 0,
            last_sequence: 0,
            now_ms: now - 1000,
        };
        let context = ControlContext::new(std::time::Duration::from_secs(5))?;
        let engine = Engine::new(config.clone(), epoch, None, &rules(&context))?;
        let health = Arc::new(Health {
            value: Mutex::new(SensorHealthSinkMetrics {
                coverage_gap: true,
                operation_capacity: 1,
                ..Default::default()
            }),
            verifier,
            config: config.clone(),
            valid_until: AtomicI64::new(0),
            closed: AtomicBool::new(false),
            rejections: AtomicU64::new(0),
            pins: AtomicUsize::new(0),
            pin_capacity: 4,
        });
        let observation = signal_rules::sensor_health::Observation {
            schema_version: 1,
            source_id: Uuid::from_u128(1),
            binding: [1; 32],
            observer_id: Uuid::from_u128(2),
            sequence: 1,
            observed_at_ms: now,
            health: signal_rules::sensor_health::ObserverHealth::Healthy,
            heartbeat_at_ms: Some(now - 1000),
            checkpoint: Some(1),
        };
        let payload = serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"policy_sha256":health.verifier.policy_sha256(),"observation":observation}),
        )?;
        let mut signed = signal_server::sensor_health::DOMAIN.to_vec();
        signed.extend_from_slice(&payload);
        let envelope = serde_json::to_string(
            &serde_json::json!({"schema_version":1,"observer_id":Uuid::from_u128(2),"payload_base64":STANDARD.encode(&payload),"signature_base64":STANDARD.encode(signer.sign(&signed).as_ref())}),
        )?;
        let event = serde_json::from_value(
            serde_json::json!({"schema_version":1,"id":Uuid::from_u128(100),"timestamp":chrono::Utc::now(),"observed_at":chrono::Utc::now(),"source":{"type":"fixture"},"resource":{"kind":"host","id":"r","account_id":"a"},"severity":"info","message":"probe","attributes":{native::ATTRIBUTE:envelope},"tags":[]}),
        )?;
        let row = StoredEvent { sequence: 1, event };
        health.validate(&row.event)?;
        let mut changed = row.event.clone();
        changed.resource.as_mut().ok_or("resource")?.account_id = Some("foreign".into());
        assert!(health.validate(&changed).is_err());
        assert_eq!(health.metrics().rejections, 1);
        let mut owner = Consumer {
            binding,
            prior: None,
            retained: Vec::new(),
            health: health.clone(),
            engine,
            current: None,
            replay_pins: Vec::new(),
            cadence: std::time::Duration::from_millis(10),
            next: tokio::time::Instant::now(),
        };
        let candidate = owner.prepare(std::slice::from_ref(&row), &context).await?;
        assert_eq!(candidate.derived.len(), 1);
        assert!(owner.current.is_none());
        assert!(health.metrics().coverage_gap);
        assert!(owner.accept(candidate, 2, &context).is_err());
        let candidate = owner.prepare(std::slice::from_ref(&row), &context).await?;
        let finding = candidate.derived[0].1.finding().clone();
        let value = candidate.value.clone();
        owner.accept(candidate, 1, &context)?;
        assert_eq!(health.metrics().pending, 1);
        assert_eq!(health.metrics().operations, 0);
        let read = StateReadResult {
            schema_version: 1,
            partition_id: owner.binding.producer.scope.partition_id,
            head: Some(Uuid::from_u128(25)),
            checkpoint: 1,
            state: Some(value),
        };
        let (snapshot, _) =
            owner
                .binding
                .restore(&owner.engine, &read, &owner.retained, &rules(&context))?;
        let mut restarted = Engine::new(
            config,
            Epoch {
                schema_version: 1,
                source_stream: Uuid::from_u128(1),
                source_binding: configuration.source_binding()?,
                checkpoint: 1,
                last_sequence: 1,
                now_ms: chrono::Utc::now().timestamp_millis(),
            },
            Some(&snapshot),
            &rules(&context),
        )?;
        health.refresh(&restarted.inspect(
            &snapshot,
            chrono::Utc::now().timestamp_millis(),
            &rules(&context),
        )?)?;
        assert_eq!(health.metrics().pending, 1);
        assert_eq!(health.metrics().indeterminate, 1);
        assert!(health.metrics().coverage_gap);
        let recovered = restarted
            .prepare(
                Some(&snapshot),
                &[],
                chrono::Utc::now().timestamp_millis(),
                true,
                rules(&context),
            )
            .await?;
        let preview = restarted.preview(&recovered, &rules(&context))?;
        assert_eq!(preview.assessments[0].outcome, Outcome::Indeterminate);
        assert_eq!(preview.findings[0].budget_preview().id, finding.id);
        assert_eq!(
            recovered.snapshot().record().outbox,
            snapshot.record().outbox
        );
        health.stop();
        assert!(health.metrics().closed);
        Ok(())
    }
}
