//! Native monitor/evidence/outbox orchestration. The monolith supplies current
//! authenticated admission and independent host authorization; this is no grant.
use super::{ObserverKey, Verifier};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_buffer::SequencedEvent;
use signal_event::SignalEvent;
use signal_findings::{DerivedFinding, DetectionSeverity, Finding};
use signal_protocol::access::ScopeFacts;
use signal_rules::{
    RuleContext,
    sensor_health::{self as core, Admission, Assessment, Monitor, Outcome, Reason},
    state_journal::{self, Journal, Output, Record},
};
use std::{
    collections::BTreeSet,
    io::{self, Write},
    path::PathBuf,
};
use thiserror::Error;
use uuid::Uuid;

pub const ATTRIBUTE: &str = "signal.sensor_health.observation";
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid native sensor-health state or policy")]
    Configuration,
    #[error("native sensor-health original evidence conflicts")]
    Conflict,
    #[error("native sensor-health evidence capacity exhausted")]
    Capacity,
    #[error(transparent)]
    Core(#[from] core::Error),
    #[error(transparent)]
    Verification(#[from] super::Error),
    #[error(transparent)]
    Journal(#[from] state_journal::Error),
    #[error(transparent)]
    Finding(#[from] signal_findings::FindingError),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventScope {
    pub schema_version: u16,
    pub source: String,
    pub account: String,
    pub resource: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceScope {
    pub schema_version: u16,
    pub source_id: Uuid,
    pub event_scope: EventScope,
}
impl EventScope {
    fn includes(&self, event: &SignalEvent) -> bool {
        let facts = ScopeFacts::event(event);
        facts.source == Some(self.source.as_str())
            && facts.account == Some(self.account.as_str())
            && facts.resource == Some(self.resource.as_str())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u16,
    pub policy: core::Policy,
    pub observer_keys: Vec<ObserverKey>,
    pub source_scopes: Vec<SourceScope>,
    pub title: String,
    pub severity: DetectionSeverity,
    pub max_proofs: usize,
    pub max_event_bytes: usize,
    pub max_state_bytes: usize,
    pub max_record_bytes: usize,
    pub max_outputs: usize,
    pub max_output_bytes: usize,
}
fn identity(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.trim() == s && !s.chars().any(char::is_control)
}
impl Config {
    /// Pure admission preflight; the caller still proves native transport authority.
    pub fn validate_event(
        &self,
        event: &SignalEvent,
        verifier: &Verifier,
        now: i64,
    ) -> Result<(), Error> {
        if !event.attributes.contains_key(ATTRIBUTE) {
            return Ok(());
        }
        event.validate().map_err(|_| Error::Configuration)?;
        encode(event, self.max_event_bytes)?;
        let proof = verifier.verify(envelope(event)?, now)?;
        if !self.includes(proof.observation().source_id, event) {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.policy.validate()?;
        if self.schema_version != 1
            || self.source_scopes.len() != self.policy.expected.len()
            || self
                .source_scopes
                .iter()
                .zip(&self.policy.expected)
                .any(|(scope, expected)| {
                    scope.schema_version != 1
                        || scope.source_id != expected.source_id
                        || scope.event_scope.schema_version != 1
                        || [
                            &scope.event_scope.source,
                            &scope.event_scope.account,
                            &scope.event_scope.resource,
                        ]
                        .iter()
                        .any(|s| !identity(s))
                })
            || self.title.trim().is_empty()
            || self.title.len() > 4096
            || self.max_proofs < self.policy.expected.len()
            || self.max_proofs > self.policy.expected.len() * 3
            || !(1024..=16384).contains(&self.max_event_bytes)
            || !(1024..=16 * 1024 * 1024).contains(&self.max_state_bytes)
            || self.max_state_bytes < self.policy.max_state_bytes
        {
            return Err(Error::Configuration);
        }
        self.journal(Uuid::from_u128(1), [1; 32], [1; 32])
            .validate()?;
        Verifier::new(self.policy.clone(), self.observer_keys.clone())?;
        Ok(())
    }
    fn includes(&self, source: Uuid, event: &SignalEvent) -> bool {
        self.source_scopes
            .binary_search_by_key(&source, |s| s.source_id)
            .is_ok_and(|index| self.source_scopes[index].event_scope.includes(event))
    }
    fn journal(
        &self,
        stream: Uuid,
        source: [u8; 32],
        enrollment: [u8; 32],
    ) -> state_journal::Config {
        state_journal::Config {
            schema_version: 1,
            source_stream: stream,
            source_binding: source,
            enrollment_binding: enrollment,
            max_record_bytes: self.max_record_bytes,
            max_state_bytes: self.max_state_bytes,
            max_outputs: self.max_outputs,
            max_output_bytes: self.max_output_bytes,
        }
    }
}
struct Limit(usize);
impl Write for Limit {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(b.len())
            .ok_or_else(|| io::Error::other("native sensor capacity"))?;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, Error> {
    serde_json::to_writer(Limit(limit), value).map_err(|_| Error::Capacity)?;
    serde_json::to_vec(value).map_err(|_| Error::Configuration)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    schema_version: u16,
    wal_sequence: u64,
    authenticated_after: u64,
    epoch_ms: i64,
    event: SignalEvent,
    observation: core::Observation,
    payload_sha256: [u8; 32],
}
fn envelope(event: &SignalEvent) -> Result<&[u8], Error> {
    event
        .attributes
        .get(ATTRIBUTE)
        .and_then(|v| v.as_str())
        .map(str::as_bytes)
        .ok_or(Error::Configuration)
}
fn validate_proof(config: &Config, verifier: &Verifier, p: &Proof) -> Result<(), Error> {
    if p.schema_version != 1
        || p.epoch_ms < 0
        || p.wal_sequence == 0
        || p.wal_sequence <= p.authenticated_after
        || p.observation.observed_at_ms < p.epoch_ms
        || !config.includes(p.observation.source_id, &p.event)
    {
        return Err(Error::Conflict);
    }
    p.event.validate().map_err(|_| Error::Configuration)?;
    encode(&p.event, config.max_event_bytes)?;
    // Historical signature authentication only. The supplied time is checked
    // against the signed observation below; it never supplies current health.
    let original = verifier.verify(envelope(&p.event)?, p.observation.observed_at_ms)?;
    if original.observation() != &p.observation || original.payload_sha256() != p.payload_sha256 {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn reconstruct(
    config: &Config,
    proofs: &[Proof],
    clock: i64,
    context: &RuleContext,
) -> Result<Monitor, Error> {
    let mut monitor = Monitor::new(config.policy.clone(), clock)?;
    let mut ordered: Vec<_> = proofs.iter().collect();
    ordered.sort_by_key(|p| (p.observation.source_id, p.observation.sequence));
    for p in ordered {
        check(context)?;
        monitor.observe(p.observation.clone(), clock)?;
    }
    Ok(monitor)
}
fn required(monitor: &Monitor, proofs: &[Proof]) -> Result<Vec<Proof>, Error> {
    let mut kept = BTreeSet::new();
    for (source, latest, heartbeat, checkpoint) in monitor.retained_progress() {
        if let Some(latest) = latest {
            let matching = |p: &&Proof| p.observation.source_id == source;
            let current = proofs
                .iter()
                .filter(matching)
                .find(|p| p.observation == *latest)
                .ok_or(Error::Conflict)?;
            kept.insert(current.wal_sequence);
            if let Some(t) = heartbeat {
                kept.insert(
                    proofs
                        .iter()
                        .filter(matching)
                        .filter(|p| p.observation.heartbeat_at_ms == Some(t))
                        .min_by_key(|p| p.wal_sequence)
                        .ok_or(Error::Conflict)?
                        .wal_sequence,
                );
            }
            if let Some(c) = checkpoint {
                kept.insert(
                    proofs
                        .iter()
                        .filter(matching)
                        .filter(|p| p.observation.checkpoint == Some(c))
                        .min_by_key(|p| p.wal_sequence)
                        .ok_or(Error::Conflict)?
                        .wal_sequence,
                );
            }
        }
    }
    let mut result: Vec<_> = proofs
        .iter()
        .filter(|p| kept.contains(&p.wal_sequence))
        .cloned()
        .collect();
    result.sort_by_key(|p| p.wal_sequence);
    Ok(result)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema_version: u16,
    assessment: Assessment,
    evidence: Vec<Proof>,
    finding: Finding,
}
fn finding(config: &Config, assessment: &Assessment, evidence: &[Proof]) -> Result<Finding, Error> {
    if evidence.is_empty() {
        return Err(Error::Conflict);
    }
    let mut result = Finding {
        schema_version: signal_findings::SCHEMA_VERSION,
        id: assessment.gap_id.ok_or(Error::Conflict)?,
        rule_id: config.policy.rule_id.clone(),
        created_at: DateTime::<Utc>::from_timestamp_millis(assessment.assessed_at_ms)
            .ok_or(Error::Configuration)?,
        severity: config.severity,
        title: config.title.clone(),
        event_ids: evidence.iter().map(|p| p.event.id).collect(),
        attributes: serde_json::Map::new(),
    };
    result.attributes.insert("signal.sensor_health.v1".into(),serde_json::json!({"source_id":assessment.source_id,"deadline_ms":assessment.deadline_ms,"rule_revision":config.policy.revision,"outcome":"collection_gap","cause":"unknown"}));
    result.validate()?;
    Ok(result)
}
fn validate_pending(
    config: &Config,
    verifier: &Verifier,
    p: &Pending,
    context: &RuleContext,
) -> Result<(), Error> {
    if p.schema_version != 1
        || p.evidence.is_empty()
        || p.evidence.len() > 3
        || p.assessment.outcome != Outcome::Match
        || p.evidence
            .iter()
            .any(|e| e.observation.source_id != p.assessment.source_id)
        || p.evidence
            .windows(2)
            .any(|v| v[0].wal_sequence >= v[1].wal_sequence)
    {
        return Err(Error::Conflict);
    }
    for proof in &p.evidence {
        check(context)?;
        validate_proof(config, verifier, proof)?;
    }
    let mut monitor = reconstruct(config, &p.evidence, p.assessment.assessed_at_ms, context)?;
    let expected = monitor
        .assess(p.assessment.assessed_at_ms)?
        .into_iter()
        .find(|a| a.source_id == p.assessment.source_id)
        .ok_or(Error::Conflict)?;
    if expected != p.assessment || finding(config, &expected, &p.evidence)? != p.finding {
        return Err(Error::Conflict);
    }
    DerivedFinding::from_events(
        p.finding.clone(),
        &p.evidence.iter().map(|p| &p.event).collect::<Vec<_>>(),
        true,
    )?;
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema_version: u16,
    monitor: Vec<u8>,
    proofs: Vec<Proof>,
    known: Vec<Pending>,
}
fn decode(
    config: &Config,
    verifier: &Verifier,
    record: &Record,
    context: &RuleContext,
) -> Result<State, Error> {
    if record.state.len() > config.max_state_bytes {
        return Err(Error::Capacity);
    }
    let state: State = serde_json::from_slice(&record.state).map_err(|_| Error::Configuration)?;
    if state.schema_version != 1
        || state.proofs.len() > config.max_proofs
        || state.known.len() > config.policy.expected.len()
    {
        return Err(Error::Capacity);
    }
    let mut sequences = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for p in &state.proofs {
        check(context)?;
        validate_proof(config, verifier, p)?;
        if p.wal_sequence > record.checkpoint
            || !sequences.insert(p.wal_sequence)
            || !ids.insert(p.event.id)
        {
            return Err(Error::Conflict);
        }
    }
    let monitor = Monitor::restore(config.policy.clone(), &state.monitor)?;
    if reconstruct(config, &state.proofs, monitor.clock_ms(), context)?.snapshot()? != state.monitor
        || required(&monitor, &state.proofs)?.len() != state.proofs.len()
    {
        return Err(Error::Conflict);
    }
    let mut sources = BTreeSet::new();
    for p in &state.known {
        validate_pending(config, verifier, p, context)?;
        if p.assessment.assessed_at_ms > monitor.clock_ms()
            || !sources.insert(p.assessment.source_id)
            || p.evidence
                .iter()
                .any(|e| e.wal_sequence > record.checkpoint)
        {
            return Err(Error::Conflict);
        }
    }
    for output in &record.outbox {
        let p: Pending = serde_json::from_slice(&output.bytes).map_err(|_| Error::Configuration)?;
        validate_pending(config, verifier, &p, context)?;
        if output.schema_version != 1
            || p.assessment.assessed_at_ms > monitor.clock_ms()
            || output.id != p.finding.id
            || p.evidence
                .iter()
                .any(|e| e.wal_sequence > record.checkpoint)
        {
            return Err(Error::Conflict);
        }
    }
    Ok(state)
}

pub struct Completion {
    pub revision: u64,
    pub published_prefix: usize,
    pub findings: Vec<DerivedFinding>,
    pub assessments: Vec<Assessment>,
    pub proofs: usize,
    pub bytes: usize,
    pub valid_until_ms: i64,
}
/// Captured by the native host at startup. Serialization never authenticates it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub schema_version: u16,
    pub source_stream: Uuid,
    pub source_binding: [u8; 32],
    pub checkpoint: u64,
    pub last_sequence: u64,
    pub now_ms: i64,
}
/// Serial session: native admission floor/time and current source authority are
/// supplied by the embedding host, never by event attributes or saved snapshots.
pub struct Session {
    config: Config,
    verifier: Verifier,
    journal: Journal,
    baseline: u64,
    floor: u64,
    epoch_ms: i64,
    fresh: BTreeSet<Uuid>,
}
impl Session {
    pub async fn open(
        mut config: Config,
        path: PathBuf,
        epoch: Epoch,
        context: RuleContext,
    ) -> Result<Self, Error> {
        let Epoch {
            schema_version,
            source_stream: stream,
            source_binding,
            checkpoint,
            last_sequence,
            now_ms: now,
        } = epoch;
        config.validate()?;
        if schema_version != 1 || last_sequence < checkpoint || source_binding == [0; 32] {
            return Err(Error::Configuration);
        }
        Monitor::new(config.policy.clone(), now)?;
        config.observer_keys.sort_by_key(|k| k.observer_id);
        let verifier = Verifier::new(config.policy.clone(), config.observer_keys.clone())?;
        let mut digest = Sha256::new();
        digest.update(b"platform-signal/native-sensor-policy/v1\0");
        digest.update(encode(&config, 4 * 1024 * 1024)?);
        digest.update(verifier.enrollment_sha256());
        let binding: [u8; 32] = digest.finalize().into();
        let (journal, ready) = Journal::begin_open(
            path,
            config.journal(stream, source_binding, binding),
            context.clone(),
        )?;
        ready.wait().await?;
        let current = journal.load(context.clone()).await?;
        if let Some(record) = &current {
            if record.checkpoint < checkpoint || record.checkpoint > last_sequence {
                return Err(Error::Conflict);
            }
            let state = decode(&config, &verifier, record, &context)?;
            if Monitor::restore(config.policy.clone(), &state.monitor)?.clock_ms() > now {
                return Err(core::Error::Clock.into());
            }
        }
        Ok(Self {
            config,
            verifier,
            journal,
            baseline: checkpoint,
            floor: last_sequence,
            epoch_ms: now,
            fresh: BTreeSet::new(),
        })
    }
    pub fn metrics(&self) -> (usize, usize, u64) {
        self.journal.metrics()
    }
    pub fn monitor(&self) -> state_journal::Monitor {
        self.journal.monitor()
    }
    pub fn is_closed(&self) -> bool {
        self.journal.is_closed()
    }
    pub async fn shutdown(&self, context: RuleContext) -> Result<(), Error> {
        self.journal.shutdown(context).await?;
        Ok(())
    }
    pub async fn complete(
        &mut self,
        rows: &[SequencedEvent],
        now: i64,
        trusted_current: bool,
        context: RuleContext,
    ) -> Result<Completion, Error> {
        if rows.len() > 4096 {
            return Err(Error::Capacity);
        }
        let current = self.journal.load(context.clone()).await?;
        let checkpoint = current.as_ref().map_or(self.baseline, |r| r.checkpoint);
        let last = rows.last().map_or(checkpoint, |r| r.sequence);
        if !rows.is_empty() && last <= checkpoint {
            return self.completion(
                current.ok_or(Error::Conflict)?,
                now,
                false,
                &self.fresh,
                &context,
            );
        }
        let mut state = match &current {
            Some(r) => decode(&self.config, &self.verifier, r, &context)?,
            None => State {
                schema_version: 1,
                monitor: Monitor::new(self.config.policy.clone(), now)?.snapshot()?,
                proofs: vec![],
                known: vec![],
            },
        };
        let mut monitor = Monitor::restore(self.config.policy.clone(), &state.monitor)?;
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
                Err(super::Error::Expired) => continue,
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
            encode(&state, self.config.max_state_bytes)?;
        }
        let assessments = assess(&mut monitor, now, &fresh, trusted_current)?;
        let mut outbox = current.as_ref().map_or_else(Vec::new, |r| r.outbox.clone());
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
            encode(&state, self.config.max_state_bytes)?;
        }
        state.monitor = monitor.snapshot()?;
        let expected = current.as_ref().map_or(0, |r| r.revision);
        let next = Record {
            schema_version: 1,
            revision: expected.checked_add(1).ok_or(Error::Conflict)?,
            checkpoint: last,
            state: encode(&state, self.config.max_state_bytes)?,
            outbox,
        };
        decode(&self.config, &self.verifier, &next, &context)?;
        let committed = self.journal.commit(expected, next, context.clone()).await?;
        let result = self.completion(committed, now, trusted_current, &fresh, &context)?;
        check(&context)?;
        self.fresh = fresh;
        Ok(result)
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
        })
    }
    pub async fn acknowledge(
        &self,
        revision: u64,
        count: usize,
        context: RuleContext,
    ) -> Result<(), Error> {
        let current = self
            .journal
            .load(context.clone())
            .await?
            .ok_or(Error::Conflict)?;
        if current.revision != revision || current.outbox.len() != count {
            return Err(Error::Conflict);
        }
        if count > 0 {
            let record = self
                .journal
                .retire(revision, count, context.clone())
                .await?;
            decode(&self.config, &self.verifier, &record, &context)?;
        }
        Ok(())
    }
}
fn check(context: &RuleContext) -> Result<(), Error> {
    if context.cancellation.is_cancelled() {
        return Err(state_journal::Error::Cancelled.into());
    }
    if tokio::time::Instant::now() >= context.deadline {
        return Err(state_journal::Error::Timeout.into());
    }
    Ok(())
}
fn assess(
    monitor: &mut Monitor,
    now: i64,
    fresh: &BTreeSet<Uuid>,
    trusted: bool,
) -> Result<Vec<Assessment>, Error> {
    let mut values = monitor.assess(now)?;
    for a in &mut values {
        if !trusted || !fresh.contains(&a.source_id) {
            a.outcome = Outcome::Indeterminate;
            a.reason = Reason::ObserverUnknown;
            a.gap_id = None;
        }
    }
    Ok(values)
}

#[cfg(test)]
mod tests;
