//! Bounded sealed event-time authentication windows. Private policy and trusted
//! source coverage are supplied by the host; this pure stage grants no commit.
use chrono::{DateTime, Duration, Utc};
mod metadata;
mod store;
mod worker;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_event::SignalEvent;
use std::collections::BTreeSet;
pub use store::{
    ArchiveEvidence, HistoryCursor, HistoryPage, HistoryRecord, HistoryUsage, Snapshot,
};
use thiserror::Error;
use uuid::Uuid;
pub(crate) use worker::WORKERS;
pub use worker::{Journal, Ready};
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid authentication window policy or state")]
    Configuration,
    #[error("authentication window atomic journal failed; reload durable state")]
    Journal,
    #[error("authentication window worker capacity exhausted")]
    Busy,
    #[error("authentication window operation cancelled")]
    Cancelled,
    #[error("authentication window original deadline expired")]
    Timeout,
    #[error("authentication window worker closed")]
    Closed,
    #[error("authentication window state capacity exhausted")]
    Capacity,
    #[error("authentication attempt identity conflicts with retained evidence")]
    Conflict,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u16,
    pub partition: Uuid,
    pub rule_id: String,
    pub revision: String,
    pub title: String,
    pub severity: signal_findings::DetectionSeverity,
    pub threshold: usize,
    pub window_ms: i64,
    pub lateness_ms: i64,
    pub ttl_ms: i64,
    pub max_keys: usize,
    pub max_attempts_per_key: usize,
    pub max_attempts: usize,
    pub max_outputs: usize,
    pub max_state_bytes: usize,
    pub max_history_assessments: usize,
    pub max_history_bytes: usize,
    pub history_retention_ms: i64,
}
impl Policy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.partition.is_nil()
            || !identity(&self.rule_id)
            || !identity(&self.revision)
            || !identity(&self.title)
            || self.threshold == 0
            || self.threshold > 1000
            || !(1..=86_400_000).contains(&self.window_ms)
            || self.lateness_ms < 0
            || self.lateness_ms > self.window_ms
            || self.ttl_ms < self.window_ms + self.lateness_ms
            || self.ttl_ms > 172_800_000
            || self.max_keys == 0
            || self.max_keys > 4096
            || self.max_attempts_per_key < self.threshold
            || self.max_attempts_per_key > 1000
            || self.max_attempts < self.max_attempts_per_key
            || self.max_attempts > 16384
            || self.max_outputs == 0
            || self.max_outputs > 4096
            || !(4096..=16 * 1024 * 1024).contains(&self.max_state_bytes)
            || !(1..=16384).contains(&self.max_history_assessments)
            || !(4096..=32 * 1024 * 1024).contains(&self.max_history_bytes)
            || !(1..=31_536_000_000).contains(&self.history_retention_ms)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}
fn identity(v: &str) -> bool {
    !v.is_empty() && v.len() <= 256 && v.trim() == v && !v.chars().any(char::is_control)
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub authority: String,
    pub principal: String,
    pub target: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(deny_unknown_fields)]
pub struct AttemptId {
    pub source_type: String,
    pub source_name: String,
    pub boot_id: String,
    pub sequence: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Attempt {
    event: SignalEvent,
    native_id: AttemptId,
    identity: Identity,
    event_id: Uuid,
    timestamp: DateTime<Utc>,
    observed_at: DateTime<Utc>,
    failure: bool,
    content_digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Match,
    NoMatch,
    Indeterminate,
}
/// Persisted evidence loss is visible even when no usable identity exists to
/// anchor an assessment. Hosts must publish this alongside detector outcomes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    pub degraded_through: DateTime<Utc>,
    pub rejected_inputs: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub schema_version: u16,
    pub rule_id: String,
    pub rule_revision: String,
    pub identity: Identity,
    pub anchor: DateTime<Utc>,
    pub outcome: Outcome,
    pub event_ids: Vec<Uuid>,
    evidence: Vec<SignalEvent>,
}
impl Assessment {
    /// Exact canonical inputs retained until the host durably publishes this
    /// assessment. Their bytes count toward the detector's finite state budget.
    pub fn canonical_events(&self) -> &[SignalEvent] {
        &self.evidence
    }
    pub fn finding(&self, policy: &Policy) -> Result<Option<signal_findings::Finding>, Error> {
        policy.validate()?;
        if self.schema_version != 1
            || self.rule_id != policy.rule_id
            || self.rule_revision != policy.revision
        {
            return Err(Error::Configuration);
        }
        if self.outcome != Outcome::Match {
            return Ok(None);
        }
        let mut name = Vec::new();
        name.extend_from_slice(policy.partition.as_bytes());
        for text in [
            &self.rule_id,
            &self.rule_revision,
            &self.identity.authority,
            &self.identity.principal,
            &self.identity.target,
        ] {
            name.extend_from_slice(&(text.len() as u64).to_be_bytes());
            name.extend_from_slice(text.as_bytes());
        }
        name.extend_from_slice(&self.anchor.timestamp().to_be_bytes());
        name.extend_from_slice(&self.anchor.timestamp_subsec_nanos().to_be_bytes());
        for id in &self.event_ids {
            name.extend_from_slice(id.as_bytes());
        }
        let mut attributes = serde_json::Map::new();
        attributes.insert("window".into(),serde_json::json!({"partition":policy.partition,"rule_revision":policy.revision,"identity":self.identity,"anchor":self.anchor,"window_ms":policy.window_ms,"threshold":policy.threshold}));
        let finding = signal_findings::Finding {
            schema_version: 1,
            id: Uuid::new_v5(&Uuid::from_bytes(*b"SIGNAL-WINDOW001"), &name),
            rule_id: self.rule_id.clone(),
            created_at: self.anchor,
            severity: policy.severity,
            title: policy.title.clone(),
            event_ids: self.event_ids.clone(),
            attributes,
        };
        finding.validate().map_err(|_| Error::Configuration)?;
        Ok(Some(finding))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u16,
    policy: Policy,
    watermark: Option<DateTime<Utc>>,
    attempts: Vec<Attempt>,
    finalized: BTreeSet<AttemptId>,
    outputs: Vec<Assessment>,
    degraded_until: Option<DateTime<Utc>>,
    rejected: u64,
    duplicates: u64,
}
impl State {
    pub fn new(policy: Policy) -> Result<Self, Error> {
        policy.validate()?;
        Ok(Self {
            schema_version: 1,
            policy,
            watermark: None,
            attempts: Vec::new(),
            finalized: BTreeSet::new(),
            outputs: Vec::new(),
            degraded_until: None,
            rejected: 0,
            duplicates: 0,
        })
    }
    /// Deserialize only through this bounded, policy-pinned boundary before use.
    pub fn decode(bytes: &[u8], policy: &Policy) -> Result<Self, Error> {
        policy.validate()?;
        if bytes.len() > policy.max_state_bytes {
            return Err(Error::Capacity);
        }
        let state: Self = serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
        state.validate(policy)?;
        Ok(state)
    }
    pub fn validate(&self, expected: &Policy) -> Result<(), Error> {
        self.policy.validate()?;
        if self.schema_version != 1
            || &self.policy != expected
            || self.attempts.len() > self.policy.max_attempts
            || self.outputs.len() > self.policy.max_outputs
            || self.finalized.len() > self.policy.max_attempts
        {
            return Err(Error::Configuration);
        }
        let mut ids = BTreeSet::new();
        let mut canonical_ids = BTreeSet::new();
        let mut keys = std::collections::BTreeMap::<&Identity, usize>::new();
        for a in &self.attempts {
            if a.event.validate().is_err()
                || attempt(&a.event).as_ref() != Some(a)
                || a.event_id.is_nil()
                || !canonical_ids.insert(a.event_id)
                || !ids.insert(&a.native_id)
                || [
                    &a.native_id.source_type,
                    &a.native_id.source_name,
                    &a.native_id.boot_id,
                    &a.identity.authority,
                    &a.identity.principal,
                    &a.identity.target,
                ]
                .iter()
                .any(|v| !identity(v))
            {
                return Err(Error::Configuration);
            }
            *keys.entry(&a.identity).or_default() += 1;
        }
        if keys.len() > self.policy.max_keys
            || keys.values().any(|n| *n > self.policy.max_attempts_per_key)
            || self.finalized.iter().any(|id| !ids.contains(id))
        {
            return Err(Error::Configuration);
        }
        for a in &self.outputs {
            if a.schema_version != 1
                || a.rule_id != self.policy.rule_id
                || a.rule_revision != self.policy.revision
                || [
                    &a.identity.authority,
                    &a.identity.principal,
                    &a.identity.target,
                ]
                .iter()
                .any(|v| !identity(v))
                || a.event_ids.len() > self.policy.max_attempts_per_key
                || a.event_ids.iter().any(Uuid::is_nil)
                || a.event_ids.iter().collect::<BTreeSet<_>>().len() != a.event_ids.len()
                || (a.outcome == Outcome::Match && a.event_ids.len() < self.policy.threshold)
                || (a.outcome == Outcome::NoMatch && a.event_ids.len() >= self.policy.threshold)
                || self.watermark.is_none_or(|w| a.anchor > w)
                || a.evidence.len() != a.event_ids.len()
            {
                return Err(Error::Configuration);
            }
            let start = a
                .anchor
                .checked_sub_signed(Duration::milliseconds(self.policy.window_ms))
                .ok_or(Error::Configuration)?;
            let mut previous = None;
            for (event, id) in a.evidence.iter().zip(&a.event_ids) {
                event.validate().map_err(|_| Error::Configuration)?;
                let input = attempt(event).ok_or(Error::Configuration)?;
                let order = (input.timestamp, input.native_id);
                if event.id != *id
                    || !input.failure
                    || input.identity != a.identity
                    || event.timestamp < start
                    || event.timestamp > a.anchor
                    || previous.as_ref().is_some_and(|p| p >= &order)
                {
                    return Err(Error::Configuration);
                }
                previous = Some(order);
            }
        }
        self.bound()
    }
    pub fn watermark(&self) -> Option<DateTime<Utc>> {
        self.watermark
    }
    pub fn assessments(&self) -> &[Assessment] {
        &self.outputs
    }
    pub fn coverage_gap(&self) -> Option<CoverageGap> {
        self.degraded_until.map(|degraded_through| CoverageGap {
            degraded_through,
            rejected_inputs: self.rejected,
        })
    }
    /// Retire a published prefix only after the host has durably persisted its
    /// assessments and findings. The host commits this change with its next
    /// source checkpoint; a crash before that commit republishes stable IDs.
    pub fn retire_assessments(&mut self, published: usize) -> Result<(), Error> {
        self.validate(&self.policy)?;
        if published > self.outputs.len() {
            return Err(Error::Conflict);
        }
        self.outputs.drain(..published);
        Ok(())
    }
    pub fn metrics(&self) -> (usize, usize, usize, usize, u64, u64) {
        (
            self.attempts.len(),
            self.policy.max_attempts,
            self.outputs.len(),
            self.policy.max_outputs,
            self.rejected,
            self.duplicates,
        )
    }
    /// Shape validation and replay are separate from durable publication. Host
    /// supplies independently checked coverage, never event attributes.
    pub fn admit(&mut self, event: &SignalEvent, coverage_verified: bool) -> Result<(), Error> {
        self.validate(&self.policy)?;
        event.validate().map_err(|_| Error::Configuration)?;
        let Some(attempt) = attempt(event) else {
            self.degrade(event.observed_at)?;
            return Ok(());
        };
        if !coverage_verified {
            self.degrade(event.observed_at)?;
            return Ok(());
        }
        if let Some(existing) = self
            .attempts
            .iter()
            .find(|a| a.native_id == attempt.native_id)
        {
            if !equivalent(existing, &attempt) {
                return Err(Error::Conflict);
            }
            self.duplicates = self.duplicates.saturating_add(1);
            return Ok(());
        }
        if self.attempts.iter().any(|a| a.event_id == attempt.event_id) {
            return Err(Error::Conflict);
        }
        if self.watermark.is_some_and(|w| attempt.timestamp <= w) {
            self.degrade(event.observed_at)?;
            return Ok(());
        }
        let identities: BTreeSet<_> = self.attempts.iter().map(|a| &a.identity).collect();
        if self.attempts.len() >= self.policy.max_attempts
            || self
                .attempts
                .iter()
                .filter(|a| a.identity == attempt.identity)
                .count()
                >= self.policy.max_attempts_per_key
            || (!identities.contains(&attempt.identity) && identities.len() >= self.policy.max_keys)
        {
            self.degrade(event.observed_at)?;
            return Err(Error::Capacity);
        }
        // Stage on a clone: a byte limit cannot leave a partial admitted attempt.
        let mut next = self.clone();
        next.attempts.push(attempt);
        if let Err(error) = next.bound() {
            self.degrade(event.observed_at)?;
            return Err(error);
        }
        *self = next;
        Ok(())
    }
    /// Trusted caller advances a source watermark after its lateness budget;
    /// source time, not receiver processing time, determines window membership.
    /// Window/journal integration must persist outputs+watermark atomically.
    pub fn seal(&mut self, watermark: DateTime<Utc>, coverage_verified: bool) -> Result<(), Error> {
        self.seal_inner(watermark, coverage_verified, None)
    }
    /// Seal only windows wholly inside the independently verified source
    /// interval. The interval end, minus configured lateness, bounds watermark.
    pub fn seal_covered(&mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<(), Error> {
        let watermark = end
            .checked_sub_signed(Duration::milliseconds(self.policy.lateness_ms))
            .ok_or(Error::Configuration)?;
        if start >= end {
            return Err(Error::Configuration);
        }
        self.seal_inner(watermark, true, Some((start, end)))
    }
    fn seal_inner(
        &mut self,
        watermark: DateTime<Utc>,
        coverage_verified: bool,
        interval: Option<(DateTime<Utc>, DateTime<Utc>)>,
    ) -> Result<(), Error> {
        self.validate(&self.policy)?;
        if self.watermark.is_some_and(|w| watermark < w) {
            return Err(Error::Configuration);
        }
        let mut next = self.clone();
        let mut anchors: Vec<_> = next
            .attempts
            .iter()
            .filter(|a| a.timestamp <= watermark && !next.finalized.contains(&a.native_id))
            .cloned()
            .collect();
        anchors.sort_by(|a, b| (&a.timestamp, &a.native_id).cmp(&(&b.timestamp, &b.native_id)));
        for anchor in anchors {
            if next.outputs.len() >= next.policy.max_outputs {
                return Err(Error::Capacity);
            }
            let start = anchor
                .timestamp
                .checked_sub_signed(Duration::milliseconds(next.policy.window_ms))
                .ok_or(Error::Configuration)?;
            if let Some((from, _)) = interval
                && start < from
            {
                // Coverage excludes the earlier portion of this lookback. Keep
                // an explicit durable gap, without poisoning the first wholly
                // covered window whose inclusive start is exactly `from`.
                let until = from
                    .checked_add_signed(Duration::milliseconds(next.policy.window_ms))
                    .and_then(|t| t.checked_sub_signed(Duration::nanoseconds(1)))
                    .ok_or(Error::Configuration)?;
                next.degraded_until = Some(next.degraded_until.map_or(until, |old| old.max(until)));
                next.rejected = next.rejected.saturating_add(1);
            }
            let mut members: Vec<_> = next
                .attempts
                .iter()
                .filter(|a| {
                    a.failure
                        && a.identity == anchor.identity
                        && a.timestamp >= start
                        && a.timestamp <= anchor.timestamp
                })
                .collect();
            members.sort_by(|a, b| (&a.timestamp, &a.native_id).cmp(&(&b.timestamp, &b.native_id)));
            let outcome = if !coverage_verified
                || interval.is_some_and(|(from, to)| start < from || anchor.timestamp > to)
                || next.degraded_until.is_some_and(|t| anchor.timestamp <= t)
            {
                Outcome::Indeterminate
            } else if members.len() >= next.policy.threshold {
                Outcome::Match
            } else {
                Outcome::NoMatch
            };
            next.outputs.push(Assessment {
                schema_version: 1,
                rule_id: next.policy.rule_id.clone(),
                rule_revision: next.policy.revision.clone(),
                identity: anchor.identity.clone(),
                anchor: anchor.timestamp,
                outcome,
                event_ids: members.iter().map(|a| a.event_id).collect(),
                evidence: members.iter().map(|a| a.event.clone()).collect(),
            });
            next.finalized.insert(anchor.native_id);
        }
        next.watermark = Some(watermark);
        // Keep lookback and dedup together. Older replay degrades, never recounts.
        let floor = watermark
            .checked_sub_signed(Duration::milliseconds(next.policy.ttl_ms))
            .ok_or(Error::Configuration)?;
        next.attempts.retain(|a| a.timestamp >= floor);
        let kept: BTreeSet<_> = next.attempts.iter().map(|a| a.native_id.clone()).collect();
        next.finalized.retain(|id| kept.contains(id));
        next.bound()?;
        *self = next;
        Ok(())
    }
    fn degrade(&mut self, at: DateTime<Utc>) -> Result<(), Error> {
        let until = at
            .checked_add_signed(Duration::milliseconds(
                self.policy.window_ms + self.policy.lateness_ms,
            ))
            .ok_or(Error::Configuration)?;
        self.degraded_until = Some(self.degraded_until.map_or(until, |old| old.max(until)));
        self.rejected = self.rejected.saturating_add(1);
        Ok(())
    }
    fn bound(&self) -> Result<(), Error> {
        if serde_json::to_vec(self)
            .map_err(|_| Error::Configuration)?
            .len()
            > self.policy.max_state_bytes
        {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
}
fn equivalent(a: &Attempt, b: &Attempt) -> bool {
    a.native_id == b.native_id
        && a.identity == b.identity
        && a.timestamp == b.timestamp
        && a.failure == b.failure
        && a.content_digest == b.content_digest
}
fn attempt(event: &SignalEvent) -> Option<Attempt> {
    let mut content = serde_json::to_value(event).ok()?;
    let fields = content.as_object_mut()?;
    fields.remove("id");
    fields.remove("observed_at");
    let encoded = serde_json::to_vec(&content).ok()?;
    if encoded.len() > 65536 {
        return None;
    }
    let content_digest: [u8; 32] = Sha256::digest(encoded).into();
    let auth = event.attributes.get("authentication")?.as_object()?;
    let producer = event.attributes.get("producer")?.as_object()?;
    let field = |key: &str| {
        auth.get(key)?
            .as_str()
            .filter(|v| identity(v))
            .map(str::to_owned)
    };
    let key = Identity {
        authority: field("identity_authority")?,
        principal: field("principal_id")?,
        target: field("target_id")?,
    };
    let source_name = event.source.name.as_ref()?.clone();
    let source_type = event.source.source_type.clone();
    let boot = producer
        .get("boot_id")?
        .as_str()
        .filter(|v| identity(v))?
        .to_owned();
    if !identity(&source_name) || !identity(&source_type) {
        return None;
    }
    let failure = match auth.get("outcome")?.as_str()? {
        "failure" => true,
        "success" => false,
        _ => return None,
    };
    Some(Attempt {
        event: event.clone(),
        native_id: AttemptId {
            source_type,
            source_name,
            boot_id: boot,
            sequence: producer.get("sequence")?.as_u64()?,
        },
        identity: key,
        event_id: event.id,
        timestamp: event.timestamp,
        observed_at: event.observed_at,
        failure,
        content_digest,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use signal_event::IngestEvent;
    fn policy() -> Policy {
        Policy {
            schema_version: 1,
            partition: Uuid::from_u128(1),
            rule_id: "fixture-window".into(),
            revision: "fixture-revision".into(),
            title: "fixture authentication burst".into(),
            severity: signal_findings::DetectionSeverity::Medium,
            threshold: 3,
            window_ms: 60000,
            lateness_ms: 10000,
            ttl_ms: 70000,
            max_keys: 4,
            max_attempts_per_key: 8,
            max_attempts: 32,
            max_outputs: 32,
            max_state_bytes: 65536,
            max_history_assessments: 32,
            max_history_bytes: 262144,
            history_retention_ms: 60000,
        }
    }
    fn time(second: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1791972000 + second, 0).unwrap()
    }
    fn event(sequence: u64, second: i64) -> SignalEvent {
        let input:IngestEvent=serde_json::from_value(serde_json::json!({"timestamp":time(second),"source":{"type":"authentication","name":"fixture-source"},"message":"fixture authentication","attributes":{"authentication":{"identity_authority":"fixture-authority","principal_id":"fixture-principal","target_id":"fixture-target","outcome":"failure"},"producer":{"boot_id":"fixture-boot","sequence":sequence}}})).unwrap();
        let mut e = input.normalize(time(second)).unwrap();
        e.id = Uuid::from_u128(sequence as u128 + 1);
        e
    }
    #[test]
    fn bounded_failure_burst_uses_event_time_and_distinct_native_attempts() {
        let mut s = State::new(policy()).unwrap();
        for (id, t) in [(1, 0), (2, 30), (3, 60)] {
            s.admit(&event(id, t), true).unwrap();
        }
        let mut duplicate = event(1, 0);
        duplicate.id = Uuid::from_u128(100);
        duplicate.observed_at = time(100);
        s.admit(&duplicate, true).unwrap();
        assert_eq!(s.metrics().0, 3);
        assert_eq!(s.metrics().5, 1);
        s.seal(time(60), true).unwrap();
        assert_eq!(s.assessments().len(), 3);
        assert_eq!(s.assessments()[2].outcome, Outcome::Match);
        assert_eq!(s.assessments()[2].event_ids.len(), 3);
        let saved = s.assessments().to_vec();
        s.seal(time(60), true).unwrap();
        assert_eq!(s.assessments(), saved);
    }
    #[test]
    fn out_of_order_admission_before_watermark_is_equivalent_and_boundary_is_inclusive() {
        let mut first = State::new(policy()).unwrap();
        let mut second = State::new(policy()).unwrap();
        for (id, t) in [(1, 0), (2, 30), (3, 60)] {
            first.admit(&event(id, t), true).unwrap();
        }
        for (id, t) in [(3, 60), (1, 0), (2, 30)] {
            second.admit(&event(id, t), true).unwrap();
        }
        first.seal(time(60), true).unwrap();
        second.seal(time(60), true).unwrap();
        assert_eq!(first.assessments(), second.assessments());
        let mut outside = State::new(policy()).unwrap();
        for (id, t) in [(1, 0), (2, 30), (3, 61)] {
            outside.admit(&event(id, t), true).unwrap();
        }
        outside.seal(time(61), true).unwrap();
        assert_eq!(outside.assessments()[2].outcome, Outcome::NoMatch);
    }
    #[test]
    fn missing_or_unknown_coverage_late_input_and_overflow_never_become_clean() {
        for scenario in ["missing", "coverage", "late", "capacity"] {
            let mut p = policy();
            if scenario == "capacity" {
                p.max_attempts = 3;
                p.max_attempts_per_key = 3;
            }
            let mut s = State::new(p).unwrap();
            s.admit(&event(1, 1), true).unwrap();
            if scenario == "late" {
                s.seal(time(0), true).unwrap();
            }
            let mut bad = event(2, 2);
            match scenario {
                "missing" => {
                    bad.attributes.remove("authentication");
                    s.admit(&bad, true).unwrap();
                }
                "coverage" => {
                    s.admit(&bad, false).unwrap();
                }
                "late" => {
                    s.admit(&event(2, 0), true).unwrap();
                }
                "capacity" => {
                    s.admit(&event(2, 2), true).unwrap();
                    s.admit(&event(3, 3), true).unwrap();
                    assert_eq!(s.admit(&event(4, 4), true), Err(Error::Capacity));
                }
                _ => unreachable!(),
            }
            s.seal(time(10), true).unwrap();
            assert!(
                s.assessments()
                    .iter()
                    .all(|a| a.outcome == Outcome::Indeterminate),
                "{scenario}"
            );
        }
    }
    #[test]
    fn conflicting_identity_and_watermark_regression_refuse_and_ttl_bounds_dedup() {
        let mut s = State::new(policy()).unwrap();
        s.admit(&event(1, 1), true).unwrap();
        let mut changed = event(1, 1);
        changed.attributes["authentication"]["outcome"] = serde_json::json!("success");
        assert_eq!(s.admit(&changed, true), Err(Error::Conflict));
        s.seal(time(2), true).unwrap();
        assert_eq!(s.seal(time(1), true), Err(Error::Configuration));
        s.seal(time(100), true).unwrap();
        assert_eq!(s.metrics().0, 0);
        s.admit(&event(1, 1), true).unwrap();
        assert_eq!(s.metrics().0, 0);
    }
    #[test]
    fn success_only_window_retains_zero_failure_no_match_and_metadata_roundtrip() {
        let policy = policy();
        let mut success = event(1, 1);
        success.attributes["authentication"]["outcome"] = serde_json::json!("success");
        let mut state = State::new(policy.clone()).unwrap();
        state.admit(&success, true).unwrap();
        state.seal(time(2), true).unwrap();
        assert_eq!(state.assessments().len(), 1);
        let assessment = &state.assessments()[0];
        assert_eq!(assessment.outcome, Outcome::NoMatch);
        assert!(assessment.event_ids.is_empty() && assessment.canonical_events().is_empty());
        assert!(assessment.finding(&policy).unwrap().is_none());
        let bytes = state.encode_metadata(65536).unwrap();
        let restored = State::restore_metadata(&bytes, &policy, &[success]).unwrap();
        assert_eq!(restored, state);
    }

    #[test]
    fn covered_sealing_uses_source_interval_and_configured_lateness() {
        let mut p = policy();
        p.lateness_ms = 1000;
        let mut s = State::new(p.clone()).unwrap();
        for n in 1..=3 {
            s.admit(&event(n, n as i64), true).unwrap();
        }
        s.seal_covered(time(-60), time(3)).unwrap();
        assert_eq!(s.watermark(), Some(time(2)));
        assert_eq!(s.assessments().len(), 2);
        assert!(
            s.assessments()
                .iter()
                .all(|a| a.outcome == Outcome::NoMatch)
        );
        s.seal_covered(time(-60), time(4)).unwrap();
        assert_eq!(s.assessments().last().unwrap().outcome, Outcome::Match);
        let mut uncovered = State::new(p).unwrap();
        for n in 1..=3 {
            uncovered.admit(&event(n, n as i64), true).unwrap();
        }
        uncovered.seal_covered(time(1), time(4)).unwrap();
        assert!(
            uncovered
                .assessments()
                .iter()
                .all(|a| a.outcome == Outcome::Indeterminate)
        );
        assert!(uncovered.coverage_gap().is_some());
        assert!(uncovered.seal_covered(time(4), time(4)).is_err());
    }

    #[test]
    fn output_capacity_refusal_does_not_advance_watermark_or_publish_prefix() {
        let mut p = policy();
        p.max_outputs = 1;
        let mut s = State::new(p).unwrap();
        s.admit(&event(1, 1), true).unwrap();
        s.admit(&event(2, 2), true).unwrap();
        assert_eq!(s.seal(time(10), true), Err(Error::Capacity));
        assert!(s.assessments().is_empty());
        assert_eq!(s.watermark(), None);
    }
}

#[cfg(test)]
mod durability_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    pub(super) fn policy() -> Policy {
        Policy {
            schema_version: 1,
            partition: Uuid::from_u128(1),
            rule_id: "fixture".into(),
            revision: "rev1".into(),
            title: "fixture".into(),
            severity: signal_findings::DetectionSeverity::Medium,
            threshold: 1,
            window_ms: 1000,
            lateness_ms: 0,
            ttl_ms: 1000,
            max_keys: 2,
            max_attempts_per_key: 2,
            max_attempts: 2,
            max_outputs: 2,
            max_state_bytes: 65536,
            max_history_assessments: 32,
            max_history_bytes: 262144,
            history_retention_ms: 60000,
        }
    }
    pub(super) fn state() -> State {
        let mut s = State::new(policy()).unwrap();
        let input:signal_event::IngestEvent=serde_json::from_value(serde_json::json!({"timestamp":"2026-10-14T12:00:00Z","source":{"type":"auth","name":"fixture"},"message":"fixture","attributes":{"authentication":{"identity_authority":"fixture","principal_id":"user","target_id":"target","outcome":"failure","method":"password","session_id":"one"},"producer":{"boot_id":"boot","sequence":1}}})).unwrap();
        let t: DateTime<Utc> = "2026-10-14T12:00:00Z".parse().unwrap();
        s.admit(&input.normalize(t).unwrap(), true).unwrap();
        s.seal(t, true).unwrap();
        s
    }
    #[test]
    fn persisted_state_pins_revision_and_refuses_duplicate_or_invalid_identity() {
        let state = state();
        let raw = serde_json::to_vec(&state).unwrap();
        assert_eq!(State::decode(&raw, &policy()).unwrap(), state);
        let mut different = policy();
        different.revision = "rev2".into();
        assert!(State::decode(&raw, &different).is_err());
        let mut duplicate: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let attempt = duplicate["attempts"][0].clone();
        duplicate["attempts"].as_array_mut().unwrap().push(attempt);
        assert!(State::decode(&serde_json::to_vec(&duplicate).unwrap(), &policy()).is_err());
        let mut bad: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        bad["outputs"][0]["rule_revision"] = serde_json::json!("changed");
        assert!(State::decode(&serde_json::to_vec(&bad).unwrap(), &policy()).is_err());
    }
    #[tokio::test]
    async fn actual_sqlite_atomic_snapshot_finding_checkpoint_reload_and_stale_revision_refusal() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("window.sqlite");
        let p = policy();
        let (journal, ready) = Journal::begin_open(
            path.clone(),
            p.clone(),
            crate::RuleContext::new(std::time::Duration::from_secs(3)),
        )
        .unwrap();
        ready.wait().await.unwrap();
        let state = state();
        let findings = state
            .assessments()
            .iter()
            .filter_map(|a| a.finding(&p).unwrap())
            .collect::<Vec<_>>();
        let next = Snapshot {
            history: Default::default(),
            source_stream: Uuid::from_u128(1),
            source_binding: [1; 32],
            schema_version: 1,
            revision: 1,
            checkpoint: 1,
            state: state.clone(),
            findings: findings.clone(),
        };
        journal
            .commit(
                0,
                next.clone(),
                crate::RuleContext::new(std::time::Duration::from_secs(3)),
            )
            .await
            .unwrap();
        assert_eq!(
            journal
                .load(crate::RuleContext::new(std::time::Duration::from_secs(3)))
                .await
                .unwrap()
                .unwrap()
                .findings,
            findings
        );
        assert!(matches!(
            journal
                .commit(
                    0,
                    next,
                    crate::RuleContext::new(std::time::Duration::from_secs(3))
                )
                .await,
            Err(Error::Conflict)
        ));
        journal
            .shutdown(crate::RuleContext::new(std::time::Duration::from_secs(3)))
            .await
            .unwrap();
        drop(journal);
        let (fresh, ready) = Journal::begin_open(
            path,
            p,
            crate::RuleContext::new(std::time::Duration::from_secs(3)),
        )
        .unwrap();
        ready.wait().await.unwrap();
        let loaded = fresh
            .load(crate::RuleContext::new(std::time::Duration::from_secs(3)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.checkpoint, 1);
        assert_eq!(loaded.revision, 1);
        assert_eq!(loaded.state, state);
        assert_eq!(loaded.findings, findings);
    }
    #[tokio::test]
    async fn oversized_stored_blob_is_refused_and_capacity_released() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("oversized.sqlite");
        let p = policy();
        let (journal, ready) = Journal::begin_open(
            path.clone(),
            p.clone(),
            crate::RuleContext::new(std::time::Duration::from_secs(3)),
        )
        .unwrap();
        ready.wait().await.unwrap();
        let external = rusqlite::Connection::open(&path).unwrap();
        external
            .execute(
                "INSERT INTO window_snapshot VALUES(1,1,1,zeroblob(?1))",
                [(p.max_state_bytes * 8) as i64],
            )
            .unwrap();
        assert!(matches!(
            journal
                .load(crate::RuleContext::new(std::time::Duration::from_secs(3)))
                .await,
            Err(Error::Capacity)
        ));
        assert_eq!(journal.metrics(), (0, 1, 1));
        journal
            .shutdown(crate::RuleContext::new(std::time::Duration::from_secs(3)))
            .await
            .unwrap();
        drop(journal);
        assert!(matches!(
            store::Engine::open(&path, p),
            Err(Error::Capacity)
        ));
    }

    #[test]
    fn lost_reply_reloads_atomic_commit_and_refuses_stale_replay() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("lost-reply.sqlite");
        let p = policy();
        let state = state();
        let findings = state
            .assessments()
            .iter()
            .filter_map(|a| a.finding(&p).unwrap())
            .collect::<Vec<_>>();
        let next = Snapshot {
            history: Default::default(),
            source_stream: Uuid::from_u128(1),
            source_binding: [1; 32],
            schema_version: 1,
            revision: 1,
            checkpoint: 7,
            state: state.clone(),
            findings: findings.clone(),
        };
        let mut engine = store::Engine::open(&path, p.clone()).unwrap();
        // The physical commit finishes, but its caller never receives the value.
        drop(engine.commit(0, next.clone()).unwrap());
        drop(engine);
        let mut reopened = store::Engine::open(&path, p).unwrap();
        let recovered = reopened.load().unwrap().unwrap();
        assert_eq!(recovered.checkpoint, 7);
        assert_eq!(recovered.revision, 1);
        assert_eq!(recovered.state, state);
        assert_eq!(recovered.findings, findings);
        assert!(matches!(reopened.commit(0, next), Err(Error::Conflict)));
        assert_eq!(reopened.load().unwrap().unwrap().revision, 1);
    }

    #[test]
    fn published_prefix_retirement_preserves_dedup_and_missing_identity_gap_survives_reload() {
        let mut s = state();
        let t: DateTime<Utc> = "2026-10-14T12:00:00Z".parse().unwrap();
        let missing: signal_event::IngestEvent = serde_json::from_value(serde_json::json!({"timestamp":t,"source":{"type":"auth","name":"fixture"},"message":"missing","attributes":{}})).unwrap();
        s.admit(&missing.normalize(t).unwrap(), true).unwrap();
        let gap = s.coverage_gap().unwrap();
        assert_eq!(gap.rejected_inputs, 1);
        let before = s.clone();
        assert_eq!(s.retire_assessments(2), Err(Error::Conflict));
        assert_eq!(s, before);
        s.retire_assessments(1).unwrap();
        assert!(s.assessments().is_empty());
        s.seal(t, true).unwrap();
        assert!(s.assessments().is_empty());
        let recovered = State::decode(&serde_json::to_vec(&s).unwrap(), &policy()).unwrap();
        assert_eq!(recovered.coverage_gap(), Some(gap));
        assert_eq!(recovered.finalized, before.finalized);
    }

    #[test]
    fn canonical_window_evidence_survives_ttl_and_derives_scoped_finding() {
        let mut s = state();
        let p = policy();
        let finding = s.assessments()[0].finding(&p).unwrap().unwrap();
        let expected = s.assessments()[0].canonical_events().to_vec();
        let later: DateTime<Utc> = "2026-10-14T12:00:02Z".parse().unwrap();
        s.seal(later, true).unwrap();
        assert!(s.attempts.is_empty());
        let restored = State::decode(&serde_json::to_vec(&s).unwrap(), &p).unwrap();
        let references = restored.assessments()[0]
            .canonical_events()
            .iter()
            .collect::<Vec<_>>();
        assert_eq!(restored.assessments()[0].canonical_events(), expected);
        let scoped =
            signal_findings::DerivedFinding::from_events(finding.clone(), &references, true)
                .unwrap()
                .into_scoped(Uuid::from_u128(9))
                .unwrap();
        assert_eq!(scoped.finding().id, finding.id);
        assert_eq!(scoped.facts().source, Some("auth"));
    }

    #[test]
    fn restored_evidence_cannot_substitute_references_authority_time_or_outcome() {
        let p = policy();
        let raw = serde_json::to_value(state()).unwrap();
        for (field, replacement) in [
            ("id", serde_json::json!(Uuid::from_u128(99))),
            ("timestamp", serde_json::json!("2026-10-14T11:00:00Z")),
        ] {
            let mut changed = raw.clone();
            changed["outputs"][0]["evidence"][0][field] = replacement;
            assert!(State::decode(&serde_json::to_vec(&changed).unwrap(), &p).is_err());
        }
        for (field, replacement) in [("principal_id", "other"), ("outcome", "success")] {
            let mut changed = raw.clone();
            changed["outputs"][0]["evidence"][0]["attributes"]["authentication"][field] =
                serde_json::json!(replacement);
            assert!(State::decode(&serde_json::to_vec(&changed).unwrap(), &p).is_err());
        }
        let mut changed = raw.clone();
        changed["attempts"][0]["event"]["source"]["name"] = serde_json::json!("other");
        assert!(State::decode(&serde_json::to_vec(&changed).unwrap(), &p).is_err());
        let mut changed = raw;
        changed["outputs"][0]["outcome"] = serde_json::json!("no_match");
        assert!(State::decode(&serde_json::to_vec(&changed).unwrap(), &p).is_err());
    }

    #[tokio::test]
    async fn journal_has_one_writer_and_shutdown_confirms_lease_release() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("lease.sqlite");
        let context = || crate::RuleContext::new(std::time::Duration::from_secs(3));
        let (first, ready) = Journal::begin_open(path.clone(), policy(), context()).unwrap();
        ready.wait().await.unwrap();
        let (_second, ready) = Journal::begin_open(path.clone(), policy(), context()).unwrap();
        assert!(matches!(ready.wait().await, Err(Error::Busy)));
        let old = first.clone();
        first.shutdown(context()).await.unwrap();
        assert!(matches!(old.load(context()).await, Err(Error::Closed)));
        let (fresh, ready) = Journal::begin_open(path, policy(), context()).unwrap();
        ready.wait().await.unwrap();
        assert!(fresh.load(context()).await.unwrap().is_none());
        fresh.shutdown(context()).await.unwrap();
    }

    #[test]
    fn journal_refuses_symlinks_hardlinks_and_public_custody() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = temp.path().join("target");
        std::fs::write(&target, b"preserve").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let path = temp.path().join("link.sqlite");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(matches!(
            store::Engine::open(&path, policy()),
            Err(Error::Configuration)
        ));
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        assert!(matches!(
            store::Engine::open(&path, policy()),
            Err(Error::Configuration)
        ));
        assert_eq!(std::fs::read(&target).unwrap(), b"preserve");
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            store::Engine::open(&path, policy()),
            Err(Error::Configuration)
        ));
        std::fs::remove_file(&path).unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            store::Engine::open(&path, policy()),
            Err(Error::Configuration)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn assessment_history_retirement_is_atomic_replay_stable_and_expires_only_published_rows() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("history.sqlite");
        let mut p = policy();
        p.history_retention_ms = 1;
        let mut s = state();
        s.policy = p.clone();
        let findings = s
            .assessments()
            .iter()
            .filter_map(|a| a.finding(&p).unwrap())
            .collect();
        let mut snapshot = Snapshot {
            history: Default::default(),
            schema_version: 1,
            revision: 1,
            checkpoint: 1,
            source_stream: Uuid::from_u128(1),
            source_binding: [1; 32],
            state: s,
            findings,
        };
        let mut engine = store::Engine::open(&path, p.clone()).unwrap();
        engine.commit(0, snapshot.clone()).unwrap();
        let reader = rusqlite::Connection::open(&path).unwrap();
        let receipt = || {
            reader.query_row("SELECT checkpoint,recorded_at,expires_at,pending,payload FROM window_assessments",[],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,Vec<u8>>(4)?))).unwrap()
        };
        let first = receipt();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while Utc::now().timestamp_millis() <= first.2 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let expired = engine.history(None, 1, 1024).unwrap();
        assert_eq!(expired.records.len(), 1);
        assert!(expired.records[0].evidence.is_none() && expired.missing_evidence);
        snapshot.revision = 2;
        snapshot.checkpoint = 2;
        engine.commit(1, snapshot).unwrap();
        assert_eq!(
            receipt(),
            first,
            "pending replay must retain original custody and expiry"
        );
        let retired = engine.retire(2, 1).unwrap();
        assert_eq!((retired.revision, retired.checkpoint), (3, 2));
        assert!(retired.state.assessments().is_empty());
        assert!(retired.findings.is_empty());
        assert_eq!(receipt().3, 0);
        let record: serde_json::Value = serde_json::from_slice(&receipt().4).unwrap();
        assert_eq!(
            record["assessment"]["evidence"][0]["id"],
            serde_json::json!(first_event(&retired.state))
        );
        assert!(matches!(engine.retire(2, 1), Err(Error::Conflict)));
        drop(engine);
        let mut reopened = store::Engine::open(&path, p).unwrap();
        let mut next = reopened.load().unwrap().unwrap();
        assert!(next.findings.is_empty());
        next.revision += 1;
        next.checkpoint += 1;
        reopened.commit(3, next).unwrap();
        let count: i64 = reader
            .query_row("SELECT count(*) FROM window_assessments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
    fn first_event(state: &State) -> Uuid {
        state.attempts[0].event_id
    }

    #[test]
    fn history_quota_refuses_entire_snapshot_and_archive_transaction() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("history-quota.sqlite");
        let mut p = policy();
        p.max_history_assessments = 1;
        let mut s = state();
        s.policy = p.clone();
        let original = s.assessments()[0].clone();
        let findings = s
            .assessments()
            .iter()
            .filter_map(|a| a.finding(&p).unwrap())
            .collect();
        let mut snapshot = Snapshot {
            history: Default::default(),
            schema_version: 1,
            revision: 1,
            checkpoint: 1,
            source_stream: Uuid::from_u128(1),
            source_binding: [1; 32],
            state: s,
            findings,
        };
        let mut engine = store::Engine::open(&path, p.clone()).unwrap();
        engine.commit(0, snapshot.clone()).unwrap();
        snapshot.revision = 2;
        snapshot.checkpoint = 2;
        let mut extra = original.clone();
        extra.outcome = Outcome::Indeterminate;
        snapshot.state.outputs.push(extra);
        assert!(matches!(engine.commit(1, snapshot), Err(Error::Capacity)));
        let saved = engine.load().unwrap().unwrap();
        assert_eq!((saved.revision, saved.checkpoint), (1, 1));
        assert_eq!(saved.state.assessments(), &[original]);
        let reader = rusqlite::Connection::open(&path).unwrap();
        let count: i64 = reader
            .query_row("SELECT count(*) FROM window_assessments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn history_byte_quota_and_corruption_refuse_without_losing_source_progress() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("history-bytes.sqlite");
        let mut p = policy();
        p.max_history_bytes = 4096;
        let mut s = state();
        s.policy = p.clone();
        let mut event = s.attempts[0].event.clone();
        event.message = Some("x".repeat(5000));
        s.attempts[0] = attempt(&event).unwrap();
        s.outputs[0].evidence[0] = event;
        let findings = s
            .assessments()
            .iter()
            .filter_map(|a| a.finding(&p).unwrap())
            .collect();
        let snapshot = Snapshot {
            history: Default::default(),
            schema_version: 1,
            revision: 1,
            checkpoint: 1,
            source_stream: Uuid::from_u128(1),
            source_binding: [1; 32],
            state: s,
            findings,
        };
        let mut engine = store::Engine::open(&path, p.clone()).unwrap();
        assert!(matches!(engine.commit(0, snapshot), Err(Error::Capacity)));
        assert!(engine.load().unwrap().is_none());
        let reader = rusqlite::Connection::open(&path).unwrap();
        let count: i64 = reader
            .query_row("SELECT count(*) FROM window_assessments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let mut s = state();
        s.policy = p.clone();
        let findings = s
            .assessments()
            .iter()
            .filter_map(|a| a.finding(&p).unwrap())
            .collect();
        let snapshot = Snapshot {
            history: Default::default(),
            schema_version: 1,
            revision: 1,
            checkpoint: 1,
            source_stream: Uuid::from_u128(1),
            source_binding: [1; 32],
            state: s,
            findings,
        };
        engine.commit(0, snapshot).unwrap();
        reader
            .execute(
                "UPDATE window_assessments SET payload=zeroblob(length(payload))",
                [],
            )
            .unwrap();
        assert!(matches!(engine.retire(1, 1), Err(Error::Conflict)));
        assert_eq!(engine.load().unwrap().unwrap().checkpoint, 1);
        drop(engine);
        assert!(matches!(
            store::Engine::open(&path, p),
            Err(Error::Conflict)
        ));
    }

    #[tokio::test]
    async fn history_reader_pages_export_and_refuses_stale_foreign_or_cancelled_requests() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (journal, ready) = Journal::begin_open(
            temp.path().join("reader.sqlite"),
            policy(),
            crate::RuleContext::new(std::time::Duration::from_secs(3)),
        )
        .unwrap();
        ready.wait().await.unwrap();
        let context = || crate::RuleContext::new(std::time::Duration::from_secs(3));
        let empty = journal.history(1, 1024, context()).await.unwrap();
        assert!(empty.records.is_empty() && empty.missing_evidence && !empty.truncated);
        let mut s = state();
        let mut extra = s.outputs[0].clone();
        extra.outcome = Outcome::Indeterminate;
        s.outputs.push(extra);
        let findings = s
            .assessments()
            .iter()
            .filter_map(|a| a.finding(&policy()).unwrap())
            .collect();
        let next = Snapshot {
            history: Default::default(),
            schema_version: 1,
            revision: 1,
            checkpoint: 1,
            source_stream: Uuid::from_u128(1),
            source_binding: [1; 32],
            state: s,
            findings,
        };
        journal.commit(0, next, context()).await.unwrap();
        let first = journal.history(1, 16384, context()).await.unwrap();
        assert_eq!((first.records.len(), first.retained_count), (1, 2));
        assert!(first.truncated && first.missing_evidence);
        assert!(serde_json::to_vec(&first).unwrap().len() <= 16384);
        let cursor = first.next.unwrap();
        let exported = serde_json::to_vec(&cursor).unwrap();
        let restored: HistoryCursor = serde_json::from_slice(&exported).unwrap();
        let last = journal
            .history_after(Some(restored), 1, 16384, context())
            .await
            .unwrap();
        assert_eq!(last.records.len(), 1);
        assert!(!last.truncated && !last.missing_evidence && last.next.is_none());
        assert_ne!(first.records[0].id, last.records[0].id);
        assert_eq!(last.records[0].evidence.as_ref().unwrap().policy, policy());
        let mut foreign = cursor.clone();
        foreign.source_stream = Uuid::from_u128(9);
        assert!(matches!(
            journal
                .history_after(Some(foreign), 1, 16384, context())
                .await,
            Err(Error::Conflict)
        ));
        assert!(matches!(
            journal.history(1, 256, context()).await,
            Err(Error::Capacity)
        ));
        assert!(matches!(
            journal.history(0, 16384, context()).await,
            Err(Error::Configuration)
        ));
        let cancelled = context();
        cancelled.cancellation.cancel();
        assert!(matches!(
            journal.history(1, 16384, cancelled).await,
            Err(Error::Cancelled)
        ));
        journal.retire(1, 2, context()).await.unwrap();
        assert!(matches!(
            journal
                .history_after(Some(cursor), 1, 16384, context())
                .await,
            Err(Error::Conflict)
        ));
        assert_eq!(journal.metrics().0, 0);
        journal.shutdown(context()).await.unwrap();
    }

    #[test]
    fn native_attempt_conflicts_include_method_session_and_other_source_content() {
        let mut state = State::new(policy()).unwrap();
        let t: DateTime<Utc> = "2026-10-14T12:00:00Z".parse().unwrap();
        let input:signal_event::IngestEvent=serde_json::from_value(serde_json::json!({"timestamp":t,"source":{"type":"auth","name":"fixture"},"message":"fixture","attributes":{"authentication":{"identity_authority":"fixture","principal_id":"user","target_id":"target","outcome":"failure","method":"password","session_id":"one"},"producer":{"boot_id":"boot","sequence":1}}})).unwrap();
        let event = input.normalize(t).unwrap();
        state.admit(&event, true).unwrap();
        let mut changed = event;
        changed.id = Uuid::new_v4();
        changed.attributes["authentication"]["session_id"] = serde_json::json!("two");
        assert_eq!(state.admit(&changed, true), Err(Error::Conflict));
    }
}

#[cfg(test)]
mod recovery_tests;
