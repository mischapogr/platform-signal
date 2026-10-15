//! Bounded heartbeat assessment over host-authenticated independent observations.
//! This pure transition stage grants no authentication or durable commit authority.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use thiserror::Error;
use uuid::Uuid;

const MAX_TIME: i64 = 253_402_300_799_999;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid sensor-health policy or snapshot")]
    Configuration,
    #[error("sensor-health inventory or byte capacity exhausted")]
    Capacity,
    #[error("sensor-health source, binding or observer mismatch")]
    Scope,
    #[error("sensor-health observation identity or progress conflicts")]
    Conflict,
    #[error("sensor-health clock is invalid, future or regressed")]
    Clock,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSource {
    pub source_id: Uuid,
    /// Digest of the complete private source/collector/account/resource/stream binding.
    pub binding: [u8; 32],
    pub observer_id: Uuid,
    pub expected_since_ms: i64,
    pub require_checkpoint: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u16,
    pub rule_id: String,
    pub revision: String,
    pub heartbeat_ms: i64,
    pub grace_ms: i64,
    pub observer_freshness_ms: i64,
    pub max_sources: usize,
    pub max_state_bytes: usize,
    /// Canonical ascending source-ID order; explicit policy, never telemetry discovery.
    pub expected: Vec<ExpectedSource>,
}
fn identity(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.trim() == s && !s.chars().any(char::is_control)
}
fn valid_time(t: i64) -> bool {
    (0..=MAX_TIME).contains(&t)
}
impl Policy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || !identity(&self.rule_id)
            || !identity(&self.revision)
            || !(1..=86_400_000).contains(&self.heartbeat_ms)
            || !(0..=86_400_000).contains(&self.grace_ms)
            || !(1..=86_400_000).contains(&self.observer_freshness_ms)
            || !(1..=4096).contains(&self.max_sources)
            || !(1024..=16 * 1024 * 1024).contains(&self.max_state_bytes)
        {
            return Err(Error::Configuration);
        }
        if self.expected.is_empty() || self.expected.len() > self.max_sources {
            return Err(Error::Capacity);
        }
        for s in &self.expected {
            if s.source_id.is_nil()
                || s.observer_id.is_nil()
                || s.binding == [0; 32]
                || !valid_time(s.expected_since_ms)
                || s.expected_since_ms > MAX_TIME - self.heartbeat_ms - self.grace_ms
            {
                return Err(Error::Configuration);
            }
        }
        if self
            .expected
            .windows(2)
            .any(|p| p[0].source_id >= p[1].source_id)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ObserverHealth {
    Healthy,
    Unhealthy,
}

/// Only a trusted independent-probe adapter may supply this input. Public fields
/// facilitate transport; successful decoding is not proof authentication.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u16,
    pub source_id: Uuid,
    pub binding: [u8; 32],
    pub observer_id: Uuid,
    /// Identity/progress within the enrolled observer/configuration revision.
    pub sequence: u64,
    pub observed_at_ms: i64,
    pub health: ObserverHealth,
    pub heartbeat_at_ms: Option<i64>,
    pub checkpoint: Option<u64>,
}
impl Observation {
    /// Structural checks against an enrolled source and trusted receiver clock.
    /// This does not authenticate a probe or establish observer independence.
    pub fn validate(&self, expected: &ExpectedSource, now: i64) -> Result<(), Error> {
        if self.schema_version != 1 || self.sequence == 0 {
            return Err(Error::Configuration);
        }
        if self.source_id != expected.source_id
            || self.binding != expected.binding
            || self.observer_id != expected.observer_id
        {
            return Err(Error::Scope);
        }
        if !valid_time(now)
            || !valid_time(self.observed_at_ms)
            || self.observed_at_ms > now
            || self.observed_at_ms < expected.expected_since_ms
            || self
                .heartbeat_at_ms
                .is_some_and(|t| !valid_time(t) || t > self.observed_at_ms)
        {
            return Err(Error::Clock);
        }
        if (self.health == ObserverHealth::Unhealthy
            && (self.heartbeat_at_ms.is_some() || self.checkpoint.is_some()))
            || (self.checkpoint.is_some() && self.heartbeat_at_ms.is_none())
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    latest: Option<Observation>,
    heartbeat_at_ms: Option<i64>,
    checkpoint: Option<u64>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u16,
    policy: Policy,
    clock_ms: i64,
    slots: Vec<Slot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Accepted,
    Replayed,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Match,
    NoMatch,
    Indeterminate,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    HeartbeatCurrent,
    GracePeriod,
    HeartbeatAbsent,
    ObserverUnknown,
    ObserverUnhealthy,
    ObserverStale,
    CheckpointMissing,
    ObservationIncomplete,
}
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub schema_version: u16,
    pub source_id: Uuid,
    pub outcome: Outcome,
    pub reason: Reason,
    pub assessed_at_ms: i64,
    pub deadline_ms: i64,
    pub observation_sequence: Option<u64>,
    /// Stable collection-gap identity, not a persisted finding or compromise claim.
    pub gap_id: Option<Uuid>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Metrics {
    pub accepted: u64,
    pub replayed: u64,
    pub rejected: u64,
}

struct LimitedWriter {
    remaining: usize,
}
impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("sensor-health byte capacity"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bound(snapshot: &Snapshot) -> Result<(), Error> {
    serde_json::to_writer(
        LimitedWriter {
            remaining: snapshot.policy.max_state_bytes,
        },
        snapshot,
    )
    .map_err(|_| Error::Capacity)
}

/// Serial pure transitions. Persist the candidate and its outputs atomically in
/// the embedding host before installing it or acknowledging source progress.
pub struct Monitor {
    state: Snapshot,
    metrics: Metrics,
}
impl Monitor {
    pub fn new(policy: Policy, now: i64) -> Result<Self, Error> {
        policy.validate()?;
        if !valid_time(now) || policy.expected.iter().any(|s| s.expected_since_ms > now) {
            return Err(Error::Clock);
        }
        let state = Snapshot {
            schema_version: 1,
            clock_ms: now,
            slots: vec![
                Slot {
                    latest: None,
                    heartbeat_at_ms: None,
                    checkpoint: None
                };
                policy.expected.len()
            ],
            policy,
        };
        bound(&state)?;
        Ok(Self {
            state,
            metrics: Metrics::default(),
        })
    }
    pub fn metrics(&self) -> Metrics {
        self.metrics
    }
    pub fn clock_ms(&self) -> i64 {
        self.state.clock_ms
    }
    /// Read-only provenance requirements for a host's bounded original-evidence
    /// custody. Returned values confer no source or observer authority.
    pub fn retained_progress(
        &self,
    ) -> impl Iterator<Item = (Uuid, Option<&Observation>, Option<i64>, Option<u64>)> {
        self.state
            .policy
            .expected
            .iter()
            .zip(&self.state.slots)
            .map(|(expected, slot)| {
                (
                    expected.source_id,
                    slot.latest.as_ref(),
                    slot.heartbeat_at_ms,
                    slot.checkpoint,
                )
            })
    }
    pub fn snapshot(&self) -> Result<Vec<u8>, Error> {
        bound(&self.state)?;
        serde_json::to_vec(&self.state).map_err(|_| Error::Configuration)
    }
    /// The host must authenticate snapshot custody; validation is structural and
    /// policy-bound. Neither restoring nor evaluating renews observer verification.
    pub fn restore(policy: Policy, bytes: &[u8]) -> Result<Self, Error> {
        policy.validate()?;
        if bytes.len() > policy.max_state_bytes {
            return Err(Error::Capacity);
        }
        let state: Snapshot = serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
        if state.schema_version != 1
            || state.policy != policy
            || state.slots.len() != policy.expected.len()
            || !valid_time(state.clock_ms)
            || policy
                .expected
                .iter()
                .any(|s| s.expected_since_ms > state.clock_ms)
        {
            return Err(Error::Configuration);
        }
        for (s, expected) in state.slots.iter().zip(&policy.expected) {
            match &s.latest {
                None if s.heartbeat_at_ms.is_some() || s.checkpoint.is_some() => {
                    return Err(Error::Configuration);
                }
                Some(o) => {
                    o.validate(expected, state.clock_ms)?;
                    if s.heartbeat_at_ms
                        .is_some_and(|t| !valid_time(t) || t > o.observed_at_ms)
                        || (s.checkpoint.is_some() && s.heartbeat_at_ms.is_none())
                        || o.heartbeat_at_ms
                            .is_some_and(|t| s.heartbeat_at_ms != Some(t))
                        || o.checkpoint.is_some_and(|c| s.checkpoint != Some(c))
                    {
                        return Err(Error::Configuration);
                    }
                }
                None => {}
            }
        }
        bound(&state)?;
        Ok(Self {
            state,
            metrics: Metrics::default(),
        })
    }
    fn clock(&self, now: i64) -> Result<(), Error> {
        if !valid_time(now) || now < self.state.clock_ms {
            Err(Error::Clock)
        } else {
            Ok(())
        }
    }
    pub fn observe(&mut self, observation: Observation, now: i64) -> Result<Admission, Error> {
        let result = self.observe_inner(observation, now);
        match result {
            Ok(Admission::Accepted) => {
                self.metrics.accepted = self.metrics.accepted.saturating_add(1)
            }
            Ok(Admission::Replayed) => {
                self.metrics.replayed = self.metrics.replayed.saturating_add(1)
            }
            Err(_) => self.metrics.rejected = self.metrics.rejected.saturating_add(1),
        }
        result
    }
    fn observe_inner(&mut self, observation: Observation, now: i64) -> Result<Admission, Error> {
        self.clock(now)?;
        let index = self
            .state
            .policy
            .expected
            .binary_search_by_key(&observation.source_id, |s| s.source_id)
            .map_err(|_| Error::Scope)?;
        observation.validate(&self.state.policy.expected[index], now)?;
        let slot = &self.state.slots[index];
        if let Some(old) = &slot.latest {
            if observation == *old {
                return Ok(Admission::Replayed);
            }
            if observation.sequence <= old.sequence
                || observation.observed_at_ms <= old.observed_at_ms
                || observation
                    .heartbeat_at_ms
                    .zip(slot.heartbeat_at_ms)
                    .is_some_and(|(a, b)| a < b)
                || observation
                    .checkpoint
                    .zip(slot.checkpoint)
                    .is_some_and(|(a, b)| a < b)
            {
                return Err(Error::Conflict);
            }
        }
        let mut candidate = self.state.clone();
        let slot = &mut candidate.slots[index];
        if observation.heartbeat_at_ms.is_some() {
            slot.heartbeat_at_ms = observation.heartbeat_at_ms;
        }
        if observation.checkpoint.is_some() {
            slot.checkpoint = observation.checkpoint;
        }
        slot.latest = Some(observation);
        candidate.clock_ms = now;
        bound(&candidate)?;
        self.state = candidate;
        Ok(Admission::Accepted)
    }
    pub fn assess(&mut self, now: i64) -> Result<Vec<Assessment>, Error> {
        self.clock(now)?;
        let policy = &self.state.policy;
        let policy_bytes = serde_json::to_vec(policy).map_err(|_| Error::Configuration)?;
        let fingerprint = Sha256::digest(policy_bytes);
        let mut result = Vec::with_capacity(policy.expected.len());
        for (expected, slot) in policy.expected.iter().zip(&self.state.slots) {
            let basis = slot
                .heartbeat_at_ms
                .unwrap_or(expected.expected_since_ms)
                .max(expected.expected_since_ms);
            let deadline = basis
                .checked_add(policy.heartbeat_ms)
                .and_then(|v| v.checked_add(policy.grace_ms))
                .filter(|v| valid_time(*v))
                .ok_or(Error::Clock)?;
            let (outcome, reason) = match &slot.latest {
                None => (Outcome::Indeterminate, Reason::ObserverUnknown),
                Some(o) if o.health == ObserverHealth::Unhealthy => {
                    (Outcome::Indeterminate, Reason::ObserverUnhealthy)
                }
                Some(o) if now - o.observed_at_ms >= policy.observer_freshness_ms => {
                    (Outcome::Indeterminate, Reason::ObserverStale)
                }
                Some(o)
                    if expected.require_checkpoint
                        && o.heartbeat_at_ms.is_some()
                        && o.checkpoint.is_none() =>
                {
                    (Outcome::Indeterminate, Reason::CheckpointMissing)
                }
                Some(o) if now >= deadline && o.observed_at_ms < deadline => {
                    (Outcome::Indeterminate, Reason::ObservationIncomplete)
                }
                Some(_) if now >= deadline => (Outcome::Match, Reason::HeartbeatAbsent),
                Some(_) if slot.heartbeat_at_ms.is_none() => {
                    (Outcome::NoMatch, Reason::GracePeriod)
                }
                Some(_) => (Outcome::NoMatch, Reason::HeartbeatCurrent),
            };
            let gap_id = if outcome == Outcome::Match {
                let mut hash = Sha256::new();
                hash.update(b"SIGNAL-SENSOR-GAP-V1");
                hash.update(fingerprint);
                hash.update(expected.source_id.as_bytes());
                hash.update(deadline.to_be_bytes());
                let bytes: [u8; 32] = hash.finalize().into();
                let mut id = [0; 16];
                id.copy_from_slice(&bytes[..16]);
                id[6] = (id[6] & 0x0f) | 0x80;
                id[8] = (id[8] & 0x3f) | 0x80;
                Some(Uuid::from_bytes(id))
            } else {
                None
            };
            result.push(Assessment {
                schema_version: 1,
                source_id: expected.source_id,
                outcome,
                reason,
                assessed_at_ms: now,
                deadline_ms: deadline,
                observation_sequence: slot.latest.as_ref().map(|o| o.sequence),
                gap_id,
            });
        }
        let mut candidate = self.state.clone();
        candidate.clock_ms = now;
        bound(&candidate)?;
        self.state = candidate;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "sensor_health_tests.rs"]
mod tests;
