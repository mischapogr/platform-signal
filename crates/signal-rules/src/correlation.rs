//! Bounded native authentication episodes. Host artifacts do not grant scope.
mod binding;
mod codec;
mod d11;
pub mod d14;
mod engine;
mod epoch;
pub mod history;
pub mod journal;
use crate::RuleContext;
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_event::SignalEvent;
use signal_findings::{DetectionSeverity, Finding};
use std::collections::BTreeSet;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid correlation configuration or input")]
    Invalid,
    #[error("correlation capacity exhausted; history is not silently evicted")]
    Capacity,
    #[error("correlation identity, predecessor or generation conflicts")]
    Conflict,
    #[error("correlation source authority unavailable")]
    Unverified,
    #[error("publish and retire original pending correlation outputs first")]
    Pending,
    #[error("fresh complete protected history lookup required")]
    ArchiveRequired,
    #[error("correlation original deadline expired or cancelled")]
    Cancelled,
    #[error("correlation journal uncertain; reload original committed bytes")]
    Journal,
}
fn check(context: &RuleContext) -> Result<(), Error> {
    if context.cancellation.is_cancelled() || tokio::time::Instant::now() >= context.deadline {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn identity(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 256
        && text.trim() == text
        && !text.chars().any(char::is_control)
}
fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub stream: Uuid,
    pub binding: [u8; 32],
    pub config_revision: String,
    pub source_type: String,
    pub source_name: String,
    pub identity_authority: String,
    pub failures: bool,
    pub successes: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u16,
    pub partition: Uuid,
    pub revision: String,
    pub title: String,
    pub severity: DetectionSeverity,
    pub authority_keys_sha256: [u8; 32],
    pub sources: Vec<Source>,
    pub threshold: usize,
    pub window_ms: i64,
    pub correlation_ms: i64,
    pub lateness_ms: i64,
    pub ttl_ms: i64,
    pub max_events: usize,
    pub max_keys: usize,
    pub max_episodes: usize,
    pub max_state_bytes: usize,
}
impl Config {
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || self.partition.is_nil()
            || !identity(&self.revision)
            || !identity(&self.title)
            || self.authority_keys_sha256 == [0; 32]
            || self.sources.is_empty()
            || self.sources.len() > 8
            || !(1..=32).contains(&self.threshold)
            || !(1..=86_400_000).contains(&self.window_ms)
            || !(1..=86_400_000).contains(&self.correlation_ms)
            || !(0..=86_400_000).contains(&self.lateness_ms)
            || self.ttl_ms < self.window_ms + self.correlation_ms + self.lateness_ms
            || self.ttl_ms > 604_800_000
            || self.max_events < self.threshold + 1
            || self.max_events > 128
            || !(1..=64).contains(&self.max_keys)
            || !(1..=64).contains(&self.max_episodes)
            || !(4096..=4 * 1024 * 1024).contains(&self.max_state_bytes)
        {
            return Err(Error::Invalid);
        }
        let mut ids = BTreeSet::new();
        let mut bindings = BTreeSet::new();
        for s in &self.sources {
            if s.stream.is_nil()
                || s.binding == [0; 32]
                || !ids.insert(s.stream)
                || !bindings.insert(s.binding)
                || [
                    &s.config_revision,
                    &s.source_type,
                    &s.source_name,
                    &s.identity_authority,
                ]
                .iter()
                .any(|t| !identity(t))
                || (!s.failures && !s.successes)
            {
                return Err(Error::Invalid);
            }
            if !self
                .sources
                .iter()
                .any(|x| x.identity_authority == s.identity_authority && x.failures)
                || !self
                    .sources
                    .iter()
                    .any(|x| x.identity_authority == s.identity_authority && x.successes)
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}
/// Current host-selected configuration; historical state never constructs it.
pub struct Binding {
    config: Config,
    digest: [u8; 32],
}
impl Binding {
    pub fn new(config: Config, context: &RuleContext) -> Result<Self, Error> {
        check(context)?;
        config.validate()?;
        let digest = hash(
            b"PLATFORM::SIGNAL/correlation/enrollment/v1\0",
            &codec::encode(&config, 16384, context)?,
        );
        Ok(Self { config, digest })
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
}
/// Independently verified host facts; not deserializable and never read from events.
pub struct Verification {
    pub stream: Uuid,
    pub position: u64,
    pub source_binding: [u8; 32],
    pub source_config_revision: String,
    pub authority_keys_sha256: [u8; 32],
    pub verification_reference: String,
    pub verified_at: DateTime<Utc>,
    pub verified_until: DateTime<Utc>,
    pub now: DateTime<Utc>,
    pub coverage_from: DateTime<Utc>,
    pub frontier: DateTime<Utc>,
    pub complete: bool,
    pub authenticated: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationEvidence {
    stream: Uuid,
    position: u64,
    source_binding: [u8; 32],
    source_config_revision: String,
    authority_keys_sha256: [u8; 32],
    verification_reference: String,
    verified_at: DateTime<Utc>,
    verified_until: DateTime<Utc>,
    assessed_at: DateTime<Utc>,
    coverage_from: DateTime<Utc>,
    frontier: DateTime<Utc>,
    complete: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "epoch::capture_evidence"
    )]
    runtime: Option<d14::CaptureEvidence>,
}
/// Fresh lifetime is pinned at construction. Missing streams cannot advance a watermark.
pub struct Epoch {
    binding: [u8; 32],
    evidence: Vec<VerificationEvidence>,
    context: RuleContext,
    policy: Vec<d14::PolicyCoverageEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub authority: String,
    pub principal: String,
    pub target: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct NativeId {
    pub stream: Uuid,
    pub boot: String,
    pub sequence: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Observation {
    event: SignalEvent,
    canonical_sha256: [u8; 32],
    native: Option<NativeId>,
    content_sha256: [u8; 32],
    key: Option<Key>,
    success: Option<bool>,
    verification: VerificationEvidence,
    admission_watermark: Option<DateTime<Utc>>,
    source_position: u64,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Match,
    NoMatch,
    Indeterminate,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Contributor {
    pub stream: Uuid,
    pub source_binding: [u8; 32],
    pub source_type: String,
    pub source_name: Option<String>,
    pub account: Option<String>,
    pub resource: Option<String>,
}
/// Immutable host artifact. Publication/read must authorize EVERY contributor;
/// this is deliberately not a ScopedFinding or a fresh authorization credential.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Episode {
    pub schema_version: u16,
    pub id: Uuid,
    pub rule_id: String,
    pub rule_revision: String,
    pub policy_sha256: [u8; 32],
    pub anchor: DateTime<Utc>,
    pub success_native: Option<NativeId>,
    pub sealed_watermark: DateTime<Utc>,
    pub observation_count: usize,
    pub coverage_degraded_through: Option<DateTime<Utc>>,
    pub status: Status,
    pub coverage_gap: bool,
    pub reasons: Vec<String>,
    pub event_ids: Vec<Uuid>,
    pub originals: Vec<SignalEvent>,
    pub contributors: Vec<Contributor>,
    pub verification: Vec<VerificationEvidence>,
    pub finding: Option<Finding>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Alias {
    id: Uuid,
    original_id: Uuid,
    origin_archive: Option<[u8; 32]>,
    effect: Option<history::EffectRef>,
    lookup: Option<history::LookupEvidence>,
    canonical_sha256: [u8; 32],
    native: Option<NativeId>,
    content_sha256: [u8; 32],
    stream: Uuid,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Effect {
    id: Uuid,
    #[serde(with = "codec::bytes")]
    bytes: Vec<u8>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Completion {
    canonical_id: Uuid,
    effect: history::EffectRef,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u16,
    binding: [u8; 32],
    observations: Vec<Observation>,
    aliases: Vec<Alias>,
    episodes: Vec<Episode>,
    effects: Vec<Effect>,
    completions: Vec<Completion>,
    archive: Option<history::Anchor>,
    positions: Vec<(Uuid, u64)>,
    watermark: Option<DateTime<Utc>>,
    last_seal_evidence: Vec<VerificationEvidence>,
    degraded_through: Option<DateTime<Utc>>,
    retired_late_inputs: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    New,
    Duplicate,
    Late,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seal {
    pub watermark: Option<DateTime<Utc>>,
    pub new_episodes: usize,
    pub coverage_gap: bool,
}

/// Finite retained-state depth/capacity and durable exclusions; no identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metrics {
    pub retained_events: usize,
    pub event_capacity: usize,
    pub retained_aliases: usize,
    pub alias_capacity: usize,
    pub retained_episodes: usize,
    pub episode_capacity: usize,
    pub late_inputs: u64,
}
