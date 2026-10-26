//! Typed runtime input and historical classification boundary. Source capture,
//! coverage, policy and publication are separate authorities. No SDK dependency.
use super::*;
use std::net::IpAddr;
mod epoch;
pub(super) use epoch::coverage_evidence;
pub use epoch::{
    CaptureEvidence, PolicyCoverageEvidence, PolicyCoverageVerification, RuntimeEpoch,
    RuntimeVerification,
};

pub const PROFILE: &str = "linux-owned-syscall-metadata/v1";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSource {
    pub stream: Uuid,
    pub binding: [u8; 32],
    pub config_revision: String,
    pub source_type: String,
    pub source_name: String,
    pub host: String,
    pub metadata_config_sha256: [u8; 32],
    pub audit_arch: u32,
    pub reads: bool,
    pub connects: bool,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Asset,
    Destination,
}
/// Proof-only inventory. These authorities have no invented runtime ordinals.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthority {
    pub id: Uuid,
    pub binding: [u8; 32],
    pub source_type: String,
    pub source_name: String,
    /// Exact configured dimensions; None means absent, never a wildcard grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub config_revision: String,
    pub authority_keys_sha256: [u8; 32],
    pub role: Role,
    pub policy_revision: String,
    pub policy_config_sha256: [u8; 32],
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub schema_version: u16,
    pub partition: Uuid,
    pub revision: String,
    pub title: String,
    pub severity: DetectionSeverity,
    pub authority_keys_sha256: [u8; 32],
    pub sources: Vec<RuntimeSource>,
    pub policy_authorities: Vec<PolicyAuthority>,
    pub correlation_ms: i64,
    pub lateness_ms: i64,
    pub ttl_ms: i64,
    pub max_events: usize,
    pub max_keys: usize,
    pub max_episodes: usize,
    pub max_state_bytes: usize,
}
impl RuntimeConfig {
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 2
            || self.partition.is_nil()
            || !identity(&self.revision)
            || !identity(&self.title)
            || self.authority_keys_sha256 == [0; 32]
            || self.sources.is_empty()
            || self.sources.len() > 8
            || self.policy_authorities.len() < 2
            || self.policy_authorities.len() > 8
            || !(1..=86_400_000).contains(&self.correlation_ms)
            || !(0..=86_400_000).contains(&self.lateness_ms)
            || self.ttl_ms < self.correlation_ms + self.lateness_ms
            || self.ttl_ms > 604_800_000
            || !(2..=128).contains(&self.max_events)
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
                || !ids.insert(s.stream)
                || s.binding == [0; 32]
                || !bindings.insert(s.binding)
                || [&s.config_revision, &s.source_type, &s.source_name, &s.host]
                    .iter()
                    .any(|s| !identity(s))
                || s.host.len() > 128
                || !s
                    .host
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || b"-_.".contains(&v))
                || s.metadata_config_sha256 == [0; 32]
                || !matches!(s.audit_arch, 0xc000003e | 0xc00000b7)
                || (!s.reads && !s.connects)
            {
                return Err(Error::Invalid);
            }
            if !self.sources.iter().any(|x| x.host == s.host && x.reads)
                || !self.sources.iter().any(|x| x.host == s.host && x.connects)
            {
                return Err(Error::Invalid);
            }
        }
        for a in &self.policy_authorities {
            if a.id.is_nil()
                || !ids.insert(a.id)
                || a.binding == [0; 32]
                || !bindings.insert(a.binding)
                || [
                    &a.source_type,
                    &a.source_name,
                    &a.config_revision,
                    &a.policy_revision,
                ]
                .iter()
                .any(|s| !identity(s))
                || a.authority_keys_sha256 == [0; 32]
                || a.policy_config_sha256 == [0; 32]
                || a.account.as_deref().is_some_and(|s| !identity(s))
                || a.resource.as_deref().is_some_and(|s| !identity(s))
            {
                return Err(Error::Invalid);
            }
        }
        if !self
            .policy_authorities
            .iter()
            .any(|a| a.role == Role::Asset)
            || !self
                .policy_authorities
                .iter()
                .any(|a| a.role == Role::Destination)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
/// Separate schema2 branch: no authentication fields or D11 digest changes.
pub struct RuntimeBinding {
    pub(super) config: RuntimeConfig,
    pub(super) digest: [u8; 32],
}
impl RuntimeBinding {
    pub fn new(config: RuntimeConfig, c: &RuleContext) -> Result<Self, Error> {
        check(c)?;
        config.validate()?;
        let digest = hash(
            b"PLATFORM::SIGNAL/correlation/D14-enrollment/v2\0",
            &codec::encode(&config, 16384, c)?,
        );
        Ok(Self { config, digest })
    }
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }
    /// Exact verification target as data; the digest grants no authority.
    pub fn enrollment_sha256(&self) -> [u8; 32] {
        self.digest
    }
}

// Rules-owned selected canonical projection; composition pins its SDK contract.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Process {
    pub host: String,
    pub boot: Uuid,
    pub capture: Uuid,
    pub pid: u32,
    pub start_ticks: u64,
    pub clock_ticks: u64,
    pub mount_ns: u64,
    pub audit_arch: u32,
    pub execution_generation: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Native {
    capture: Uuid,
    sequence: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub object_type: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
    pub mount_id: u64,
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Interval {
    pub entry_ns: u64,
    pub exit_ns: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Exec,
    Read {
        fd: i32,
        object: Object,
        interval: Interval,
        requested: u64,
        result: i64,
        error: bool,
    },
    Connect {
        fd: i32,
        object: Object,
        interval: Interval,
        address: IpAddr,
        port: u16,
        scope_id: u32,
        result: i64,
        error: bool,
    },
    End {
        stops: u32,
    },
    Gap {
        stops: u32,
        reason: String,
    },
}
impl Operation {
    pub fn interval(&self) -> Option<Interval> {
        match self {
            Self::Read { interval, .. } | Self::Connect { interval, .. } => Some(*interval),
            _ => None,
        }
    }
    fn role(&self) -> Option<Role> {
        match self {
            Self::Read {
                object,
                result,
                error: false,
                ..
            } if object.object_type == 0o100000 && *result > 0 => Some(Role::Asset),
            Self::Connect {
                object,
                result: 0,
                error: false,
                ..
            } if object.object_type == 0o140000 => Some(Role::Destination),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Projection {
    schema_version: u16,
    native: Native,
    process: Process,
    config_sha256: [u8; 32],
    original_record_sha256: [u8; 32],
    observed_ns: u64,
    operation: Operation,
}
impl Projection {
    fn validate(&self, s: &RuntimeSource, event: &SignalEvent) -> Result<(), Error> {
        let p = &self.process;
        if self.schema_version != 1
            || p.host != s.host
            || p.audit_arch != s.audit_arch
            || p.boot.is_nil()
            || p.capture.is_nil()
            || self.native.capture != p.capture
            || !(1..=4096).contains(&self.native.sequence)
            || p.pid == 0
            || p.pid > i32::MAX as u32
            || p.start_ticks == 0
            || p.clock_ticks == 0
            || p.mount_ns == 0
            || self.config_sha256 != s.metadata_config_sha256
            || self.original_record_sha256 == [0; 32]
            || self.observed_ns == 0
            || self.observed_ns > i64::MAX as u64
            || event.timestamp.timestamp_nanos_opt() != Some(self.observed_ns as i64)
            || p.execution_generation > self.native.sequence
            || (p.execution_generation == 0 && !matches!(self.operation, Operation::Gap { .. }))
        {
            return Err(Error::Invalid);
        }
        match &self.operation {
            Operation::Read {
                fd,
                object,
                interval,
                requested,
                result,
                error,
            } => {
                if !s.reads || (!error && (*result as u64) > *requested) {
                    return Err(Error::Unverified);
                }
                validate_operation(*fd, object, *interval, *result, *error, self.observed_ns)?;
            }
            Operation::Connect {
                fd,
                object,
                interval,
                address,
                port,
                scope_id,
                result,
                error,
            } => {
                if !s.connects
                    || (address.is_ipv4() && *scope_id != 0)
                    || (!error && (*result != 0 || object.object_type != 0o140000 || *port == 0))
                {
                    return Err(Error::Unverified);
                }
                validate_operation(*fd, object, *interval, *result, *error, self.observed_ns)?;
            }
            Operation::End { stops } if *stops == 0 || *stops > 100000 => {
                return Err(Error::Invalid);
            }
            Operation::Gap { stops, reason }
                if !identity(reason)
                    || ![
                        "cancelled",
                        "timeout",
                        "wait",
                        "child_failed",
                        "stop_limit",
                        "initialization",
                        "exec_pairing",
                        "output_limit",
                        "syscall_operation",
                        "syscall_abi",
                        "unsupported_syscall",
                        "entry_metadata",
                        "exit_pairing",
                        "exit_metadata",
                        "signal_or_event",
                        "resume",
                    ]
                    .contains(&reason.as_str())
                    || *stops
                        > if reason == "stop_limit" {
                            100001
                        } else {
                            100000
                        } =>
            {
                return Err(Error::Invalid);
            }
            _ => (),
        }
        Ok(())
    }
}
fn validate_operation(
    fd: i32,
    o: &Object,
    i: Interval,
    result: i64,
    error: bool,
    observed: u64,
) -> Result<(), Error> {
    if i.entry_ns == 0
        || i.entry_ns > i.exit_ns
        || i.exit_ns > observed
        || error != (result < 0)
        || result < -4095
        || (-516..=-512).contains(&result)
        || o.ctime_nsec >= 1_000_000_000
    {
        return Err(Error::Invalid);
    }
    if o.object_type == 0 {
        if result != -9
            || o.dev_major != 0
            || o.dev_minor != 0
            || o.inode != 0
            || o.mount_id != 0
            || o.ctime_sec != 0
            || o.ctime_nsec != 0
        {
            return Err(Error::Invalid);
        }
    } else if !matches!(
        o.object_type,
        0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o100000 | 0o120000 | 0o140000
    ) || o.inode == 0
        || o.mount_id == 0
        || fd < 0
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
/// Bounded input commitment. This verifies the selected data contract, not the
/// actual capture, operation clock, policy or current source authority.
pub struct Input {
    binding: [u8; 32],
    pub(super) event: SignalEvent,
    pub(super) stream: Uuid,
    canonical_sha256: [u8; 32],
    content_sha256: [u8; 32],
    projection: Projection,
    original: RuleContext,
}
impl Input {
    pub fn new(
        b: &RuntimeBinding,
        stream: Uuid,
        event: &SignalEvent,
        c: &RuleContext,
    ) -> Result<Self, Error> {
        check(c)?;
        let s = b
            .config
            .sources
            .iter()
            .find(|s| s.stream == stream)
            .ok_or(Error::Unverified)?;
        let bytes = codec::canonical(event, c)?;
        if event.source.source_type != s.source_type
            || event.source.name.as_deref() != Some(&s.source_name)
            || event
                .attributes
                .get("evidence")
                .and_then(|e| e.get("profile"))
                .and_then(|v| v.as_str())
                != Some(PROFILE)
            || event
                .resource
                .as_ref()
                .is_none_or(|r| r.kind != "host" || r.id != s.host)
        {
            return Err(Error::Unverified);
        }
        let projection: Projection = serde_json::from_value(
            event
                .attributes
                .get("runtime_metadata")
                .ok_or(Error::Invalid)?
                .clone(),
        )
        .map_err(|_| Error::Invalid)?;
        projection.validate(s, event)?;
        let mut content = serde_json::to_value(event).map_err(|_| Error::Invalid)?;
        let object = content.as_object_mut().ok_or(Error::Invalid)?;
        object.remove("id");
        object.remove("observed_at");
        let content_sha256 = hash(
            b"PLATFORM::SIGNAL/correlation/D14-native-content/v2\0",
            &codec::encode(&content, 65536, c)?,
        );
        Ok(Self {
            binding: b.digest,
            event: event.clone(),
            stream,
            canonical_sha256: hash(b"PLATFORM::SIGNAL/correlation/input/v1\0", &bytes),
            content_sha256,
            projection,
            original: c.clone(),
        })
    }
    pub fn process(&self) -> &Process {
        &self.projection.process
    }
    pub fn operation(&self) -> &Operation {
        &self.projection.operation
    }
    pub fn native_sequence(&self) -> u64 {
        self.projection.native.sequence
    }
    pub fn canonical_sha256(&self) -> [u8; 32] {
        self.canonical_sha256
    }
    pub fn content_sha256(&self) -> [u8; 32] {
        self.content_sha256
    }
    pub fn event(&self) -> &SignalEvent {
        &self.event
    }
    pub fn stream(&self) -> Uuid {
        self.stream
    }
    pub fn claim(&self, c: &RuleContext) -> Result<Claim, Error> {
        check(c)?;
        check(&self.original)?;
        let role = self.operation().role().ok_or(Error::Invalid)?;
        Ok(Claim {
            binding: self.binding,
            input_sha256: self.canonical_sha256,
            content_sha256: self.content_sha256,
            stream: self.stream,
            role,
            process: self.process().clone(),
            operation: self.operation().clone(),
        })
    }
}
/// Exact classification target as data; never a fresh permit.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    binding: [u8; 32],
    input_sha256: [u8; 32],
    content_sha256: [u8; 32],
    stream: Uuid,
    role: Role,
    process: Process,
    operation: Operation,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    Asset { protected_credential: bool },
    Destination { suspicious: bool },
}
impl Decision {
    fn role(&self) -> Role {
        match self {
            Self::Asset { .. } => Role::Asset,
            Self::Destination { .. } => Role::Destination,
        }
    }
    pub fn matches(&self) -> bool {
        match self {
            Self::Asset {
                protected_credential,
            } => *protected_credential,
            Self::Destination { suspicious } => *suspicious,
        }
    }
}
/// Results from the private host's independently authenticated historical policy
/// verifier. These facts must not be copied from event attributes or archives.
pub struct Verification {
    pub claim: Claim,
    pub authority: Uuid,
    pub authority_binding: [u8; 32],
    pub config_revision: String,
    pub authority_keys_sha256: [u8; 32],
    pub policy_revision: String,
    pub policy_config_sha256: [u8; 32],
    pub decision: Decision,
    pub covered_from: DateTime<Utc>,
    pub covered_through: DateTime<Utc>,
    pub reference: String,
    pub verified_at: DateTime<Utc>,
    pub verified_until: DateTime<Utc>,
    pub now: DateTime<Utc>,
    pub authenticated: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecisionEvidence {
    claim: Claim,
    authority: Uuid,
    authority_binding: [u8; 32],
    config_revision: String,
    authority_keys_sha256: [u8; 32],
    policy_revision: String,
    policy_config_sha256: [u8; 32],
    decision: Decision,
    covered_from: DateTime<Utc>,
    covered_through: DateTime<Utc>,
    reference: String,
    verified_at: DateTime<Utc>,
    verified_until: DateTime<Utc>,
    assessed_at: DateTime<Utc>,
}
impl DecisionEvidence {
    pub fn decision(&self) -> &Decision {
        &self.decision
    }
    /// Historical scope that publication/read adapters must authorize. This
    /// artifact does not itself grant access or current classification authority.
    pub fn contributor(
        &self,
        b: &RuntimeBinding,
        input: &Input,
        c: &RuleContext,
    ) -> Result<Contributor, Error> {
        self.validate_historical(b, input, c)?;
        let a = b
            .config
            .policy_authorities
            .iter()
            .find(|a| a.id == self.authority)
            .ok_or(Error::Unverified)?;
        Ok(Contributor {
            stream: a.id,
            source_binding: a.binding,
            source_type: a.source_type.clone(),
            source_name: Some(a.source_name.clone()),
            account: a.account.clone(),
            resource: a.resource.clone(),
        })
    }
    /// Pure retained-data validation. Success grants no current authority and
    /// never constructs a CurrentDecision or resets its original deadline.
    pub fn validate_historical(
        &self,
        b: &RuntimeBinding,
        input: &Input,
        c: &RuleContext,
    ) -> Result<(), Error> {
        check(c)?;
        let a = b
            .config
            .policy_authorities
            .iter()
            .find(|a| a.id == self.authority)
            .ok_or(Error::Unverified)?;
        // Historical reconstruction must remain possible after input work budget
        // expires; rebuild only exact data, never input.claim's fresh context.
        let claim = Claim {
            binding: input.binding,
            input_sha256: input.canonical_sha256,
            content_sha256: input.content_sha256,
            stream: input.stream,
            role: input.operation().role().ok_or(Error::Invalid)?,
            process: input.process().clone(),
            operation: input.operation().clone(),
        };
        let interval = input.operation().interval().ok_or(Error::Invalid)?;
        let from = self
            .covered_from
            .timestamp_nanos_opt()
            .ok_or(Error::Unverified)?;
        let through = self
            .covered_through
            .timestamp_nanos_opt()
            .ok_or(Error::Unverified)?;
        if input.binding != b.digest
            || self.claim != claim
            || a.role != claim.role
            || self.decision.role() != a.role
            || self.authority_binding != a.binding
            || self.config_revision != a.config_revision
            || self.authority_keys_sha256 != a.authority_keys_sha256
            || self.policy_revision != a.policy_revision
            || self.policy_config_sha256 != a.policy_config_sha256
            || !identity(&self.reference)
            || self.verified_at > self.assessed_at
            || self.assessed_at >= self.verified_until
            || self.assessed_at < input.event.timestamp
            || self.assessed_at < input.event.observed_at
            || from < 0
            || through < 0
            || from as u64 > interval.entry_ns
            || (through as u64) < interval.exit_ns
            || self
                .assessed_at
                .timestamp_nanos_opt()
                .is_none_or(|n| n < 0 || (n as u64) < interval.exit_ns)
        {
            return Err(Error::Unverified);
        }
        Ok(())
    }
}
/// Fresh lifetime-bound permit. Serialization of DecisionEvidence never creates
/// this object; every admission needs current independent private verification.
pub struct CurrentDecision {
    evidence: DecisionEvidence,
    context: RuleContext,
    original: RuleContext,
}
impl CurrentDecision {
    pub fn new(
        b: &RuntimeBinding,
        input: &Input,
        p: Verification,
        c: &RuleContext,
    ) -> Result<Self, Error> {
        check(c)?;
        check(&input.original)?;
        if !p.authenticated || p.claim != input.claim(c)? {
            return Err(Error::Unverified);
        }
        let evidence = DecisionEvidence {
            claim: p.claim,
            authority: p.authority,
            authority_binding: p.authority_binding,
            config_revision: p.config_revision,
            authority_keys_sha256: p.authority_keys_sha256,
            policy_revision: p.policy_revision,
            policy_config_sha256: p.policy_config_sha256,
            decision: p.decision,
            covered_from: p.covered_from,
            covered_through: p.covered_through,
            reference: p.reference,
            verified_at: p.verified_at,
            verified_until: p.verified_until,
            assessed_at: p.now,
        };
        evidence.validate_historical(b, input, c)?;
        let ttl = (evidence.verified_until - evidence.assessed_at)
            .to_std()
            .map_err(|_| Error::Unverified)?;
        let mut context = c.clone();
        context.deadline = context.deadline.min(input.original.deadline).min(
            tokio::time::Instant::now()
                .checked_add(ttl)
                .ok_or(Error::Invalid)?,
        );
        Ok(Self {
            evidence,
            context,
            original: input.original.clone(),
        })
    }
    pub fn retained(
        &self,
        b: &RuntimeBinding,
        input: &Input,
        c: &RuleContext,
    ) -> Result<DecisionEvidence, Error> {
        check(c)?;
        check(&self.context)?;
        check(&self.original)?;
        self.evidence.validate_historical(b, input, c)?;
        Ok(self.evidence.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    Match,
    NotApplicable,
    Uncertain,
}
/// Historical pair relation only. A clean episode still needs complete source
/// and policy coverage, processed prefixes, bounded history and original effects.
pub fn relation(
    b: &RuntimeBinding,
    read: &Input,
    asset: &DecisionEvidence,
    connect: &Input,
    destination: &DecisionEvidence,
    c: &RuleContext,
) -> Result<Relation, Error> {
    check(c)?;
    asset.validate_historical(b, read, c)?;
    destination.validate_historical(b, connect, c)?;
    if asset.claim.role != Role::Asset || destination.claim.role != Role::Destination {
        return Err(Error::Invalid);
    }
    if read.process() != connect.process()
        || !asset.decision.matches()
        || !destination.decision.matches()
    {
        return Ok(Relation::NotApplicable);
    }
    if read.projection.config_sha256 != connect.projection.config_sha256 {
        return Err(Error::Conflict);
    }
    if read.native_sequence() >= connect.native_sequence() {
        return Ok(Relation::Uncertain);
    }
    let r = read.operation().interval().ok_or(Error::Invalid)?;
    let d = connect.operation().interval().ok_or(Error::Invalid)?;
    if r.entry_ns > d.exit_ns {
        return Ok(Relation::NotApplicable);
    }
    let c_ns = (b.config.correlation_ms as u64) * 1_000_000;
    if d.entry_ns.saturating_sub(r.exit_ns) > c_ns {
        return Ok(Relation::NotApplicable);
    }
    if r.exit_ns >= d.entry_ns || d.exit_ns.saturating_sub(r.entry_ns) > c_ns {
        return Ok(Relation::Uncertain);
    }
    Ok(Relation::Match)
}
