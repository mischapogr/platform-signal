//! Selected owned-process metadata, not source health or private classification.
//! Serializable facts and continuity checks are data validation, never authority.
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use signal_event::{IngestEvent, SignalEvent, Source};
use std::net::IpAddr;
use thiserror::Error;
use uuid::Uuid;

pub const PROFILE: &str = "linux-owned-syscall-metadata/v1";
pub const MAX_RECORD_BYTES: usize = 4096;
pub const MAX_RECORDS: u64 = 4096;
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
pub const AUDIT_X86_64: u32 = 0xc000003e;
pub const AUDIT_ARM64: u32 = 0xc00000b7;
pub const REGULAR_FILE: u32 = 0o100000;
pub const SOCKET: u32 = 0o140000;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid runtime metadata enrollment")]
    Configuration,
    #[error("invalid selected runtime metadata record")]
    Record,
    #[error("runtime metadata bound exhausted")]
    Limit,
    #[error("runtime metadata continuity gap")]
    Continuity,
}

/// Host-selected expected enrollment. Construction does not verify the actual
/// tracer, binary, permissions, exclusive task scope or original record custody.
pub struct Profile {
    host: String,
    boot: Uuid,
    capture: Uuid,
    config: [u8; 32],
    audit_arch: u32,
}
impl Profile {
    pub fn new(
        host: &str,
        boot: Uuid,
        capture: Uuid,
        config: [u8; 32],
        audit_arch: u32,
    ) -> Result<Self, Error> {
        if host.is_empty()
            || host.len() > 128
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || boot.is_nil()
            || capture.is_nil()
            || config == [0; 32]
            || !matches!(audit_arch, AUDIT_X86_64 | AUDIT_ARM64)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            host: host.into(),
            boot,
            capture,
            config,
            audit_arch,
        })
    }
}

/// Capture UUID prevents native sequence and execution-generation reuse on a
/// restarted tracer. A stream enrollment remains the consuming host's concern.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct NativeIdentity {
    pub capture: Uuid,
    pub sequence: u64,
}
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
    /// A positive regular-file read is still not private protected-asset policy.
    pub fn positive_regular_read(&self) -> bool {
        matches!(self, Self::Read { object, result, error: false, .. } if object.object_type == REGULAR_FILE && *result > 0)
    }
    pub fn successful_connect(&self) -> bool {
        matches!(self, Self::Connect { object, result: 0, error: false, .. } if object.object_type == SOCKET)
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub schema_version: u16,
    pub native: NativeIdentity,
    pub process: Process,
    pub config_sha256: [u8; 32],
    pub original_record_sha256: [u8; 32],
    pub observed_ns: u64,
    pub operation: Operation,
}

const BASE: &[&str] = &[
    "schema_version",
    "profile",
    "capture_id",
    "config_sha256",
    "host",
    "boot_id",
    "sequence",
    "timestamp_ns",
    "pid",
    "tid",
    "start_ticks",
    "clock_ticks",
    "mount_ns",
    "audit_arch",
    "execution_generation",
    "kind",
];
const OBJECT: &[&str] = &[
    "fd",
    "object_type",
    "dev_major",
    "dev_minor",
    "inode",
    "mount_id",
    "ctime_sec",
    "ctime_nsec",
    "result",
    "error",
    "syscall_entry_ns",
    "syscall_exit_ns",
];
fn record(raw: &[u8]) -> Result<Map<String, Value>, Error> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(Error::Limit);
    }
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = Map<String, Value>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique bounded scalar runtime metadata")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut a: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = Map::new();
            while let Some(key) = a.next_key::<String>()? {
                if out.len() >= 40 || out.contains_key(&key) {
                    return Err(serde::de::Error::custom("duplicate or excessive fields"));
                }
                let value: Value = a.next_value()?;
                if value.is_array() || value.is_object() || value.is_null() {
                    return Err(serde::de::Error::custom("non-scalar metadata"));
                }
                out.insert(key, value);
            }
            Ok(out)
        }
    }
    let mut d = serde_json::Deserializer::from_slice(raw);
    let value = d.deserialize_map(Unique).map_err(|_| Error::Record)?;
    d.end().map_err(|_| Error::Record)?;
    Ok(value)
}
fn number(r: &Map<String, Value>, name: &str) -> Result<u64, Error> {
    r.get(name).and_then(Value::as_u64).ok_or(Error::Record)
}
fn small(r: &Map<String, Value>, name: &str) -> Result<u32, Error> {
    u32::try_from(number(r, name)?).map_err(|_| Error::Record)
}
fn signed(r: &Map<String, Value>, name: &str) -> Result<i64, Error> {
    r.get(name).and_then(Value::as_i64).ok_or(Error::Record)
}
fn text<'a>(r: &'a Map<String, Value>, name: &str) -> Result<&'a str, Error> {
    r.get(name).and_then(Value::as_str).ok_or(Error::Record)
}
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse data only. Missing/forged sensor proof must never be repaired from
/// producer fields or this function's success. Exact raw bytes stay committed.
pub fn parse(raw: &[u8], profile: &Profile) -> Result<Metadata, Error> {
    let r = record(raw)?;
    let kind = text(&r, "kind")?;
    let details: &[&str] = match kind {
        "exec" => &[],
        "read" => &["requested"],
        "connect" => &["family", "address", "port", "scope_id"],
        "end" | "gap" => &["reason", "stops"],
        _ => return Err(Error::Record),
    };
    let operation_fields = matches!(kind, "read" | "connect");
    let expected = BASE.len() + details.len() + if operation_fields { OBJECT.len() } else { 0 };
    if r.len() != expected
        || r.keys().any(|key| {
            !(BASE.contains(&key.as_str())
                || details.contains(&key.as_str())
                || (operation_fields && OBJECT.contains(&key.as_str())))
        })
        || number(&r, "schema_version")? != 1
        || text(&r, "profile")? != PROFILE
        || text(&r, "host")? != profile.host
        || text(&r, "boot_id")? != profile.boot.to_string()
        || text(&r, "capture_id")? != profile.capture.to_string()
        || text(&r, "config_sha256")? != hex(profile.config)
        || small(&r, "audit_arch")? != profile.audit_arch
    {
        return Err(Error::Record);
    }
    let pid = small(&r, "pid")?;
    let sequence = number(&r, "sequence")?;
    let observed_ns = number(&r, "timestamp_ns")?;
    let generation = number(&r, "execution_generation")?;
    let process = Process {
        host: profile.host.clone(),
        boot: profile.boot,
        capture: profile.capture,
        pid,
        start_ticks: number(&r, "start_ticks")?,
        clock_ticks: number(&r, "clock_ticks")?,
        mount_ns: number(&r, "mount_ns")?,
        audit_arch: profile.audit_arch,
        execution_generation: generation,
    };
    if pid == 0
        || pid > i32::MAX as u32
        || number(&r, "tid")? != pid as u64
        || sequence == 0
        || sequence > MAX_RECORDS
        || observed_ns == 0
        || observed_ns > i64::MAX as u64
        || process.start_ticks == 0
        || process.clock_ticks == 0
        || process.mount_ns == 0
        || (generation == 0 && kind != "gap")
        || generation > sequence
    {
        return Err(Error::Record);
    }
    let operation = if operation_fields {
        let object = Object {
            object_type: small(&r, "object_type")?,
            dev_major: small(&r, "dev_major")?,
            dev_minor: small(&r, "dev_minor")?,
            inode: number(&r, "inode")?,
            mount_id: number(&r, "mount_id")?,
            ctime_sec: signed(&r, "ctime_sec")?,
            ctime_nsec: small(&r, "ctime_nsec")?,
        };
        let interval = Interval {
            entry_ns: number(&r, "syscall_entry_ns")?,
            exit_ns: number(&r, "syscall_exit_ns")?,
        };
        let result = signed(&r, "result")?;
        let error = r
            .get("error")
            .and_then(Value::as_bool)
            .ok_or(Error::Record)?;
        let fd = i32::try_from(signed(&r, "fd")?).map_err(|_| Error::Record)?;
        if interval.entry_ns == 0
            || interval.entry_ns > interval.exit_ns
            || interval.exit_ns > observed_ns
            || error != (result < 0)
            || result < -4095
            || (-516..=-512).contains(&result)
            || object.ctime_nsec >= 1_000_000_000
        {
            return Err(Error::Record);
        }
        if object.object_type == 0 {
            if result != -9
                || object.dev_major != 0
                || object.dev_minor != 0
                || object.inode != 0
                || object.mount_id != 0
                || object.ctime_sec != 0
                || object.ctime_nsec != 0
            {
                return Err(Error::Record);
            }
        } else if !matches!(
            object.object_type,
            0o010000 | 0o020000 | 0o040000 | 0o060000 | REGULAR_FILE | 0o120000 | SOCKET
        ) || object.inode == 0
            || object.mount_id == 0
            || fd < 0
        {
            return Err(Error::Record);
        }
        if kind == "read" {
            let requested = number(&r, "requested")?;
            if !error && result as u64 > requested {
                return Err(Error::Record);
            }
            Operation::Read {
                fd,
                object,
                interval,
                requested,
                result,
                error,
            }
        } else {
            let address: IpAddr = text(&r, "address")?.parse().map_err(|_| Error::Record)?;
            let port = u16::try_from(number(&r, "port")?).map_err(|_| Error::Record)?;
            let scope_id = small(&r, "scope_id")?;
            if number(&r, "family")? != if address.is_ipv4() { 4 } else { 6 }
                || (address.is_ipv4() && scope_id != 0)
                || (!error && (result != 0 || object.object_type != SOCKET || port == 0))
            {
                return Err(Error::Record);
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
            }
        }
    } else if kind == "exec" {
        Operation::Exec
    } else {
        let stops = small(&r, "stops")?;
        let reason = text(&r, "reason")?;
        let limit = if kind == "gap" && reason == "stop_limit" {
            100001
        } else {
            100000
        };
        if stops > limit {
            return Err(Error::Record);
        }
        if kind == "end" {
            if reason != "exited" || stops == 0 {
                return Err(Error::Record);
            }
            Operation::End { stops }
        } else {
            if ![
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
            .contains(&reason)
            {
                return Err(Error::Record);
            }
            Operation::Gap {
                stops,
                reason: reason.into(),
            }
        }
    };
    Ok(Metadata {
        schema_version: 1,
        native: NativeIdentity {
            capture: profile.capture,
            sequence,
        },
        process,
        config_sha256: profile.config,
        original_record_sha256: Sha256::digest(raw).into(),
        observed_ns,
        operation,
    })
}

/// No source-health claim: a terminal End means only that this exact selected
/// byte sequence passed continuity validation. Host coverage remains separate.
pub struct Continuity {
    sequence: u64,
    bytes: usize,
    process: Option<Process>,
    config: Option<[u8; 32]>,
    observed_ns: u64,
    generation: u64,
    terminal: bool,
}
impl Default for Continuity {
    fn default() -> Self {
        Self::new()
    }
}
impl Continuity {
    pub fn new() -> Self {
        Self {
            sequence: 0,
            bytes: 0,
            process: None,
            config: None,
            observed_ns: 0,
            generation: 0,
            terminal: false,
        }
    }
    /// Validates each raw record before advancing. Refusal preserves old state.
    pub fn admit(&mut self, raw: &[u8], profile: &Profile) -> Result<Metadata, Error> {
        let m = parse(raw, profile)?;
        let bytes = self.bytes.checked_add(raw.len()).ok_or(Error::Limit)?;
        if bytes > MAX_CAPTURE_BYTES {
            return Err(Error::Limit);
        }
        let mut process = m.process.clone();
        process.execution_generation = 0;
        let generation = self.generation + u64::from(matches!(m.operation, Operation::Exec));
        if self.terminal
            || m.native.sequence != self.sequence + 1
            || m.observed_ns < self.observed_ns
            || self.process.as_ref().is_some_and(|p| p != &process)
            || self.config.is_some_and(|c| c != m.config_sha256)
            || m.process.execution_generation != generation
            || m.operation
                .interval()
                .is_some_and(|i| i.entry_ns < self.observed_ns)
        {
            return Err(Error::Continuity);
        }
        self.sequence = m.native.sequence;
        self.bytes = bytes;
        self.process = Some(process);
        self.config = Some(m.config_sha256);
        self.observed_ns = m.observed_ns;
        self.generation = generation;
        self.terminal = matches!(m.operation, Operation::End { .. } | Operation::Gap { .. });
        Ok(m)
    }
}

pub fn normalize(
    raw: &[u8],
    profile: &Profile,
    source: Source,
    id: Uuid,
    observed_at: DateTime<Utc>,
) -> Result<SignalEvent, Error> {
    let source_text = |s: &str| {
        !s.is_empty() && s.len() <= 256 && s.trim() == s && !s.chars().any(char::is_control)
    };
    if id.is_nil()
        || !source_text(&source.source_type)
        || source.name.as_deref().is_some_and(|s| !source_text(s))
        || !(1..=9999).contains(&observed_at.year())
        || observed_at.timestamp_subsec_nanos() >= 1_000_000_000
    {
        return Err(Error::Record);
    }
    let metadata = parse(raw, profile)?;
    let timestamp = DateTime::<Utc>::from_timestamp(
        (metadata.observed_ns / 1_000_000_000) as i64,
        (metadata.observed_ns % 1_000_000_000) as u32,
    )
    .ok_or(Error::Record)?;
    let input: IngestEvent = serde_json::from_value(serde_json::json!({"timestamp":timestamp,"source":source,"severity":"info", "message":"Owned runtime metadata observed", "resource":{"kind":"host","id":profile.host}, "attributes":{"runtime_metadata":metadata,"evidence":{"profile":PROFILE,"runtime_sensor_coverage":"not_assessed","policy_classification":"private"}}})).map_err(|_| Error::Record)?;
    let mut event = input.normalize(observed_at).map_err(|_| Error::Record)?;
    event.id = id;
    Ok(event)
}
