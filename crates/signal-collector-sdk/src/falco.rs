//! Selected Falco syscall metadata projection; private host owns kernel capture,
//! source binding, protected originals and independent sensor coverage.
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map, Value};
use signal_event::{IngestEvent, SignalEvent, Source};
use thiserror::Error;
use uuid::Uuid;
pub const PINNED_SENSOR_VERSION: &str = "0.44.1";
pub const MAX_RECORD_BYTES: usize = 65536;
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid Falco runtime profile configuration")]
    Configuration,
    #[error("invalid selected Falco runtime record")]
    Record,
    #[error("Falco runtime record or field limit")]
    Limit,
}
/// Configuration is a trusted private binding, never derived from record host
/// names. This value does not establish kernel capabilities or capture health.
pub struct Profile {
    host: String,
    boot: Uuid,
}
impl Profile {
    pub fn new(host: &str, boot: Uuid) -> Result<Self, Error> {
        if !identity(host) || boot.is_nil() {
            return Err(Error::Configuration);
        }
        Ok(Self {
            host: host.into(),
            boot,
        })
    }
}
fn identity(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.trim() == s && !s.chars().any(char::is_control)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    source: String,
    time: DateTime<Utc>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    rule: Option<String>,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(deserialize_with = "unique_fields")]
    output_fields: Map<String, Value>,
}
fn unique_fields<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Map<String, Value>, D::Error> {
    struct Fields;
    impl<'de> serde::de::Visitor<'de> for Fields {
        type Value = Map<String, Value>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("unique bounded Falco fields")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut a: A,
        ) -> Result<Self::Value, A::Error> {
            let mut fields = Map::new();
            while let Some(key) = a.next_key::<String>()? {
                if fields.len() >= 256 || fields.contains_key(&key) {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive Falco fields",
                    ));
                }
                fields.insert(key, a.next_value()?);
            }
            Ok(fields)
        }
    }
    d.deserialize_map(Fields)
}
fn number(f: &Map<String, Value>, key: &str) -> Result<u64, Error> {
    f.get(key).and_then(Value::as_u64).ok_or(Error::Record)
}
fn text<'a>(f: &'a Map<String, Value>, key: &str) -> Result<&'a str, Error> {
    f.get(key)
        .and_then(Value::as_str)
        .filter(|s| identity(s))
        .ok_or(Error::Record)
}
fn record(raw: &[u8]) -> Result<Record, Error> {
    if raw.len() > MAX_RECORD_BYTES {
        return Err(Error::Limit);
    }
    let r: Record = serde_json::from_slice(raw).map_err(|_| Error::Record)?;
    if r.output_fields.len() > 256
        || r.tags.len() > 16
        || r.tags.iter().any(|s| !identity(s))
        || [&r.hostname, &r.rule, &r.priority]
            .iter()
            .any(|s| s.as_ref().is_some_and(|s| !identity(s)))
    {
        return Err(Error::Limit);
    }
    Ok(r)
}
/// Strict metadata-only input: configure Falco json_include_output_property=false
/// and emit exactly the selected fields. No command lines, env, read buffers,
/// freeform output or policy priorities are copied or accepted.
pub fn normalize_syscall(
    raw: &[u8],
    profile: &Profile,
    source: Source,
    id: Uuid,
    observed_at: DateTime<Utc>,
) -> Result<SignalEvent, Error> {
    let r = record(raw)?;
    let f = &r.output_fields;
    if r.source != "syscall" || id.is_nil() {
        return Err(Error::Record);
    }
    let allowed = [
        "evt.num",
        "evt.rawtime",
        "evt.type",
        "evt.rawres",
        "evt.is_open_read",
        "proc.pid",
        "proc.pid.ts",
        "proc.ppid",
        "proc.ppid.ts",
        "proc.exepath",
        "fd.name",
        "fd.sip",
        "fd.sport",
    ];
    if f.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(Error::Record);
    }
    let sequence = number(f, "evt.num")?;
    let nanos = number(f, "evt.rawtime")?;
    let seconds = i64::try_from(nanos / 1_000_000_000).map_err(|_| Error::Record)?;
    let timestamp = DateTime::<Utc>::from_timestamp(seconds, (nanos % 1_000_000_000) as u32)
        .ok_or(Error::Record)?;
    if r.time != timestamp {
        return Err(Error::Record);
    }
    let pid = number(f, "proc.pid")?;
    let start = number(f, "proc.pid.ts")?;
    let ppid = number(f, "proc.ppid")?;
    let parent_start = number(f, "proc.ppid.ts")?;
    if pid == 0
        || pid > i32::MAX as u64
        || ppid == 0
        || ppid > i32::MAX as u64
        || start == 0
        || start > nanos
        || parent_start == 0
        || parent_start > start
    {
        return Err(Error::Record);
    }
    let executable = text(f, "proc.exepath")?;
    let result = f
        .get("evt.rawres")
        .and_then(Value::as_i64)
        .ok_or(Error::Record)?;
    let operation = text(f, "evt.type")?;
    let (kind, detail) = match operation {
        "execve" | "execveat" => {
            if f.contains_key("fd.name")
                || f.contains_key("fd.sip")
                || f.contains_key("fd.sport")
                || f.contains_key("evt.is_open_read")
            {
                return Err(Error::Record);
            }
            ("execution", serde_json::json!({"executable":executable}))
        }
        "open" | "openat" | "openat2" => {
            if f.contains_key("fd.sip") || f.contains_key("fd.sport") {
                return Err(Error::Record);
            }
            let path = text(f, "fd.name")?;
            let read = f
                .get("evt.is_open_read")
                .and_then(Value::as_bool)
                .ok_or(Error::Record)?;
            if !path.starts_with('/') {
                return Err(Error::Record);
            }
            // A successful read-capable open is access evidence, not proof that
            // credential material was read. No read/pread buffer capture.
            (
                "file_open",
                serde_json::json!({"path":path,"read_capable":read,"contents_captured":false,"actual_read":"not_assessed"}),
            )
        }
        "connect" => {
            if f.contains_key("fd.name") || f.contains_key("evt.is_open_read") {
                return Err(Error::Record);
            }
            let ip: std::net::IpAddr = text(f, "fd.sip")?.parse().map_err(|_| Error::Record)?;
            let port = number(f, "fd.sport")?;
            if port == 0 || port > u16::MAX as u64 {
                return Err(Error::Record);
            }
            (
                "connection",
                serde_json::json!({"destination_ip":ip.to_string(),"destination_port":port}),
            )
        }
        _ => return Err(Error::Record),
    };
    let input:IngestEvent=serde_json::from_value(serde_json::json!({"timestamp":timestamp,"source":source,"severity":"info","message":format!("Runtime {kind} observed"),"resource":{"kind":"host","id":profile.host},"attributes":{"runtime":{"kind":kind,"syscall":operation,"outcome":if result>=0{"success"}else{"failure"},"return_value":result,"detail":detail},"process":{"host_id":profile.host,"boot_id":profile.boot,"pid":pid,"start_epoch_ns":start,"parent_pid":ppid,"parent_start_epoch_ns":parent_start,"executable":executable},"producer":{"sequence":sequence,"sequence_basis":"falco_capture_event_number","dropped_events":"requires_metrics_stream"},"evidence":{"profile":"falco-syscall-metadata-v1","runtime_sensor_coverage":"not_assessed","policy_classification":"private"}}})).map_err(|_|Error::Record)?;
    let mut event = input.normalize(observed_at).map_err(|_| Error::Record)?;
    event.id = id;
    Ok(event)
}
/// Native sensor-side counters are assertions, not independent coverage evidence.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    pub schema_version: u16,
    pub timestamp: DateTime<Utc>,
    pub sensor_start_epoch_ns: u64,
    pub reload_epoch_ns: u64,
    pub host_boot_epoch_ns: u64,
    pub captured_events: u64,
    pub kernel_drops: u64,
    pub output_queue_drops: u64,
    pub failed_fd_lookups: u64,
    pub failed_thread_lookups: u64,
    pub full_threadtable_drops: u64,
    pub store_event_drops: u64,
    pub retrieve_event_drops: u64,
    pub engine: String,
    pub version: String,
}
/// Strict selected internal metrics. Unknown native metric fields are omitted;
/// freeform output is refused. Counters never default to zero when missing.
pub fn parse_metrics(raw: &[u8]) -> Result<Metrics, Error> {
    let r = record(raw)?;
    let f = &r.output_fields;
    if r.source != "internal"
        || r.rule.as_deref() != Some("Falco internal: metrics snapshot")
        || text(f, "evt.source")? != "syscall"
        || text(f, "scap.engine_name")? != "modern_bpf"
        || text(f, "falco.version")? != PINNED_SENSOR_VERSION
    {
        return Err(Error::Record);
    }
    let nanos = number(f, "evt.time")?;
    if r.time
        .timestamp_nanos_opt()
        .and_then(|n| u64::try_from(n).ok())
        != Some(nanos)
    {
        return Err(Error::Record);
    }
    let start = number(f, "falco.start_ts")?;
    let reload = number(f, "falco.reload_ts")?;
    let boot = number(f, "falco.host_boot_ts")?;
    if boot == 0 || start < boot || reload < start || reload > nanos {
        return Err(Error::Record);
    }
    Ok(Metrics {
        schema_version: 1,
        timestamp: r.time,
        sensor_start_epoch_ns: start,
        reload_epoch_ns: reload,
        host_boot_epoch_ns: boot,
        captured_events: number(f, "scap.n_evts")?,
        kernel_drops: number(f, "scap.n_drops")?,
        output_queue_drops: number(f, "falco.outputs_queue_num_drops")?,
        failed_fd_lookups: number(f, "falco.n_failed_fd_lookups")?,
        failed_thread_lookups: number(f, "falco.n_failed_thread_lookups")?,
        full_threadtable_drops: number(f, "falco.n_drops_full_threadtable")?,
        store_event_drops: number(f, "falco.n_store_evts_drops")?,
        retrieve_event_drops: number(f, "falco.n_retrieve_evts_drops")?,
        engine: "modern_bpf".into(),
        version: text(f, "falco.version")?.into(),
    })
}

/// Normalize the selected native health stream without granting current coverage.
pub fn normalize_metrics(
    raw: &[u8],
    profile: &Profile,
    source: Source,
    id: Uuid,
    observed_at: DateTime<Utc>,
) -> Result<SignalEvent, Error> {
    if id.is_nil() {
        return Err(Error::Record);
    }
    let metrics = parse_metrics(raw)?;
    let input:IngestEvent=serde_json::from_value(serde_json::json!({
        "timestamp":metrics.timestamp,"source":source,"severity":"info",
        "message":"Runtime sensor counters observed",
        "resource":{"kind":"host","id":profile.host},
        "attributes":{"sensor_health":metrics,"producer":{"boot_id":profile.boot},
        "evidence":{"profile":"falco-sensor-metrics-v1","runtime_sensor_coverage":"not_assessed","scope_basis":"configured_private_sensor_route"}}
    })).map_err(|_|Error::Record)?;
    let mut event = input.normalize(observed_at).map_err(|_| Error::Record)?;
    event.id = id;
    Ok(event)
}
