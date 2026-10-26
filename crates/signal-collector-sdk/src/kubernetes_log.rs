//! Selected CRI physical records. The host owns rooted file custody, metadata
//! authority, durable source positions and original event pins.
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use signal_event::{SCHEMA_VERSION, Severity, SignalEvent, Source};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// Includes worst-case JSON escaping or binary base64 expansion and metadata.
pub const MAX_EVENT_BYTES: usize = 512 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum Error {
    #[error("invalid Kubernetes node log source configuration")]
    Configuration,
    #[error("invalid or oversized complete CRI physical record")]
    Record,
}
fn identity(v: &str) -> bool {
    !v.is_empty() && v.len() <= 256 && v.trim() == v && !v.chars().any(char::is_control)
}
fn label(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 63
        && v.as_bytes()[0].is_ascii_alphanumeric()
        && v.as_bytes()[v.len() - 1].is_ascii_alphanumeric()
        && v.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn pod_name(v: &str) -> bool {
    v.len() <= 253 && v.split('.').all(label)
}
/// Relative source identity from a trusted rooted /var/log/pods traversal.
/// Deserialization alone is not validation; all consumers must call validate.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogIdentity {
    pub schema_version: u16,
    pub namespace: String,
    pub pod_name: String,
    /// Opaque kubelet directory UID; not necessarily the API mirror Pod UID.
    pub runtime_pod_uid: String,
    pub container: String,
    pub restart_count: u32,
}
impl LogIdentity {
    pub fn from_relative(
        pod_directory: &str,
        container: &str,
        log_file: &str,
    ) -> Result<Self, Error> {
        if pod_directory.len() > 255 || container.len() > 63 || log_file.len() > 14 {
            return Err(Error::Configuration);
        }
        let mut parts = pod_directory.splitn(3, '_');
        let namespace = parts.next().ok_or(Error::Configuration)?;
        let pod_name = parts.next().ok_or(Error::Configuration)?;
        let pod_uid = parts.next().ok_or(Error::Configuration)?;
        if parts.next().is_some() {
            return Err(Error::Configuration);
        }
        let count = log_file.strip_suffix(".log").ok_or(Error::Configuration)?;
        let restart_count = count.parse::<u32>().map_err(|_| Error::Configuration)?;
        if restart_count.to_string() != count {
            return Err(Error::Configuration);
        }
        let result = Self {
            schema_version: 1,
            namespace: namespace.into(),
            pod_name: pod_name.into(),
            runtime_pod_uid: pod_uid.into(),
            container: container.into(),
            restart_count,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || !label(&self.namespace)
            || !pod_name(&self.pod_name)
            || !label(&self.container)
        {
            return Err(Error::Configuration);
        }
        let uid = &self.runtime_pod_uid;
        if uid.is_empty()
            || uid.len() > 128
            || uid == "."
            || uid == ".."
            || !uid
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'/' && b != b'\\')
            || self.namespace.len() + self.pod_name.len() + uid.len() + 2 > 255
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    pub fn relative_components(&self) -> Result<[String; 3], Error> {
        self.validate()?;
        Ok([
            format!(
                "{}_{}_{}",
                self.namespace, self.pod_name, self.runtime_pod_uid
            ),
            self.container.clone(),
            format!("{}.log", self.restart_count),
        ])
    }
}
/// Cluster and node are supplied by deployment configuration, never log payload.
#[derive(Clone)]
pub struct Profile {
    cluster: String,
    node: String,
}
impl Profile {
    pub fn new(cluster: &str, node: &str) -> Result<Self, Error> {
        if !identity(cluster) || !pod_name(node) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            cluster: cluster.into(),
            node: node.into(),
        })
    }
    pub fn cluster(&self) -> &str {
        &self.cluster
    }
    pub fn node(&self) -> &str {
        &self.node
    }
}
struct EventLimit {
    bytes: usize,
}
impl std::io::Write for EventLimit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.saturating_add(bytes.len());
        if self.bytes > MAX_EVENT_BYTES {
            return Err(std::io::Error::other("CRI canonical byte limit"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Normalize exactly one LF-terminated native CRI record. Every P/F record is a
/// separate event, explicitly labelled physical framing. There is no volatile
/// partial assembly: interleaved streams and split UTF8 preserve their bytes.
/// The host must atomically admit this event and its physical cursor; replay
/// reuses the original ID and observed_at. This function allocates neither.
pub fn normalize_record(
    raw: &[u8],
    profile: &Profile,
    source: &LogIdentity,
    id: Uuid,
    observed_at: DateTime<Utc>,
) -> Result<SignalEvent, Error> {
    source.validate()?;
    if id.is_nil()
        || !(1..=9999).contains(&observed_at.year())
        || observed_at.timestamp_subsec_nanos() >= 1_000_000_000
        || raw.len() > MAX_RECORD_BYTES
    {
        return Err(Error::Record);
    }
    let line = raw.strip_suffix(b"\n").ok_or(Error::Record)?;
    if line.contains(&b'\n') {
        return Err(Error::Record);
    }
    let mut fields = line.splitn(4, |b| *b == b' ');
    let timestamp = fields.next().ok_or(Error::Record)?;
    if timestamp.len() > 64 {
        return Err(Error::Record);
    }
    let original_timestamp = std::str::from_utf8(timestamp).map_err(|_| Error::Record)?;
    let timestamp = DateTime::parse_from_rfc3339(original_timestamp)
        .map_err(|_| Error::Record)?
        .with_timezone(&Utc);
    if !(1..=9999).contains(&timestamp.year())
        || timestamp.timestamp_subsec_nanos() >= 1_000_000_000
    {
        return Err(Error::Record);
    }
    let stream = match fields.next() {
        Some(b"stdout") => "stdout",
        Some(b"stderr") => "stderr",
        _ => return Err(Error::Record),
    };
    let tag = match fields.next() {
        Some(b"P") => "P",
        Some(b"F") => "F",
        _ => return Err(Error::Record),
    };
    let payload = fields.next().ok_or(Error::Record)?;
    let (message, encoding, encoded) = match std::str::from_utf8(payload) {
        Ok(text) => (Some(text.to_owned()), "utf8", None),
        Err(_) => (None, "base64", Some(STANDARD.encode(payload))),
    };
    let sha256: String = Sha256::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let attributes=json!({"kubernetes":{"schema_version":1,"cluster_id":profile.cluster,"node_name":profile.node,"namespace":source.namespace,"pod":{"name":source.pod_name,"runtime_uid":source.runtime_pod_uid},"container":{"name":source.container,"restart_count":source.restart_count}},
        "log":{"schema_version":1,"framing":"cri_physical_record","stream":stream,"tag":tag,"timestamp_original":original_timestamp,"payload_encoding":encoding,"payload_base64":encoded,"original_sha256":sha256}}).as_object().ok_or(Error::Record)?.clone();
    let event = SignalEvent {
        schema_version: SCHEMA_VERSION,
        id,
        timestamp,
        observed_at,
        source: Source {
            source_type: "kubernetes.container".into(),
            name: Some(profile.cluster.clone()),
        },
        severity: Severity::Info,
        message,
        attributes,
        resource: None,
        trace_id: None,
        span_id: None,
        tags: vec![],
    };
    serde_json::to_writer(EventLimit { bytes: 0 }, &event).map_err(|_| Error::Record)?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn source() -> LogIdentity {
        LogIdentity::from_relative(
            "team_workload_00000000-0000-4000-8000-000000000001",
            "main",
            "2.log",
        )
        .unwrap()
    }
    fn normalize(raw: &[u8]) -> Result<SignalEvent, Error> {
        normalize_record(
            raw,
            &Profile::new("cluster", "node-a").unwrap(),
            &source(),
            Uuid::from_u128(5),
            DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        )
    }
    #[test]
    fn native_timestamp_stream_fragment_and_payload_are_exact() {
        let raw = b"2026-10-25T10:12:13.123456789Z stderr P  spaces\r\n";
        let e = normalize(raw).unwrap();
        assert_eq!(
            e.timestamp.to_rfc3339(),
            "2026-10-25T10:12:13.123456789+00:00"
        );
        assert_eq!(e.message.as_deref(), Some(" spaces\r"));
        assert_eq!(e.attributes["log"]["stream"], "stderr");
        assert_eq!(e.attributes["log"]["tag"], "P");
        assert_eq!(e.attributes["log"]["framing"], "cri_physical_record");
        assert_eq!(e.attributes["kubernetes"]["container"]["restart_count"], 2);
        assert_eq!(
            serde_json::to_vec(&e).unwrap(),
            serde_json::to_vec(&normalize(raw).unwrap()).unwrap()
        );
    }
    #[test]
    fn interleaved_partial_records_never_require_volatile_assembly() {
        let a = normalize(b"2026-10-25T10:12:13Z stdout P prefix\n").unwrap();
        let b = normalize(b"2026-10-25T10:12:14Z stderr F independent\n").unwrap();
        let c = normalize(b"2026-10-25T10:12:15Z stdout F suffix\n").unwrap();
        assert_eq!(a.message.as_deref(), Some("prefix"));
        assert_eq!(b.message.as_deref(), Some("independent"));
        assert_eq!(c.message.as_deref(), Some("suffix"));
        assert_eq!(c.attributes["log"]["tag"], "F");
    }
    #[test]
    fn split_utf8_and_binary_payload_are_lossless() {
        for payload in [vec![0xf0, 0x9f], vec![0x98, 0x80], vec![0, 255, 13]] {
            let mut raw = b"2026-10-25T10:12:13Z stdout P ".to_vec();
            raw.extend(&payload);
            raw.push(b'\n');
            let e = normalize(&raw).unwrap();
            assert!(e.message.is_none() || std::str::from_utf8(&payload).is_ok());
            assert_eq!(e.attributes["log"]["payload_encoding"], "base64");
            assert_eq!(
                STANDARD
                    .decode(e.attributes["log"]["payload_base64"].as_str().unwrap())
                    .unwrap(),
                payload
            );
        }
    }
    #[test]
    fn bad_headers_truncation_multiple_lines_and_limits_refuse() {
        for raw in [
            b"2026-10-25T10:12:13Z stdout F missing newline".as_slice(),
            b"bad stdout F message\n",
            b"2026-10-25T10:12:13Z other F message\n",
            b"2026-10-25T10:12:13Z stdout X message\n",
            b"2026-10-25T10:12:13Z stdout F a\nb\n",
            b"2026-10-25T10:12:13Z stdout F\n",
        ] {
            assert_eq!(normalize(raw).unwrap_err(), Error::Record);
        }
        assert_eq!(
            normalize(&vec![b'x'; MAX_RECORD_BYTES + 1]).unwrap_err(),
            Error::Record
        );
        assert_eq!(
            normalize(b"2026-10-25T10:12:13Z stdout F \n")
                .unwrap()
                .message
                .as_deref(),
            Some("")
        );
    }
    #[test]
    fn relative_identity_is_canonical_and_never_a_path_escape() {
        let s = source();
        assert_eq!(s.relative_components().unwrap()[2], "2.log");
        for (pod, container, file) in [
            (
                "team_../escape_00000000-0000-4000-8000-000000000001",
                "main",
                "0.log",
            ),
            ("team_workload_../escape", "main", "0.log"),
            (
                "team_workload_00000000-0000-4000-8000-000000000001",
                "../main",
                "0.log",
            ),
            (
                "team_workload_00000000-0000-4000-8000-000000000001",
                "main",
                "00.log",
            ),
            (
                "team_workload_00000000-0000-4000-8000-000000000001",
                "main",
                "0.log.old",
            ),
        ] {
            assert!(LogIdentity::from_relative(pod, container, file).is_err());
        }
        let mut forged = s;
        forged.container = "escape/path".into();
        assert!(
            normalize_record(
                b"2026-10-25T10:12:13Z stdout F x\n",
                &Profile::new("cluster", "node").unwrap(),
                &forged,
                Uuid::from_u128(5),
                Utc::now()
            )
            .is_err()
        );
    }
    #[test]
    fn maximum_native_binary_and_json_escaping_fit_explicit_canonical_budget() {
        for byte in [0xff, 0, b'"', b'\\'] {
            let mut raw = b"2026-10-25T10:12:13Z stdout P ".to_vec();
            raw.resize(MAX_RECORD_BYTES - 1, byte);
            raw.push(b'\n');
            let e = normalize(&raw).unwrap();
            let canonical = serde_json::to_vec(&e).unwrap();
            assert!(canonical.len() <= MAX_EVENT_BYTES);
            assert!(canonical.len() > MAX_RECORD_BYTES);
            if byte == 0xff {
                assert_eq!(
                    STANDARD
                        .decode(e.attributes["log"]["payload_base64"].as_str().unwrap())
                        .unwrap()
                        .len(),
                    MAX_RECORD_BYTES - b"2026-10-25T10:12:13Z stdout P ".len() - 1
                );
            }
        }
    }
    #[test]
    fn runtime_uid_is_opaque_and_not_an_api_identity_grant() {
        for uid in [
            "a1234567890abcdef1234567890abcdef",
            "00000000-0000-4000-8000-000000000001",
            "opaque_runtime:uid",
        ] {
            let source =
                LogIdentity::from_relative(&format!("team_workload_{uid}"), "main", "0.log")
                    .unwrap();
            let e = normalize_record(
                b"2026-10-25T10:12:13Z stdout F x\n",
                &Profile::new("cluster", "node").unwrap(),
                &source,
                Uuid::from_u128(5),
                Utc::now(),
            )
            .unwrap();
            assert_eq!(e.attributes["kubernetes"]["pod"]["runtime_uid"], uid);
            assert!(e.attributes["kubernetes"]["pod"].get("uid").is_none());
        }
        assert!(LogIdentity::from_relative(&"x".repeat(256), "main", "0.log").is_err());
        assert!(
            LogIdentity::from_relative(&format!("team_{}_uid", "x".repeat(250)), "main", "0.log")
                .is_err()
        );
        let mut forged = source();
        forged.schema_version = 2;
        assert!(forged.validate().is_err());
    }
    #[test]
    fn timestamps_reject_leap_seconds_invalid_pins_and_utc_year_escape() {
        assert!(normalize(b"2016-12-31T23:59:60Z stdout F leap\n").is_err());
        let leap = DateTime::from_timestamp(1_483_228_799, 1_000_000_000).unwrap();
        assert!(
            normalize_record(
                b"2026-10-25T10:12:13Z stdout F x\n",
                &Profile::new("cluster", "node").unwrap(),
                &source(),
                Uuid::from_u128(5),
                leap
            )
            .is_err()
        );
        let e = normalize(b"2026-10-25T11:12:13+01:00 stdout F x\n").unwrap();
        assert_eq!(e.timestamp.to_rfc3339(), "2026-10-25T10:12:13+00:00");
        assert!(normalize(b"0001-01-01T00:00:00+01:00 stdout F x\n").is_err());
        assert!(
            normalize_record(
                b"2026-10-25T10:12:13Z stdout F x\n",
                &Profile::new("cluster", "node").unwrap(),
                &source(),
                Uuid::nil(),
                Utc::now()
            )
            .is_err()
        );
    }
}
