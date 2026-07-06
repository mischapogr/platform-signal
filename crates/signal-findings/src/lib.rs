//! Versioned deterministic findings and bounded durable journal persistence.
mod store;
pub use store::*;

use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use signal_event::SignalEvent;
use uuid::Uuid;

pub const SCHEMA_VERSION: u16 = 1;
/// Detection severity is independent of event log severity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema_version: u16,
    pub id: Uuid,
    pub rule_id: String,
    pub created_at: DateTime<Utc>,
    pub severity: DetectionSeverity,
    pub title: String,
    pub event_ids: Vec<Uuid>,
    pub attributes: Map<String, Value>,
}
impl Finding {
    /// Stable identity and observed time make repeated WAL evaluation identical.
    pub fn for_event(
        rule_id: &str,
        event: &SignalEvent,
        severity: DetectionSeverity,
        title: &str,
    ) -> Result<Self, FindingError> {
        event
            .validate()
            .map_err(|_| FindingError::Invalid("event"))?;
        if title.len() > 4096 || title.trim().is_empty() {
            return Err(FindingError::Invalid("title"));
        }
        if rule_id.len() > 256 || rule_id.trim().is_empty() {
            return Err(FindingError::Invalid("rule_id"));
        }
        // Fixed public namespace, then length-prefixed UTF-8 rule ID and raw event UUID.
        let namespace = Uuid::from_bytes(*b"SIGNAL-FINDING01");
        let mut name = Vec::with_capacity(8 + rule_id.len() + 16);
        name.extend_from_slice(&(rule_id.len() as u64).to_be_bytes());
        name.extend_from_slice(rule_id.as_bytes());
        name.extend_from_slice(event.id.as_bytes());
        let result = Self {
            schema_version: SCHEMA_VERSION,
            id: Uuid::new_v5(&namespace, &name),
            rule_id: rule_id.into(),
            created_at: event.observed_at,
            severity,
            title: title.into(),
            event_ids: vec![event.id],
            attributes: Map::new(),
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(FindingError::Invalid("schema_version"));
        }
        if self.id.is_nil() {
            return Err(FindingError::Invalid("id"));
        }
        if self.rule_id.len() > 256 || self.rule_id.trim().is_empty() {
            return Err(FindingError::Invalid("rule_id"));
        }
        if self.title.len() > 4096 || self.title.trim().is_empty() {
            return Err(FindingError::Invalid("title"));
        }
        if self.event_ids.is_empty()
            || self.event_ids.len() > 1000
            || self.event_ids.iter().any(Uuid::is_nil)
        {
            return Err(FindingError::Invalid("event_ids"));
        }
        if !(0..=9999).contains(&self.created_at.year()) {
            return Err(FindingError::Invalid("created_at"));
        }
        let mut nodes = 0;
        for (key, value) in &self.attributes {
            if key.len() > 65536 {
                return Err(FindingError::Invalid("attribute key"));
            }
            check_value(value, 1, &mut nodes)?;
        }
        let mut counter = BoundedWriter {
            bytes: 0,
            limit: 65536,
            data: None,
        };
        serde_json::to_writer(&mut counter, self)
            .map_err(|_| FindingError::Invalid("record size"))?;
        Ok(())
    }
}

fn check_value(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), FindingError> {
    *nodes += 1;
    if depth > 32 || *nodes > 4096 {
        return Err(FindingError::Invalid("attribute complexity"));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                check_value(value, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if key.len() > 65536 {
                    return Err(FindingError::Invalid("attribute key"));
                }
                check_value(value, depth + 1, nodes)?;
            }
        }
        Value::String(value) if value.len() > 65536 => {
            return Err(FindingError::Invalid("attribute size"));
        }
        _ => {}
    }
    Ok(())
}
struct BoundedWriter {
    bytes: usize,
    limit: usize,
    data: Option<Vec<u8>>,
}
impl std::io::Write for BoundedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let size = self
            .bytes
            .checked_add(data.len())
            .ok_or_else(|| std::io::Error::other("record size"))?;
        if size > self.limit {
            return Err(std::io::Error::other("record size"));
        }
        if let Some(out) = &mut self.data {
            out.extend_from_slice(data);
        }
        self.bytes = size;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode(finding: &Finding, limit: usize) -> Result<Vec<u8>, FindingError> {
    let mut writer = BoundedWriter {
        bytes: 0,
        limit,
        data: Some(Vec::new()),
    };
    serde_json::to_writer(&mut writer, finding).map_err(|_| FindingError::Quota)?;
    writer.data.ok_or(FindingError::Invalid("serialization"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        io::{Seek, SeekFrom, Write},
        time::Duration,
    };
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn context() -> FindingContext {
        FindingContext::new(Duration::from_secs(2))
    }
    fn event() -> Result<SignalEvent, Box<dyn std::error::Error>> {
        Ok(serde_json::from_str::<signal_event::IngestEvent>(
            r#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"app"},"message":"hello"}"#,
        )?
        .normalize("2026-10-06T12:01:00Z".parse()?)?)
    }
    fn config(directory: &std::path::Path) -> FindingConfig {
        FindingConfig {
            directory: directory.into(),
            ..Default::default()
        }
    }
    fn finding(rule: &str) -> Result<Finding, Box<dyn std::error::Error>> {
        Ok(Finding::for_event(
            rule,
            &event()?,
            DetectionSeverity::High,
            "Detection",
        )?)
    }
    #[test]
    fn deterministic_contract_and_validation() -> TestResult {
        let e = event()?;
        let a = Finding::for_event("rule", &e, DetectionSeverity::High, "Title")?;
        assert_eq!(
            a,
            Finding::for_event("rule", &e, DetectionSeverity::High, "Title")?
        );
        assert_ne!(
            a.id,
            Finding::for_event("rule2", &e, DetectionSeverity::High, "Title")?.id
        );
        assert_eq!(a.created_at, e.observed_at);
        let mut value = serde_json::to_value(&a)?;
        value["unexpected"] = Value::Bool(true);
        assert!(serde_json::from_value::<Finding>(value).is_err());
        assert!(Finding::for_event("", &e, DetectionSeverity::High, "Title").is_err());
        assert!(Finding::for_event("rule", &e, DetectionSeverity::High, " ").is_err());
        Ok(())
    }
    #[test]
    fn attribute_limits_and_canonical_event_times() -> TestResult {
        let mut f = finding("a")?;
        f.attributes
            .insert("large".into(), Value::String("x".repeat(65537)));
        assert!(f.validate().is_err());
        f.attributes.clear();
        let mut deep = Value::Null;
        for _ in 0..33 {
            deep = Value::Array(vec![deep]);
        }
        f.attributes.insert("deep".into(), deep);
        assert!(f.validate().is_err());
        f.attributes.clear();
        f.attributes
            .insert("wide".into(), Value::Array(vec![Value::Null; 4097]));
        assert!(f.validate().is_err());
        let mut e = event()?;
        for time in ["0000-01-01T00:00:00Z", "2016-12-31T23:59:60Z"] {
            e.observed_at = time.parse()?;
            let f = Finding::for_event("a", &e, DetectionSeverity::High, "Title")?;
            assert_eq!(f.created_at, e.observed_at);
            assert_eq!(serde_json::from_slice::<Finding>(&encode(&f, 65536)?)?, f);
        }
        Ok(())
    }
    #[tokio::test]
    async fn replay_restart_and_conflict() -> TestResult {
        let temp = tempfile::tempdir()?;
        let cfg = config(temp.path());
        let stream = Uuid::new_v4();
        let f = finding("a")?;
        let store = FindingStore::open(cfg.clone(), stream).await?;
        assert_eq!(
            store.append(vec![f.clone(), f.clone()], context()).await?,
            FindingReceipt {
                inserted: 1,
                duplicates: 1
            }
        );
        let mut conflict = f.clone();
        conflict.title = "Changed".into();
        assert!(matches!(
            store.append(vec![conflict], context()).await,
            Err(FindingError::Conflict)
        ));
        assert_eq!(store.metrics().findings, 1);
        assert!(matches!(
            FindingStore::open(cfg.clone(), stream).await,
            Err(FindingError::Locked)
        ));
        store.shutdown(context()).await?;
        let reopened = FindingStore::open(cfg.clone(), stream).await?;
        assert_eq!(
            reopened
                .append(vec![f.clone()], context())
                .await?
                .duplicates,
            1
        );
        assert_eq!(
            reopened
                .query(
                    FindingQuery {
                        limit: 10,
                        ..Default::default()
                    },
                    context()
                )
                .await?,
            vec![f]
        );
        reopened.shutdown(context()).await?;
        assert!(matches!(
            FindingStore::open(cfg, Uuid::new_v4()).await,
            Err(FindingError::StreamMismatch)
        ));
        Ok(())
    }
    #[tokio::test]
    async fn bounded_query_filters_and_order() -> TestResult {
        let temp = tempfile::tempdir()?;
        let store = FindingStore::open(config(temp.path()), Uuid::new_v4()).await?;
        let mut a = finding("a")?;
        let mut b = finding("b")?;
        let mut c = finding("a")?;
        a.created_at = "2026-10-06T12:00:00Z".parse()?;
        b.created_at = "2026-10-06T13:00:00Z".parse()?;
        c.created_at = "2026-10-06T14:00:00Z".parse()?;
        b.severity = DetectionSeverity::Low;
        store
            .append(vec![c.clone(), b.clone(), a.clone()], context())
            .await?;
        let result = store
            .query(
                FindingQuery {
                    from: Some(a.created_at),
                    to: Some(c.created_at),
                    limit: 10,
                    ..Default::default()
                },
                context(),
            )
            .await?;
        assert_eq!(result, vec![a.clone(), b]);
        assert_eq!(
            store
                .query(
                    FindingQuery {
                        severity: Some(DetectionSeverity::High),
                        rule_id: Some("a".into()),
                        limit: 1,
                        ..Default::default()
                    },
                    context()
                )
                .await?,
            vec![a]
        );
        assert!(
            store
                .query(
                    FindingQuery {
                        limit: 1001,
                        ..Default::default()
                    },
                    context()
                )
                .await
                .is_err()
        );
        store.shutdown(context()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn quotas_reject_before_mutation() -> TestResult {
        let temp = tempfile::tempdir()?;
        let mut cfg = config(temp.path());
        cfg.max_findings = 1;
        let store = FindingStore::open(cfg, Uuid::new_v4()).await?;
        let a = finding("a")?;
        store.append(vec![a.clone()], context()).await?;
        let before = fs::metadata(temp.path().join("findings.journal"))?.len();
        assert!(matches!(
            store.append(vec![finding("b")?], context()).await,
            Err(FindingError::Quota)
        ));
        assert_eq!(
            before,
            fs::metadata(temp.path().join("findings.journal"))?.len()
        );
        assert_eq!(store.append(vec![a], context()).await?.duplicates, 1);
        store.shutdown(context()).await?;
        let temp2 = tempfile::tempdir()?;
        let mut cfg = config(temp2.path());
        cfg.max_disk_bytes = 24;
        let store = FindingStore::open(cfg, Uuid::new_v4()).await?;
        assert!(matches!(
            store.append(vec![finding("a")?], context()).await,
            Err(FindingError::Quota)
        ));
        store.shutdown(context()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn unfinished_initial_header_is_recoverable_but_final_header_corruption_is_fatal()
    -> TestResult {
        for length in [0, 1, 8, 23, 24] {
            let temp = tempfile::tempdir()?;
            fs::write(temp.path().join("findings.journal.tmp"), vec![0; length])?;
            let store = FindingStore::open(config(temp.path()), Uuid::new_v4()).await?;
            assert_eq!(store.metrics().disk_bytes, 24);
            assert!(!temp.path().join("findings.journal.tmp").exists());
            store.shutdown(context()).await?;
        }
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("findings.journal"), b"SIG")?;
        assert!(matches!(
            FindingStore::open(config(temp.path()), Uuid::new_v4()).await,
            Err(FindingError::Corrupt(_))
        ));
        assert_eq!(fs::read(temp.path().join("findings.journal"))?, b"SIG");
        Ok(())
    }
    #[tokio::test]
    async fn incomplete_tail_only_is_repaired() -> TestResult {
        for tail in [vec![1, 2, 3], {
            let mut b = 100u32.to_le_bytes().to_vec();
            b.extend_from_slice(&0u32.to_le_bytes());
            let crc = crc32fast::hash(&b);
            b.extend_from_slice(&crc.to_le_bytes());
            b.extend_from_slice(b"partial");
            b
        }] {
            let temp = tempfile::tempdir()?;
            let cfg = config(temp.path());
            let stream = Uuid::new_v4();
            let f = finding("a")?;
            let store = FindingStore::open(cfg.clone(), stream).await?;
            store.append(vec![f.clone()], context()).await?;
            store.shutdown(context()).await?;
            let path = temp.path().join("findings.journal");
            let before = fs::metadata(&path)?.len();
            OpenOptions::new()
                .append(true)
                .open(&path)?
                .write_all(&tail)?;
            let store = FindingStore::open(cfg, stream).await?;
            assert_eq!(store.metrics().disk_bytes, before);
            assert_eq!(store.metrics().findings, 1);
            store.shutdown(context()).await?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn corrupt_committed_length_or_payload_crc_never_truncates() -> TestResult {
        for field in [0usize, 4] {
            let temp = tempfile::tempdir()?;
            let cfg = config(temp.path());
            let stream = Uuid::new_v4();
            let store = FindingStore::open(cfg.clone(), stream).await?;
            store.append(vec![finding("a")?], context()).await?;
            store.shutdown(context()).await?;
            let path = temp.path().join("findings.journal");
            let mut bytes = fs::read(&path)?;
            if field == 0 {
                let length = u32::from_le_bytes(bytes[24..28].try_into()?);
                bytes[24..28].copy_from_slice(&(length + 1).to_le_bytes());
            } else {
                bytes[24 + field] ^= 1;
            }
            fs::write(&path, &bytes)?;
            assert!(matches!(
                FindingStore::open(cfg, stream).await,
                Err(FindingError::Corrupt("frame header checksum"))
            ));
            assert_eq!(fs::read(&path)?, bytes);
        }
        Ok(())
    }
    #[tokio::test]
    async fn checksum_corruption_unknown_paths_fail_closed() -> TestResult {
        let temp = tempfile::tempdir()?;
        let cfg = config(temp.path());
        let stream = Uuid::new_v4();
        let store = FindingStore::open(cfg.clone(), stream).await?;
        store
            .append(vec![finding("a")?, finding("b")?], context())
            .await?;
        store.shutdown(context()).await?;
        let path = temp.path().join("findings.journal");
        let before = fs::metadata(&path)?.len();
        let mut file = OpenOptions::new().write(true).open(&path)?;
        file.seek(SeekFrom::Start(24 + FINDING_FRAME_BYTES as u64))?;
        file.write_all(b"!")?;
        assert!(matches!(
            FindingStore::open(cfg, stream).await,
            Err(FindingError::Corrupt(_))
        ));
        assert_eq!(fs::metadata(&path)?.len(), before);
        let other = tempfile::tempdir()?;
        fs::write(other.path().join("unknown"), b"x")?;
        assert!(matches!(
            FindingStore::open(config(other.path()), stream).await,
            Err(FindingError::Corrupt(_))
        ));
        Ok(())
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_are_rejected() -> TestResult {
        let temp = tempfile::tempdir()?;
        let dest = tempfile::tempdir()?;
        std::os::unix::fs::symlink(dest.path(), temp.path().join("root"))?;
        assert!(matches!(
            FindingStore::open(config(&temp.path().join("root")), Uuid::new_v4()).await,
            Err(FindingError::Corrupt(_))
        ));
        Ok(())
    }
    #[tokio::test]
    async fn response_byte_bound_and_cancelled_read_leave_append_healthy() -> TestResult {
        let temp = tempfile::tempdir()?;
        let mut cfg = config(temp.path());
        cfg.max_query_bytes = 2;
        let store = FindingStore::open(cfg, Uuid::new_v4()).await?;
        store.append(vec![finding("a")?], context()).await?;
        assert!(matches!(
            store
                .query(
                    FindingQuery {
                        limit: 1,
                        ..Default::default()
                    },
                    context()
                )
                .await,
            Err(FindingError::Quota)
        ));
        let cancelled = context();
        cancelled.cancellation.cancel();
        assert!(matches!(
            store
                .query(
                    FindingQuery {
                        limit: 1,
                        ..Default::default()
                    },
                    cancelled
                )
                .await,
            Err(FindingError::Cancelled)
        ));
        assert!(!store.metrics().closed);
        store.append(vec![finding("b")?], context()).await?;
        store.shutdown(context()).await?;
        Ok(())
    }
}
