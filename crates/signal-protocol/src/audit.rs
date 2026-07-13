//! Bounded control audit records and exact-byte destination acknowledgements.
//! These records never grant access, prove source completeness or roll back effects.
use crate::access::Operation;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use thiserror::Error;
use uuid::Uuid;

pub const RECORD_BYTES: usize = 4096;
pub const ACK_BYTES: usize = 1024;
pub const HEALTH_BYTES: usize = 1024;

/// Aggregate receiver state, never source completeness, restore freshness or
/// permission proof. Fields preserve the independent receiver's version1 wire.
/// The private health owner decides assessment, polling and observation expiry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReceiverHealth {
    pub schema_version: u16,
    pub held: bool,
    pub records: usize,
    pub bytes: u64,
    pub record_capacity: usize,
    pub byte_capacity: u64,
    pub physical_depth: usize,
    pub physical_capacity: usize,
    pub physical_rejected: u64,
    pub rejected: u64,
    pub uncertain: u64,
    pub append_http_depth: usize,
    pub append_http_capacity: usize,
    pub append_http_rejected: u64,
    pub health_http_rejected: u64,
}
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("invalid bounded audit receiver health")]
pub struct InvalidReceiverHealth;
impl AuditReceiverHealth {
    fn validate(&self) -> Result<(), InvalidReceiverHealth> {
        if self.schema_version != 1
            || !(1..=16_384).contains(&self.record_capacity)
            || !(4168..=64 * 1024 * 1024).contains(&self.byte_capacity)
            || self.records > self.record_capacity
            || self.bytes > self.byte_capacity
            || self.physical_capacity != 1
            || self.physical_depth > 1
            || self.append_http_capacity != 1
            || self.append_http_depth > 1
        {
            return Err(InvalidReceiverHealth);
        }
        // Independently read atomics need not form a transactional record/byte
        // pair. Reject impossible individual bounds, not a transient live pair.
        Ok(())
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self, InvalidReceiverHealth> {
        if bytes.is_empty()
            || bytes.len() > HEALTH_BYTES
            || bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
        {
            return Err(InvalidReceiverHealth);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| InvalidReceiverHealth)?;
        value.validate()?;
        Ok(value)
    }
    pub fn to_json(&self) -> Result<Vec<u8>, InvalidReceiverHealth> {
        self.validate()?;
        bounded_json(self, HEALTH_BYTES).map_err(|_| InvalidReceiverHealth)
    }
}

/// Static append classes never contain destination, credentials or record data.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AppendError {
    #[error("audit append capacity is busy")]
    Busy,
    #[error("audit append outcome is uncertain")]
    Uncertain,
}

/// Physical capacity and confirmed replies, without identity/record metadata.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuditMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub rejected: u64,
    pub confirmed: u64,
    pub uncertain: u64,
}
pub type AppendFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppendError>> + Send + 'a>>;

/// Restricted destination seam, independent of event/query/WAL storage.
/// The host supplies its original monotonic deadline. Dropping the caller may
/// leave effects uncertain; implementations retain physical worker ownership.
/// Success requires an exact complete ACK from the configured destination and
/// does not itself prove that destination's storage durability or encryption.
pub trait AuditSink: Send + Sync + 'static {
    fn append<'a>(
        &'a self,
        record: &'a PreparedAudit,
        deadline: std::time::Instant,
    ) -> AppendFuture<'a>;
    fn metrics(&self) -> AuditMetrics;
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuditError {
    #[error("invalid bounded audit record")]
    InvalidRecord,
    #[error("invalid audit acknowledgement")]
    InvalidAcknowledgement,
    #[error("audit document exceeds capacity")]
    TooLarge,
    #[error("audit serialization failed")]
    Serialization,
}
// No Debug: audit identity/revision metadata belongs only at the restricted sink.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Actor {
    VerifiedSubject { key: String },
    // Empty struct variants enforce unknown-field rejection in tagged JSON.
    Bootstrap {},
    Anonymous {},
    Unattributed {},
    System {},
}
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Granted,
    Denied,
    Unavailable,
}
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    Success,
    Denied,
    Failed,
    Uncertain,
}
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigurationKind {
    Runtime,
    Rules,
}
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    AccessDecision {
        operation: Operation,
        operation_id: Uuid,
        decision: Decision,
    },
    OperationCompletion {
        operation: Operation,
        operation_id: Uuid,
        completion: Completion,
    },
    ConfigurationActivation {
        configuration: ConfigurationKind,
        revision_sha256: String,
    },
}
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub schema_version: u16,
    pub record_id: Uuid,
    pub producer_id: Uuid,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub actor: Actor,
    pub action: Action,
}
fn digest_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl AuditRecord {
    pub fn validate(&self) -> Result<(), AuditError> {
        let action_valid = match &self.action {
            Action::AccessDecision { operation_id, .. }
            | Action::OperationCompletion { operation_id, .. } => !operation_id.is_nil(),
            Action::ConfigurationActivation {
                revision_sha256, ..
            } => digest_text(revision_sha256),
        };
        if self.schema_version != 1
            || self.record_id.is_nil()
            || self.producer_id.is_nil()
            || self.sequence == 0
            || !(0..=253_402_300_799).contains(&self.timestamp.timestamp())
            || self.timestamp.timestamp_subsec_nanos() >= 1_000_000_000
            || matches!(&self.actor, Actor::VerifiedSubject { key } if !digest_text(key))
            || !action_valid
        {
            return Err(AuditError::InvalidRecord);
        }
        Ok(())
    }
    pub fn prepare(self) -> Result<PreparedAudit, AuditError> {
        self.validate()?;
        let body = bounded_json(&self, RECORD_BYTES)?;
        Ok(PreparedAudit::freeze(self, body))
    }
}
/// Frozen validated record and exact transmitted bytes. No mutable body exposure,
/// Debug, token, credential, forwarding claims or authorization capability.
pub struct PreparedAudit {
    record: AuditRecord,
    body: Vec<u8>,
    sha256: String,
}
impl PreparedAudit {
    fn freeze(record: AuditRecord, body: Vec<u8>) -> Self {
        let hash = Sha256::digest(&body);
        let sha256 = hash.iter().map(|b| format!("{b:02x}")).collect();
        let mut record = record;
        if let Actor::VerifiedSubject { key } = &mut record.actor {
            *key = std::mem::take(key).into_boxed_str().into_string();
        }
        if let Action::ConfigurationActivation {
            revision_sha256, ..
        } = &mut record.action
        {
            *revision_sha256 = std::mem::take(revision_sha256)
                .into_boxed_str()
                .into_string();
        }
        Self {
            record,
            body,
            sha256,
        }
    }
    /// Destination intake preserves original bytes, including field order/spacing.
    /// Parsing a record does not establish sender authority or durable custody.
    pub fn from_original(body: &[u8]) -> Result<Self, AuditError> {
        if body.len() > RECORD_BYTES {
            return Err(AuditError::TooLarge);
        }
        if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return Err(AuditError::InvalidRecord);
        }
        let record: AuditRecord =
            serde_json::from_slice(body).map_err(|_| AuditError::InvalidRecord)?;
        record.validate()?;
        Ok(Self::freeze(record, body.to_vec()))
    }
    pub fn record(&self) -> &AuditRecord {
        &self.record
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    /// Exact semantic binding only; the configured destination must separately
    /// qualify sync, deduplication, independent permissions, encryption and health.
    pub fn verify_acknowledgement(&self, bytes: &[u8]) -> Result<(), AuditError> {
        if bytes.len() > ACK_BYTES {
            return Err(AuditError::TooLarge);
        }
        if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
            return Err(AuditError::InvalidAcknowledgement);
        }
        let ack: AuditAcknowledgement =
            serde_json::from_slice(bytes).map_err(|_| AuditError::InvalidAcknowledgement)?;
        if ack.schema_version != 1
            || ack.record_id != self.record.record_id
            || ack.producer_id != self.record.producer_id
            || ack.sequence != self.record.sequence
            || !digest_text(&ack.body_sha256)
            || ack.body_sha256 != self.sha256
        {
            return Err(AuditError::InvalidAcknowledgement);
        }
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAcknowledgement {
    pub schema_version: u16,
    pub record_id: Uuid,
    pub producer_id: Uuid,
    pub sequence: u64,
    pub body_sha256: String,
}
impl AuditAcknowledgement {
    /// Call only after qualifying durable acceptance at the restricted destination.
    /// Constructing/serializing this claim itself proves no storage guarantee.
    pub fn for_prepared(record: &PreparedAudit) -> Self {
        Self {
            schema_version: 1,
            record_id: record.record.record_id,
            producer_id: record.record.producer_id,
            sequence: record.record.sequence,
            body_sha256: record.sha256.clone(),
        }
    }
    pub fn to_json(&self) -> Result<Vec<u8>, AuditError> {
        if self.schema_version != 1
            || self.record_id.is_nil()
            || self.producer_id.is_nil()
            || self.sequence == 0
            || !digest_text(&self.body_sha256)
        {
            return Err(AuditError::InvalidAcknowledgement);
        }
        bounded_json(self, ACK_BYTES)
    }
}
fn bounded_json(value: &impl Serialize, cap: usize) -> Result<Vec<u8>, AuditError> {
    struct Writer {
        bytes: Vec<u8>,
        cap: usize,
    }
    impl Write for Writer {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            if input.len() > self.cap - self.bytes.len() {
                return Err(std::io::Error::other("audit capacity"));
            }
            self.bytes.extend_from_slice(input);
            Ok(input.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        bytes: Vec::new(),
        cap,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| AuditError::Serialization)?;
    Ok(writer.bytes)
}
#[cfg(test)]
mod tests;
