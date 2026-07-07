//! Generic scoped analyst feedback; storage and authenticated actor mapping are host responsibilities.
use crate::{BoundedWriter, FindingContext};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use std::future::Future;
use thiserror::Error;
use uuid::Uuid;

pub const DISPOSITION_SCHEMA_VERSION: u16 = 1;
pub const MAX_DISPOSITION_BYTES: usize = 8192;
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingReference {
    pub stream_id: Uuid,
    pub finding_id: Uuid,
}
impl FindingReference {
    pub fn validate(self) -> Result<(), DispositionError> {
        if self.stream_id.is_nil() || self.finding_id.is_nil() {
            Err(DispositionError::Invalid)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalystOutcome {
    TruePositive,
    BenignPositive,
    FalsePositive,
    Incident,
}
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DispositionRequest {
    pub schema_version: u16,
    pub operation_id: Uuid,
    pub reference: FindingReference,
    pub expected_revision: u64,
    pub outcome: AnalystOutcome,
    pub incident_id: Option<Uuid>,
    pub note: Option<String>,
}
impl DispositionRequest {
    pub fn validate(&self) -> Result<(), DispositionError> {
        self.reference.validate()?;
        if self.schema_version != DISPOSITION_SCHEMA_VERSION
            || self.operation_id.is_nil()
            || self.expected_revision >= 1_000_000
            || self
                .note
                .as_ref()
                .is_some_and(|s| s.len() > 4096 || s.capacity() > 4096)
            || (self.outcome == AnalystOutcome::Incident) != self.incident_id.is_some()
            || self.incident_id.is_some_and(|id| id.is_nil())
        {
            Err(DispositionError::Invalid)
        } else {
            Ok(())
        }
    }
}
/// Separate, non-serialized authority supplied by trusted application code after authentication.
/// This constructor validates shape; it does not authenticate or establish RBAC itself.
#[derive(Clone)]
pub struct DispositionAuthority {
    actor: String,
    reference: FindingReference,
}
impl DispositionAuthority {
    pub fn new(actor: String, reference: FindingReference) -> Result<Self, DispositionError> {
        reference.validate()?;
        if !valid_actor(&actor) || actor.capacity() > 256 {
            return Err(DispositionError::Invalid);
        }
        Ok(Self { actor, reference })
    }
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn reference(&self) -> FindingReference {
        self.reference
    }
    pub fn authorize(&self, request: &DispositionRequest) -> Result<(), DispositionError> {
        request.validate()?;
        if self.reference != request.reference {
            Err(DispositionError::Forbidden)
        } else {
            Ok(())
        }
    }
}
fn valid_actor(actor: &str) -> bool {
    !actor.trim().is_empty() && actor.len() <= 256 && !actor.chars().any(char::is_control)
}
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DispositionRecord {
    pub schema_version: u16,
    pub operation_id: Uuid,
    pub reference: FindingReference,
    pub revision: u64,
    pub recorded_at: DateTime<Utc>,
    pub actor: String,
    pub outcome: AnalystOutcome,
    pub incident_id: Option<Uuid>,
    pub note: Option<String>,
}
impl DispositionRecord {
    /// Assign receipt time once; exact retry must recover this record rather than call again.
    pub fn from_authorized(
        authority: &DispositionAuthority,
        request: DispositionRequest,
    ) -> Result<Self, DispositionError> {
        authority.authorize(&request)?;
        let result = Self {
            schema_version: DISPOSITION_SCHEMA_VERSION,
            operation_id: request.operation_id,
            reference: request.reference,
            revision: request.expected_revision + 1,
            recorded_at: Utc::now(),
            actor: authority.actor.clone(),
            outcome: request.outcome,
            incident_id: request.incident_id,
            note: request.note,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), DispositionError> {
        if !valid_actor(&self.actor)
            || self.actor.capacity() > 256
            || self
                .note
                .as_ref()
                .is_some_and(|s| s.len() > 4096 || s.capacity() > 4096)
        {
            return Err(DispositionError::Invalid);
        }
        let request = DispositionRequest {
            schema_version: self.schema_version,
            operation_id: self.operation_id,
            reference: self.reference,
            expected_revision: self
                .revision
                .checked_sub(1)
                .ok_or(DispositionError::Invalid)?,
            outcome: self.outcome,
            incident_id: self.incident_id,
            note: self.note.clone(),
        };
        request.validate()?;
        if !valid_actor(&self.actor) || !(0..=9999).contains(&self.recorded_at.year()) {
            return Err(DispositionError::Invalid);
        }
        let mut counter = BoundedWriter {
            bytes: 0,
            limit: MAX_DISPOSITION_BYTES,
            data: None,
        };
        serde_json::to_writer(&mut counter, self).map_err(|_| DispositionError::Invalid)?;
        Ok(())
    }
}
#[derive(Clone, Serialize)]
pub struct DispositionReceipt {
    pub schema_version: u16,
    pub record: DispositionRecord,
    pub replayed: bool,
}
#[derive(Clone, Serialize)]
pub struct DispositionHistory {
    pub schema_version: u16,
    pub records: Vec<DispositionRecord>,
    pub next_revision: u64,
    pub has_more: bool,
}
impl DispositionHistory {
    pub fn encoded_len(&self) -> Result<usize, DispositionError> {
        let mut counter = BoundedWriter {
            bytes: 0,
            limit: usize::MAX,
            data: None,
        };
        serde_json::to_writer(&mut counter, self).map_err(|_| DispositionError::Invalid)?;
        Ok(counter.bytes)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DispositionError {
    #[error("invalid disposition input")]
    Invalid,
    #[error("disposition scope denied")]
    Forbidden,
    #[error("referenced finding unavailable")]
    UnknownFinding,
    #[error("disposition revision or operation conflict")]
    Conflict,
    #[error("disposition capacity exhausted")]
    Capacity,
    #[error("disposition backend unavailable")]
    Unavailable,
    #[error("disposition operation timed out")]
    Timeout,
    #[error("disposition operation cancelled")]
    Cancelled,
}
/// The host must verify finding existence, atomically preserve audit/revision,
/// retain exact replay, and enforce finite history/operation limits.
pub trait DispositionBackend: Send + Sync {
    fn record(
        &self,
        authority: DispositionAuthority,
        request: DispositionRequest,
        context: FindingContext,
    ) -> impl Future<Output = Result<DispositionReceipt, DispositionError>> + Send;
    fn history(
        &self,
        authority: DispositionAuthority,
        after_revision: u64,
        limit: usize,
        context: FindingContext,
    ) -> impl Future<Output = Result<DispositionHistory, DispositionError>> + Send;
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> DispositionRequest {
        DispositionRequest {
            schema_version: 1,
            operation_id: Uuid::from_u128(1),
            reference: FindingReference {
                stream_id: Uuid::from_u128(2),
                finding_id: Uuid::from_u128(3),
            },
            expected_revision: 0,
            outcome: AnalystOutcome::TruePositive,
            incident_id: None,
            note: None,
        }
    }
    #[test]
    fn strict_request_rejects_actor_time_unknown_fields_and_malformed_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        let r = request();
        for field in ["actor", "recorded_at", "permissions"] {
            let mut value = serde_json::to_value(&r)?;
            value[field] = "producer-claim".into();
            assert!(serde_json::from_value::<DispositionRequest>(value).is_err());
        }
        let mut r = request();
        r.note = Some("x".repeat(4097));
        assert_eq!(r.validate(), Err(DispositionError::Invalid));
        let mut spare = String::with_capacity(8192);
        spare.push('x');
        r.note = Some(spare);
        assert_eq!(r.validate(), Err(DispositionError::Invalid));
        r = request();
        r.expected_revision = 1_000_000;
        assert_eq!(r.validate(), Err(DispositionError::Invalid));
        r = request();
        r.reference.finding_id = Uuid::nil();
        assert_eq!(r.validate(), Err(DispositionError::Invalid));
        Ok(())
    }
    #[test]
    fn outcomes_require_valid_incident_link_and_separate_exact_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let r = request();
        let a = DispositionAuthority::new("authenticated-fixture".into(), r.reference)?;
        let mut foreign = r.clone();
        foreign.reference.stream_id = Uuid::new_v4();
        assert_eq!(a.authorize(&foreign), Err(DispositionError::Forbidden));
        for outcome in [
            AnalystOutcome::TruePositive,
            AnalystOutcome::BenignPositive,
            AnalystOutcome::FalsePositive,
            AnalystOutcome::Incident,
        ] {
            let mut r = request();
            r.outcome = outcome;
            r.incident_id = (outcome == AnalystOutcome::Incident).then(|| Uuid::from_u128(4));
            let record = DispositionRecord::from_authorized(&a, r.clone())?;
            assert_eq!(record.revision, 1);
            assert_eq!(record.actor, a.actor());
            record.validate()?;
            let restored: DispositionRecord =
                serde_json::from_slice(&serde_json::to_vec(&record)?)?;
            assert!(restored == record);
            r.incident_id = if r.incident_id.is_some() {
                None
            } else {
                Some(Uuid::new_v4())
            };
            assert_eq!(r.validate(), Err(DispositionError::Invalid));
        }
        Ok(())
    }
}
