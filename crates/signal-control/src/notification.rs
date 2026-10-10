//! At-least-once notification metadata only. No destination or network adapter.
use crate::{ControlError, LeaseToken};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationOutcome {
    Uncertain,
    Retryable,
    Delivered,
    Permanent,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum NotificationAction {
    /// New intent only; an identical claim returns Conflict, never another send permission.
    Claim {},
    /// Read-only evidence. A resolved intent must not be sent again as that attempt.
    Resolve {},
    Finish {
        outcome: NotificationOutcome,
        evidence: Vec<u8>,
    },
    /// Explicit recovery of an interrupted intent under the current owner fence.
    Interrupt { evidence: Vec<u8> },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationInput {
    pub schema_version: u32,
    /// Original immutable delivery ID; retry never substitutes a new delivery key.
    pub work_id: Uuid,
    pub attempt_id: Uuid,
    pub action: NotificationAction,
}
impl NotificationInput {
    pub(crate) fn wire(&self) -> Result<Vec<u8>, ControlError> {
        if self.schema_version != 1 || self.work_id.is_nil() || self.attempt_id.is_nil() {
            return Err(ControlError::Invalid);
        }
        let mut value = serde_json::json!({"schema_version":1,"work_id":self.work_id,"attempt_id":self.attempt_id});
        let (operation, evidence) = match &self.action {
            NotificationAction::Claim {} => ("claim", None),
            NotificationAction::Resolve {} => ("resolve", None),
            NotificationAction::Finish { outcome, evidence } => {
                value["outcome"] =
                    serde_json::to_value(outcome).map_err(|_| ControlError::Invalid)?;
                ("finish", Some(evidence))
            }
            NotificationAction::Interrupt { evidence } => ("interrupt", Some(evidence)),
        };
        value["operation"] = operation.into();
        if let Some(evidence) = evidence {
            if evidence.is_empty() || evidence.len() > 4096 || evidence.capacity() > 4096 {
                return Err(ControlError::Invalid);
            }
            value["evidence"] = crate::publication::hex(evidence).into();
        }
        crate::publication::encode(&value)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationState {
    Intent,
    Uncertain,
    Retryable,
    Delivered,
    Permanent,
    Exhausted,
}
/// Committed metadata, not a serializable/replayable dispatch capability. Only
/// a successful fresh Claim may precede an adapter's first send. Uncertain COMMIT
/// and Resolve require explicit interruption and a different attempt ID to retry.
/// A lease cannot revoke an already in-flight remote effect.
#[derive(Debug)]
pub struct NotificationResult {
    pub work_id: Uuid,
    pub attempt_id: Uuid,
    pub ordinal: u32,
    pub claim_authority: LeaseToken,
    pub outcome: NotificationState,
    pub work_status: NotificationState,
    pub plan: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotificationReply {
    schema_version: u32,
    work_id: Uuid,
    attempt_id: Uuid,
    ordinal: u32,
    claim_generation: Uuid,
    claim_owner: Uuid,
    claim_epoch: u64,
    outcome: NotificationState,
    work_status: NotificationState,
    plan: String,
    plan_sha256: String,
    request_sha256: String,
}
impl NotificationReply {
    pub(crate) fn validate(
        self,
        token: &LeaseToken,
        input: &NotificationInput,
        raw: &[u8],
    ) -> Result<NotificationResult, ControlError> {
        if self.schema_version != 1
            || self.work_id != input.work_id
            || self.attempt_id != input.attempt_id
            || !(1..=10).contains(&self.ordinal)
            || self.claim_generation.is_nil()
            || self.claim_owner.is_nil()
            || self.claim_epoch == 0
            || self.claim_epoch > i64::MAX as u64
            || self.outcome == NotificationState::Exhausted
            || self.request_sha256 != crate::publication::request_digest(raw)
            || self.plan.is_empty()
            || self.plan.len() > 2 * crate::ITEM_BYTES
            || !self.plan.len().is_multiple_of(2)
            || !self
                .plan
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ControlError::Corrupt);
        }
        let mut plan = Vec::with_capacity(self.plan.len() / 2);
        for pair in self.plan.as_bytes().chunks_exact(2) {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            plan.push(digit(pair[0]) * 16 + digit(pair[1]));
        }
        if crate::publication::request_digest(&plan) != self.plan_sha256 {
            return Err(ControlError::Corrupt);
        }
        let mut authority = token.clone();
        authority.scope.generation = self.claim_generation;
        authority.owner = self.claim_owner;
        authority.epoch = self.claim_epoch;
        if matches!(
            input.action,
            NotificationAction::Claim {} | NotificationAction::Finish { .. }
        ) && authority != *token
        {
            return Err(ControlError::Corrupt);
        }
        if matches!(input.action, NotificationAction::Claim {})
            && (self.outcome != NotificationState::Intent
                || self.work_status != NotificationState::Intent)
        {
            return Err(ControlError::Corrupt);
        }
        let requested_outcome = match &input.action {
            NotificationAction::Finish { outcome, .. } => Some(match outcome {
                NotificationOutcome::Uncertain => NotificationState::Uncertain,
                NotificationOutcome::Retryable => NotificationState::Retryable,
                NotificationOutcome::Delivered => NotificationState::Delivered,
                NotificationOutcome::Permanent => NotificationState::Permanent,
            }),
            NotificationAction::Interrupt { .. } => Some(NotificationState::Uncertain),
            _ => None,
        };
        if requested_outcome.is_some_and(|expected| self.outcome != expected) {
            return Err(ControlError::Corrupt);
        }
        Ok(NotificationResult {
            work_id: self.work_id,
            attempt_id: self.attempt_id,
            ordinal: self.ordinal,
            claim_authority: authority,
            outcome: self.outcome,
            work_status: self.work_status,
            plan,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notification_bounds_and_unknown_outcomes_fail_closed() {
        let mut input = NotificationInput {
            schema_version: 1,
            work_id: Uuid::from_u128(1),
            attempt_id: Uuid::from_u128(2),
            action: NotificationAction::Interrupt {
                evidence: vec![0; 4097],
            },
        };
        assert!(input.wire().is_err());
        input.action = NotificationAction::Claim {};
        input.attempt_id = Uuid::nil();
        assert!(input.wire().is_err());
        assert!(serde_json::from_str::<NotificationOutcome>("\"intent\"").is_err());
        assert!(
            serde_json::from_str::<NotificationAction>(r#"{"operation":"claim","force":true}"#)
                .is_err()
        );
    }
}
