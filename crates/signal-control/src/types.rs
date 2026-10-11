//! Bounded versioned inputs. Caller configuration, never producer fields, owns scope.
use crate::ControlError;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const REQUEST_BYTES: usize = 1024 * 1024;
pub const REPLY_BYTES: usize = 1024 * 1024;
pub const COMMANDS: usize = 32;
pub const CONNECTIONS: usize = 4;
pub const MANIFEST_BYTES: usize = 256 * 1024;
pub const ITEM_BYTES: usize = 64 * 1024;
pub const ITEMS: usize = 128;

#[derive(Clone)]
pub struct ControlContext {
    pub(crate) deadline: tokio::time::Instant,
    pub(crate) cancellation: CancellationToken,
}
impl ControlContext {
    pub fn new(duration: Duration) -> Result<Self, ControlError> {
        if duration.is_zero() || duration > Duration::from_secs(5) {
            return Err(ControlError::Invalid);
        }
        Ok(Self {
            deadline: tokio::time::Instant::now() + duration,
            cancellation: CancellationToken::new(),
        })
    }
    /// Start a distinct finite operation under the caller's cancellation tree.
    /// Use limited_to on the same context for later stages of that operation.
    pub fn new_cancellable(
        duration: Duration,
        parent: &CancellationToken,
    ) -> Result<Self, ControlError> {
        let mut context = Self::new(duration)?;
        context.cancellation = parent.child_token();
        context.check()?;
        Ok(context)
    }
    /// Cancel this context and its submitted children.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }
    /// Derive a stricter deadline; this can never extend the original budget.
    pub fn limited_to(mut self, deadline: tokio::time::Instant) -> Self {
        self.deadline = self.deadline.min(deadline);
        self
    }
    /// Derived external-I/O cancellation: parent cancellation reaches the child;
    /// dropping/cancelling the child does not cancel the shared parent context.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.child_token()
    }
    pub fn check(&self) -> Result<(), ControlError> {
        if self.cancellation.is_cancelled() {
            return Err(ControlError::Cancelled);
        }
        if tokio::time::Instant::now() >= self.deadline {
            return Err(ControlError::Timeout);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub schema_version: u32,
    pub store_id: Uuid,
    pub generation: Uuid,
    pub tenant: String,
    pub stream: Uuid,
    pub partition_id: Uuid,
}
impl Scope {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 1
            || self.store_id.is_nil()
            || self.generation.is_nil()
            || self.stream.is_nil()
            || self.partition_id.is_nil()
            || self.tenant.is_empty()
            || self.tenant.len() > 256
            || self.tenant.capacity() > 256
            || self.tenant.chars().any(char::is_control)
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseToken {
    pub scope: Scope,
    pub owner: Uuid,
    pub epoch: u64,
}
impl LeaseToken {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.scope.validate()?;
        if self.owner.is_nil() || self.epoch == 0 || self.epoch > i64::MAX as u64 {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionedState {
    pub key: String,
    pub revision: [u8; 32],
    pub bytes: Vec<u8>,
}
impl RevisionedState {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.key.is_empty()
            || self.key.len() > 256
            || self.key.capacity() > 256
            || self.key.chars().any(char::is_control)
            || self.bytes.is_empty()
            || self.bytes.len() > ITEM_BYTES
            || self.bytes.capacity() > ITEM_BYTES
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingInput {
    pub id: Uuid,
    /// Original first-occurrence wire bytes, never reserialized for cursor hashing.
    pub bytes: Vec<u8>,
}
impl FindingInput {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.id.is_nil()
            || self.bytes.is_empty()
            || self.bytes.len() > ITEM_BYTES
            || self.bytes.capacity() > ITEM_BYTES
        {
            return Err(ControlError::Invalid);
        }
        let finding: signal_findings::Finding =
            serde_json::from_slice(&self.bytes).map_err(|_| ControlError::Invalid)?;
        finding.validate().map_err(|_| ControlError::Invalid)?;
        if finding.id != self.id {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkInput {
    pub id: Uuid,
    pub finding_id: Uuid,
    /// Opaque immutable work plan. Runtime credentials must never be serialized here.
    pub bytes: Vec<u8>,
}
impl WorkInput {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.id.is_nil()
            || self.finding_id.is_nil()
            || self.bytes.is_empty()
            || self.bytes.len() > ITEM_BYTES
            || self.bytes.capacity() > ITEM_BYTES
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> Scope {
        Scope {
            schema_version: 1,
            store_id: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            tenant: "synthetic-tenant".into(),
            stream: Uuid::new_v4(),
            partition_id: Uuid::new_v4(),
        }
    }
    #[test]
    fn scope_and_fence_reject_nil_unknown_or_signed_overflow() -> Result<(), ControlError> {
        let mut s = scope();
        s.validate()?;
        s.generation = Uuid::nil();
        assert!(s.validate().is_err());
        let mut token = LeaseToken {
            scope: scope(),
            owner: Uuid::new_v4(),
            epoch: 1,
        };
        token.validate()?;
        token.epoch = 0;
        assert!(token.validate().is_err());
        token.epoch = i64::MAX as u64 + 1;
        assert!(token.validate().is_err());
        Ok(())
    }
    #[test]
    fn spare_capacity_cannot_hide_unbounded_queued_metadata() -> Result<(), ControlError> {
        let mut state = RevisionedState {
            key: "k".into(),
            revision: [1; 32],
            bytes: vec![1],
        };
        state.validate()?;
        state.bytes.reserve_exact(ITEM_BYTES + 1);
        assert!(state.validate().is_err());
        let mut s = scope();
        s.tenant.reserve_exact(257);
        assert!(s.validate().is_err());
        Ok(())
    }
    #[test]
    fn original_operation_budget_is_finite_and_cancellation_explicit() -> Result<(), ControlError> {
        assert!(ControlContext::new(Duration::ZERO).is_err());
        assert!(ControlContext::new(Duration::from_secs(6)).is_err());
        let context = ControlContext::new(Duration::from_secs(1))?;
        assert_eq!(
            context
                .clone()
                .limited_to(context.deadline() + Duration::from_secs(5))
                .deadline(),
            context.deadline()
        );
        assert!(matches!(
            context
                .clone()
                .limited_to(tokio::time::Instant::now())
                .check(),
            Err(ControlError::Timeout)
        ));
        let child = context.cancellation_token();
        child.cancel();
        context.check()?;
        let child = context.cancellation_token();
        context.cancellation.cancel();
        assert!(child.is_cancelled());
        assert!(matches!(context.check(), Err(ControlError::Cancelled)));
        Ok(())
    }
}

#[cfg(test)]
mod cancellable_context_tests {
    use super::*;
    #[test]
    fn parent_cancellation_is_retained_without_budget_renewal() -> Result<(), ControlError> {
        let parent = CancellationToken::new();
        let original = ControlContext::new_cancellable(Duration::from_secs(1), &parent)?;
        let deadline = original.deadline();
        let child = original
            .clone()
            .limited_to(deadline + Duration::from_secs(1));
        assert_eq!(child.deadline(), deadline);
        parent.cancel();
        assert!(matches!(original.check(), Err(ControlError::Cancelled)));
        assert!(matches!(child.check(), Err(ControlError::Cancelled)));
        assert!(matches!(
            ControlContext::new_cancellable(Duration::from_secs(1), &parent),
            Err(ControlError::Cancelled)
        ));
        Ok(())
    }
}
