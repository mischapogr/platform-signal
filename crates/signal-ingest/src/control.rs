//! Optional host-owned control auditing; it supplies no admission authority.
use signal_protocol::audit::{Actor, Completion, Decision};
use std::{future::Future, pin::Pin};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct AuditContext {
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("admission control audit is unavailable")]
pub struct AuditUnavailable;

pub type AuditFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AuditUnavailable>> + Send + 'a>>;

/// One nonclone request session. Implementations retain physical work after
/// cancellation and account for an incomplete session on drop; no detached
/// completion or implicit retry is authorized by this interface.
pub trait IngestAuditSession: Send {
    fn finish(self: Box<Self>, completion: Completion) -> AuditFuture<'static, ()>;
}

/// A host chooses this hook explicitly. Inputs contain neither credentials nor
/// event bodies/IDs. A granted decision permits request processing, not admission
/// of unexamined events; whole-batch canonical scope validation still follows.
pub trait IngestAudit: Send + Sync {
    fn begin(
        &self,
        actor: Actor,
        decision: Decision,
        context: AuditContext,
    ) -> AuditFuture<'_, Box<dyn IngestAuditSession>>;
}
