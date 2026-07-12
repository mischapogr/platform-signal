//! Optional explicitly selected access control auditing. Confirmation never grants API authority.
mod activation;
use crate::config::{self, ConfigError, Settings};
pub(crate) use activation::{HashWriter, RuntimeInputs, runtime_revision, within_startup};
use chrono::Utc;
use serde::Deserialize;
use signal_collector_sdk::{
    ExtensionContext,
    audit::{HttpAuditSink, outbox::AuditOutbox},
};
use signal_protocol::{
    AuditControlMetrics,
    access::Operation,
    audit::{Action, Actor, AuditSink, Completion, ConfigurationKind, Decision},
};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: u16,
    #[serde(default)]
    operations: Vec<Operation>,
    #[serde(default)]
    configuration_activations: Vec<ConfigurationKind>,
    endpoint: String,
    tls_config: String,
    outbox_directory: String,
    connect_timeout_ms: u64,
}
impl Wire {
    fn parse(text: &str) -> Result<Self, ConfigError> {
        let invalid = || ConfigError::Invalid("bounded access audit configuration");
        if text.is_empty()
            || text.len() > 65_536
            || text.bytes().find(|b| !b.is_ascii_whitespace()) != Some(b'{')
        {
            return Err(invalid());
        }
        let wire: Self = serde_json::from_str(text).map_err(|_| invalid())?;
        if wire.schema_version != 1
            || !valid_profile(&wire.operations, &wire.configuration_activations)
            || wire.endpoint.is_empty()
            || wire.endpoint.len() > 2048
            || !(1..=30_000).contains(&wire.connect_timeout_ms)
            || [&wire.tls_config, &wire.outbox_directory]
                .iter()
                .any(|path| path.is_empty() || path.len() > 4096 || !Path::new(path).is_absolute())
        {
            return Err(invalid());
        }
        Ok(wire)
    }
}
fn valid_operations(operations: &[Operation]) -> bool {
    !operations.is_empty()
        && operations.len() <= 6
        && operations.iter().enumerate().all(|(index, operation)| {
            matches!(
                operation,
                Operation::QueryEvents
                    | Operation::ReadFindings
                    | Operation::ReadFindingsFeed
                    | Operation::ReadCoverage
                    | Operation::WriteCoverage
                    | Operation::IngestEvents
            ) && !operations[..index].contains(operation)
        })
}
fn valid_profile(operations: &[Operation], activations: &[ConfigurationKind]) -> bool {
    (!operations.is_empty() || !activations.is_empty())
        && (operations.is_empty() || valid_operations(operations))
        && activations.len() <= 2
        && activations.iter().enumerate().all(|(index, kind)| {
            matches!(kind, ConfigurationKind::Runtime | ConfigurationKind::Rules)
                && !activations[..index].contains(kind)
        })
}

pub fn actor(grant: Option<&signal_protocol::access::RequestGrant>, bootstrap: bool) -> Actor {
    match grant {
        Some(grant) => crate::access::now()
            .and_then(|now| grant.audit_subject_key(now))
            .map_or(Actor::Unattributed {}, |key| Actor::VerifiedSubject { key }),
        None if bootstrap => Actor::Bootstrap {},
        None => Actor::Anonymous {},
    }
}

pub fn completion(status: axum::http::StatusCode, decision: Decision) -> Completion {
    if status.is_success() {
        Completion::Success
    } else if decision == Decision::Denied || status == axum::http::StatusCode::FORBIDDEN {
        Completion::Denied
    } else if matches!(
        status,
        axum::http::StatusCode::REQUEST_TIMEOUT | axum::http::StatusCode::SERVICE_UNAVAILABLE
    ) {
        Completion::Uncertain
    } else {
        Completion::Failed
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("restricted audit is unavailable")]
pub struct Unavailable;

pub struct Control {
    operations: Vec<Operation>,
    activations: Vec<ConfigurationKind>,
    outbox: AuditOutbox,
    destination: Arc<dyn AuditSink>,
    slots: Arc<Semaphore>,
    rejected: AtomicU64,
    incomplete: AtomicU64,
}
impl Control {
    pub async fn load(
        settings: &Settings,
        startup: &ExtensionContext,
    ) -> Result<Option<Arc<Self>>, ConfigError> {
        let Some(path) = settings.optional("SIGNAL_AUDIT_CONFIG")? else {
            return Ok(None);
        };
        if path.is_empty() || path.len() > 4096 {
            return Err(ConfigError::Invalid("audit configuration path"));
        }
        let load_deadline = Instant::now() + Duration::from_secs(5);
        let cancellation = startup.cancellation().child_token();
        let wire = config::read_document(
            path.into(),
            load_deadline,
            cancellation.clone(),
            Wire::parse,
        )
        .await?;
        // Only explicit activation selection adds the original startup clock.
        // Existing operations-only profiles retain their five-second load cap.
        let deadline = if wire.configuration_activations.is_empty() {
            load_deadline
        } else {
            startup.check().map_err(|_| ConfigError::Timeout)?;
            load_deadline.min(startup.deadline())
        };
        // Dedicated environment secret only. Never use the ordinary API token.
        let token = settings.secret_environment("SIGNAL_AUDIT_TOKEN")?;
        let root = PathBuf::from(wire.outbox_directory);
        let destination = config::read_limited_document(
            wire.tls_config.into(),
            signal_protocol::transport::TLS_DOCUMENT_BYTES,
            deadline,
            cancellation.clone(),
            move |text| {
                HttpAuditSink::from_private_tls(
                    &wire.endpoint,
                    &token,
                    Duration::from_millis(wire.connect_timeout_ms),
                    text.as_bytes(),
                )
                .map_err(|_| ConfigError::Invalid("restricted audit destination configuration"))
            },
        )
        .await?;
        let context = ExtensionContext::from_deadline(cancellation, deadline)
            .map_err(|_| ConfigError::Timeout)?;
        Self::open_profile(
            &root,
            Arc::new(destination),
            wire.operations,
            wire.configuration_activations,
            context,
        )
        .await
        .map(Some)
        .map_err(|_| ConfigError::Invalid("audit outbox or recovery unavailable"))
    }
    #[cfg(test)]
    async fn open(
        root: &Path,
        destination: Arc<dyn AuditSink>,
        operations: Vec<Operation>,
        context: ExtensionContext,
    ) -> Result<Arc<Self>, Unavailable> {
        Self::open_profile(root, destination, operations, Vec::new(), context).await
    }
    async fn open_profile(
        root: &Path,
        destination: Arc<dyn AuditSink>,
        operations: Vec<Operation>,
        activations: Vec<ConfigurationKind>,
        context: ExtensionContext,
    ) -> Result<Arc<Self>, Unavailable> {
        if !valid_profile(&operations, &activations) {
            return Err(Unavailable);
        }
        let outbox = AuditOutbox::open(root, context.clone())
            .await
            .map_err(|_| Unavailable)?;
        // Replay old bytes before enabling this scope. Old confirmation cannot
        // authorize a fresh request: begin always stages a new operation UUID.
        outbox
            .flush(destination.as_ref(), context)
            .await
            .map_err(|_| Unavailable)?;
        Ok(Arc::new(Self {
            operations,
            activations,
            outbox,
            destination,
            slots: Arc::new(Semaphore::new(1)),
            rejected: AtomicU64::new(0),
            incomplete: AtomicU64::new(0),
        }))
    }
    #[cfg(test)]
    pub(crate) async fn test_open(
        root: &Path,
        destination: Arc<dyn AuditSink>,
        operations: Vec<Operation>,
        context: ExtensionContext,
    ) -> Result<Arc<Self>, Unavailable> {
        Self::open(root, destination, operations, context).await
    }
    pub fn selected(&self, operation: Operation) -> bool {
        self.operations.contains(&operation)
    }
    pub fn ingest_auditor(
        self: &Arc<Self>,
    ) -> Option<Arc<dyn signal_ingest::control::IngestAudit>> {
        self.selected(Operation::IngestEvents).then(|| {
            Arc::new(IngestAuditor(self.clone())) as Arc<dyn signal_ingest::control::IngestAudit>
        })
    }
    pub fn metrics(&self) -> AuditControlMetrics {
        let disk = self.outbox.metrics();
        let destination = self.destination.metrics();
        AuditControlMetrics {
            depth: 1 - self.slots.available_permits(),
            capacity: 1,
            rejected: self.rejected.load(Ordering::Relaxed),
            incomplete: self.incomplete.load(Ordering::Relaxed),
            pending: disk.depth,
            pending_capacity: disk.capacity,
            disk_depth: disk.physical_depth,
            disk_capacity: disk.physical_capacity,
            disk_rejected: disk.physical_rejected,
            destination_depth: destination.depth,
            destination_capacity: destination.capacity,
            destination_rejected: destination.rejected,
            uncertain: disk.uncertain.saturating_add(destination.uncertain),
            held: disk.held
                || (disk.depth != 0 && self.slots.available_permits() == 1)
                || self.incomplete.load(Ordering::Relaxed) != 0,
        }
    }
    pub async fn begin(
        self: &Arc<Self>,
        mut actor: Actor,
        decision: Decision,
        operation: Operation,
        deadline: Instant,
        cancellation: CancellationToken,
    ) -> Result<Session, Unavailable> {
        let context =
            ExtensionContext::from_deadline(cancellation, deadline).map_err(|_| Unavailable)?;
        context.check().map_err(|_| Unavailable)?;
        if !self.selected(operation) || self.metrics().held {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(Unavailable);
        }
        let permit = self.slots.clone().try_acquire_owned().map_err(|_| {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            Unavailable
        })?;
        if let Actor::VerifiedSubject { key } = &mut actor {
            *key = std::mem::take(key).into_boxed_str().into_string();
        }
        let session = Session {
            control: self.clone(),
            _permit: permit,
            actor,
            decision,
            operation,
            operation_id: Uuid::new_v4(),
            context,
            completed: false,
        };
        session
            .publish(Action::AccessDecision {
                operation,
                operation_id: session.operation_id,
                decision,
            })
            .await?;
        Ok(session)
    }
}

pub struct Session {
    control: Arc<Control>,
    _permit: OwnedSemaphorePermit,
    actor: Actor,
    decision: Decision,
    operation: Operation,
    operation_id: Uuid,
    context: ExtensionContext,
    completed: bool,
}
struct IngestAuditor(Arc<Control>);
impl signal_ingest::control::IngestAudit for IngestAuditor {
    fn begin(
        &self,
        actor: Actor,
        decision: Decision,
        context: signal_ingest::control::AuditContext,
    ) -> signal_ingest::control::AuditFuture<'_, Box<dyn signal_ingest::control::IngestAuditSession>>
    {
        Box::pin(async move {
            let session = self
                .0
                .begin(
                    actor,
                    decision,
                    Operation::IngestEvents,
                    context.deadline,
                    context.cancellation,
                )
                .await
                .map_err(|_| signal_ingest::control::AuditUnavailable)?;
            Ok(Box::new(session) as Box<dyn signal_ingest::control::IngestAuditSession>)
        })
    }
}
impl signal_ingest::control::IngestAuditSession for Session {
    fn finish(
        self: Box<Self>,
        completion: Completion,
    ) -> signal_ingest::control::AuditFuture<'static, ()> {
        Box::pin(async move {
            Session::finish(*self, completion)
                .await
                .map_err(|_| signal_ingest::control::AuditUnavailable)
        })
    }
}
impl Session {
    async fn publish(&self, action: Action) -> Result<(), Unavailable> {
        self.context.check().map_err(|_| Unavailable)?;
        let record = self
            .control
            .outbox
            .stage(self.actor.clone(), action, Utc::now(), self.context.clone())
            .await
            .map_err(|_| Unavailable)?;
        let confirmed = self
            .control
            .outbox
            .flush(self.control.destination.as_ref(), self.context.clone())
            .await
            .map_err(|_| Unavailable)?;
        if confirmed != Some(record.record().record_id) {
            return Err(Unavailable);
        }
        self.context.check().map_err(|_| Unavailable)
    }
    pub async fn finish(mut self, completion: Completion) -> Result<(), Unavailable> {
        if (self.decision == Decision::Denied && completion != Completion::Denied)
            || (self.decision == Decision::Unavailable && completion == Completion::Success)
        {
            return Err(Unavailable);
        }
        self.publish(Action::OperationCompletion {
            operation: self.operation,
            operation_id: self.operation_id,
            completion,
        })
        .await?;
        self.completed = true;
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if !self.completed {
            self.control.incomplete.fetch_add(1, Ordering::Relaxed);
        }
    }
}
#[cfg(test)]
pub(crate) mod tests;
