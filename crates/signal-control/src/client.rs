//! Four owned workers and a finite admission queue; cancelled work keeps its worker.
use crate::{
    COMMANDS, CONNECTIONS, CatalogInput, CatalogPin, ConnectionSettings, ControlContext,
    ControlError, LeaseToken, NotificationInput, NotificationResult, ObjectControlResult,
    ObjectControlState, PublicationInput, PublicationResult, ReceiptInput, ReceiptResult,
    ReleasePinInput, RetentionPinInput, RetirementInput, Scope, SnapshotInput, SnapshotPin,
};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Compiled bundle identity; runtime never migrates or silently accepts drift.
pub fn schema_identity() -> ([u8; 32], [u8; 32]) {
    (
        Sha256::digest(include_bytes!("../../../schemas/shared-control/001.sql")).into(),
        Sha256::digest(include_bytes!(
            "../../../schemas/shared-control/003-administration.sql"
        ))
        .into(),
    )
}

#[derive(Default)]
struct Counters {
    queued: AtomicUsize,
    active: AtomicUsize,
    rejected: AtomicU64,
    quarantined: AtomicUsize,
    notification_uncertain_results: AtomicU64,
    snapshot_expired: AtomicU64,
    snapshot_retries: AtomicU64,
}
#[derive(Clone, Copy, Debug)]
pub struct ControlMetrics {
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub active: usize,
    pub connection_capacity: usize,
    pub rejected: u64,
    /// Seats withheld because remote rollback could not be confirmed.
    pub quarantined: usize,
    /// Uncertain COMMIT errors or replies reporting an uncertain attempt, including resolution.
    /// Counts observed results, not distinct obligations or remote effects.
    pub notification_uncertain_results: u64,
    pub snapshot_expired: u64,
    pub snapshot_retries: u64,
}
enum Reply {
    ProducerCredentials,
    FindingScope(crate::FindingScopeBinding),
    Feed(crate::AuthorizedFindingsPage),
    ScopedList(crate::AuthorizedFindingsList),
    Restore(crate::postgres_restore::RestoreReply),
    Administration(crate::AdministrativeResult),
    Notification(NotificationResult),
    Lease(LeaseToken),
    Receipt(ReceiptResult),
    Publication(PublicationResult),
    Snapshot(SnapshotPin),
    Catalog(CatalogPin),
    Object(ObjectControlResult),
}
enum Operation {
    ProducerCredentials {
        owner: String,
    },
    ExistingFindingScope {
        scope: Scope,
        binding: crate::ScopedFindingsBinding,
    },
    FindingScope {
        owner: String,
        profile: crate::FindingScopeProfile,
        action: crate::finding_scope::Action,
    },
    Feed {
        read: crate::global_feed::FeedRead,
    },
    ScopedList {
        read: crate::scoped_read::ScopedRead,
    },
    Catalog {
        scope: Scope,
        input: CatalogInput,
        started: tokio::time::Instant,
    },
    Restore {
        owner: String,
        plan: Arc<crate::postgres_restore::RestorePlan>,
        action: Box<crate::postgres_restore::RestoreAction>,
    },
    Administration {
        owner: String,
        action: crate::administration::AdministrativeAction,
    },
    Notification {
        token: LeaseToken,
        input: NotificationInput,
        raw: Vec<u8>,
    },
    Object {
        token: LeaseToken,
        raw: Vec<u8>,
        id: Uuid,
        state: ObjectControlState,
        reference: Option<String>,
    },
    Snapshot {
        scope: Scope,
        input: SnapshotInput,
        started: tokio::time::Instant,
    },
    Acquire {
        scope: Scope,
        owner: Uuid,
        lease_ms: i32,
    },
    Renew {
        token: LeaseToken,
        lease_ms: i32,
    },
    Receipt {
        token: LeaseToken,
        raw: Vec<u8>,
        expected: ReceiptResult,
    },
    Publish {
        token: LeaseToken,
        raw: Vec<u8>,
        claims: Option<Vec<u8>>,
        resolve_only: bool,
        expected: PublicationResult,
    },
}
struct QueueMark {
    counters: Arc<Counters>,
    active: bool,
}
impl QueueMark {
    fn new(counters: Arc<Counters>) -> Self {
        counters.queued.fetch_add(1, Ordering::Relaxed);
        Self {
            counters,
            active: false,
        }
    }
    fn activate(&mut self) {
        self.counters.queued.fetch_sub(1, Ordering::Relaxed);
        self.counters.active.fetch_add(1, Ordering::Relaxed);
        self.active = true;
    }
}
impl Drop for QueueMark {
    fn drop(&mut self) {
        if self.active {
            self.counters.active.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.counters.queued.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
struct Job {
    mark: QueueMark,
    operation: Operation,
    context: ControlContext,
    reply: oneshot::Sender<Result<Reply, ControlError>>,
}
struct Inner {
    sender: mpsc::Sender<Job>,
    stop: CancellationToken,
    counters: Arc<Counters>,
    workers: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
#[derive(Clone)]
pub struct ControlClient {
    inner: Arc<Inner>,
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl ControlClient {
    pub fn new(settings: ConnectionSettings) -> Result<Self, ControlError> {
        Self::with_identity(settings, schema_identity().1)
    }
    /// Explicit revision3 restored runtime profile, never an automatic fallback.
    pub fn restored(settings: ConnectionSettings) -> Result<Self, ControlError> {
        Self::with_identity(settings, crate::restored_schema_identity().1)
    }
    /// Explicit revision4 catalog profile; never migrate or fall back during open.
    pub fn catalog(settings: ConnectionSettings) -> Result<Self, ControlError> {
        Self::with_identity(settings, crate::catalog_schema_identity().1)
    }
    /// Explicit revision5 restored catalog runtime; never automatic fallback.
    pub fn restored_catalog(settings: ConnectionSettings) -> Result<Self, ControlError> {
        Self::with_identity(settings, crate::restored_catalog_schema_identity().1)
    }
    fn with_identity(
        settings: ConnectionSettings,
        routines_identity: [u8; 32],
    ) -> Result<Self, ControlError> {
        tokio::runtime::Handle::try_current().map_err(|_| ControlError::Invalid)?;
        let (sender, receiver) = mpsc::channel::<Job>(COMMANDS);
        let receiver = Arc::new(Mutex::new(receiver));
        let settings = Arc::new(settings);
        let counters = Arc::new(Counters::default());
        let stop = CancellationToken::new();
        let mut workers = Vec::with_capacity(CONNECTIONS);
        for _ in 0..CONNECTIONS {
            let receiver = receiver.clone();
            let settings = settings.clone();
            let stopping = stop.clone();
            workers.push(tokio::spawn(async move {
                loop {
                    let job = tokio::select! { biased;
                        ()=stopping.cancelled()=>None,
                        value=async { receiver.lock().await.recv().await }=>value,
                    };
                    let Some(mut job) = job else {
                        break;
                    };
                    job.mark.activate();
                    // All read retries share the original admission context and
                    // one transaction budget. Only confirmed aborted transactions retry.
                    let budget = job
                        .context
                        .deadline
                        .min(tokio::time::Instant::now() + std::time::Duration::from_secs(2));
                    let mut rounds = 1;
                    let mut completion = execute(
                        &settings,
                        &job.operation,
                        &job.context,
                        &stopping,
                        budget,
                        routines_identity,
                    )
                    .await;
                    while matches!(
                        &job.operation,
                        Operation::Snapshot { .. }
                            | Operation::Catalog { .. }
                            | Operation::Feed { .. }
                            | Operation::ScopedList { .. }
                            | Operation::ExistingFindingScope { .. }
                            | Operation::ProducerCredentials { .. }
                    ) && completion.rollback_confirmed
                        && matches!(&completion.result, Err(ControlError::Retryable))
                        && rounds < 3
                        && job.context.check().is_ok()
                        && !stopping.is_cancelled()
                        && tokio::time::Instant::now() < budget
                    {
                        rounds += 1;
                        job.mark
                            .counters
                            .snapshot_retries
                            .fetch_add(1, Ordering::Relaxed);
                        completion = execute(
                            &settings,
                            &job.operation,
                            &job.context,
                            &stopping,
                            budget,
                            routines_identity,
                        )
                        .await;
                    }
                    let result = match completion.result {
                        Ok(value) => job
                            .context
                            .check()
                            .map(|()| value)
                            .map_err(|_| ControlError::Uncertain),
                        error => error,
                    };
                    let _ = job.reply.send(result);
                    if !completion.rollback_confirmed {
                        // Do not replace an unconfirmed remote transaction with new work.
                        job.mark
                            .counters
                            .quarantined
                            .fetch_add(1, Ordering::Relaxed);
                        stopping.cancelled().await;
                        break;
                    }
                }
                // Shutdown retires every accepted queued command, without false success.
                let mut receiver = receiver.lock().await;
                receiver.close();
                while let Ok(job) = receiver.try_recv() {
                    let _ = job.reply.send(Err(ControlError::Cancelled));
                }
            }));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                sender,
                stop,
                counters,
                workers: Mutex::new(workers),
            }),
        })
    }
    pub fn metrics(&self) -> ControlMetrics {
        ControlMetrics {
            queue_depth: self.inner.counters.queued.load(Ordering::Relaxed),
            queue_capacity: COMMANDS,
            active: self.inner.counters.active.load(Ordering::Relaxed),
            connection_capacity: CONNECTIONS,
            rejected: self.inner.counters.rejected.load(Ordering::Relaxed),
            quarantined: self.inner.counters.quarantined.load(Ordering::Relaxed),
            notification_uncertain_results: self
                .inner
                .counters
                .notification_uncertain_results
                .load(Ordering::Relaxed),
            snapshot_expired: self.inner.counters.snapshot_expired.load(Ordering::Relaxed),
            snapshot_retries: self.inner.counters.snapshot_retries.load(Ordering::Relaxed),
        }
    }
    pub async fn acquire(
        &self,
        scope: Scope,
        owner: Uuid,
        lease_ms: u32,
        context: ControlContext,
    ) -> Result<LeaseToken, ControlError> {
        scope.validate()?;
        if owner.is_nil() || !(15000..=60000).contains(&lease_ms) {
            return Err(ControlError::Invalid);
        }
        self.submit(
            Operation::Acquire {
                scope,
                owner,
                lease_ms: lease_ms as i32,
            },
            context,
        )
        .await
        .and_then(|reply| match reply {
            Reply::Lease(token) => Ok(token),
            _ => Err(ControlError::Corrupt),
        })
    }
    pub async fn renew(
        &self,
        token: LeaseToken,
        lease_ms: u32,
        context: ControlContext,
    ) -> Result<LeaseToken, ControlError> {
        token.validate()?;
        if !(15000..=60000).contains(&lease_ms) {
            return Err(ControlError::Invalid);
        }
        self.submit(
            Operation::Renew {
                token,
                lease_ms: lease_ms as i32,
            },
            context,
        )
        .await
        .and_then(|reply| match reply {
            Reply::Lease(token) => Ok(token),
            _ => Err(ControlError::Corrupt),
        })
    }
    /// Retain metadata only; this never grants source acknowledgement authority.
    pub async fn record_receipt(
        &self,
        token: LeaseToken,
        receipt: ReceiptInput,
        context: ControlContext,
    ) -> Result<ReceiptResult, ControlError> {
        token.validate()?;
        context.check()?;
        let raw = receipt.wire()?;
        let expected = ReceiptResult {
            schema_version: 1,
            id: receipt.id,
            prepared_count: receipt.prepared_count,
            source_record_count: receipt.source_record_count,
            verified_prefix: 0,
        };
        match self
            .submit(
                Operation::Receipt {
                    token,
                    raw,
                    expected,
                },
                context,
            )
            .await?
        {
            Reply::Receipt(value) => Ok(value),
            _ => Err(ControlError::Corrupt),
        }
    }
    pub async fn publish(
        &self,
        token: LeaseToken,
        publication: PublicationInput,
        context: ControlContext,
    ) -> Result<PublicationResult, ControlError> {
        self.publication(token, publication, None, false, context)
            .await
    }
    /// Resolve the exact retained request under current authority. Absence stays uncertain.
    pub async fn resolve_publication(
        &self,
        token: LeaseToken,
        publication: PublicationInput,
        context: ControlContext,
    ) -> Result<PublicationResult, ControlError> {
        self.publication(token, publication, None, true, context)
            .await
    }
    pub async fn publish_scoped(
        &self,
        token: LeaseToken,
        input: crate::ScopedPublicationInput,
        context: ControlContext,
    ) -> Result<PublicationResult, ControlError> {
        context.check()?;
        token.validate()?;
        let claims = input.wire(&token.scope)?;
        self.publication(
            token,
            input.publication().clone(),
            Some(claims),
            false,
            context,
        )
        .await
    }
    pub async fn resolve_scoped_publication(
        &self,
        token: LeaseToken,
        input: crate::ScopedPublicationInput,
        context: ControlContext,
    ) -> Result<PublicationResult, ControlError> {
        context.check()?;
        token.validate()?;
        let claims = input.wire(&token.scope)?;
        self.publication(
            token,
            input.publication().clone(),
            Some(claims),
            true,
            context,
        )
        .await
    }
    async fn publication(
        &self,
        token: LeaseToken,
        publication: PublicationInput,
        claims: Option<Vec<u8>>,
        resolve_only: bool,
        context: ControlContext,
    ) -> Result<PublicationResult, ControlError> {
        token.validate()?;
        context.check()?;
        let raw = publication.wire(&token.scope)?;
        let expected = PublicationResult {
            schema_version: 1,
            id: publication.id,
            first_sequence: publication.first_sequence,
            last_sequence: publication.last_sequence,
            cursor: String::new(),
            request_sha256: crate::publication::request_digest(&raw),
        };
        match self
            .submit(
                Operation::Publish {
                    token,
                    raw,
                    claims,
                    resolve_only,
                    expected,
                },
                context,
            )
            .await?
        {
            Reply::Publication(value) => Ok(value),
            _ => Err(ControlError::Corrupt),
        }
    }
    /// Requires explicit database global SELECT authority AND an authenticated
    /// current all-scope host grant. Producer permissions confer neither.
    pub async fn read_findings_feed(
        &self,
        store: Uuid,
        generation: Uuid,
        query: signal_protocol::findings_feed::FindingsFeedQuery,
        grant: Arc<signal_protocol::access::RequestGrant>,
        context: ControlContext,
    ) -> Result<crate::AuthorizedFindingsPage, ControlError> {
        let mut read = crate::global_feed::FeedRead {
            store,
            generation,
            query,
            grant,
            output_context: context.clone(),
            stopping: self.inner.stop.child_token(),
        };
        let context = read.budget(context)?;
        read.output_context = context.clone();
        match self.submit(Operation::Feed { read }, context).await? {
            Reply::Feed(page) => {
                page.next_cursor()?;
                Ok(page)
            }
            _ => Err(ControlError::Corrupt),
        }
    }
    /// Requires independently configured SELECT credentials plus a current
    /// ReadFindings grant. Producer EXECUTE authority is insufficient. No feed
    /// cursor is created; paired scope selection precedes user filters/limits.
    pub async fn read_scoped_findings(
        &self,
        binding: crate::ScopedFindingsBinding,
        query: signal_findings::FindingQuery,
        grant: Arc<signal_protocol::access::RequestGrant>,
        context: ControlContext,
    ) -> Result<crate::AuthorizedFindingsList, ControlError> {
        let mut read = crate::scoped_read::ScopedRead {
            binding,
            query,
            grant,
            output_context: context.clone(),
            stopping: self.inner.stop.child_token(),
        };
        let context = read.budget(context)?;
        read.output_context = context.clone();
        match self.submit(Operation::ScopedList { read }, context).await? {
            Reply::ScopedList(list) => {
                list.findings()?;
                Ok(list)
            }
            _ => Err(ControlError::Corrupt),
        }
    }
    /// Fresh inspection of an existing owner-enrolled producer, using separately
    /// configured read-only credentials. Never activates or enrolls a producer.
    /// The pin is current configuration evidence, not credentials for old rows.
    pub async fn inspect_existing_finding_scope(
        &self,
        scope: Scope,
        binding: crate::ScopedFindingsBinding,
        context: ControlContext,
    ) -> Result<crate::FindingScopePin, ControlError> {
        scope.validate()?;
        binding.validate()?;
        if scope.store_id != binding.store || scope.generation != binding.generation {
            return Err(ControlError::Fenced);
        }
        context.check()?;
        let original = context.clone();
        match self
            .submit(Operation::ExistingFindingScope { scope, binding }, context)
            .await?
        {
            Reply::FindingScope(binding) => {
                crate::FindingScopePin::new(binding, original, self.inner.stop.child_token())
            }
            _ => Err(ControlError::Corrupt),
        }
    }
    /// Check captured runtime credentials without owner role switching or DDL.
    /// This proves privilege separation at inspection time, not future ACL state.
    pub async fn verify_producer_credentials(
        &self,
        schema_owner: String,
        context: ControlContext,
    ) -> Result<(), ControlError> {
        if schema_owner.is_empty()
            || schema_owner.len() > 63
            || schema_owner.capacity() > 63
            || !schema_owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(ControlError::Invalid);
        }
        context.check()?;
        match self
            .submit(
                Operation::ProducerCredentials {
                    owner: schema_owner,
                },
                context,
            )
            .await?
        {
            Reply::ProducerCredentials => Ok(()),
            _ => Err(ControlError::Corrupt),
        }
    }
    /// Pin exact committed manifests without holding a DB transaction during object I/O.
    pub async fn read_catalog_snapshot(
        &self,
        scope: Scope,
        input: CatalogInput,
        context: ControlContext,
    ) -> Result<CatalogPin, ControlError> {
        scope.validate()?;
        input.validate()?;
        context.check()?;
        let started = tokio::time::Instant::now();
        let result = match self
            .submit(
                Operation::Catalog {
                    scope,
                    input,
                    started,
                },
                context,
            )
            .await
        {
            Ok(Reply::Catalog(pin)) => pin.snapshot().map(|_| ()).map(|()| pin),
            Ok(_) => Err(ControlError::Corrupt),
            Err(error) => Err(error),
        };
        if matches!(&result, Err(ControlError::SnapshotExpired)) {
            self.inner
                .counters
                .snapshot_expired
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }
    /// Pin caller-supplied exact IDs; complete dynamic discovery uses read_catalog_snapshot.
    pub async fn read_snapshot(
        &self,
        scope: Scope,
        input: SnapshotInput,
        context: ControlContext,
    ) -> Result<SnapshotPin, ControlError> {
        scope.validate()?;
        input.validate()?;
        context.check()?;
        let started = tokio::time::Instant::now();
        let result = match self
            .submit(
                Operation::Snapshot {
                    scope,
                    input,
                    started,
                },
                context,
            )
            .await
        {
            Ok(Reply::Snapshot(pin)) => pin.check().map(|()| pin),
            Ok(_) => Err(ControlError::Corrupt),
            Err(error) => Err(error),
        };
        if matches!(&result, Err(ControlError::SnapshotExpired)) {
            self.inner
                .counters
                .snapshot_expired
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }
    pub async fn pin_object(
        &self,
        token: LeaseToken,
        input: RetentionPinInput,
        context: ControlContext,
    ) -> Result<ObjectControlResult, ControlError> {
        let raw = input.wire(&token.scope)?;
        let reference = crate::publication::hex(&input.object.digest()?);
        self.object_control(
            token,
            raw,
            input.id,
            ObjectControlState::Retained,
            Some(reference),
            context,
        )
        .await
    }
    pub async fn release_object_pin(
        &self,
        token: LeaseToken,
        input: ReleasePinInput,
        context: ControlContext,
    ) -> Result<ObjectControlResult, ControlError> {
        self.object_control(
            token,
            input.wire()?,
            input.id,
            ObjectControlState::Released,
            None,
            context,
        )
        .await
    }
    /// Logical irreversible retirement only; never an authority to delete provider bytes.
    pub async fn retire_object(
        &self,
        token: LeaseToken,
        input: RetirementInput,
        context: ControlContext,
    ) -> Result<ObjectControlResult, ControlError> {
        let raw = input.wire(&token.scope)?;
        let reference = crate::publication::hex(&input.object.digest()?);
        self.object_control(
            token,
            raw,
            input.id,
            ObjectControlState::Retired,
            Some(reference),
            context,
        )
        .await
    }
    pub(crate) async fn administer(
        &self,
        owner: String,
        action: crate::administration::AdministrativeAction,
        context: ControlContext,
    ) -> Result<crate::AdministrativeResult, ControlError> {
        action.validate()?;
        context.check()?;
        match self
            .submit(Operation::Administration { owner, action }, context)
            .await?
        {
            Reply::Administration(result) => Ok(result),
            _ => Err(ControlError::Corrupt),
        }
    }
    pub(crate) async fn administer_finding_scope(
        &self,
        owner: String,
        profile: crate::FindingScopeProfile,
        action: crate::finding_scope::Action,
        context: ControlContext,
    ) -> Result<crate::FindingScopePin, ControlError> {
        action.validate()?;
        context.check()?;
        let original = context.clone();
        match self
            .submit(
                Operation::FindingScope {
                    owner,
                    profile,
                    action,
                },
                context,
            )
            .await?
        {
            Reply::FindingScope(binding) => {
                crate::FindingScopePin::new(binding, original, self.inner.stop.child_token())
            }
            _ => Err(ControlError::Corrupt),
        }
    }
    /// Execute notification metadata only. Resolve never authorizes a send.
    pub async fn notification(
        &self,
        token: LeaseToken,
        input: NotificationInput,
        context: ControlContext,
    ) -> Result<NotificationResult, ControlError> {
        token.validate()?;
        context.check()?;
        let raw = input.wire()?;
        let result = self
            .submit(Operation::Notification { token, input, raw }, context)
            .await;
        if matches!(&result, Err(ControlError::Uncertain))
            || matches!(&result,Ok(Reply::Notification(r)) if r.outcome==crate::NotificationState::Uncertain)
        {
            self.inner
                .counters
                .notification_uncertain_results
                .fetch_add(1, Ordering::Relaxed);
        }
        match result? {
            Reply::Notification(result) => Ok(result),
            _ => Err(ControlError::Corrupt),
        }
    }
    async fn object_control(
        &self,
        token: LeaseToken,
        raw: Vec<u8>,
        id: Uuid,
        state: ObjectControlState,
        reference: Option<String>,
        context: ControlContext,
    ) -> Result<ObjectControlResult, ControlError> {
        token.validate()?;
        context.check()?;
        match self
            .submit(
                Operation::Object {
                    token,
                    raw,
                    id,
                    state,
                    reference,
                },
                context,
            )
            .await?
        {
            Reply::Object(result) => Ok(result),
            _ => Err(ControlError::Corrupt),
        }
    }
    async fn submit(
        &self,
        operation: Operation,
        mut context: ControlContext,
    ) -> Result<Reply, ControlError> {
        context.check()?;
        if self.inner.stop.is_cancelled() {
            return Err(ControlError::Cancelled);
        }
        context.cancellation = context.cancellation.child_token();
        let _cancel = CancelOnDrop(context.cancellation.clone());
        let permit = self.inner.sender.try_reserve().map_err(|_| {
            self.inner.counters.rejected.fetch_add(1, Ordering::Relaxed);
            ControlError::Full
        })?;
        let (reply, receiver) = oneshot::channel();
        permit.send(Job {
            mark: QueueMark::new(self.inner.counters.clone()),
            operation,
            context: context.clone(),
            reply,
        });
        receive(receiver, &context, &self.inner.stop).await
    }
    pub(crate) async fn restore(
        &self,
        owner: String,
        plan: Arc<crate::postgres_restore::RestorePlan>,
        action: crate::postgres_restore::RestoreAction,
        context: ControlContext,
    ) -> Result<crate::postgres_restore::RestoreReply, ControlError> {
        context.check()?;
        match self
            .submit(
                Operation::Restore {
                    owner,
                    plan,
                    action: Box::new(action),
                },
                context,
            )
            .await?
        {
            Reply::Restore(r) => Ok(r),
            _ => Err(ControlError::Corrupt),
        }
    }
    pub async fn shutdown(&self, context: ControlContext) -> Result<(), ControlError> {
        context.check()?;
        self.inner.stop.cancel();
        let mut workers = tokio::select! {biased;
            ()=context.cancellation.cancelled()=>return Err(ControlError::Cancelled),
            value=tokio::time::timeout_at(context.deadline, self.inner.workers.lock())=>value.map_err(|_|ControlError::Timeout)?,
        };
        // Await borrowed handles: a timeout leaves ownership retained for another shutdown.
        while let Some(worker) = workers.last_mut() {
            let result = tokio::select! {biased;
                ()=context.cancellation.cancelled()=>return Err(ControlError::Cancelled),
                value=tokio::time::timeout_at(context.deadline,worker)=>value.map_err(|_|ControlError::Timeout)?,
            };
            workers.pop();
            result.map_err(|_| ControlError::Unavailable)?;
        }
        context.check()?;
        if self.inner.counters.quarantined.load(Ordering::Relaxed) != 0 {
            return Err(ControlError::Uncertain);
        }
        Ok(())
    }
}
pub(crate) fn database_error(error: tokio_postgres::Error) -> ControlError {
    if let Some(db) = error.as_db_error() {
        if matches!(db.code().code(), "42501") {
            return ControlError::Fenced;
        }
        if matches!(db.code().code(), "42P01" | "42703" | "42P07") {
            return ControlError::Corrupt;
        }
        if matches!(db.code().code(), "42P06") {
            return ControlError::Conflict;
        }
        if matches!(db.code().code(), "40001" | "40P01" | "55P03") {
            return ControlError::Retryable;
        }
        return match db.message() {
            "SIGNAL_INVALID" => ControlError::Invalid,
            "SIGNAL_FENCED" => ControlError::Fenced,
            "SIGNAL_FULL" => ControlError::Full,
            "SIGNAL_CONFLICT" => ControlError::Conflict,
            "SIGNAL_UNCERTAIN" => ControlError::Uncertain,
            "SIGNAL_CORRUPT" => ControlError::Corrupt,
            "SIGNAL_SNAPSHOT_EXPIRED" => ControlError::SnapshotExpired,
            _ => ControlError::Unavailable,
        };
    }
    ControlError::Unavailable
}
async fn receive<T>(
    receiver: oneshot::Receiver<Result<T, ControlError>>,
    context: &ControlContext,
    stop: &CancellationToken,
) -> Result<T, ControlError> {
    // The command is admitted: absence of its reply never proves no mutation.
    let result = tokio::select! {biased;
        ()=context.cancellation.cancelled()=>Err(ControlError::Uncertain),
        ()=stop.cancelled()=>Err(ControlError::Uncertain),
        value=tokio::time::timeout_at(context.deadline,receiver)=>match value {
            Ok(Ok(value))=>value,
            _=>Err(ControlError::Uncertain),
        },
    };
    match result {
        Ok(value) => context
            .check()
            .map(|()| value)
            .map_err(|_| ControlError::Uncertain),
        error => error,
    }
}
fn final_transaction_result<T>(
    result: Result<T, ControlError>,
    deadline: tokio::time::Instant,
    context: &ControlContext,
) -> Result<T, ControlError> {
    if result.is_ok() && (tokio::time::Instant::now() >= deadline || context.check().is_err()) {
        Err(ControlError::Uncertain)
    } else {
        result
    }
}
struct Completion {
    result: Result<Reply, ControlError>,
    rollback_confirmed: bool,
}
async fn execute(
    settings: &ConnectionSettings,
    operation: &Operation,
    context: &ControlContext,
    stop: &CancellationToken,
    transaction_deadline: tokio::time::Instant,
    routines_identity: [u8; 32],
) -> Completion {
    let connection_context = if matches!(
        operation,
        Operation::Snapshot { .. }
            | Operation::Catalog { .. }
            | Operation::Feed { .. }
            | Operation::ScopedList { .. }
            | Operation::ExistingFindingScope { .. }
            | Operation::ProducerCredentials { .. }
    ) {
        ControlContext {
            deadline: transaction_deadline,
            cancellation: context.cancellation.clone(),
        }
    } else {
        context.clone()
    };
    let connection = tokio::select! {biased;
        ()=stop.cancelled()=>Err(ControlError::Cancelled),
        value=settings.connect(&connection_context)=>value,
    };
    let mut connection = match connection {
        Ok(value) => value,
        Err(error) => {
            return Completion {
                result: Err(error),
                rollback_confirmed: true,
            };
        }
    };
    let transaction_deadline = if matches!(
        operation,
        Operation::Snapshot { .. }
            | Operation::Catalog { .. }
            | Operation::Feed { .. }
            | Operation::ScopedList { .. }
            | Operation::ExistingFindingScope { .. }
            | Operation::ProducerCredentials { .. }
    ) {
        transaction_deadline
    } else {
        context
            .deadline
            .min(tokio::time::Instant::now() + std::time::Duration::from_secs(2))
    };
    let schema = schema_identity().0;
    let routines = routines_identity;
    let schema = schema.as_slice();
    let routines = routines.as_slice();
    let mut commit_started = false;
    let query = async {
        context.check()?;
        connection
            .client
            .batch_execute(
                if matches!(
                    operation,
                    Operation::Snapshot { .. }
                        | Operation::Catalog { .. }
                        | Operation::Feed { .. }
                        | Operation::ScopedList { .. }
                        | Operation::ExistingFindingScope { .. }
                        | Operation::ProducerCredentials { .. }
                ) {
                    if matches!(
                        operation,
                        Operation::Feed { .. }
                            | Operation::ScopedList { .. }
                            | Operation::ExistingFindingScope { .. }
                            | Operation::ProducerCredentials { .. }
                    ) {
                        "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY"
                    } else {
                        "BEGIN ISOLATION LEVEL REPEATABLE READ"
                    }
                } else {
                    "BEGIN"
                },
            )
            .await
            .map_err(database_error)?;
        let reply = if let Operation::ProducerCredentials { owner } = operation {
            let row = connection.client.query_one(
                "SELECT NOT pg_has_role(session_user,$1::name,'MEMBER')
                AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE pg_has_role(session_user,r.oid,'MEMBER')
                    AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
                    OR has_database_privilege(r.oid,current_database(),'CREATE')
                    OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('signal_control','signal_finding_scope')
                        AND (has_schema_privilege(r.oid,n.oid,'CREATE') OR pg_has_role(r.oid,n.nspowner,'MEMBER')))
                    OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                        WHERE n.nspname IN ('signal_control','signal_finding_scope')
                        AND (has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION')
                        OR (has_function_privilege(r.oid,p.oid,'EXECUTE') AND p.oid NOT IN (
                            'signal_control.acquire(jsonb,uuid,integer,bytea,bytea)'::regprocedure,
                            'signal_control.renew(jsonb,integer,bytea,bytea)'::regprocedure,
                            'signal_control.read_catalog_snapshot(jsonb,uuid,integer,bytea,bytea)'::regprocedure,
                            'signal_control.publish(jsonb,bytea,boolean,bytea,bytea)'::regprocedure,
                            'signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text)'::regprocedure))))
                    OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                        WHERE n.nspname IN ('signal_control','signal_finding_scope')
                        AND (pg_has_role(r.oid,c.relowner,'MEMBER')
                        OR (c.relkind IN ('r','p','v','m','f') AND
                            (has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
                            OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
                        OR (c.relkind='S' AND has_sequence_privilege(r.oid,c.oid,'USAGE,SELECT,UPDATE'))))))",
                &[owner],
            ).await.map_err(database_error)?;
            if !row
                .try_get::<_, bool>(0)
                .map_err(|_| ControlError::Corrupt)?
            {
                return Err(ControlError::Fenced);
            }
            Reply::ProducerCredentials
        } else if let Operation::FindingScope {
            owner,
            profile,
            action,
        } = operation
        {
            Reply::FindingScope(
                crate::finding_scope::run(&connection.client, owner, *profile, action, context)
                    .await?,
            )
        } else if let Operation::ExistingFindingScope { scope, binding } = operation {
            Reply::FindingScope(
                crate::finding_scope::read_existing(
                    &connection.client,
                    scope,
                    binding,
                    context,
                    routines_identity,
                )
                .await?,
            )
        } else if let Operation::Feed { read } = operation {
            Reply::Feed(
                crate::global_feed::run(&connection.client, read, context, routines_identity)
                    .await?,
            )
        } else if let Operation::ScopedList { read } = operation {
            Reply::ScopedList(
                crate::scoped_read::run(&connection.client, read, context, routines_identity)
                    .await?,
            )
        } else {
            let row = if let Operation::Restore {
                owner,
                plan,
                action,
            } = operation
            {
                crate::postgres_restore::run(&connection.client, owner, plan, action, context)
                    .await?
            } else if let Operation::Administration { owner, action } = operation {
                crate::administration::run(&connection.client, owner, action).await?
            } else {
                match operation {
                    Operation::Catalog { scope, input, .. } => {
                        let scope =
                            serde_json::to_value(scope).map_err(|_| ControlError::Invalid)?;
                        let lifetime = input.pin_ms as i32;
                        connection
                            .client
                            .query_one(
                                "SELECT signal_control.read_catalog_snapshot($1,$2,$3,$4,$5)",
                                &[&scope, &input.id, &lifetime, &schema, &routines],
                            )
                            .await
                    }
                    Operation::Administration { .. }
                    | Operation::Restore { .. }
                    | Operation::Feed { .. } | Operation::ScopedList { .. }
                        | Operation::ExistingFindingScope { .. }
                        | Operation::ProducerCredentials { .. }
                    | Operation::FindingScope { .. } => {
                        return Err(ControlError::Corrupt);
                    }
                    Operation::Notification { token, raw, .. } => {
                        let token =
                            serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
                        connection
                            .client
                            .query_one(
                                "SELECT signal_control.notification($1,$2,$3,$4)",
                                &[&token, raw, &schema, &routines],
                            )
                            .await
                    }
                    Operation::Object { token, raw, .. } => {
                        let token =
                            serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
                        connection
                            .client
                            .query_one(
                                "SELECT signal_control.object_control($1,$2,$3,$4)",
                                &[&token, raw, &schema, &routines],
                            )
                            .await
                    }
                    Operation::Snapshot { scope, input, .. } => {
                        let scope =
                            serde_json::to_value(scope).map_err(|_| ControlError::Invalid)?;
                        let pin_ms = input.pin_ms as i32;
                        connection
                            .client
                            .query_one(
                                "SELECT signal_control.read_snapshot($1,$2,$3,$4,$5,$6)",
                                &[
                                    &scope,
                                    &input.id,
                                    &input.manifest_ids,
                                    &pin_ms,
                                    &schema,
                                    &routines,
                                ],
                            )
                            .await
                    }
                    Operation::Acquire {
                        scope,
                        owner,
                        lease_ms,
                    } => {
                        let scope =
                            serde_json::to_value(scope).map_err(|_| ControlError::Invalid)?;
                        connection
                            .client
                            .query_one(
                                "SELECT signal_control.acquire($1,$2,$3,$4,$5)",
                                &[&scope, owner, lease_ms, &schema, &routines],
                            )
                            .await
                    }
                    Operation::Renew { token, lease_ms } => {
                        let token =
                            serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
                        connection
                            .client
                            .query_one(
                                "SELECT signal_control.renew($1,$2,$3,$4)",
                                &[&token, lease_ms, &schema, &routines],
                            )
                            .await
                    }
                    Operation::Receipt { token, raw, .. } => {
                        let token =
                            serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
                        connection
                            .client
                            .query_one(
                                "SELECT signal_control.record_receipt($1,$2,$3,$4)",
                                &[&token, raw, &schema, &routines],
                            )
                            .await
                    }
                    Operation::Publish {
                        token, raw, claims, resolve_only, ..
                    } => {
                        let token = serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
                        if let Some(claims) = claims {
                            let catalog = include_str!("../../../schemas/shared-control/008-scoped-publication-catalog.sha256").trim();
                            let functions = include_str!("../../../schemas/shared-control/008-scoped-publication-functions.sha256").trim();
                            connection.client.query_one(
                                "SELECT signal_finding_scope.publish($1,$2,$3,$4,$5,$6,$7,$8)",
                                &[&token, raw, claims, resolve_only, &schema, &routines, &catalog, &functions],
                            ).await
                        } else {
                            connection.client.query_one(
                                "SELECT signal_control.publish($1,$2,$3,$4,$5)",
                                &[&token, raw, resolve_only, &schema, &routines],
                            ).await
                        }
                    }
                }
                .map_err(database_error)?
            };
            let value: serde_json::Value = row.try_get(0).map_err(|_| ControlError::Corrupt)?;
            match operation {
                Operation::Feed { .. }
                | Operation::ScopedList { .. }
                | Operation::ExistingFindingScope { .. }
                | Operation::ProducerCredentials { .. }
                | Operation::FindingScope { .. } => {
                    return Err(ControlError::Corrupt);
                }
                Operation::Restore { action, plan, .. } => {
                    let reply: crate::postgres_restore::RestoreReply =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    crate::postgres_restore::validate_reply(action, &reply, plan)?;
                    Reply::Restore(reply)
                }
                Operation::Administration { action, .. } => {
                    let result: crate::AdministrativeResult =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    let scope = action.scope();
                    if result.schema_version != 1
                        || result.store_id != scope.store_id
                        || result.generation != scope.generation
                        || result.revision != action.revision()
                        || result.routines_sha256 != crate::publication::hex(&action.identity())
                        || (!action.inspection() && result.ready)
                    {
                        return Err(ControlError::Corrupt);
                    }
                    Reply::Administration(result)
                }
                Operation::Notification { token, input, raw } => {
                    let result: crate::notification::NotificationReply =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    Reply::Notification(result.validate(token, input, raw)?)
                }
                Operation::Object {
                    raw,
                    id,
                    state,
                    reference,
                    ..
                } => {
                    let result: ObjectControlResult =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    if result.schema_version != 1
                        || result.id != *id
                        || result.state != *state
                        || result.request_sha256 != crate::publication::request_digest(raw)
                        || result.reference_sha256.len() != 64
                        || !result
                            .reference_sha256
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        || reference
                            .as_ref()
                            .is_some_and(|r| r != &result.reference_sha256)
                    {
                        return Err(ControlError::Corrupt);
                    }
                    Reply::Object(result)
                }
                Operation::Snapshot {
                    scope,
                    input,
                    started,
                } => {
                    let result: crate::snapshot::SnapshotReply =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    Reply::Snapshot(result.pin(scope, input, *started)?)
                }
                Operation::Catalog {
                    scope,
                    input,
                    started,
                } => {
                    let result: crate::catalog::CatalogReply =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    Reply::Catalog(result.pin(scope, input, *started)?)
                }
                Operation::Acquire { scope, owner, .. } => {
                    let token: LeaseToken =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    token.validate()?;
                    if &token.scope != scope || &token.owner != owner {
                        return Err(ControlError::Corrupt);
                    }
                    Reply::Lease(token)
                }
                Operation::Renew {
                    token: expected, ..
                } => {
                    let token: LeaseToken =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    token.validate()?;
                    if &token != expected {
                        return Err(ControlError::Corrupt);
                    }
                    Reply::Lease(token)
                }
                Operation::Receipt { expected, .. } => {
                    let result: ReceiptResult =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    if result.schema_version != 1
                        || result.id != expected.id
                        || result.prepared_count != expected.prepared_count
                        || result.source_record_count != expected.source_record_count
                        || result.verified_prefix > result.prepared_count
                    {
                        return Err(ControlError::Corrupt);
                    }
                    Reply::Receipt(result)
                }
                Operation::Publish {
                    token, expected, ..
                } => {
                    let result: PublicationResult =
                        serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
                    let cursor =
                        signal_protocol::findings_feed::FindingsCursor::decode(&result.cursor)
                            .map_err(|_| ControlError::Corrupt)?;
                    if result.schema_version != 1
                        || result.id != expected.id
                        || result.first_sequence != expected.first_sequence
                        || result.last_sequence != expected.last_sequence
                        || result.request_sha256 != expected.request_sha256
                        || cursor.stream() != token.scope.store_id
                        || cursor.position() > i64::MAX as u64
                    {
                        return Err(ControlError::Corrupt);
                    }
                    Reply::Publication(result)
                }
            }
        };
        // Publish only while the original transaction and operation budgets remain.
        context.check()?;
        if tokio::time::Instant::now() >= transaction_deadline {
            return Err(ControlError::Timeout);
        }
        commit_started = true;
        connection
            .client
            .batch_execute("COMMIT")
            .await
            .map_err(database_error)?;
        Ok(reply)
    };
    let result = tokio::select! {biased;
        ()=stop.cancelled()=>Err(ControlError::Cancelled),
        ()=context.cancellation.cancelled()=>Err(ControlError::Cancelled),
        value=tokio::time::timeout_at(transaction_deadline,query)=>match value {Ok(value)=>value,Err(_)=>Err(ControlError::Timeout)},
    };
    let result = final_transaction_result(result, transaction_deadline, context);
    // Protocol ordering puts ROLLBACK after any dropped in-flight query. Keep
    // the driver and seat until its response, even after the caller has left.
    let (result, rollback_confirmed) = match result {
        Ok(value) => (Ok(value), true),
        Err(error) => {
            let rolled_back = matches!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(2500),
                    connection.client.batch_execute("ROLLBACK"),
                )
                .await,
                Ok(Ok(()))
            );
            let error = if commit_started || !rolled_back {
                ControlError::Uncertain
            } else {
                error
            };
            (Err(error), rolled_back)
        }
    };
    connection.retire().await;
    Completion {
        result,
        rollback_confirmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::IpAddr, time::Duration};
    fn scope() -> Scope {
        Scope {
            schema_version: 1,
            store_id: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            tenant: "synthetic".into(),
            stream: Uuid::new_v4(),
            partition_id: Uuid::new_v4(),
        }
    }
    #[tokio::test]
    async fn buffered_success_after_deadline_never_grants_authority() -> Result<(), ControlError> {
        let context = ControlContext::new(Duration::from_millis(1))?;
        let (send, receive_reply) = oneshot::channel();
        let _ = send.send(Ok(LeaseToken {
            scope: scope(),
            owner: Uuid::new_v4(),
            epoch: 1,
        }));
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(matches!(
            receive(receive_reply, &context, &CancellationToken::new()).await,
            Err(ControlError::Uncertain)
        ));
        Ok(())
    }
    #[tokio::test]
    async fn late_commit_reply_cannot_extend_the_transaction_budget() -> Result<(), ControlError> {
        let context = ControlContext::new(Duration::from_secs(5))?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1);
        tokio::time::sleep(Duration::from_millis(5)).await;
        let reply = Ok(LeaseToken {
            scope: scope(),
            owner: Uuid::new_v4(),
            epoch: 1,
        });
        assert!(matches!(
            final_transaction_result(reply, deadline, &context),
            Err(ControlError::Uncertain)
        ));
        assert!(context.check().is_ok());
        Ok(())
    }
    #[tokio::test]
    async fn admitted_cancellation_is_uncertain_and_not_success() -> Result<(), ControlError> {
        let context = ControlContext::new(Duration::from_secs(1))?;
        let (send, receive_reply) = oneshot::channel();
        let _ = send.send(Ok(LeaseToken {
            scope: scope(),
            owner: Uuid::new_v4(),
            epoch: 1,
        }));
        context.cancel();
        assert!(matches!(
            receive(receive_reply, &context, &CancellationToken::new()).await,
            Err(ControlError::Uncertain)
        ));
        Ok(())
    }
    #[test]
    fn queue_mark_counts_discarded_and_active_work_exactly() {
        let counters = Arc::new(Counters::default());
        let queued = QueueMark::new(counters.clone());
        let mut active = QueueMark::new(counters.clone());
        active.activate();
        assert_eq!(counters.queued.load(Ordering::Relaxed), 1);
        assert_eq!(counters.active.load(Ordering::Relaxed), 1);
        drop(queued);
        drop(active);
        assert_eq!(counters.queued.load(Ordering::Relaxed), 0);
        assert_eq!(counters.active.load(Ordering::Relaxed), 0);
    }
    #[tokio::test]
    async fn shutdown_retries_keep_unfinished_handles_and_honor_cancellation()
    -> Result<(), ControlError> {
        let settings = ConnectionSettings::fixture_loopback(
            IpAddr::from([127, 0, 0, 1]),
            9,
            "fixture".into(),
            "fixture".into(),
            vec![1],
        )?;
        let client = ControlClient::new(settings)?;
        let release = CancellationToken::new();
        let waiting = release.clone();
        // Two extra owned test handles: completed is popped before delayed fails.
        {
            let mut workers = client.inner.workers.lock().await;
            workers.push(tokio::spawn(async move {
                waiting.cancelled().await;
            }));
            workers.push(tokio::spawn(async {}));
        }
        let first = client
            .shutdown(ControlContext::new(Duration::from_millis(5))?)
            .await;
        assert!(matches!(first, Err(ControlError::Timeout)));
        let cancelled = ControlContext::new(Duration::from_secs(1))?;
        let signal = cancelled.clone();
        let trigger = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            signal.cancel();
        });
        assert!(matches!(
            client.shutdown(cancelled).await,
            Err(ControlError::Cancelled)
        ));
        trigger.await.map_err(|_| ControlError::Unavailable)?;
        release.cancel();
        client
            .shutdown(ControlContext::new(Duration::from_secs(1))?)
            .await?;
        client
            .shutdown(ControlContext::new(Duration::from_secs(1))?)
            .await?;
        assert_eq!(client.metrics().active, 0);
        assert_eq!(client.metrics().queue_depth, 0);
        Ok(())
    }
}
