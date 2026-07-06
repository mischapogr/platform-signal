use crate::{
    AuthorizedBinding, CoverageConfig, CoverageError as Error, CoverageMetrics, CoverageSubmission,
    IntakeContext, IntakeOutcome, PreparedObservation, Receipt,
    format::Timestamp,
    store::{Engine, StoredObservation},
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Request deadline/cancellation; receiver admission clocks are separate trusted metadata.
#[derive(Clone, Debug)]
pub struct OperationContext {
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}
impl OperationContext {
    pub fn new(duration: Duration) -> Self {
        Self {
            deadline: Instant::now() + duration.min(Duration::from_secs(300)),
            cancellation: CancellationToken::new(),
        }
    }
}
#[derive(Clone)]
pub(crate) struct WorkContext {
    context: OperationContext,
    phase: Arc<AtomicU8>,
}
impl WorkContext {
    fn new(context: OperationContext, maximum: Duration) -> Self {
        Self {
            context: OperationContext {
                deadline: context.deadline.min(Instant::now() + maximum),
                cancellation: context.cancellation.child_token(),
            },
            phase: Arc::new(AtomicU8::new(0)),
        }
    }
    pub fn check(&self) -> Result<(), Error> {
        if self.context.cancellation.is_cancelled() || self.phase.load(Ordering::Acquire) == 2 {
            Err(Error::Cancelled)
        } else if Instant::now() >= self.context.deadline {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }
    pub fn start(&self) -> Result<(), Error> {
        self.check()?;
        // Cancellation and durable mutation arbitrate through this same transition.
        match self
            .phase
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(1) => Ok(()),
            _ => Err(Error::Cancelled),
        }
    }
    fn started(&self) -> bool {
        self.phase.load(Ordering::Acquire) == 1
    }
    fn abort(&self) -> bool {
        let started = self
            .phase
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
            && self.started();
        self.context.cancellation.cancel();
        started
    }
}
struct Shared {
    stopped: AtomicBool,
    failed: AtomicBool,
    exited: AtomicBool,
    exit: Notify,
    snapshot: Mutex<CoverageMetrics>,
    active_deadline: Mutex<Option<Instant>>,
    accepted: AtomicU64,
    replayed: AtomicU64,
    rejected: AtomicU64,
    timeouts: AtomicU64,
    failures: AtomicU64,
}
impl Shared {
    fn fail(&self) {
        if !self.failed.swap(true, Ordering::AcqRel) {
            increment(&self.failures);
        }
    }
    fn publish(&self, m: CoverageMetrics) {
        match self.snapshot.lock() {
            Ok(mut s) => *s = m,
            Err(_) => self.fail(),
        }
    }
}
fn increment(value: &AtomicU64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(1))
    });
}
struct AbortGuard {
    ctx: WorkContext,
    shared: Arc<Shared>,
    armed: bool,
}
impl Drop for AbortGuard {
    fn drop(&mut self) {
        if self.armed {
            increment(&self.shared.rejected);
            if self.ctx.abort() {
                self.shared.fail();
            }
        }
    }
}
struct ExitGuard(Arc<Shared>);
impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.0.stopped.store(true, Ordering::Release);
        self.0.exited.store(true, Ordering::Release);
        self.0.exit.notify_waiters();
    }
}
enum Operation {
    Append(Box<PreparedObservation>),
    Intake(Box<IntakeCommand>),
    AuthorizedLoad(Uuid, Box<AuthorizedBinding>),
    Load(Uuid),
    Wake,
    #[cfg(test)]
    Pause(oneshot::Sender<()>, std::sync::mpsc::Receiver<()>, bool),
}
struct IntakeCommand {
    submission: CoverageSubmission,
    intake: IntakeContext,
    reference: Option<Receipt>,
}
enum Value {
    Receipt(Box<Receipt>),
    Intake(Box<IntakeOutcome>),
    Observation(Option<Box<StoredObservation>>),
    Done,
}
struct Response {
    result: Result<Value, Error>,
    _permit: Option<Arc<OwnedSemaphorePermit>>,
}
struct Command {
    operation: Operation,
    ctx: WorkContext,
    reply: oneshot::Sender<Response>,
    permit: Option<Arc<OwnedSemaphorePermit>>,
}

/// Single worker and private root owner. No service, retry-success policy, pruning or scan API.
pub struct CoverageStore {
    sender: mpsc::Sender<Command>,
    shared: Arc<Shared>,
    permits: Arc<Semaphore>,
    config: CoverageConfig,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl CoverageStore {
    pub async fn initialize(
        config: CoverageConfig,
        history: Uuid,
        clock: Timestamp,
    ) -> Result<Self, Error> {
        Self::launch(config, Some((history, clock))).await
    }
    pub async fn open(config: CoverageConfig) -> Result<Self, Error> {
        Self::launch(config, None).await
    }
    async fn launch(
        config: CoverageConfig,
        initial: Option<(Uuid, Timestamp)>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let shared = Arc::new(Shared {
            stopped: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            exit: Notify::new(),
            snapshot: Mutex::new(CoverageMetrics::default()),
            active_deadline: Mutex::new(None),
            accepted: AtomicU64::new(0),
            replayed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        });
        let startup = WorkContext::new(
            OperationContext::new(config.operation_timeout),
            config.operation_timeout,
        );
        let mut abort = AbortGuard {
            ctx: startup.clone(),
            shared: shared.clone(),
            armed: true,
        };
        let worker_config = config.clone();
        let worker_shared = shared.clone();
        let worker_startup = startup.clone();
        let (sender, mut receiver) = mpsc::channel::<Command>(config.operation_capacity + 1);
        let (ready, answer) = oneshot::channel();
        let worker = thread::Builder::new()
            .name("signal-coverage".into())
            .spawn(move || {
                let _exit = ExitGuard(worker_shared.clone());
                let mut engine = match Engine::open(worker_config, initial, &worker_startup) {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = ready.send(Err(e));
                        return;
                    }
                };
                worker_shared.publish(engine.metrics());
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Some(command) = receiver.blocking_recv() {
                    if matches!(command.operation, Operation::Wake) {
                        break;
                    }
                    if worker_shared.stopped.load(Ordering::Acquire)
                        || worker_shared.failed.load(Ordering::Acquire)
                    {
                        break;
                    }
                    if let Ok(mut deadline) = worker_shared.active_deadline.lock() {
                        *deadline = Some(command.ctx.context.deadline);
                    }
                    let mut result = if command.reply.is_closed() {
                        Err(Error::Cancelled)
                    } else {
                        command
                            .ctx
                            .check()
                            .and_then(|()| engine.begin(&command.ctx))
                            .and_then(|()| match command.operation {
                                Operation::Append(p) => engine
                                    .append(*p, &command.ctx)
                                    .map(|r| Value::Receipt(Box::new(r))),
                                Operation::Intake(p) => engine
                                    .submit(p.submission, p.intake, p.reference, &command.ctx)
                                    .map(|r| Value::Intake(Box::new(r))),
                                Operation::AuthorizedLoad(id, authority) => engine
                                    .get_authorized(id, &authority, &command.ctx)
                                    .map(|v| Value::Observation(v.map(Box::new))),
                                Operation::Load(id) => engine
                                    .load(id, &command.ctx)
                                    .map(|v| Value::Observation(v.map(Box::new))),
                                Operation::Wake => Ok(Value::Done),
                                #[cfg(test)]
                                Operation::Pause(started, release, mutation) => {
                                    if mutation {
                                        command.ctx.start()?;
                                    }
                                    let _ = started.send(());
                                    release
                                        .recv_timeout(Duration::from_secs(10))
                                        .map_err(|_| Error::Timeout)?;
                                    command.ctx.check()?;
                                    Ok(Value::Done)
                                }
                            })
                    };
                    if let Err(e) = &result {
                        if command.ctx.started()
                            || matches!(
                                e,
                                Error::Io(_)
                                    | Error::Sqlite(_)
                                    | Error::Corrupt(_)
                                    | Error::Exhausted
                            )
                        {
                            worker_shared.fail();
                        }
                        if command.ctx.started() {
                            result = Err(Error::OutcomeUnknown);
                        }
                    } else if matches!(result, Ok(Value::Receipt(_))) {
                        increment(&worker_shared.accepted);
                    } else if let Ok(Value::Intake(outcome)) = &result {
                        match outcome.as_ref() {
                            IntakeOutcome::Accepted(_) => increment(&worker_shared.accepted),
                            IntakeOutcome::Replayed(_) => increment(&worker_shared.replayed),
                        }
                    }
                    worker_shared.publish(engine.metrics());
                    if let Ok(mut deadline) = worker_shared.active_deadline.lock() {
                        *deadline = None;
                    }
                    let _ = command.reply.send(Response {
                        result,
                        _permit: command.permit,
                    });
                    if worker_shared.failed.load(Ordering::Acquire) {
                        break;
                    }
                }
                if engine.close().is_err() {
                    worker_shared.fail();
                }
            })?;
        let result = tokio::select! {
            value=timeout_at(startup.context.deadline,answer)=>match value {
                Ok(Ok(v))=>v,Ok(Err(_))=>Err(Error::Unavailable),Err(_)=>{
                    increment(&shared.timeouts);
                    Err(if startup.abort() {Error::OutcomeUnknown} else {Error::Timeout})
                }
            },
            _=startup.context.cancellation.cancelled()=>Err(if startup.abort() {Error::OutcomeUnknown} else {Error::Cancelled}),
        };
        if let Err(error) = result {
            shared.stopped.store(true, Ordering::Release);
            // Dropping sender/ready receiver wakes idle work; active work owns the root until settled.
            return Err(error);
        }
        abort.armed = false;
        Ok(Self {
            sender,
            shared,
            permits: Arc::new(Semaphore::new(config.operation_capacity)),
            config,
            worker: Mutex::new(Some(worker)),
        })
    }
    /// Low-level trusted append. The caller owns authorization, age and retention policy.
    pub async fn append(
        &self,
        p: PreparedObservation,
        context: OperationContext,
    ) -> Result<Receipt, Error> {
        match self
            .request(Operation::Append(Box::new(p)), context)
            .await?
        {
            Value::Receipt(r) => Ok(*r),
            _ => Err(Error::Unavailable),
        }
    }
    /// Admit a new assertion or replay the retained original under a current exact grant.
    pub async fn submit(
        &self,
        submission: CoverageSubmission,
        intake: IntakeContext,
        context: OperationContext,
    ) -> Result<IntakeOutcome, Error> {
        self.intake_request(submission, intake, None, context).await
    }
    /// Reconcile an original receipt. Unavailable/divergent history never becomes admission.
    pub async fn retry(
        &self,
        receipt: Receipt,
        submission: CoverageSubmission,
        intake: IntakeContext,
        context: OperationContext,
    ) -> Result<IntakeOutcome, Error> {
        if let Err(error) = receipt.validate_reference() {
            increment(&self.shared.rejected);
            return Err(error);
        }
        if receipt.record_id != submission.record_id {
            increment(&self.shared.rejected);
            return Err(Error::ReceiptMismatch);
        }
        self.intake_request(submission, intake, Some(receipt), context)
            .await
    }
    async fn intake_request(
        &self,
        submission: CoverageSubmission,
        intake: IntakeContext,
        reference: Option<Receipt>,
        context: OperationContext,
    ) -> Result<IntakeOutcome, Error> {
        let command = IntakeCommand {
            submission,
            intake,
            reference,
        };
        match self
            .request(Operation::Intake(Box::new(command)), context)
            .await?
        {
            Value::Intake(outcome) => Ok(*outcome),
            _ => Err(Error::Unavailable),
        }
    }
    /// Read retained historical evidence only after checking its full original binding.
    pub async fn get_authorized(
        &self,
        id: Uuid,
        authority: AuthorizedBinding,
        context: OperationContext,
    ) -> Result<Option<StoredObservation>, Error> {
        match self
            .request(Operation::AuthorizedLoad(id, Box::new(authority)), context)
            .await?
        {
            Value::Observation(value) => Ok(value.map(|v| *v)),
            _ => Err(Error::Unavailable),
        }
    }
    /// Trusted local inspection only. Absence grants no source-health or negative-detection claim.
    pub async fn load(
        &self,
        id: Uuid,
        context: OperationContext,
    ) -> Result<Option<StoredObservation>, Error> {
        match self.request(Operation::Load(id), context).await? {
            Value::Observation(r) => Ok(r.map(|v| *v)),
            _ => Err(Error::Unavailable),
        }
    }
    async fn request(
        &self,
        operation: Operation,
        context: OperationContext,
    ) -> Result<Value, Error> {
        if !self.metrics().available {
            increment(&self.shared.rejected);
            return Err(Error::Unavailable);
        }
        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(p) => Arc::new(p),
            Err(_) => {
                increment(&self.shared.rejected);
                return Err(Error::Capacity);
            }
        };
        let ctx = WorkContext::new(context, self.config.operation_timeout);
        let mut abort = AbortGuard {
            ctx: ctx.clone(),
            shared: self.shared.clone(),
            armed: true,
        };
        ctx.check()?;
        let (reply, response) = oneshot::channel();
        if self
            .sender
            .try_send(Command {
                operation,
                ctx: ctx.clone(),
                reply,
                permit: Some(permit),
            })
            .is_err()
        {
            return Err(Error::Capacity);
        }
        let result = tokio::select! {
            value=timeout_at(ctx.context.deadline,response)=>match value {
                Ok(Ok(reply))=>{abort.armed=false;reply.result},
                Ok(Err(_))=>Err(if ctx.started() {Error::OutcomeUnknown} else {Error::Unavailable}),
                Err(_)=>{increment(&self.shared.timeouts);Err(if ctx.abort() {Error::OutcomeUnknown} else {Error::Timeout})}
            },
            _=ctx.context.cancellation.cancelled()=>Err(if ctx.abort() {Error::OutcomeUnknown} else {Error::Cancelled}),
        };
        if abort.armed {
            if ctx.started() {
                self.shared.fail();
            }
        } else if result.is_err() {
            increment(&self.shared.rejected);
        }
        result
    }
    pub fn metrics(&self) -> CoverageMetrics {
        if self
            .shared
            .active_deadline
            .lock()
            .map(|d| d.is_some_and(|deadline| Instant::now() >= deadline))
            .unwrap_or(true)
        {
            self.shared.fail();
        }
        let mut m = self.shared.snapshot.lock().map(|s| *s).unwrap_or_default();
        m.available = m.available
            && !self.shared.failed.load(Ordering::Acquire)
            && !self.shared.stopped.load(Ordering::Acquire);
        m.operations_in_flight = self.config.operation_capacity - self.permits.available_permits();
        m.command_capacity = self.sender.max_capacity();
        m.command_depth = m.command_capacity - self.sender.capacity();
        m.accepted = self.shared.accepted.load(Ordering::Relaxed);
        m.replayed = self.shared.replayed.load(Ordering::Relaxed);
        m.rejected = self.shared.rejected.load(Ordering::Relaxed);
        m.timeouts = self.shared.timeouts.load(Ordering::Relaxed);
        m.failures = self.shared.failures.load(Ordering::Relaxed);
        m
    }
    fn stop(&self) {
        if !self.shared.stopped.swap(true, Ordering::AcqRel) {
            let ctx = WorkContext::new(
                OperationContext::new(self.config.operation_timeout),
                self.config.operation_timeout,
            );
            // The additional channel slot is reserved for this control wake.
            let (reply, _) = oneshot::channel();
            let _ = self.sender.try_send(Command {
                operation: Operation::Wake,
                ctx,
                reply,
                permit: None,
            });
        }
    }
    pub async fn shutdown(&self, context: OperationContext) -> Result<(), Error> {
        self.stop();
        loop {
            let notified = self.shared.exit.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.shared.exited.load(Ordering::Acquire) {
                if let Some(worker) = self.worker.lock().map_err(|_| Error::Unavailable)?.take() {
                    worker.join().map_err(|_| Error::Unavailable)?;
                }
                return if self.shared.failed.load(Ordering::Acquire) {
                    Err(Error::Unavailable)
                } else {
                    Ok(())
                };
            }
            tokio::select! {
                _=&mut notified=>{},_ = context.cancellation.cancelled()=>return Err(Error::Cancelled),
                _=tokio::time::sleep_until(context.deadline)=>return Err(Error::Timeout),
            }
        }
    }
}
impl Drop for CoverageStore {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{TestResult, clock, fixture, prepared};
    fn cfg(path: std::path::PathBuf, capacity: usize) -> CoverageConfig {
        CoverageConfig {
            directory: path,
            operation_capacity: capacity,
            ..CoverageConfig::default()
        }
    }
    fn context() -> OperationContext {
        OperationContext::new(Duration::from_secs(10))
    }
    #[tokio::test]
    async fn active_timeout_retains_slot_and_root_until_worker_settles() -> TestResult {
        let t = tempfile::tempdir()?;
        let c = cfg(t.path().join("coverage"), 1);
        let store = Arc::new(
            CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:05:29Z")?)
                .await?,
        );
        let (started, wait) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::sync_channel(1);
        let task_store = store.clone();
        let task = tokio::spawn(async move {
            task_store
                .request(
                    Operation::Pause(started, blocked, true),
                    OperationContext::new(Duration::from_millis(100)),
                )
                .await
        });
        wait.await?;
        assert!(matches!(task.await?, Err(Error::OutcomeUnknown)));
        assert_eq!(store.metrics().operations_in_flight, 1);
        assert!(!store.metrics().available);
        assert!(matches!(
            CoverageStore::open(c.clone()).await,
            Err(Error::Locked)
        ));
        assert!(matches!(
            store
                .shutdown(OperationContext::new(Duration::from_millis(20)))
                .await,
            Err(Error::Timeout)
        ));
        release.send(())?;
        let _ = store.shutdown(context()).await;
        assert_eq!(store.metrics().operations_in_flight, 0);
        let reopened = CoverageStore::open(c).await?;
        assert_eq!(reopened.metrics().committed_sequence, 0);
        reopened.shutdown(context()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn queued_cancellation_cannot_race_into_durable_mutation() -> TestResult {
        let t = tempfile::tempdir()?;
        let store = Arc::new(
            CoverageStore::initialize(
                cfg(t.path().join("coverage"), 2),
                Uuid::new_v4(),
                clock("2026-10-07T00:05:29Z")?,
            )
            .await?,
        );
        let (started, wait) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::sync_channel(1);
        let task_store = store.clone();
        let task = tokio::spawn(async move {
            task_store
                .request(Operation::Pause(started, blocked, false), context())
                .await
        });
        wait.await?;
        let f = fixture()?;
        assert!(matches!(
            store
                .submit(
                    crate::intake_tests::submission(&prepared(&f["chains"][0]["commits"][0], &f)?)?,
                    crate::intake_tests::intake(
                        &prepared(&f["chains"][0]["commits"][0], &f)?,
                        "2026-10-07T00:05:30Z"
                    )?,
                    OperationContext::new(Duration::from_millis(20))
                )
                .await,
            Err(Error::Timeout)
        ));
        assert_eq!(store.metrics().operations_in_flight, 2);
        release.send(())?;
        task.await??;
        // FIFO load waits until the cancelled command has been settled.
        assert!(store.load(Uuid::new_v4(), context()).await?.is_none());
        assert_eq!(store.metrics().committed_sequence, 0);
        assert!(store.metrics().available);
        store.shutdown(context()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn future_abort_of_started_work_does_not_release_ownership_early() -> TestResult {
        let t = tempfile::tempdir()?;
        let c = cfg(t.path().join("coverage"), 1);
        let store = Arc::new(
            CoverageStore::initialize(c.clone(), Uuid::new_v4(), clock("2026-10-07T00:05:29Z")?)
                .await?,
        );
        let (started, wait) = oneshot::channel();
        let (release, blocked) = std::sync::mpsc::sync_channel(1);
        let task_store = store.clone();
        let task = tokio::spawn(async move {
            task_store
                .request(Operation::Pause(started, blocked, true), context())
                .await
        });
        wait.await?;
        task.abort();
        assert!(task.await.is_err());
        assert_eq!(store.metrics().operations_in_flight, 1);
        assert!(matches!(CoverageStore::open(c).await, Err(Error::Locked)));
        release.send(())?;
        let _ = store.shutdown(context()).await;
        assert_eq!(store.metrics().operations_in_flight, 0);
        Ok(())
    }
    #[test]
    fn cancellation_mutation_gate_is_exclusive() -> TestResult {
        for _ in 0..1000 {
            let c = WorkContext::new(context(), Duration::from_secs(10));
            let other = c.clone();
            let started = thread::spawn(move || other.start().is_ok());
            let uncertain = c.abort();
            assert_eq!(started.join().map_err(|_| "gate worker panic")?, uncertain);
        }
        Ok(())
    }
}
