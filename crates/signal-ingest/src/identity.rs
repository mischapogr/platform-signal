//! Fixed authenticated-provider introspection, independent of server policy/routes.
//! Physical worker leases survive caller timeout, cancellation and noncancellable DNS.
mod native;

use signal_protocol::access::{CompiledPolicy, RequestGrant, introspection::IntrospectionProfile};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

/// Private operator inputs. Secrets are not debug-printed or serialized.
pub struct IdentityConfig {
    pub endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    /// Additional DER trust roots, capped individually and in aggregate.
    pub extra_roots: Vec<Vec<u8>>,
    /// Fixed physical worker count, 1..16. No additional waiting admission queue.
    pub workers: usize,
    /// Clamp every caller deadline to this positive limit, at most30 seconds.
    pub max_request_duration: std::time::Duration,
}
#[derive(Clone)]
pub struct IdentityContext {
    pub deadline: Instant,
    pub cancellation: CancellationToken,
}
impl IdentityContext {
    fn check(&self) -> Result<(), IdentityError> {
        if self.cancellation.is_cancelled() {
            return Err(IdentityError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(IdentityError::Timeout);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IdentityError {
    #[error("invalid bounded identity configuration")]
    Configuration,
    #[error("identity backend unavailable")]
    Unavailable,
    #[error("identity capacity is full")]
    Busy,
    #[error("invalid access credential")]
    InvalidCredential,
    #[error("identity access denied")]
    Denied,
    #[error("invalid identity provider response")]
    InvalidResponse,
    #[error("identity deadline exceeded")]
    Timeout,
    #[error("identity request cancelled")]
    Cancelled,
    #[error("identity backend is stopped")]
    Stopped,
}
#[derive(Clone, Copy, Debug)]
pub struct IdentityMetrics {
    pub closed: bool,
    pub depth: usize,
    pub capacity: usize,
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub running: usize,
    pub workers_alive: usize,
    pub requests: u64,
    pub rejected: u64,
    pub denied: u64,
    pub failures: u64,
}
struct Shared {
    stopping: CancellationToken,
    slots: Arc<Semaphore>,
    capacity: usize,
    queued: AtomicUsize,
    running: AtomicUsize,
    alive: AtomicUsize,
    requests: AtomicU64,
    rejected: AtomicU64,
    denied: AtomicU64,
    failures: AtomicU64,
}
struct Command {
    body: Vec<u8>,
    context: IdentityContext,
    reply: oneshot::Sender<Completion>,
    slot: OwnedSemaphorePermit,
}
struct Completion {
    result: Result<RequestGrant, IdentityError>,
    _slot: OwnedSemaphorePermit,
}
struct Inner {
    sender: Mutex<Option<mpsc::SyncSender<Command>>>,
    workers: Mutex<Vec<thread::JoinHandle<()>>>,
    shared: Arc<Shared>,
    max_request_duration: std::time::Duration,
    #[cfg(test)]
    transport: Arc<native::Transport>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.shared.stopping.cancel();
        // Drop all frontend senders even if the mutex was poisoned. Workers
        // retain only receiver/state/physical leases, never a sender cycle.
        match self.sender.get_mut() {
            Ok(sender) => {
                sender.take();
            }
            Err(poisoned) => {
                poisoned.into_inner().take();
            }
        }
    }
}
#[derive(Clone)]
pub struct IdentityBackend {
    inner: Arc<Inner>,
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct WorkerExit(Arc<Shared>);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.alive.fetch_sub(1, Ordering::AcqRel);
    }
}
struct RequestAttempt {
    shared: Arc<Shared>,
    accepted: bool,
}
impl Drop for RequestAttempt {
    fn drop(&mut self) {
        if !self.accepted {
            // Includes aborted caller futures, which never return an Err.
            self.shared.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl IdentityBackend {
    /// HTTP credentials never derive authority from forwarded user/role headers.
    pub async fn authenticate_headers(
        &self,
        headers: &axum::http::HeaderMap,
        context: IdentityContext,
    ) -> Result<RequestGrant, IdentityError> {
        use axum::http::header;
        if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
            return Err(IdentityError::InvalidCredential);
        }
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
            .map(|(_, token)| token)
            .ok_or(IdentityError::InvalidCredential)?;
        self.authenticate(token, context).await
    }
    /// Requires an existing live Tokio runtime. No provider discovery or network
    /// work occurs at construction; all endpoint/credential/trust validation
    /// precedes spawning the finite physical workers.
    pub fn new(
        config: IdentityConfig,
        profile: IntrospectionProfile,
        policy: Arc<CompiledPolicy>,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, IdentityError> {
        if !(1..=16).contains(&config.workers)
            || config.max_request_duration.is_zero()
            || config.max_request_duration > std::time::Duration::from_secs(30)
        {
            return Err(IdentityError::Configuration);
        }
        let count = config.workers;
        let max_request_duration = config.max_request_duration;
        let transport = Arc::new(native::Transport::new(config)?);
        let profile = Arc::new(profile);
        let shared = Arc::new(Shared {
            stopping: CancellationToken::new(),
            slots: Arc::new(Semaphore::new(count)),
            capacity: count,
            queued: AtomicUsize::new(0),
            running: AtomicUsize::new(0),
            alive: AtomicUsize::new(0),
            requests: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        });
        let (sender, receiver) = mpsc::sync_channel::<Command>(count);
        let receiver = Arc::new(Mutex::new(receiver));
        let inner = Arc::new(Inner {
            sender: Mutex::new(Some(sender)),
            workers: Mutex::new(Vec::with_capacity(count)),
            shared: shared.clone(),
            max_request_duration,
            #[cfg(test)]
            transport: transport.clone(),
        });
        for index in 0..count {
            let state = shared.clone();
            let receiver = receiver.clone();
            let transport = transport.clone();
            let profile = profile.clone();
            let policy = policy.clone();
            let runtime = runtime.clone();
            // Count before spawn so a fast worker exit cannot underflow.
            state.alive.fetch_add(1, Ordering::AcqRel);
            let spawned=thread::Builder::new().name(format!("signal-identity-{index}")).spawn(move|| {
                let _exit=WorkerExit(state.clone());
                loop {
                    let command=match receiver.lock() {Ok(receiver)=>receiver.recv(),Err(_)=>break};
                    let Ok(command)=command else {break;};
                    state.queued.fetch_sub(1,Ordering::AcqRel);
                    state.running.fetch_add(1,Ordering::AcqRel);
                    let result=runtime.block_on(async {
                        if state.stopping.is_cancelled() {return Err(IdentityError::Stopped);}
                        command.context.check()?;
                        let operation=async {
                            let bytes=transport.fetch(command.body,&command.context,&state.stopping).await?;
                            command.context.check()?;
                            let now=SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|IdentityError::Unavailable)?.as_secs();
                            let identity=profile.from_authenticated_response(&bytes,now).map_err(|error|match error {
                                signal_protocol::access::introspection::IntrospectionError::Denied=>IdentityError::Denied,
                                _=>IdentityError::InvalidResponse,
                            })?;
                            policy.grant(identity,now).map_err(|_|IdentityError::Denied)
                        };
                        tokio::select! {biased;
                            _=state.stopping.cancelled()=>Err(IdentityError::Stopped),
                            _=command.context.cancellation.cancelled()=>Err(IdentityError::Cancelled),
                            result=timeout_at(command.context.deadline,operation)=>result.map_err(|_|IdentityError::Timeout)?,
                        }
                    });
                    state.running.fetch_sub(1,Ordering::AcqRel);
                    if matches!(result,Err(IdentityError::Denied|IdentityError::InvalidCredential)) {state.denied.fetch_add(1,Ordering::Relaxed);}
                    else if result.is_err() {state.failures.fetch_add(1,Ordering::Relaxed);}
                    // Slot transfers to completion only after physical work is
                    // finished. Lost replies/drop cannot free a live DNS lease.
                    let _=command.reply.send(Completion {result,_slot:command.slot});
                }
            });
            match spawned {
                Ok(worker) => inner
                    .workers
                    .lock()
                    .map_err(|_| IdentityError::Unavailable)?
                    .push(worker),
                Err(_) => {
                    shared.alive.fetch_sub(1, Ordering::AcqRel);
                    return Err(IdentityError::Unavailable);
                }
            }
        }
        Ok(Self { inner })
    }
    /// Fixed opaque access token only; endpoint/identity/roles are never supplied
    /// by this caller. Every request introspects anew, with no revocation cache.
    pub async fn authenticate(
        &self,
        token: &str,
        context: IdentityContext,
    ) -> Result<RequestGrant, IdentityError> {
        let shared = &self.inner.shared;
        shared.requests.fetch_add(1, Ordering::Relaxed);
        let mut attempt = RequestAttempt {
            shared: shared.clone(),
            accepted: false,
        };
        let result = self.authenticate_inner(token, context).await;
        attempt.accepted = result.is_ok();
        result
    }
    async fn authenticate_inner(
        &self,
        token: &str,
        mut context: IdentityContext,
    ) -> Result<RequestGrant, IdentityError> {
        context.deadline = context
            .deadline
            .min(Instant::now() + self.inner.max_request_duration);
        context.check()?;
        if self.inner.shared.stopping.is_cancelled() {
            return Err(IdentityError::Stopped);
        }
        if token.is_empty()
            || token.len() > 4096
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(IdentityError::InvalidCredential);
        }
        let slot = self
            .inner
            .shared
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| IdentityError::Busy)?;
        let body =
            serde_urlencoded::to_string([("token", token), ("token_type_hint", "access_token")])
                .map_err(|_| IdentityError::InvalidCredential)?
                .into_bytes();
        if body.len() > 16 * 1024 {
            return Err(IdentityError::InvalidCredential);
        }
        let context = IdentityContext {
            deadline: context.deadline,
            cancellation: context.cancellation.child_token(),
        };
        let _guard = CancelOnDrop(context.cancellation.clone());
        let (reply, receive) = oneshot::channel();
        let deadline = context.deadline;
        let cancellation = context.cancellation.clone();
        {
            let sender = self
                .inner
                .sender
                .lock()
                .map_err(|_| IdentityError::Unavailable)?;
            let sender = sender.as_ref().ok_or(IdentityError::Stopped)?;
            self.inner.shared.queued.fetch_add(1, Ordering::AcqRel);
            if sender
                .try_send(Command {
                    body,
                    context,
                    reply,
                    slot,
                })
                .is_err()
            {
                self.inner.shared.queued.fetch_sub(1, Ordering::AcqRel);
                return Err(IdentityError::Unavailable);
            }
        }
        tokio::select! {biased;
            _=self.inner.shared.stopping.cancelled()=>Err(IdentityError::Stopped),
            _=cancellation.cancelled()=>Err(IdentityError::Cancelled),
            result=timeout_at(deadline,receive)=>match result {
                Err(_)=>Err(IdentityError::Timeout),
                Ok(Err(_))=>Err(IdentityError::Unavailable),
                Ok(Ok(completion))=>{cancellation_check(deadline,&cancellation)?;completion.result}
            },
        }
    }
    pub fn close(&self) -> Result<(), IdentityError> {
        self.inner.shared.stopping.cancel();
        self.inner
            .sender
            .lock()
            .map_err(|_| IdentityError::Unavailable)?
            .take();
        Ok(())
    }
    /// Failure leaves physical workers/leases visible. Native OS DNS is not
    /// force-cancelled; do not claim shutdown until all workers actually exit.
    pub async fn shutdown(&self, deadline: Instant) -> Result<(), IdentityError> {
        self.close()?;
        loop {
            {
                let mut workers = self
                    .inner
                    .workers
                    .lock()
                    .map_err(|_| IdentityError::Unavailable)?;
                let mut index = 0;
                while index < workers.len() {
                    if workers[index].is_finished() {
                        workers
                            .swap_remove(index)
                            .join()
                            .map_err(|_| IdentityError::Unavailable)?;
                    } else {
                        index += 1;
                    }
                }
                if workers.is_empty() {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(IdentityError::Timeout);
            }
            tokio::time::sleep_until(
                (Instant::now() + std::time::Duration::from_millis(5)).min(deadline),
            )
            .await;
        }
    }
    pub fn metrics(&self) -> IdentityMetrics {
        let state = &self.inner.shared;
        IdentityMetrics {
            closed: state.stopping.is_cancelled(),
            depth: state.capacity - state.slots.available_permits(),
            capacity: state.capacity,
            queue_depth: state.queued.load(Ordering::Acquire),
            queue_capacity: state.capacity,
            running: state.running.load(Ordering::Acquire),
            workers_alive: state.alive.load(Ordering::Acquire),
            requests: state.requests.load(Ordering::Relaxed),
            rejected: state.rejected.load(Ordering::Relaxed),
            denied: state.denied.load(Ordering::Relaxed),
            failures: state.failures.load(Ordering::Relaxed),
        }
    }
}
fn cancellation_check(
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), IdentityError> {
    IdentityContext {
        deadline,
        cancellation: cancellation.clone(),
    }
    .check()
}

#[cfg(test)]
mod tests;
