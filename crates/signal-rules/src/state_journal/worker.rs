//! Single retained physical worker; caller cancellation never releases its slot.
use super::{Config, Engine, Error, Record};
use crate::RuleContext;
use crate::window::WORKERS;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    thread,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

#[derive(Clone)]
struct Work {
    context: RuleContext,
    phase: Arc<AtomicU8>,
}
impl Work {
    fn check(&self) -> Result<(), Error> {
        if self.context.cancellation.is_cancelled() || self.phase.load(Ordering::Acquire) == 2 {
            Err(Error::Cancelled)
        } else if tokio::time::Instant::now() >= self.context.deadline {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }
    fn start(&self) -> Result<(), Error> {
        self.check()?;
        self.phase
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Cancelled)?;
        Ok(())
    }
}
struct Abort(Work);
// Count every unsuccessful admitted call, including a dropped future. This guard
// does not own the physical slot: the worker releases that only after I/O ends.
struct CallOutcome {
    failures: Arc<AtomicU64>,
    succeeded: bool,
}
impl Drop for CallOutcome {
    fn drop(&mut self) {
        if !self.succeeded {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl Drop for Abort {
    fn drop(&mut self) {
        let _ = self
            .0
            .phase
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
        self.0.context.cancellation.cancel();
    }
}
enum Action {
    Load,
    Commit { expected: u64, next: Box<Record> },
    Retire { expected: u64, published: usize },
    Shutdown,
}
struct Command {
    action: Action,
    work: Work,
    permit: OwnedSemaphorePermit,
    reply: oneshot::Sender<Result<Option<Record>, Error>>,
}
#[derive(Clone)]
pub struct Journal {
    config: Arc<Config>,
    sender: mpsc::Sender<Command>,
    slots: Arc<Semaphore>,
    failures: Arc<AtomicU64>,
}
/// Read-only telemetry; it does not keep a dropped writer alive.
#[derive(Clone)]
pub struct Monitor {
    sender: mpsc::WeakSender<Command>,
    slots: Arc<Semaphore>,
    failures: Arc<AtomicU64>,
}
impl Monitor {
    pub fn metrics(&self) -> (usize, usize, u64) {
        (
            1 - self.slots.available_permits(),
            1,
            self.failures.load(Ordering::Relaxed),
        )
    }
    pub fn is_closed(&self) -> bool {
        self.sender
            .upgrade()
            .is_none_or(|sender| sender.is_closed())
    }
}
pub struct Ready {
    reply: oneshot::Receiver<Result<(), Error>>,
    work: Work,
}
impl Ready {
    pub async fn wait(self) -> Result<(), Error> {
        let guard = Abort(self.work.clone());
        self.work.check()?;
        let result = tokio::select! {biased;_=self.work.context.cancellation.cancelled()=>Err(Error::Cancelled),r=tokio::time::timeout_at(self.work.context.deadline,self.reply)=>r.map_err(|_|Error::Timeout)?.map_err(|_|Error::Closed)?};
        self.work.check()?;
        drop(guard);
        result
    }
}
impl Journal {
    /// Immutable configuration of the actual opened journal generation.
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn monitor(&self) -> Monitor {
        Monitor {
            sender: self.sender.downgrade(),
            slots: self.slots.clone(),
            failures: self.failures.clone(),
        }
    }
    /// Handle exists before waiting for physical startup; dropping readiness
    /// cancels admission and the worker retires when opening physically ends.
    pub fn begin_open(
        path: PathBuf,
        config: Config,
        context: RuleContext,
    ) -> Result<(Self, Ready), Error> {
        config.validate()?;
        let retained_config = Arc::new(config.clone());
        let lifetime = WORKERS
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        let work = Work {
            context: RuleContext {
                deadline: context.deadline,
                cancellation: context.cancellation.child_token(),
            },
            phase: Arc::new(AtomicU8::new(0)),
        };
        work.check()?;
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().map_err(|_| Error::Busy)?;
        let failures = Arc::new(AtomicU64::new(0));
        let (sender, mut receiver) = mpsc::channel::<Command>(1);
        let (reply, ready) = oneshot::channel();
        let startup = work.clone();
        thread::Builder::new()
            .name("signal-state-journal".into())
            .spawn(move || {
                let _lifetime = lifetime;
                let mut engine = match startup.check().and_then(|_| Engine::open(&path, config)) {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = reply.send(Err(e));
                        return;
                    }
                };
                if startup.check().is_err() {
                    return;
                }
                drop(permit);
                if reply.send(Ok(())).is_err() {
                    return;
                }
                while let Some(command) = receiver.blocking_recv() {
                    let Command {
                        action,
                        work,
                        permit,
                        reply,
                    } = command;
                    let shutdown = matches!(action, Action::Shutdown);
                    let result = work.check().and_then(|_| match action {
                        Action::Load => engine.load(),
                        Action::Commit { expected, next } => {
                            work.start()?;
                            engine.commit(expected, *next).map(Some)
                        }
                        Action::Retire {
                            expected,
                            published,
                        } => {
                            work.start()?;
                            engine.retire(expected, published).map(Some)
                        }
                        Action::Shutdown => {
                            work.start()?;
                            Ok(None)
                        }
                    });
                    if shutdown && result.is_ok() {
                        // Confirmation follows physical close and lease release.
                        drop(engine);
                        receiver.close();
                        drop(permit);
                        drop(_lifetime);
                        let _ = reply.send(result);
                        return;
                    }
                    let result = result.and_then(|r| {
                        work.check()?;
                        Ok(r)
                    });
                    drop(permit);
                    let _ = reply.send(result);
                }
            })
            .map_err(|_| Error::Journal)?;
        Ok((
            Self {
                config: retained_config,
                sender,
                slots,
                failures,
            },
            Ready { reply: ready, work },
        ))
    }
    pub fn metrics(&self) -> (usize, usize, u64) {
        (
            1 - self.slots.available_permits(),
            1,
            self.failures.load(Ordering::Relaxed),
        )
    }
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
    async fn call(&self, action: Action, context: RuleContext) -> Result<Option<Record>, Error> {
        let mut outcome = CallOutcome {
            failures: self.failures.clone(),
            succeeded: false,
        };
        let work = Work {
            context: RuleContext {
                deadline: context.deadline,
                cancellation: context.cancellation.child_token(),
            },
            phase: Arc::new(AtomicU8::new(0)),
        };
        work.check()?;
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        let guard = Abort(work.clone());
        let (reply, answer) = oneshot::channel();
        self.sender
            .try_send(Command {
                action,
                work: work.clone(),
                permit,
                reply,
            })
            .map_err(|_| Error::Closed)?;
        let result = tokio::select! {biased;_=work.context.cancellation.cancelled()=>Err(Error::Cancelled),r=tokio::time::timeout_at(work.context.deadline,answer)=>r.map_err(|_|Error::Timeout)?.map_err(|_|Error::Closed)?};
        let result = result.and_then(|r| {
            work.check()?;
            Ok(r)
        });
        outcome.succeeded = result.is_ok();
        drop(guard);
        result
    }
    pub async fn load(&self, context: RuleContext) -> Result<Option<Record>, Error> {
        self.call(Action::Load, context).await
    }
    pub async fn retire(
        &self,
        expected_revision: u64,
        published: usize,
        context: RuleContext,
    ) -> Result<Record, Error> {
        self.call(
            Action::Retire {
                expected: expected_revision,
                published,
            },
            context,
        )
        .await?
        .ok_or(Error::Journal)
    }
    /// Wait for physical database close and writer-lease release using the
    /// original operation budget. Cloned handles subsequently refuse commands.
    pub async fn shutdown(&self, context: RuleContext) -> Result<(), Error> {
        self.call(Action::Shutdown, context).await.map(|_| ())
    }
    pub async fn commit(
        &self,
        expected_revision: u64,
        next: Record,
        context: RuleContext,
    ) -> Result<Record, Error> {
        self.call(
            Action::Commit {
                expected: expected_revision,
                next: Box::new(next),
            },
            context,
        )
        .await?
        .ok_or(Error::Journal)
    }
}
