//! One fixed physical worker and retained handle, independent of caller lifetime.
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
};
use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum WorkerError {
    #[error("invalid private agent TLS configuration")]
    Configuration,
    #[error("agent configuration I/O failed")]
    Io,
    #[error("agent physical worker is busy")]
    Busy,
    #[error("agent physical worker deadline exceeded")]
    Timeout,
    #[error("agent physical worker cancelled")]
    Cancelled,
    #[error("agent physical worker unavailable")]
    Unavailable,
}
pub(crate) fn check(
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<(), WorkerError> {
    if cancellation.is_cancelled() {
        Err(WorkerError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(WorkerError::Timeout)
    } else {
        Ok(())
    }
}
pub(crate) struct Worker {
    busy: AtomicBool,
    rejections: AtomicU64,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
}
struct Lease(&'static Worker);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}
impl Worker {
    pub const fn new() -> Self {
        Self {
            busy: AtomicBool::new(false),
            rejections: AtomicU64::new(0),
            handle: Mutex::new(None),
        }
    }
    pub fn depth(&self) -> usize {
        usize::from(self.busy.load(Ordering::Acquire))
    }
    pub fn rejections(&self) -> u64 {
        self.rejections.load(Ordering::Relaxed)
    }
    pub async fn run<T, F>(
        &'static self,
        name: &'static str,
        deadline: Instant,
        cancellation: CancellationToken,
        operation: F,
    ) -> Result<T, WorkerError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, WorkerError> + Send + 'static,
    {
        check(deadline, &cancellation)?;
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(WorkerError::Busy);
        }
        let lease = Arc::new(Lease(self));
        let physical_lease = lease.clone();
        let (reply, receive) = oneshot::channel();
        {
            let mut handle = self.handle.lock().map_err(|_| WorkerError::Unavailable)?;
            if handle.as_ref().is_some_and(|h| !h.is_finished()) {
                self.rejections.fetch_add(1, Ordering::Relaxed);
                return Err(WorkerError::Busy);
            }
            if let Some(old) = handle.take() {
                old.join().map_err(|_| WorkerError::Unavailable)?;
            }
            *handle = Some(
                thread::Builder::new()
                    .name(name.into())
                    .spawn(move || {
                        let _physical_lease = physical_lease;
                        let _ = reply.send(operation());
                    })
                    .map_err(|_| WorkerError::Unavailable)?,
            );
        }
        let result = tokio::select! { biased;
            _ = cancellation.cancelled() => Err(WorkerError::Cancelled),
            result = timeout_at(deadline, receive) => match result {
                Ok(Ok(result)) => result, Ok(Err(_)) => Err(WorkerError::Unavailable), Err(_) => Err(WorkerError::Timeout),
            },
        };
        if matches!(result, Err(WorkerError::Cancelled | WorkerError::Timeout)) {
            return result;
        }
        loop {
            if self
                .handle
                .lock()
                .map_err(|_| WorkerError::Unavailable)?
                .as_ref()
                .is_none_or(thread::JoinHandle::is_finished)
            {
                break;
            }
            check(deadline, &cancellation)?;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        if let Some(handle) = self
            .handle
            .lock()
            .map_err(|_| WorkerError::Unavailable)?
            .take()
        {
            handle.join().map_err(|_| WorkerError::Unavailable)?;
        }
        check(deadline, &cancellation)?;
        drop(lease);
        result
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::{sync::mpsc::sync_channel, time::Duration};
    #[tokio::test]
    async fn physical_ready_reply_is_denied_when_caller_resumes_after_deadline() {
        static OWNER: Worker = Worker::new();
        let (began, started) = oneshot::channel();
        let deadline = Instant::now() + Duration::from_millis(500);
        let future = OWNER.run(
            "synthetic-ready-reply",
            deadline,
            CancellationToken::new(),
            move || {
                began.send(()).unwrap();
                Ok(7)
            },
        );
        tokio::pin!(future);
        tokio::select! { biased;
            result = started => result.unwrap(),
            result = &mut future => panic!("caller consumed reply early: {result:?}"),
        }
        while OWNER
            .handle
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|h| !h.is_finished())
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
        );
        assert_eq!(future.await, Err(WorkerError::Timeout));
    }
    #[tokio::test]
    async fn cancelled_and_expired_callers_keep_physical_capacity_until_retirement() {
        static OWNER: Worker = Worker::new();
        for expired in [false, true] {
            let cancel = CancellationToken::new();
            let (began, started) = oneshot::channel();
            let (release, wait) = sync_channel(1);
            let caller = tokio::spawn(OWNER.run(
                "synthetic-agent-worker",
                Instant::now() + Duration::from_millis(if expired { 50 } else { 1000 }),
                cancel.clone(),
                move || {
                    began.send(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(3)).unwrap();
                    Ok(7)
                },
            ));
            tokio::time::timeout(Duration::from_secs(1), started)
                .await
                .unwrap()
                .unwrap();
            if !expired {
                cancel.cancel();
            }
            assert_eq!(
                caller.await.unwrap(),
                Err(if expired {
                    WorkerError::Timeout
                } else {
                    WorkerError::Cancelled
                })
            );
            assert_eq!(OWNER.depth(), 1);
            assert_eq!(
                OWNER
                    .run(
                        "synthetic-replacement",
                        Instant::now() + Duration::from_secs(1),
                        CancellationToken::new(),
                        || Ok(9)
                    )
                    .await,
                Err(WorkerError::Busy)
            );
            release.send(()).unwrap();
            let until = Instant::now() + Duration::from_secs(1);
            while OWNER.depth() != 0
                || OWNER
                    .handle
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|h| !h.is_finished())
            {
                assert!(Instant::now() < until);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(
                OWNER
                    .run(
                        "synthetic-replacement",
                        Instant::now() + Duration::from_secs(1),
                        CancellationToken::new(),
                        || Ok(9)
                    )
                    .await,
                Ok(9)
            );
            assert_eq!(OWNER.depth(), 0);
        }
    }
    #[tokio::test]
    async fn dropping_a_caller_does_not_release_non_cancellable_physical_work() {
        static OWNER: Worker = Worker::new();
        let (began, started) = oneshot::channel();
        let (release, wait) = sync_channel(1);
        let caller = tokio::spawn(OWNER.run(
            "synthetic-dropped-worker",
            Instant::now() + Duration::from_secs(2),
            CancellationToken::new(),
            move || {
                began.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(7)
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), started)
            .await
            .unwrap()
            .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(OWNER.depth(), 1);
        assert_eq!(
            OWNER
                .run(
                    "synthetic-replacement",
                    Instant::now() + Duration::from_secs(1),
                    CancellationToken::new(),
                    || Ok(9)
                )
                .await,
            Err(WorkerError::Busy)
        );
        release.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while OWNER.depth() != 0
            || OWNER
                .handle
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|h| !h.is_finished())
        {
            assert!(Instant::now() < until);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            OWNER
                .run(
                    "synthetic-replacement",
                    Instant::now() + Duration::from_secs(1),
                    CancellationToken::new(),
                    || Ok(9)
                )
                .await,
            Ok(9)
        );
    }
}
