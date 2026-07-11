//! Fixed one-worker DNS capacity survives caller timeout/cancellation.
use super::worker::{Worker, WorkerError};
use std::{io, net::ToSocketAddrs, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
static WORKER: Worker = Worker::new();
pub struct Resolver {
    timeout: Duration,
}
impl Resolver {
    pub fn new(timeout: Duration) -> Result<Self, WorkerError> {
        if timeout.is_zero() || timeout > Duration::from_secs(86400) {
            return Err(WorkerError::Configuration);
        }
        Ok(Self { timeout })
    }
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        if name.as_str().is_empty() || name.as_str().len() > 253 {
            return Box::pin(async { Err(io::Error::other("transport DNS name invalid").into()) });
        }
        let name = name.as_str().to_owned();
        let duration = self.timeout;
        Box::pin(async move {
            let cancel = CancellationToken::new();
            let _guard = CancelOnDrop(cancel.clone());
            let deadline = Instant::now()
                .checked_add(duration)
                .ok_or_else(|| io::Error::other("transport DNS deadline invalid"))?;
            let physical_cancel = cancel.clone();
            let addresses = WORKER
                .run("signal-transport-dns", deadline, cancel, move || {
                    super::worker::check(deadline, &physical_cancel)?;
                    let addresses: Vec<_> = (name.as_str(), 0)
                        .to_socket_addrs()
                        .map_err(|_| WorkerError::Io)?
                        .take(8)
                        .collect();
                    if addresses.is_empty() {
                        return Err(WorkerError::Io);
                    }
                    super::worker::check(deadline, &physical_cancel)?;
                    Ok(addresses)
                })
                .await
                .map_err(|_| io::Error::other("transport DNS unavailable"))?;
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
pub(crate) fn depth() -> usize {
    WORKER.depth()
}
pub(crate) fn rejections() -> u64 {
    WORKER.rejections()
}
