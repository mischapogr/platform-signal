//! Fixed one-worker DNS capacity survives caller timeout/cancellation.
use crate::worker::{Worker, WorkerError};
use std::{io, net::ToSocketAddrs, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
static WORKER: Worker = Worker::new();
pub(crate) struct Resolver {
    pub timeout: Duration,
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl reqwest::dns::Resolve for Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name = name.as_str().to_owned();
        let duration = self.timeout;
        Box::pin(async move {
            let cancel = CancellationToken::new();
            let _guard = CancelOnDrop(cancel.clone());
            let deadline = Instant::now()
                .checked_add(duration)
                .ok_or_else(|| io::Error::other("agent DNS deadline invalid"))?;
            let physical_cancel = cancel.clone();
            let addresses = WORKER
                .run("signal-agent-dns", deadline, cancel, move || {
                    crate::worker::check(deadline, &physical_cancel)?;
                    if name.is_empty() || name.len() > 253 {
                        return Err(WorkerError::Configuration);
                    }
                    let addresses: Vec<_> = (name.as_str(), 0)
                        .to_socket_addrs()
                        .map_err(|_| WorkerError::Io)?
                        .take(8)
                        .collect();
                    if addresses.is_empty() {
                        return Err(WorkerError::Io);
                    }
                    crate::worker::check(deadline, &physical_cancel)?;
                    Ok(addresses)
                })
                .await
                .map_err(|_| io::Error::other("agent DNS unavailable"))?;
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
