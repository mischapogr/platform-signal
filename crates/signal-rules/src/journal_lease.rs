//! Filesystem writer lease, declared after SQLite in each engine's field order.
use std::fs::{File, TryLockError};

pub(crate) struct WriterLease {
    file: File,
}
impl WriterLease {
    pub(crate) fn acquire(file: File) -> Result<Self, TryLockError> {
        file.try_lock()?;
        Ok(Self { file })
    }
    #[cfg(test)]
    pub(crate) fn duplicate(&self) -> std::io::Result<File> {
        self.file.try_clone()
    }
}
impl Drop for WriterLease {
    fn drop(&mut self) {
        // Closing only this descriptor can leave flock held by a concurrent
        // child until exec. Release the shared description explicitly, after
        // the engine's SQLite connection has physically closed. Descriptor
        // close follows even if the OS reports an unlock failure during Drop.
        let _ = self.file.unlock();
    }
}
