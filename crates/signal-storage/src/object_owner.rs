//! Small only: one owned control root per stream, retained by the physical I/O
//! worker. It is neither distributed fencing nor original-evidence custody.
use crate::{OperationContext, StorageError, check_context};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, PathBuf},
};
use uuid::Uuid;
#[derive(Clone, Debug)]
pub struct SmallOwnerConfig {
    pub directory: PathBuf,
    pub stream_id: Uuid,
    pub backend_id: Uuid,
}
impl SmallOwnerConfig {
    pub(crate) fn bounded_copy(&self) -> Result<Self, StorageError> {
        if self.stream_id.is_nil()
            || self.backend_id.is_nil()
            || self.directory.as_os_str().is_empty()
            || self.directory.as_os_str().len() > 4096
            || self.directory.components().count() > 64
            || self
                .directory
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(StorageError::Config("bounded Small object owner"));
        }
        Ok(Self {
            directory: self.directory.as_path().to_path_buf(),
            stream_id: self.stream_id,
            backend_id: self.backend_id,
        })
    }
}
#[derive(Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Binding {
    schema_version: u16,
    stream_id: Uuid,
    backend_id: Uuid,
}
pub(crate) struct SmallOwner {
    _lock: LockGuard,
}
struct LockGuard(File);
impl Drop for LockGuard {
    fn drop(&mut self) {
        // Explicit unlock releases our ownership even if a fork/clone retained
        // the same open description. The physical worker owns this guard.
        let _ = self.0.unlock();
    }
}
impl SmallOwner {
    /// Called only on the one physical I/O worker, never a Tokio worker.
    pub(crate) fn open(
        config: &SmallOwnerConfig,
        context: &OperationContext,
    ) -> Result<Self, StorageError> {
        check_context(Some(context))?;
        let config = config.bounded_copy()?;
        for ancestor in config
            .directory
            .ancestors()
            .filter(|p| !p.as_os_str().is_empty())
        {
            check_context(Some(context))?;
            match fs::symlink_metadata(ancestor) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => return Err(StorageError::Corrupt("owner directory")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(StorageError::Io(e)),
            }
        }
        crate::fs::directory(&config.directory)?;
        check_context(Some(context))?;
        let lock_path = config.directory.join(".lock");
        let lock = match fs::symlink_metadata(&lock_path) {
            Ok(m) if m.is_file() && m.len() == 0 => OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .map_err(StorageError::Io)?,
            Ok(_) => return Err(StorageError::Corrupt("owner lock")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => crate::fs::create(&lock_path)?,
            Err(e) => return Err(StorageError::Io(e)),
        };
        lock.try_lock().map_err(|_| StorageError::Locked)?;
        let lock = LockGuard(lock);
        let mut entries = 0usize;
        let mut has_binding = false;
        let mut has_temp = false;
        for entry in fs::read_dir(&config.directory).map_err(StorageError::Io)? {
            check_context(Some(context))?;
            entries += 1;
            if entries > 3 {
                return Err(StorageError::Corrupt("owner inventory"));
            }
            let entry = entry.map_err(StorageError::Io)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(StorageError::Io)?;
            if !metadata.is_file() {
                return Err(StorageError::Corrupt("owner entry"));
            }
            match entry.file_name().to_str() {
                Some(".lock") if metadata.len() == 0 => {}
                Some("binding.json") if metadata.len() <= 256 => has_binding = true,
                Some("binding.tmp") if metadata.len() <= 256 => has_temp = true,
                _ => return Err(StorageError::Corrupt("owner unknown entry")),
            }
        }
        let expected = Binding {
            schema_version: 1,
            stream_id: config.stream_id,
            backend_id: config.backend_id,
        };
        let binding = config.directory.join("binding.json");
        let temp = config.directory.join("binding.tmp");
        if has_binding {
            verify(&binding, &expected, context)?;
            // Complete matching temp can be removed; unknown/truncated temp holds.
            if has_temp {
                verify(&temp, &expected, context)?;
                fs::remove_file(&temp).map_err(StorageError::Io)?;
                crate::fs::sync_dir(&config.directory)?;
            }
        } else {
            if has_temp {
                verify(&temp, &expected, context)?;
            } else {
                let bytes = serde_json::to_vec(&expected)
                    .map_err(|_| StorageError::Corrupt("owner binding"))?;
                let mut file = crate::fs::create(&temp)?;
                file.write_all(&bytes).map_err(StorageError::Io)?;
                file.sync_all().map_err(StorageError::Io)?;
            }
            check_context(Some(context))?;
            fs::rename(&temp, &binding).map_err(StorageError::Io)?;
            crate::fs::sync_dir(&config.directory)?;
        }
        lock.0.sync_all().map_err(StorageError::Io)?;
        crate::fs::sync_dir(&config.directory)?;
        check_context(Some(context))?;
        Ok(Self { _lock: lock })
    }
}
fn verify(
    path: &std::path::Path,
    expected: &Binding,
    context: &OperationContext,
) -> Result<(), StorageError> {
    check_context(Some(context))?;
    let mut bytes = Vec::new();
    let mut file = File::open(path).map_err(StorageError::Io)?;
    (&mut file)
        .take(257)
        .read_to_end(&mut bytes)
        .map_err(StorageError::Io)?;
    if bytes.len() > 256 {
        return Err(StorageError::Corrupt("owner binding size"));
    }
    let actual: Binding =
        serde_json::from_slice(&bytes).map_err(|_| StorageError::Corrupt("owner binding"))?;
    if actual != *expected {
        return Err(StorageError::StreamMismatch);
    }
    // Recovered complete bytes may have survived a process crash before the
    // previous writer's sync. Sync the actual validated descriptor before ready.
    check_context(Some(context))?;
    file.sync_all().map_err(StorageError::Io)?;
    check_context(Some(context))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inherited_lock_description_does_not_keep_dead_owner_alive()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::TempDir::new()?;
        let config = SmallOwnerConfig {
            directory: directory.path().to_path_buf(),
            stream_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
        };
        let context = OperationContext::new(std::time::Duration::from_secs(5));
        let owner = SmallOwner::open(&config, &context)?;
        let inherited = owner._lock.0.try_clone()?;
        assert!(matches!(
            SmallOwner::open(&config, &context),
            Err(StorageError::Locked)
        ));
        drop(owner);
        let next = SmallOwner::open(&config, &context)?;
        drop(next);
        drop(inherited);
        Ok(())
    }
    #[test]
    fn complete_temp_is_synced_and_adopted_without_reset() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::TempDir::new()?;
        let config = SmallOwnerConfig {
            directory: directory.path().to_path_buf(),
            stream_id: Uuid::new_v4(),
            backend_id: Uuid::new_v4(),
        };
        let bytes = serde_json::to_vec(&Binding {
            schema_version: 1,
            stream_id: config.stream_id,
            backend_id: config.backend_id,
        })?;
        // Simulate a process that wrote a complete temporary record but exited
        // before sync/rename. No simulated power-loss guarantee is asserted.
        std::fs::write(directory.path().join("binding.tmp"), &bytes)?;
        let context = OperationContext::new(std::time::Duration::from_secs(5));
        let owner = SmallOwner::open(&config, &context)?;
        assert_eq!(std::fs::read(directory.path().join("binding.json"))?, bytes);
        assert!(!directory.path().join("binding.tmp").exists());
        drop(owner);
        let reopened = SmallOwner::open(&config, &context)?;
        drop(reopened);
        Ok(())
    }
}
