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
    config: SmallOwnerConfig,
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
            if entries > 7 {
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
                Some("genesis.json" | "genesis.tmp") if metadata.len() <= 256 => {}
                Some("head.json" | "head.tmp")
                    if metadata.len() <= crate::object_head::HEAD_BYTES as u64 => {}
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
        let owner = Self {
            _lock: lock,
            config,
        };
        // Refused initialization records have the same no-poison rule as heads.
        for name in ["genesis.json", "genesis.tmp"] {
            let path = owner.config.directory.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => verify(&path, &expected, context)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(StorageError::Io(error)),
            }
        }
        // Refused retained heads must not pin a fresh root to the wrong owner.
        // Preflight both records/pair without renaming before writing binding.
        let current_head = owner.read_record(&owner.config.directory.join("head.json"), context)?;
        let temp_head = owner.read_record(&owner.config.directory.join("head.tmp"), context)?;
        if let Some(candidate) = &temp_head
            && current_head.as_ref() != Some(candidate)
            && candidate.previous.as_ref() != current_head.as_ref().map(|h| &h.current)
        {
            return Err(StorageError::Corrupt(
                "Small query head recovery predecessor",
            ));
        }
        if has_binding {
            verify(&binding, &expected, context)?;
            // Complete matching temp can be removed; unknown/truncated temp holds.
            if has_temp {
                verify(&temp, &expected, context)?;
                fs::remove_file(&temp).map_err(StorageError::Io)?;
                crate::fs::sync_dir(&owner.config.directory)?;
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
            crate::fs::sync_dir(&owner.config.directory)?;
        }
        owner._lock.0.sync_all().map_err(StorageError::Io)?;
        crate::fs::sync_dir(&owner.config.directory)?;
        check_context(Some(context))?;
        owner.read_head(context)?;
        owner.query_initialized(context)?;
        Ok(owner)
    }
    /// Synced initialization witnesses a previously checked empty query namespace.
    /// Only a trusted publisher may create it after bounded backend inventory.
    pub(crate) fn initialize_query(&self, context: &OperationContext) -> Result<(), StorageError> {
        if self.query_initialized(context)? {
            return Ok(());
        }
        let expected = Binding {
            schema_version: 1,
            stream_id: self.config.stream_id,
            backend_id: self.config.backend_id,
        };
        let bytes =
            serde_json::to_vec(&expected).map_err(|_| StorageError::Corrupt("query genesis"))?;
        let temp = self.config.directory.join("genesis.tmp");
        let mut file = crate::fs::create(&temp)?;
        file.write_all(&bytes).map_err(StorageError::Io)?;
        check_context(Some(context))?;
        file.sync_all().map_err(StorageError::Io)?;
        check_context(Some(context))?;
        fs::rename(&temp, self.config.directory.join("genesis.json")).map_err(StorageError::Io)?;
        crate::fs::sync_dir(&self.config.directory)?;
        check_context(Some(context))
    }
    pub(crate) fn query_initialized(
        &self,
        context: &OperationContext,
    ) -> Result<bool, StorageError> {
        check_context(Some(context))?;
        let expected = Binding {
            schema_version: 1,
            stream_id: self.config.stream_id,
            backend_id: self.config.backend_id,
        };
        let path = self.config.directory.join("genesis.json");
        let temp = self.config.directory.join("genesis.tmp");
        let exists = match fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() && m.len() <= 256 => {
                verify(&path, &expected, context)?;
                true
            }
            Ok(_) => return Err(StorageError::Corrupt("query genesis file")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(StorageError::Io(e)),
        };
        match fs::symlink_metadata(&temp) {
            Ok(m) if m.is_file() && m.len() <= 256 => {
                verify(&temp, &expected, context)?;
                check_context(Some(context))?;
                if exists {
                    fs::remove_file(&temp).map_err(StorageError::Io)?;
                } else {
                    fs::rename(&temp, &path).map_err(StorageError::Io)?;
                }
                crate::fs::sync_dir(&self.config.directory)?;
                check_context(Some(context))?;
                Ok(true)
            }
            Ok(_) => Err(StorageError::Corrupt("query genesis temp")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(exists),
            Err(e) => Err(StorageError::Io(e)),
        }
    }
    /// A missing head is uninitialized control, never proof of an empty backend.
    pub(crate) fn read_head(
        &self,
        context: &OperationContext,
    ) -> Result<Option<crate::object_head::HeadRecord>, StorageError> {
        let current_path = self.config.directory.join("head.json");
        let temp_path = self.config.directory.join("head.tmp");
        let current = self.read_record(&current_path, context)?;
        let Some(temp) = self.read_record(&temp_path, context)? else {
            return Ok(current);
        };
        if current.as_ref() == Some(&temp) {
            check_context(Some(context))?;
            fs::remove_file(&temp_path).map_err(StorageError::Io)?;
            crate::fs::sync_dir(&self.config.directory)?;
            check_context(Some(context))?;
            return Ok(current);
        }
        if temp.previous.as_ref() != current.as_ref().map(|h| &h.current) {
            return Err(StorageError::Corrupt(
                "Small query head recovery predecessor",
            ));
        }
        check_context(Some(context))?;
        fs::rename(&temp_path, &current_path).map_err(StorageError::Io)?;
        crate::fs::sync_dir(&self.config.directory)?;
        check_context(Some(context))?;
        Ok(Some(temp))
    }
    pub(crate) fn advance_head(
        &self,
        next: &crate::object_head::HeadRecord,
        context: &OperationContext,
    ) -> Result<(), StorageError> {
        check_context(Some(context))?;
        next.validate(self.config.stream_id, self.config.backend_id)?;
        let current = self.read_head(context)?;
        if current.as_ref() == Some(next) {
            return check_context(Some(context));
        }
        if next.previous.as_ref() != current.as_ref().map(|h| &h.current) {
            return Err(StorageError::InvalidBatch);
        }
        let bytes = next.encode(context)?;
        let temp_path = self.config.directory.join("head.tmp");
        let mut file = crate::fs::create(&temp_path)?;
        file.write_all(&bytes).map_err(StorageError::Io)?;
        check_context(Some(context))?;
        file.sync_all().map_err(StorageError::Io)?;
        check_context(Some(context))?;
        fs::rename(&temp_path, self.config.directory.join("head.json"))
            .map_err(StorageError::Io)?;
        crate::fs::sync_dir(&self.config.directory)?;
        check_context(Some(context))
    }
    fn read_record(
        &self,
        path: &std::path::Path,
        context: &OperationContext,
    ) -> Result<Option<crate::object_head::HeadRecord>, StorageError> {
        check_context(Some(context))?;
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(m) if m.is_file() && m.len() <= crate::object_head::HEAD_BYTES as u64 => {}
            Ok(_) => return Err(StorageError::Corrupt("Small query head file")),
            Err(error) => return Err(StorageError::Io(error)),
        }
        let mut file = File::open(path).map_err(StorageError::Io)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(crate::object_head::HEAD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(StorageError::Io)?;
        let record = crate::object_head::HeadRecord::decode(
            &bytes,
            self.config.stream_id,
            self.config.backend_id,
            context,
        )?;
        file.sync_all().map_err(StorageError::Io)?;
        check_context(Some(context))?;
        Ok(Some(record))
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
