//! Exclusively owned derived copies. No source evidence/retention or eviction.
//! All filesystem calls execute on the ordinary publication controller worker.
use crate::object_manifest::QueryFile;
use crate::object_owner::{SmallOwner, SmallOwnerConfig};
use crate::{OperationContext, PublishedFile, StorageError, check_context};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;
#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct MaterializationConfig {
    pub directory: PathBuf,
    pub max_files: usize,
    pub max_disk_bytes: u64,
}
impl MaterializationConfig {
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.directory.as_os_str().is_empty()
            || self.directory.as_os_str().len() > 4096
            || self.directory.components().count() > 64
            || self
                .directory
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            || self.max_files == 0
            || self.max_files > 100_000
            || self.max_disk_bytes == 0
            || self.max_disk_bytes > 1024 * 1024 * 1024 * 1024
        {
            return Err(StorageError::Config("bounded query materialization"));
        }
        Ok(())
    }
}
pub(crate) struct Cache {
    config: MaterializationConfig,
    _owner: SmallOwner,
    objects: PathBuf,
}
impl Cache {
    pub(crate) fn open(
        config: &MaterializationConfig,
        stream: Uuid,
        backend: Uuid,
        context: &OperationContext,
    ) -> Result<Self, StorageError> {
        config.validate()?;
        for ancestor in config
            .directory
            .ancestors()
            .filter(|p| !p.as_os_str().is_empty())
        {
            check_context(Some(context))?;
            match fs::symlink_metadata(ancestor) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => return Err(StorageError::Corrupt("cache directory")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(StorageError::Io(e)),
            }
        }
        crate::fs::directory(&config.directory)?;
        let mut entries = 0;
        for entry in fs::read_dir(&config.directory).map_err(StorageError::Io)? {
            check_context(Some(context))?;
            entries += 1;
            let entry = entry.map_err(StorageError::Io)?;
            if entries > 2
                || !matches!(entry.file_name().to_str(), Some("control" | "objects"))
                || !fs::symlink_metadata(entry.path())
                    .map_err(StorageError::Io)?
                    .is_dir()
            {
                return Err(StorageError::Corrupt("cache root entry"));
            }
        }
        let objects = config.directory.join("objects");
        crate::fs::directory(&objects)?;
        // Validate foreign/partial layout before publishing a fresh binding.
        inventory(&objects, config, context)?;
        let owner = SmallOwner::open(
            &SmallOwnerConfig {
                directory: config.directory.join("control"),
                stream_id: stream,
                backend_id: backend,
            },
            context,
        )?;
        let objects = objects.canonicalize().map_err(StorageError::Io)?;
        Ok(Self {
            config: config.clone(),
            _owner: owner,
            objects,
        })
    }
    pub(crate) fn materialize(
        &self,
        file: &QueryFile,
        bytes: &[u8],
        context: &OperationContext,
    ) -> Result<PublishedFile, StorageError> {
        check_context(Some(context))?;
        // Caller authenticated and inspected actual Parquet before this operation.
        file.object
            .verify_bytes(bytes, bytes.len() as u64)
            .map_err(|_| StorageError::Corrupt("cache selected bytes"))?;
        let stem = file
            .object
            .sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let path = self.objects.join(format!("{stem}.parquet"));
        let temp = self.objects.join(format!("{stem}.tmp"));
        let (count, total) = inventory(&self.objects, &self.config, context)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) => verify_file(&path, &meta, bytes, context)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match fs::symlink_metadata(&temp) {
                    Ok(meta) => {
                        verify_file(&temp, &meta, bytes, context)?;
                        File::open(&temp)
                            .map_err(StorageError::Io)?
                            .sync_all()
                            .map_err(StorageError::Io)?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if count >= self.config.max_files
                            || bytes.len() as u64 > self.config.max_disk_bytes.saturating_sub(total)
                        {
                            return Err(StorageError::Full);
                        }
                        let mut output = crate::fs::create(&temp)?;
                        for chunk in bytes.chunks(8192) {
                            check_context(Some(context))?;
                            output.write_all(chunk).map_err(StorageError::Io)?;
                        }
                        output.sync_all().map_err(StorageError::Io)?;
                    }
                    Err(e) => return Err(StorageError::Io(e)),
                }
                check_context(Some(context))?;
                fs::rename(&temp, &path).map_err(StorageError::Io)?;
                crate::fs::sync_dir(&self.objects)?;
            }
            Err(e) => return Err(StorageError::Io(e)),
        }
        check_context(Some(context))?;
        Ok(PublishedFile {
            path,
            rows: file.rows,
            bytes: file.object.bytes,
            uncompressed_bytes: file.decoded_bytes,
        })
    }
}
fn regular(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.is_file() && meta.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}
fn inventory(
    root: &Path,
    config: &MaterializationConfig,
    context: &OperationContext,
) -> Result<(usize, u64), StorageError> {
    let mut count = 0usize;
    let mut total = 0u64;
    for entry in fs::read_dir(root).map_err(StorageError::Io)? {
        check_context(Some(context))?;
        count += 1;
        if count > config.max_files {
            return Err(StorageError::Full);
        }
        let entry = entry.map_err(StorageError::Io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(StorageError::Corrupt("cache name"))?;
        let stem = name
            .strip_suffix(".parquet")
            .or_else(|| name.strip_suffix(".tmp"))
            .ok_or(StorageError::Corrupt("cache entry"))?;
        if stem.len() != 64
            || !stem
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(StorageError::Corrupt("cache name"));
        }
        let meta = fs::symlink_metadata(entry.path()).map_err(StorageError::Io)?;
        if !regular(&meta) {
            return Err(StorageError::Corrupt("cache file type"));
        }
        total = total.checked_add(meta.len()).ok_or(StorageError::Full)?;
        if total > config.max_disk_bytes {
            return Err(StorageError::Full);
        }
    }
    Ok((count, total))
}
fn verify_file(
    path: &Path,
    meta: &fs::Metadata,
    expected: &[u8],
    context: &OperationContext,
) -> Result<(), StorageError> {
    if !regular(meta) || meta.len() != expected.len() as u64 {
        return Err(StorageError::Corrupt("cache identity"));
    }
    let mut file = File::open(path).map_err(StorageError::Io)?;
    let mut offset = 0usize;
    let mut chunk = [0; 8192];
    loop {
        check_context(Some(context))?;
        let used = file.read(&mut chunk).map_err(StorageError::Io)?;
        if used == 0 {
            break;
        }
        let end = offset
            .checked_add(used)
            .ok_or(StorageError::Corrupt("cache bytes"))?;
        if expected.get(offset..end) != Some(&chunk[..used]) {
            return Err(StorageError::Corrupt("cache bytes"));
        }
        offset = end;
    }
    if offset != expected.len() {
        return Err(StorageError::Corrupt("cache bytes"));
    }
    check_context(Some(context))
}
