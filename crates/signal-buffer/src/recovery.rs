//! Single compare-and-swap slot, accessed only by the existing locked WAL worker.
use super::{Engine, create, io};
use crate::{BufferError, RecoveryRecord};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
};
const MAGIC: &[u8; 8] = b"SIGREC01";
fn digest(prefix: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(prefix);
    hash.update(bytes);
    hash.finalize().into()
}
impl Engine {
    pub(super) fn load_recovery(&mut self) -> Result<(), BufferError> {
        if self.recovery_capacity == 0 {
            return Ok(());
        }
        let current = self.config.directory.join("recovery");
        self.recovery = match File::open(&current) {
            Ok(mut file) => {
                let length = file.metadata().map_err(io)?.len();
                if length <= 64 || length > self.recovery_capacity as u64 + 64 {
                    return Err(BufferError::Corrupt("recovery length"));
                }
                let mut header = [0; 64];
                file.read_exact(&mut header).map_err(io)?;
                if &header[..8] != MAGIC
                    || &header[8..24] != self.metrics.stream_id.as_bytes()
                    || u64::from_le_bytes(
                        header[24..32]
                            .try_into()
                            .map_err(|_| BufferError::Corrupt("recovery framing"))?,
                    ) != length - 64
                {
                    return Err(BufferError::Corrupt("recovery binding"));
                }
                let mut bytes = vec![0; (length - 64) as usize];
                file.read_exact(&mut bytes).map_err(io)?;
                let sha256 = digest(&header[..32], &bytes);
                if sha256.as_slice() != &header[32..] {
                    return Err(BufferError::Corrupt("recovery hash"));
                }
                file.sync_all().map_err(io)?;
                self.directory.sync_all().map_err(io)?;
                Some(RecoveryRecord { sha256, bytes })
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(io(error)),
        };
        // Only the atomically published slot authorizes recovery. A bounded
        // partial staging file cannot supersede it and never authorized COMMIT.
        match fs::remove_file(self.config.directory.join("recovery.tmp")) {
            Ok(()) => self.directory.sync_all().map_err(io)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io(error)),
        }
        self.metrics.recovery_bytes = self.recovery.as_ref().map_or(0, |r| r.bytes.len());
        Ok(())
    }
    pub(crate) fn replace_recovery(
        &mut self,
        expected: Option<[u8; 32]>,
        bytes: Option<Vec<u8>>,
    ) -> Result<Option<RecoveryRecord>, BufferError> {
        if self.recovery_capacity == 0 {
            return Err(BufferError::Config("recovery disabled"));
        }
        if self.recovery.as_ref().map(|r| r.sha256) != expected {
            return Err(BufferError::RecoveryConflict);
        }
        let current = self.config.directory.join("recovery");
        match bytes {
            Some(bytes) => {
                if bytes.is_empty() || bytes.len() > self.recovery_capacity {
                    return Err(BufferError::Config("recovery payload bounds"));
                }
                let mut header = [0; 64];
                header[..8].copy_from_slice(MAGIC);
                header[8..24].copy_from_slice(self.metrics.stream_id.as_bytes());
                header[24..32].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
                let sha256 = digest(&header[..32], &bytes);
                header[32..].copy_from_slice(&sha256);
                let temporary = self.config.directory.join("recovery.tmp");
                let mut file = create(&temporary)?;
                file.write_all(&header).map_err(io)?;
                file.write_all(&bytes).map_err(io)?;
                file.sync_all().map_err(io)?;
                fs::rename(&temporary, &current).map_err(io)?;
                self.directory.sync_all().map_err(io)?;
                self.recovery = Some(RecoveryRecord { sha256, bytes });
            }
            None => {
                if self.recovery.is_some() {
                    fs::remove_file(&current).map_err(io)?;
                    self.directory.sync_all().map_err(io)?;
                }
                self.recovery = None;
            }
        }
        self.metrics.recovery_bytes = self.recovery.as_ref().map_or(0, |r| r.bytes.len());
        Ok(self.recovery.clone())
    }
}
