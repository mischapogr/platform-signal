//! Original publication identity survives uncertainty until synced WAL checkpoint.
use crate::shared::{
    PreparedPublication, PublicationDraft, ScopedPreparedPublication, SharedError, SharedPublisher,
};
use crate::shared_scoped::ScopedPublicationDraft;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signal_buffer::{BufferError, DurableBuffer, Policy, RecoveryRecord};
use signal_control::{
    ControlContext, ControlError, LeaseToken, PublicationInput, PublicationResult, Scope,
};
use signal_storage::StoredEvent;
use std::{
    future::Future,
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

pub const RECOVERY_BYTES: usize = 4 * 1024 * 1024;
const BATCH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error(transparent)]
    Shared(#[from] SharedError),
    #[error(transparent)]
    Buffer(#[from] BufferError),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    schema_version: u32,
    scope: Scope,
    backend: Uuid,
    first: u64,
    last: u64,
    rows_sha256: [u8; 32],
    phase: Phase,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Phase {
    Draft {
        draft: PublicationDraft,
    },
    Prepared {
        request: PublicationInput,
    },
    ScopedDraft {
        draft: Box<ScopedPublicationDraft>,
    },
    ScopedPrepared {
        request: Box<signal_control::ScopedPublicationInput>,
    },
}
struct Writer {
    bytes: Vec<u8>,
}
impl Write for Writer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > RECOVERY_BYTES.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("recovery capacity"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(entry: &Entry) -> Result<Vec<u8>, ControlError> {
    let mut writer = Writer { bytes: Vec::new() };
    serde_json::to_writer(&mut writer, entry).map_err(|_| ControlError::Full)?;
    Ok(writer.bytes.into_boxed_slice().into_vec())
}
struct HashWriter {
    hash: Sha256,
    bytes: usize,
}
impl Write for HashWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > BATCH_BYTES.saturating_sub(self.bytes) {
            return Err(std::io::Error::other("recovery row capacity"));
        }
        self.hash.update(data);
        self.bytes += data.len();
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn rows_hash(rows: &[StoredEvent]) -> Result<[u8; 32], ControlError> {
    let mut writer = HashWriter {
        hash: Sha256::new(),
        bytes: 0,
    };
    writer
        .write_all(b"SIGNAL-SHARED-WAL-ROWS-V1\0")
        .map_err(|_| ControlError::Full)?;
    for row in rows {
        writer
            .write_all(&row.sequence.to_le_bytes())
            .map_err(|_| ControlError::Full)?;
        serde_json::to_writer(&mut writer, &row.event).map_err(|_| ControlError::Full)?;
        writer.write_all(b"\n").map_err(|_| ControlError::Full)?;
    }
    Ok(writer.hash.finalize().into())
}
async fn wal<T>(
    context: &ControlContext,
    future: impl Future<Output = Result<T, BufferError>>,
) -> Result<T, RecoveryError> {
    context.check()?;
    let cancel = context.cancellation_token();
    let result = tokio::select! { biased;
        ()=cancel.cancelled()=>Err(ControlError::Cancelled.into()),
        result=tokio::time::timeout_at(context.deadline(),future)=>result.map_err(|_|RecoveryError::Control(ControlError::Timeout))?.map_err(Into::into),
    };
    context.check()?;
    result
}

pub struct SharedRecovery {
    publisher: Arc<SharedPublisher>,
    wal: Arc<DurableBuffer>,
    seats: Arc<Semaphore>,
    binding: Arc<()>,
    rejected: AtomicU64,
}
/// Nonserializable original-operation capability, retaining one admission seat.
pub struct RecoveryPrepared {
    publication: RecoveryPublication,
    context: ControlContext,
    record_sha256: [u8; 32],
    binding: Arc<()>,
    _seat: OwnedSemaphorePermit,
}
enum RecoveryPublication {
    Raw(Box<PreparedPublication>),
    Scoped(Box<ScopedPreparedPublication>),
}
impl RecoveryPublication {
    fn request(&self) -> &PublicationInput {
        match self {
            Self::Raw(p) => p.request(),
            Self::Scoped(p) => p.request().publication(),
        }
    }
    fn deadline(&self) -> tokio::time::Instant {
        match self {
            Self::Raw(p) => p.deadline(),
            Self::Scoped(p) => p.deadline(),
        }
    }
}
impl RecoveryPrepared {
    pub fn request(&self) -> &PublicationInput {
        self.publication.request()
    }
    pub fn scoped_request(&self) -> Option<&signal_control::ScopedPublicationInput> {
        match &self.publication {
            RecoveryPublication::Raw(_) => None,
            RecoveryPublication::Scoped(p) => Some(p.request()),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct RecoveryMetrics {
    pub active: usize,
    pub capacity: usize,
    pub rejected: u64,
    pub retained_bytes: usize,
    pub retained_capacity: usize,
}
struct Observe<'a>(&'a AtomicU64, bool);
impl Drop for Observe<'_> {
    fn drop(&mut self) {
        if self.1 {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl SharedRecovery {
    pub fn new(
        publisher: Arc<SharedPublisher>,
        wal: Arc<DurableBuffer>,
    ) -> Result<Self, RecoveryError> {
        let snapshot = wal.snapshot();
        if snapshot.stream_id != publisher.binding().0.stream {
            return Err(ControlError::Fenced.into());
        }
        if snapshot.closed
            || wal.policy() == Policy::DropOldest
            || snapshot.recovery_capacity != RECOVERY_BYTES
            || snapshot.dropped != 0
        {
            return Err(ControlError::Invalid.into());
        }
        Ok(Self {
            publisher,
            wal,
            seats: Arc::new(Semaphore::new(1)),
            binding: Arc::new(()),
            rejected: AtomicU64::new(0),
        })
    }
    pub fn metrics(&self) -> RecoveryMetrics {
        let wal = self.wal.snapshot();
        RecoveryMetrics {
            active: 1 - self.seats.available_permits(),
            capacity: 1,
            rejected: self.rejected.load(Ordering::Relaxed),
            retained_bytes: wal.recovery_bytes,
            retained_capacity: wal.recovery_capacity,
        }
    }
    fn check(&self, token: &LeaseToken, context: &ControlContext) -> Result<(), RecoveryError> {
        context.check()?;
        token.validate()?;
        let snapshot = self.wal.snapshot();
        if token.scope != *self.publisher.binding().0 || snapshot.stream_id != token.scope.stream {
            return Err(ControlError::Fenced.into());
        }
        if !snapshot.worker_available {
            return Err(ControlError::Unavailable.into());
        }
        if snapshot.dropped != 0 || snapshot.corruptions != 0 {
            return Err(ControlError::Corrupt.into());
        }
        Ok(())
    }
    async fn rows(
        &self,
        count: usize,
        context: &ControlContext,
    ) -> Result<Vec<StoredEvent>, RecoveryError> {
        if count == 0 || count > 4096 {
            return Err(ControlError::Invalid.into());
        }
        Ok(wal(
            context,
            self.wal
                .read_batch_at(count, BATCH_BYTES, context.deadline()),
        )
        .await?
        .into_iter()
        .map(|r| StoredEvent {
            sequence: r.sequence,
            event: r.event,
        })
        .collect())
    }
    async fn save(
        &self,
        entry: &Entry,
        expected: Option<[u8; 32]>,
        context: &ControlContext,
    ) -> Result<RecoveryRecord, RecoveryError> {
        context.check()?;
        let bytes = encode(entry)?;
        context.check()?;
        wal(
            context,
            self.wal
                .replace_recovery(expected, Some(bytes), context.deadline()),
        )
        .await?
        .ok_or(ControlError::Corrupt.into())
    }
    /// Read the actual unacknowledged WAL prefix and persist its original plan
    /// before uploads. Prepared request bytes are synced before returning.
    pub async fn prepare(
        &self,
        token: LeaseToken,
        draft: PublicationDraft,
        max_events: usize,
        context: ControlContext,
    ) -> Result<RecoveryPrepared, RecoveryError> {
        self.prepare_phase(token, Phase::Draft { draft }, max_events, context)
            .await
    }
    pub async fn prepare_scoped(
        &self,
        token: LeaseToken,
        draft: ScopedPublicationDraft,
        max_events: usize,
        context: ControlContext,
    ) -> Result<RecoveryPrepared, RecoveryError> {
        self.prepare_phase(
            token,
            Phase::ScopedDraft {
                draft: Box::new(draft),
            },
            max_events,
            context,
        )
        .await
    }
    async fn prepare_phase(
        &self,
        token: LeaseToken,
        phase: Phase,
        max_events: usize,
        context: ControlContext,
    ) -> Result<RecoveryPrepared, RecoveryError> {
        let mut observe = Observe(&self.rejected, true);
        self.check(&token, &context)?;
        let seat = self
            .seats
            .clone()
            .try_acquire_owned()
            .map_err(|_| ControlError::Full)?;
        if wal(&context, self.wal.read_recovery(context.deadline()))
            .await?
            .is_some()
        {
            return Err(ControlError::Conflict.into());
        }
        let rows = self.rows(max_events, &context).await?;
        let schema_version = match &phase {
            Phase::Draft { draft } => {
                draft.validate(&rows)?;
                1
            }
            Phase::ScopedDraft { draft } => {
                draft.validate(&rows, &token.scope)?;
                2
            }
            _ => return Err(ControlError::Corrupt.into()),
        };
        let first = rows.first().ok_or(ControlError::Invalid)?.sequence;
        let last = rows.last().ok_or(ControlError::Invalid)?.sequence;
        if first
            != self
                .wal
                .snapshot()
                .checkpoint
                .checked_add(1)
                .ok_or(ControlError::Corrupt)?
        {
            return Err(ControlError::Corrupt.into());
        }
        let entry = Entry {
            schema_version,
            scope: token.scope.clone(),
            backend: self.publisher.binding().1,
            first,
            last,
            rows_sha256: rows_hash(&rows)?,
            phase,
        };
        let record = self.save(&entry, None, &context).await?;
        let prepared = self
            .prepare_entry(token, entry, record.sha256, rows, seat, context)
            .await?;
        observe.1 = false;
        Ok(prepared)
    }
    async fn prepare_entry(
        &self,
        token: LeaseToken,
        mut entry: Entry,
        expected: [u8; 32],
        rows: Vec<StoredEvent>,
        seat: OwnedSemaphorePermit,
        context: ControlContext,
    ) -> Result<RecoveryPrepared, RecoveryError> {
        let publication = match &entry.phase {
            Phase::Draft { draft } => {
                draft.validate(&rows)?;
                RecoveryPublication::Raw(Box::new(
                    self.publisher
                        .prepare(token, &rows, draft.clone(), context.clone())
                        .await?,
                ))
            }
            Phase::ScopedDraft { draft } => {
                draft.validate(&rows, &token.scope)?;
                RecoveryPublication::Scoped(Box::new(
                    self.publisher
                        .prepare_scoped(token, &rows, (**draft).clone(), context.clone())
                        .await?,
                ))
            }
            _ => return Err(ControlError::Corrupt.into()),
        };
        let context = context.limited_to(publication.deadline());
        entry.phase = match &publication {
            RecoveryPublication::Raw(p) => Phase::Prepared {
                request: p.request().clone(),
            },
            RecoveryPublication::Scoped(p) => Phase::ScopedPrepared {
                request: Box::new(p.request().clone()),
            },
        };
        let record = self.save(&entry, Some(expected), &context).await?;
        Ok(RecoveryPrepared {
            publication,
            context,
            record_sha256: record.sha256,
            binding: self.binding.clone(),
            _seat: seat,
        })
    }
    pub async fn commit(
        &self,
        prepared: RecoveryPrepared,
    ) -> Result<PublicationResult, RecoveryError> {
        let mut observe = Observe(&self.rejected, true);
        if !Arc::ptr_eq(&prepared.binding, &self.binding) {
            return Err(ControlError::Fenced.into());
        }
        let request = prepared.request().clone();
        let result = match prepared.publication {
            RecoveryPublication::Raw(p) => self.publisher.commit(*p).await?,
            RecoveryPublication::Scoped(p) => self.publisher.commit_scoped(*p).await?,
        };
        self.finish(&request, &result, prepared.record_sha256, &prepared.context)
            .await?;
        observe.1 = false;
        Ok(result)
    }
    async fn finish(
        &self,
        request: &PublicationInput,
        result: &PublicationResult,
        expected: [u8; 32],
        context: &ControlContext,
    ) -> Result<(), RecoveryError> {
        if result.id != request.id
            || result.first_sequence != request.first_sequence
            || result.last_sequence != request.last_sequence
        {
            return Err(ControlError::Corrupt.into());
        }
        // Once publication is confirmed, any lost checkpoint/reclamation reply
        // remains uncertain. The slot or advanced checkpoint survives for replay.
        let local = async {
            context.check()?;
            wal(
                context,
                self.wal.ack_at(result.last_sequence, context.deadline()),
            )
            .await?;
            wal(
                context,
                self.wal
                    .replace_recovery(Some(expected), None, context.deadline()),
            )
            .await?;
            context.check()?;
            Ok::<(), RecoveryError>(())
        }
        .await;
        local.map_err(|_| ControlError::Uncertain.into())
    }
    /// Recover the retained exact plan under current authority. Absence from the
    /// DB permits only an exact verified retry while the original WAL rows exist.
    /// An acknowledged prefix never permits rebuilding a missing request.
    pub async fn resume(
        &self,
        token: LeaseToken,
        context: ControlContext,
    ) -> Result<Option<PublicationResult>, RecoveryError> {
        let mut observe = Observe(&self.rejected, true);
        self.check(&token, &context)?;
        let seat = self
            .seats
            .clone()
            .try_acquire_owned()
            .map_err(|_| ControlError::Full)?;
        let Some(record) = wal(&context, self.wal.read_recovery(context.deadline())).await? else {
            observe.1 = false;
            return Ok(None);
        };
        if record.bytes.len() > RECOVERY_BYTES {
            return Err(ControlError::Corrupt.into());
        }
        let entry: Entry =
            serde_json::from_slice(&record.bytes).map_err(|_| ControlError::Corrupt)?;
        let compatible = matches!(
            (&entry.phase, entry.schema_version),
            (Phase::Draft { .. } | Phase::Prepared { .. }, 1)
                | (Phase::ScopedDraft { .. } | Phase::ScopedPrepared { .. }, 2)
        );
        if !compatible || entry.scope != token.scope || entry.backend != self.publisher.binding().1
        {
            return Err(ControlError::Fenced.into());
        }
        if entry.first == 0
            || entry.last < entry.first
            || entry.last > i64::MAX as u64
            || entry.last - entry.first >= 4096
        {
            return Err(ControlError::Corrupt.into());
        }
        let checkpoint = self.wal.snapshot().checkpoint;
        let rows = if checkpoint < entry.last {
            if checkpoint.checked_add(1) != Some(entry.first) {
                return Err(ControlError::Corrupt.into());
            }
            let rows = self
                .rows((entry.last - entry.first + 1) as usize, &context)
                .await?;
            if rows.first().map(|r| r.sequence) != Some(entry.first)
                || rows.last().map(|r| r.sequence) != Some(entry.last)
                || rows_hash(&rows)? != entry.rows_sha256
            {
                return Err(ControlError::Corrupt.into());
            }
            Some(rows)
        } else {
            None
        };
        let result = match &entry.phase {
            Phase::Draft { .. } | Phase::ScopedDraft { .. } => {
                let rows = rows.ok_or(ControlError::Corrupt)?;
                let prepared = self
                    .prepare_entry(token, entry, record.sha256, rows, seat, context)
                    .await?;
                let result = self.commit(prepared).await?;
                observe.1 = false;
                return Ok(Some(result));
            }
            Phase::Prepared { request } => {
                request.validate(&entry.scope)?;
                if request.first_sequence != entry.first || request.last_sequence != entry.last {
                    return Err(ControlError::Corrupt.into());
                }
                match self
                    .publisher
                    .resolve(token.clone(), request.clone(), context.clone())
                    .await
                {
                    Ok(result) => result,
                    Err(SharedError::Control(ControlError::Uncertain)) if rows.is_some() => {
                        self.publisher
                            .recommit(token, request.clone(), context.clone())
                            .await?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Phase::ScopedPrepared { request } => {
                request.validate(&entry.scope)?;
                let base = request.publication();
                if base.first_sequence != entry.first || base.last_sequence != entry.last {
                    return Err(ControlError::Corrupt.into());
                }
                if let Some(rows) = &rows {
                    request.verify_rows(rows)?;
                }
                match self
                    .publisher
                    .resolve_scoped(token.clone(), (**request).clone(), context.clone())
                    .await
                {
                    Ok(result) => result,
                    Err(SharedError::Control(ControlError::Uncertain)) if rows.is_some() => {
                        self.publisher
                            .recommit_scoped(token, (**request).clone(), context.clone())
                            .await?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        };
        let request = match &entry.phase {
            Phase::Prepared { request } => request,
            Phase::ScopedPrepared { request } => request.publication(),
            _ => return Err(ControlError::Corrupt.into()),
        };
        self.finish(request, &result, record.sha256, &context)
            .await?;
        observe.1 = false;
        Ok(Some(result))
    }
}
