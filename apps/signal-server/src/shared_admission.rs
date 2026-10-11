//! Native grant-only WAL admission. HTTP202 remains synced local WAL, not READY
//! or shared publication. The host must keep this WAL's admission path exclusive.
use signal_buffer::{DurableBuffer, Policy};
use signal_control::{ControlError, FindingScopePin, ProducerEnrollment};
use signal_event::SignalEvent;
use signal_protocol::{
    AdmissionError, AdmissionFuture, EventSink, SinkMetrics,
    access::{Operation, RequestGrant, ScopeFacts},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::Semaphore;

pub struct SharedAdmission {
    wal: Arc<DurableBuffer>,
    producer: ProducerEnrollment,
    admission_floor: u64,
    callers: Semaphore,
    accepted: AtomicU64,
    rejected: AtomicU64,
    closed: AtomicBool,
}
#[derive(Clone, Copy, Debug)]
pub struct SharedAdmissionMetrics {
    pub active: usize,
    pub capacity: usize,
    pub accepted: u64,
    pub rejected: u64,
    pub closed: bool,
}
struct Attempt<'a>(&'a AtomicU64, bool);
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if self.1 {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}
fn capture_floor(
    snapshot: signal_buffer::BufferMetrics,
    original: u64,
    database_checkpoint: Option<u64>,
) -> Result<u64, ControlError> {
    let checkpoint = database_checkpoint.ok_or(ControlError::Fenced)?;
    if original > snapshot.last_sequence
        || snapshot.checkpoint > checkpoint
        || checkpoint > snapshot.last_sequence
        || snapshot.recovery_bytes != 0
        || snapshot.command_depth != 0
        || snapshot.operations_in_flight != 0
        || snapshot.waiters != 0
        || (original != snapshot.last_sequence
            && (snapshot.checkpoint != snapshot.last_sequence
                || checkpoint != snapshot.last_sequence
                || snapshot.depth != 0))
    {
        return Err(ControlError::Fenced);
    }
    Ok(snapshot.last_sequence)
}
impl SharedAdmission {
    /// Consume a live, owner-produced enrollment binding while the WAL still
    /// equals its original floor, or has completely reconciled that prefix.
    /// A copied producer record is retained
    /// configuration, not credentials, fresh enrollment authority or readiness.
    pub fn new(wal: Arc<DurableBuffer>, enrollment: FindingScopePin) -> Result<Self, ControlError> {
        let binding = enrollment.binding()?;
        let producer = binding
            .producer
            .as_ref()
            .ok_or(ControlError::Invalid)?
            .clone();
        producer.scope.validate()?;
        let snapshot = wal.snapshot();
        if producer.scope.stream != snapshot.stream_id
            || producer.scope.store_id != binding.store
            || producer.scope.generation != binding.store_generation
            || producer.scope_generation != binding.scope_generation
            || binding
                .checkpoint
                .is_none_or(|c| snapshot.checkpoint > c || c > snapshot.last_sequence)
        {
            return Err(ControlError::Fenced);
        }
        let admission_floor = capture_floor(snapshot, producer.wal_floor, binding.checkpoint)?;
        if snapshot.closed || !snapshot.worker_available {
            return Err(ControlError::Unavailable);
        }
        if wal.policy() == Policy::DropOldest
            || snapshot.dropped != 0
            || snapshot.corruptions != 0
            || snapshot.recovery_capacity != crate::shared_recovery::RECOVERY_BYTES
        {
            return Err(ControlError::Invalid);
        }
        enrollment.binding()?;
        Ok(Self {
            wal,
            producer,
            admission_floor,
            callers: Semaphore::new(1),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        })
    }
    /// Original startup/floor only. Deserialization or borrowing never proves
    /// a retained event was authenticated; legacy rows at/below floor stay unknown.
    pub fn enrollment(&self) -> &ProducerEnrollment {
        &self.producer
    }
    /// Current future-only native admission boundary, distinct from original
    /// immutable enrollment. It grants no authentication to retained rows.
    pub fn admission_floor(&self) -> u64 {
        self.admission_floor
    }
    pub fn admission_metrics(&self) -> SharedAdmissionMetrics {
        SharedAdmissionMetrics {
            active: 1 - self.callers.available_permits(),
            capacity: 1,
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            closed: self.closed.load(Ordering::Acquire) || self.wal.snapshot().closed,
        }
    }
}
impl EventSink for SharedAdmission {
    fn admit(&self, _event: SignalEvent) -> AdmissionFuture<'_> {
        Box::pin(async move {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            Err(if self.admission_metrics().closed {
                AdmissionError::Closed
            } else {
                AdmissionError::Unavailable
            })
        })
    }
    fn admit_with_grant<'a>(
        &'a self,
        event: SignalEvent,
        grant: &'a RequestGrant,
        original_deadline: Instant,
    ) -> AdmissionFuture<'a> {
        Box::pin(async move {
            let mut attempt = Attempt(&self.rejected, true);
            if self.closed.load(Ordering::Acquire) {
                return Err(AdmissionError::Closed);
            }
            let _seat = self
                .callers
                .try_acquire()
                .map_err(|_| AdmissionError::Full)?;
            // Capture the monotonic anchor first: descheduling between clock
            // reads may shorten authority but must never extend its expiry.
            let anchor = Instant::now();
            let now = SystemTime::now();
            let seconds = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| AdmissionError::Unavailable)?
                .as_secs();
            if Instant::now() >= original_deadline
                || !grant.allows(Operation::IngestEvents, ScopeFacts::event(&event), seconds)
            {
                return Err(AdmissionError::Unavailable);
            }
            let (_, expires) = grant.lease_bounds();
            let remaining = SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(expires))
                .ok_or(AdmissionError::Unavailable)?
                .duration_since(now)
                .map_err(|_| AdmissionError::Unavailable)?;
            let deadline = original_deadline.min(
                anchor
                    .checked_add(remaining)
                    .ok_or(AdmissionError::Unavailable)?,
            );
            let before = self.wal.snapshot();
            if before.stream_id != self.producer.scope.stream
                || before.last_sequence < self.producer.wal_floor
                || before.dropped != 0
                || before.corruptions != 0
                || !before.worker_available
            {
                return Err(AdmissionError::Unavailable);
            }
            self.wal
                .admit_at(event, tokio::time::Instant::from_std(deadline))
                .await?;
            // A late reply cannot grant a fresh HTTP receipt. Synced effects stay
            // owned by the WAL and follow its existing uncertain replay semantics.
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| AdmissionError::Unavailable)?
                .as_secs();
            if Instant::now() >= deadline || now >= expires || now < grant.lease_bounds().0 {
                return Err(AdmissionError::Unavailable);
            }
            let after = self.wal.snapshot();
            if after.stream_id != self.producer.scope.stream
                || after.last_sequence <= self.producer.wal_floor
                || after.dropped != 0
                || after.corruptions != 0
                || !after.worker_available
            {
                return Err(AdmissionError::Unavailable);
            }
            self.accepted.fetch_add(1, Ordering::Relaxed);
            attempt.1 = false;
            Ok(())
        })
    }
    fn metrics(&self) -> SinkMetrics {
        let mut metrics = self.wal.metrics();
        let native = self.admission_metrics();
        metrics.accepted = native.accepted;
        metrics.rejected = native.rejected;
        metrics.closed = native.closed;
        metrics
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wal.close();
    }
}

#[cfg(test)]
mod tests;
