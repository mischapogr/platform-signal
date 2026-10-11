//! Stopped-host lifecycle metadata. The original WAL stays exclusively owned;
//! no admission capability, provider DELETE or retention policy is supplied here.
use crate::{shared_recovery::RECOVERY_BYTES, shared_startup::CatalogProfile};
use signal_buffer::{BufferConfig, BufferError, BufferMetrics, BufferReady, DurableBuffer, Policy};
use signal_control::{
    CatalogInput, ConnectionSettings, ControlClient, ControlContext, ControlError, ControlMetrics,
    LeaseToken, ObjectControlResult, ReleasePinInput, RetentionPinInput, RetirementInput, Scope,
};
use signal_protocol::EventSink;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StoppedLifecycleError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error(transparent)]
    Wal(#[from] BufferError),
}

/// An explicit maintenance host supplies separately authorized database settings.
/// Schema USAGE for control and finding-scope permits credential inspection;
/// normal producers retain their existing restricted RPC allowlist. All database
/// mutations still require the current complete owner fence and SQL permission.
/// Keep this handle after cancellation/failure and explicitly call `shutdown`.
pub struct StoppedLifecycle {
    wal: DurableBuffer,
    ready: Option<BufferReady>,
    control: ControlClient,
    scope: Scope,
    backend: Uuid,
    schema_owner: String,
    token: Option<LeaseToken>,
}

impl StoppedLifecycle {
    /// Expose finite worker/queue capacity and actual RPC rejection counters
    /// without granting access to admission, credentials or a mutable client.
    pub fn metrics(&self) -> (BufferMetrics, ControlMetrics) {
        (self.wal.snapshot(), self.control.metrics())
    }

    /// Retain physical worker handles before any cancellable startup wait. An
    /// already-running server owns this same WAL lock and prevents readiness.
    pub fn begin(
        connection: ConnectionSettings,
        profile: CatalogProfile,
        scope: Scope,
        backend: Uuid,
        config: BufferConfig,
        schema_owner: String,
    ) -> Result<Self, StoppedLifecycleError> {
        scope.validate()?;
        if backend.is_nil()
            || config.policy == Policy::DropOldest
            || schema_owner.is_empty()
            || schema_owner.len() > 63
            || schema_owner.capacity() > 63
            || !schema_owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(ControlError::Invalid.into());
        }
        config.validate()?;
        let control = match profile {
            CatalogProfile::Catalog4 => ControlClient::catalog(connection)?,
            CatalogProfile::RestoredCatalog5 => ControlClient::restored_catalog(connection)?,
        };
        let (wal, ready) = DurableBuffer::begin_open_with_recovery(config, RECOVERY_BYTES)?;
        Ok(Self {
            wal,
            ready: Some(ready),
            control,
            scope,
            backend,
            schema_owner,
            token: None,
        })
    }

    fn quiescent(&self) -> Result<(), ControlError> {
        let wal = self.wal.snapshot();
        if wal.stream_id != self.scope.stream {
            return Err(ControlError::Fenced);
        }
        if wal.closed || !wal.worker_available {
            return Err(ControlError::Unavailable);
        }
        if wal.dropped != 0 || wal.corruptions != 0 || wal.last_sequence > i64::MAX as u64 {
            return Err(ControlError::Corrupt);
        }
        if wal.checkpoint != wal.last_sequence || wal.depth != 0 || wal.recovery_bytes != 0 {
            return Err(ControlError::Conflict);
        }
        Ok(())
    }

    /// No local ACK, replay, recovery deletion or migration occurs. Pending WAL
    /// work must be completed by the original runtime before maintenance starts.
    pub async fn start(
        &mut self,
        owner: Uuid,
        lease_ms: u32,
        context: ControlContext,
    ) -> Result<(), StoppedLifecycleError> {
        context.check()?;
        if owner.is_nil() || !(15000..=60000).contains(&lease_ms) || self.token.is_some() {
            return Err(ControlError::Invalid.into());
        }
        let ready = self.ready.take().ok_or(ControlError::Unavailable)?;
        let cancellation = context.cancellation_token();
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(ControlError::Cancelled.into()),
            result = ready.wait_until(context.deadline()) => result?,
        }
        context.check()?;
        self.quiescent()?;
        let recovery = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(ControlError::Cancelled.into()),
            result = self.wal.read_recovery(context.deadline()) => result?,
        };
        if recovery.is_some() {
            return Err(ControlError::Conflict.into());
        }
        self.control
            .verify_lifecycle_credentials(self.schema_owner.clone(), context.clone())
            .await?;
        let catalog = self
            .control
            .read_catalog_snapshot(
                self.scope.clone(),
                CatalogInput {
                    schema_version: 1,
                    id: Uuid::new_v4(),
                    pin_ms: 5000,
                },
                context.clone(),
            )
            .await?;
        if catalog.backend()? != self.backend
            || catalog.checkpoint()? != self.wal.snapshot().checkpoint
        {
            return Err(ControlError::Fenced.into());
        }
        self.quiescent()?;
        self.token = Some(
            self.control
                .acquire(self.scope.clone(), owner, lease_ms, context)
                .await?,
        );
        Ok(())
    }

    fn authority(&self, context: &ControlContext) -> Result<LeaseToken, ControlError> {
        context.check()?;
        self.quiescent()?;
        self.token.clone().ok_or(ControlError::Unavailable)
    }

    /// An explicit finite maintenance operation, never an implicit background
    /// lease renewal. Expired or superseded authority is rejected by the DB.
    pub async fn renew(
        &mut self,
        lease_ms: u32,
        context: ControlContext,
    ) -> Result<(), StoppedLifecycleError> {
        let token = self.authority(&context)?;
        self.token = Some(self.control.renew(token, lease_ms, context).await?);
        Ok(())
    }

    /// The external policy owner must register every applicable restore, replay
    /// and evidence hold before retirement. Provenance is not a custody proof.
    pub async fn pin(
        &self,
        input: RetentionPinInput,
        context: ControlContext,
    ) -> Result<ObjectControlResult, StoppedLifecycleError> {
        let token = self.authority(&context)?;
        if input.object.backend_id != self.backend {
            return Err(ControlError::Fenced.into());
        }
        Ok(self.control.pin_object(token, input, context).await?)
    }

    pub async fn release_pin(
        &self,
        input: ReleasePinInput,
        context: ControlContext,
    ) -> Result<ObjectControlResult, StoppedLifecycleError> {
        let token = self.authority(&context)?;
        Ok(self
            .control
            .release_object_pin(token, input, context)
            .await?)
    }

    /// Permanent exact-version tombstone only. Committed history, reader pins
    /// and retained external holds are checked atomically by the database.
    pub async fn retire(
        &self,
        input: RetirementInput,
        context: ControlContext,
    ) -> Result<ObjectControlResult, StoppedLifecycleError> {
        let token = self.authority(&context)?;
        if input.object.backend_id != self.backend {
            return Err(ControlError::Fenced.into());
        }
        Ok(self.control.retire_object(token, input, context).await?)
    }

    /// Always attempt both physical drains, including after failed/cancelled
    /// startup. A failed drain keeps its handle available for an explicit retry.
    pub async fn shutdown(&mut self, context: ControlContext) -> Result<(), StoppedLifecycleError> {
        self.token = None;
        self.ready = None;
        self.wal.close();
        let cancellation = context.cancellation_token();
        let wal = async {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => Err(StoppedLifecycleError::Control(ControlError::Cancelled)),
                result = tokio::time::timeout_at(context.deadline(), self.wal.shutdown()) => {
                    result.map_err(|_| StoppedLifecycleError::Control(ControlError::Timeout))?
                        .map_err(StoppedLifecycleError::from)
                }
            }
        };
        let (control, wal) = tokio::join!(self.control.shutdown(context.clone()), wal);
        control?;
        wal?;
        context.check()?;
        Ok(())
    }
}
