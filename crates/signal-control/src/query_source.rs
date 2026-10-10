//! Database-authorized committed catalog to exact-object query adapter.
use crate::{CatalogInput, CatalogPin, ControlClient, ControlContext, ControlError, Scope};
use chrono::{DateTime, Utc};
use signal_storage::{
    FileSelection, OperationContext, QueryFileSource, StorageError, StoreFuture,
    object_selection::{ObjectSelection, SelectionBounds},
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use uuid::Uuid;

/// The host supplies an authenticated backend mapping and current scope. This
/// adapter never falls back to a local catalog or caller-specified manifest IDs.
/// QueryEngine and its physical readers retain this source through shutdown;
/// stop queries before closing the materializer and the shared control client.
pub struct SharedQuerySource {
    control: Arc<ControlClient>,
    scope: Scope,
    objects: ObjectSelection,
    accepted: AtomicU64,
    rejected: AtomicU64,
}
#[derive(Clone, Copy, Debug)]
pub struct SharedQueryMetrics {
    pub objects: signal_storage::object_selection::SelectionMetrics,
    pub accepted: u64,
    pub rejected: u64,
}
struct Observation<'a> {
    source: &'a SharedQuerySource,
    failed: bool,
}
impl Drop for Observation<'_> {
    fn drop(&mut self) {
        if self.failed {
            self.source.rejected.fetch_add(1, Ordering::Relaxed);
        } else {
            self.source.accepted.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl SharedQuerySource {
    pub fn new(
        control: Arc<ControlClient>,
        scope: Scope,
        objects: ObjectSelection,
    ) -> Result<Self, ControlError> {
        scope.validate()?;
        if objects.binding().0 != scope.stream {
            return Err(ControlError::Invalid);
        }
        Ok(Self {
            control,
            scope,
            objects,
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        })
    }
    pub fn metrics(&self) -> SharedQueryMetrics {
        SharedQueryMetrics {
            objects: self.objects.metrics(),
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    /// Use an already admitted catalog without rediscovery or lease renewal.
    /// This also supports retried operations that retain their original capability.
    pub async fn select_pin(
        &self,
        pin: &CatalogPin,
        bounds: SelectionBounds,
        context: OperationContext,
    ) -> Result<FileSelection, StorageError> {
        let mut observation = Observation {
            source: self,
            failed: true,
        };
        let selection = self.select_pin_inner(pin, bounds, context).await?;
        observation.failed = false;
        Ok(selection)
    }
    async fn select_pin_inner(
        &self,
        pin: &CatalogPin,
        bounds: SelectionBounds,
        mut context: OperationContext,
    ) -> Result<FileSelection, StorageError> {
        self.objects.validate_bounds(bounds)?;
        let snapshot = pin.snapshot().map_err(control_error)?;
        if snapshot.scope() != &self.scope
            || pin.backend().map_err(control_error)? != self.objects.binding().1
        {
            return Err(StorageError::Corrupt("shared query scope/backend"));
        }
        context.deadline = context.deadline.min(snapshot.deadline());
        let manifests = snapshot.manifests().map_err(control_error)?;
        let bytes: Vec<&[u8]> = manifests
            .iter()
            .map(|manifest| manifest.bytes.as_slice())
            .collect();
        let selection = self.objects.materialize(&bytes, bounds, context).await?;
        snapshot
            .bind_query_selection(selection)
            .map_err(control_error)
    }
    /// Stop QueryEngine/physical readers first. ControlClient may be shared with
    /// pipeline/notification consumers and is closed explicitly by the host.
    pub async fn shutdown(&self, context: OperationContext) -> Result<(), StorageError> {
        self.objects.shutdown(context).await
    }
}
impl QueryFileSource for SharedQuerySource {
    fn select_query_files(
        &self,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        max_files: usize,
        max_decoded_bytes: u64,
        context: OperationContext,
    ) -> StoreFuture<'_, FileSelection> {
        Box::pin(async move {
            let mut observation = Observation {
                source: self,
                failed: true,
            };
            let bounds = SelectionBounds {
                from,
                to,
                max_files,
                max_decoded_bytes,
            };
            self.objects.validate_bounds(bounds)?;
            if context.cancellation.is_cancelled() {
                return Err(StorageError::Cancelled);
            }
            if tokio::time::Instant::now() >= context.deadline {
                return Err(StorageError::Timeout);
            }
            let control_context = ControlContext {
                deadline: context
                    .deadline
                    .min(tokio::time::Instant::now() + std::time::Duration::from_secs(5)),
                cancellation: context.cancellation.child_token(),
            };
            let pin = self
                .control
                .read_catalog_snapshot(
                    self.scope.clone(),
                    CatalogInput {
                        schema_version: 1,
                        id: Uuid::new_v4(),
                        pin_ms: 5000,
                    },
                    control_context,
                )
                .await
                .map_err(control_error)?;
            let selection = self.select_pin_inner(&pin, bounds, context).await?;
            observation.failed = false;
            Ok(selection)
        })
    }
}
fn control_error(error: ControlError) -> StorageError {
    match error {
        ControlError::Timeout | ControlError::SnapshotExpired => StorageError::Timeout,
        ControlError::Cancelled => StorageError::Cancelled,
        ControlError::Full => StorageError::Full,
        ControlError::Invalid => StorageError::InvalidBatch,
        ControlError::Fenced
        | ControlError::Corrupt
        | ControlError::Conflict
        | ControlError::CursorPositionUnavailable => {
            StorageError::Corrupt("shared query authority")
        }
        ControlError::Retryable | ControlError::Unavailable | ControlError::Uncertain => {
            StorageError::Closed
        }
    }
}
