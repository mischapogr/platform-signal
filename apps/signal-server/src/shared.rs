//! Object uploads and exact fenced metadata publication for the Standard monolith.
//! This component grants neither WAL checkpointing nor protected source custody.
use signal_control::{
    CatalogInput, ControlClient, ControlContext, ControlError, FindingInput, LeaseToken,
    PublicationInput, PublicationResult, ReceiptProgress, RevisionedState, Scope, WorkInput,
};
use signal_storage::{
    OperationContext, StorageConfig, StorageError, StoredEvent,
    object_codec::ObjectCodec,
    object_io::{ObjectIo, ObjectIoError},
    object_manifest::{
        ManifestLimits, PreviousManifest, QueryFile, QueryManifest, QueryObjectRef, data_key,
        manifest_key,
    },
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum SharedError {
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Object(#[from] ObjectIoError),
}

/// Exact host-selected metadata. The caller retains its request ID across replay;
/// producer event fields never select scope, backend, rules or work policy.
#[derive(Clone, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicationDraft {
    pub schema_version: u32,
    pub id: Uuid,
    pub previous: Option<Uuid>,
    pub rule_revision: [u8; 32],
    pub normalizer_revision: String,
    pub states: Vec<RevisionedState>,
    pub findings: Vec<FindingInput>,
    pub work: Vec<WorkInput>,
    pub receipts: Vec<ReceiptProgress>,
}
impl PublicationDraft {
    pub(crate) fn validate(&self, rows: &[StoredEvent]) -> Result<(), ControlError> {
        if self.schema_version != 1
            || self.id.is_nil()
            || self.previous.is_some_and(|id| id.is_nil())
            || self.normalizer_revision.is_empty()
            || self.normalizer_revision.len() > 128
            || self.normalizer_revision.capacity() > 128
            || self.normalizer_revision.chars().any(char::is_control)
            || rows.is_empty()
            || rows.len() > 4096
            || self.states.len() > 128
            || self.states.capacity() > 128
            || self.findings.len() > 128
            || self.findings.capacity() > 128
            || self.work.len() > 128
            || self.work.capacity() > 128
            || self.receipts.len() > 128
            || self.receipts.capacity() > 128
        {
            return Err(ControlError::Invalid);
        }
        let first = rows[0].sequence;
        if first == 0
            || rows.iter().enumerate().any(|(i, r)| {
                first.checked_add(i as u64) != Some(r.sequence) || r.sequence > i64::MAX as u64
            })
        {
            return Err(ControlError::Invalid);
        }
        let mut bytes = 0usize;
        let mut keys = std::collections::BTreeSet::new();
        for state in &self.states {
            state.validate()?;
            if state.revision != self.rule_revision || !keys.insert(&state.key) {
                return Err(ControlError::Invalid);
            }
            bytes += state.key.len() + state.bytes.len();
        }
        let mut ids = std::collections::BTreeSet::new();
        for finding in &self.findings {
            finding.validate()?;
            if !ids.insert(finding.id) {
                return Err(ControlError::Invalid);
            }
            bytes += finding.bytes.len();
        }
        ids.clear();
        for work in &self.work {
            work.validate()?;
            if !ids.insert(work.id) {
                return Err(ControlError::Invalid);
            }
            bytes += work.bytes.len();
        }
        ids.clear();
        let mut progress = 0u64;
        for receipt in &self.receipts {
            if receipt.id.is_nil()
                || !ids.insert(receipt.id)
                || receipt.verified_prefix > 4096
                || receipt.expected_prefix >= receipt.verified_prefix
            {
                return Err(ControlError::Invalid);
            }
            progress += u64::from(receipt.verified_prefix - receipt.expected_prefix);
        }
        if !self.receipts.is_empty() && progress != rows.len() as u64 {
            return Err(ControlError::Invalid);
        }
        if bytes > 512 * 1024 {
            return Err(ControlError::Full);
        }
        Ok(())
    }
}

/// Nonserializable operation capability. Its original budget and admission seat
/// remain fixed through preparation and COMMIT. Persist request() for recovery;
/// a retained request is evidence, never a renewable operation capability.
pub struct PreparedPublication {
    request: PublicationInput,
    token: LeaseToken,
    context: ControlContext,
    binding: Arc<()>,
    _seat: OwnedSemaphorePermit,
    objects_observed: UnconfirmedObjects,
}
impl PreparedPublication {
    pub fn request(&self) -> &PublicationInput {
        &self.request
    }
    pub fn deadline(&self) -> tokio::time::Instant {
        self.context.deadline()
    }
}
/// Scoped original-operation capability; retains the original physical seat and
/// clock without exposing a raw commit handle or a renewable enrollment.
pub struct ScopedPreparedPublication {
    prepared: PreparedPublication,
    request: signal_control::ScopedPublicationInput,
}
impl ScopedPreparedPublication {
    pub fn request(&self) -> &signal_control::ScopedPublicationInput {
        &self.request
    }
    pub fn deadline(&self) -> tokio::time::Instant {
        self.prepared.deadline()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SharedPublicationMetrics {
    pub active: usize,
    pub capacity: usize,
    pub rejected: u64,
    pub prepared: u64,
    pub committed: u64,
    /// Preparation attempts with verified references ending without confirmed publication.
    /// Includes abandoned/cancelled preparation and uncertain replies, not an inventory.
    pub orphan_candidate_results: u64,
    pub closed: bool,
    pub objects: signal_storage::object_io::ObjectIoMetrics,
    pub codec: signal_storage::object_codec::CodecMetrics,
}

pub struct SharedPublisher {
    control: Arc<ControlClient>,
    scope: Scope,
    backend: Uuid,
    io: Arc<ObjectIo>,
    codec: Arc<ObjectCodec>,
    limits: ManifestLimits,
    seats: Arc<Semaphore>,
    binding: Arc<()>,
    closed: AtomicBool,
    rejected: AtomicU64,
    prepared: AtomicU64,
    committed: AtomicU64,
    orphan_candidate_results: Arc<AtomicU64>,
}
struct UnconfirmedObjects {
    counter: Arc<AtomicU64>,
    observed: bool,
    confirmed: bool,
}
impl Drop for UnconfirmedObjects {
    fn drop(&mut self) {
        if self.observed && !self.confirmed {
            self.counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}
struct Observation<'a> {
    rejected: &'a AtomicU64,
    failed: bool,
}
impl Drop for Observation<'_> {
    fn drop(&mut self) {
        if self.failed {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}
fn operation(context: &ControlContext) -> Result<OperationContext, ControlError> {
    context.check()?;
    Ok(OperationContext {
        deadline: context.deadline(),
        cancellation: context.cancellation_token(),
    })
}
impl SharedPublisher {
    pub fn binding(&self) -> (&Scope, Uuid) {
        (&self.scope, self.backend)
    }
    /// Retry only the exact retained request, after rechecking every immutable
    /// version. This operation cannot substitute freshly uploaded object versions.
    pub async fn recommit(
        &self,
        token: LeaseToken,
        request: PublicationInput,
        context: ControlContext,
    ) -> Result<PublicationResult, SharedError> {
        self.recommit_inner(token, request, None, context).await
    }
    pub async fn recommit_scoped(
        &self,
        token: LeaseToken,
        request: signal_control::ScopedPublicationInput,
        context: ControlContext,
    ) -> Result<PublicationResult, SharedError> {
        context.check()?;
        request.validate(&self.scope)?;
        self.recommit_inner(token, request.publication().clone(), Some(request), context)
            .await
    }
    async fn recommit_inner(
        &self,
        token: LeaseToken,
        request: PublicationInput,
        scoped: Option<signal_control::ScopedPublicationInput>,
        context: ControlContext,
    ) -> Result<PublicationResult, SharedError> {
        let mut observation = Observation {
            rejected: &self.rejected,
            failed: true,
        };
        context.check()?;
        self.token(&token)?;
        request.validate(&self.scope)?;
        let _seat = self
            .seats
            .clone()
            .try_acquire_owned()
            .map_err(|_| ControlError::Full)?;
        let pin = self
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
        if pin.backend()? != self.backend {
            return Err(ControlError::Fenced.into());
        }
        let context = context.limited_to(pin.snapshot()?.deadline());
        let manifest: QueryManifest =
            serde_json::from_slice(&request.manifest).map_err(|_| ControlError::Corrupt)?;
        manifest
            .validate(self.limits, self.scope.stream)
            .map_err(|_| ControlError::Corrupt)?;
        if manifest.files.len() + usize::from(manifest.previous.is_some()) > 128 {
            return Err(ControlError::Full.into());
        }
        if let Some(prior) = &manifest.previous {
            self.io
                .read_exact(&prior.object, operation(&context)?)
                .await?;
        }
        for file in &manifest.files {
            self.io
                .read_exact(&file.object, operation(&context)?)
                .await?;
        }
        context.check()?;
        let result = if let Some(scoped) = scoped {
            self.control
                .publish_scoped(token, scoped, context.clone())
                .await?
        } else {
            self.control
                .publish(token, request, context.clone())
                .await?
        };
        context.check().map_err(|_| ControlError::Uncertain)?;
        self.committed.fetch_add(1, Ordering::Relaxed);
        observation.failed = false;
        Ok(result)
    }
    pub fn new(
        control: Arc<ControlClient>,
        scope: Scope,
        backend: Uuid,
        io: ObjectIo,
        storage: StorageConfig,
        limits: ManifestLimits,
    ) -> Result<Self, SharedError> {
        scope.validate()?;
        limits.validate().map_err(|_| ControlError::Invalid)?;
        if backend.is_nil() || io.small_owner_binding().is_some() {
            return Err(ControlError::Invalid.into());
        }
        let codec = Arc::new(ObjectCodec::new(storage.clone(), limits)?);
        Self::with_workers(
            control,
            scope,
            backend,
            Arc::new(io),
            codec,
            storage,
            limits,
        )
    }
    /// Compose host-retained workers. The host keeps clones until construction
    /// succeeds or its original cleanup budget has explicitly drained them.
    pub fn with_workers(
        control: Arc<ControlClient>,
        scope: Scope,
        backend: Uuid,
        io: Arc<ObjectIo>,
        codec: Arc<ObjectCodec>,
        storage: StorageConfig,
        limits: ManifestLimits,
    ) -> Result<Self, SharedError> {
        scope.validate()?;
        limits.validate().map_err(|_| ControlError::Invalid)?;
        if backend.is_nil()
            || io.small_owner_binding().is_some()
            || !codec.matches_configuration(&storage, limits)
            || io.metrics().closed
            || codec.metrics().closed
        {
            return Err(ControlError::Invalid.into());
        }
        Ok(Self {
            control,
            scope,
            backend,
            io,
            codec,
            limits,
            seats: Arc::new(Semaphore::new(1)),
            binding: Arc::new(()),
            closed: AtomicBool::new(false),
            rejected: AtomicU64::new(0),
            prepared: AtomicU64::new(0),
            committed: AtomicU64::new(0),
            orphan_candidate_results: Arc::new(AtomicU64::new(0)),
        })
    }
    pub fn metrics(&self) -> SharedPublicationMetrics {
        SharedPublicationMetrics {
            active: 1 - self.seats.available_permits(),
            capacity: 1,
            rejected: self.rejected.load(Ordering::Relaxed),
            prepared: self.prepared.load(Ordering::Relaxed),
            committed: self.committed.load(Ordering::Relaxed),
            orphan_candidate_results: self.orphan_candidate_results.load(Ordering::Relaxed),
            closed: self.closed.load(Ordering::Acquire),
            objects: self.io.metrics(),
            codec: self.codec.metrics(),
        }
    }
    fn token(&self, token: &LeaseToken) -> Result<(), ControlError> {
        token.validate()?;
        if token.scope != self.scope {
            return Err(ControlError::Fenced);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(ControlError::Unavailable);
        }
        Ok(())
    }
    async fn create_exact(
        &self,
        key: &str,
        bytes: &[u8],
        context: &ControlContext,
    ) -> Result<QueryObjectRef, SharedError> {
        let read = match self.io.create(key, bytes, operation(context)?).await {
            Ok(reference) => self.io.read_exact(&reference, operation(context)?).await?,
            // A lost PUT reply or existing content requires actual bounded byte
            // reconciliation. Discovery never replaces an exact-version read.
            Err(ObjectIoError::Exists | ObjectIoError::Backend) => {
                self.io
                    .discover_bounded(key, bytes.len(), operation(context)?)
                    .await?
            }
            Err(e) => return Err(e.into()),
        };
        context.check()?;
        if read.bytes() != bytes || read.reference().version.is_none() {
            return Err(ControlError::Corrupt.into());
        }
        Ok(read.reference().clone())
    }
    pub async fn prepare(
        &self,
        token: LeaseToken,
        rows: &[StoredEvent],
        draft: PublicationDraft,
        mut context: ControlContext,
    ) -> Result<PreparedPublication, SharedError> {
        let mut objects_observed = UnconfirmedObjects {
            counter: self.orphan_candidate_results.clone(),
            observed: false,
            confirmed: false,
        };
        let mut observation = Observation {
            rejected: &self.rejected,
            failed: true,
        };
        context.check()?;
        self.token(&token)?;
        draft.validate(rows)?;
        let seat = self
            .seats
            .clone()
            .try_acquire_owned()
            .map_err(|_| ControlError::Full)?;
        let pin = self
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
        if pin.backend()? != self.backend {
            return Err(ControlError::Fenced.into());
        }
        context = context.limited_to(pin.snapshot()?.deadline());
        let manifests = pin.snapshot()?.manifests()?;
        let predecessor = match draft.previous {
            None => None,
            Some(id) => Some(
                manifests
                    .iter()
                    .find(|m| m.id == id)
                    .ok_or(ControlError::Conflict)?,
            ),
        };
        // A new publication extends the observed head; exact replay may name an
        // earlier retained request but can never publish a divergent branch.
        if !manifests.iter().any(|m| m.id == draft.id)
            && (pin.head()? != draft.previous
                || pin.checkpoint()?.checked_add(1) != Some(rows[0].sequence))
        {
            return Err(ControlError::Conflict.into());
        }
        let previous = match predecessor {
            None => None,
            Some(prior) => {
                let parsed: QueryManifest =
                    serde_json::from_slice(&prior.bytes).map_err(|_| ControlError::Corrupt)?;
                parsed
                    .validate(self.limits, self.scope.stream)
                    .map_err(|_| ControlError::Corrupt)?;
                if parsed.last_sequence.checked_add(1) != Some(rows[0].sequence) {
                    return Err(ControlError::Conflict.into());
                }
                // Only a database-committed predecessor gets a canonical manifest
                // object. No pending current manifest can reserve a future head.
                let object = self
                    .create_exact(
                        &manifest_key(self.scope.stream, parsed.first_sequence),
                        &prior.bytes,
                        &context,
                    )
                    .await?;
                objects_observed.observed = true;
                Some(PreviousManifest {
                    first_sequence: parsed.first_sequence,
                    last_sequence: parsed.last_sequence,
                    object,
                })
            }
        };
        let batch = self.codec.prepare(rows, operation(&context)?).await?;
        if batch.files().len() + usize::from(previous.is_some()) > 128 {
            return Err(ControlError::Full.into());
        }
        let mut files = Vec::with_capacity(batch.files().len());
        for file in batch.files() {
            let object = self
                .create_exact(
                    &data_key(self.scope.stream, file.date(), file.hour(), file.sha256()),
                    file.bytes(),
                    &context,
                )
                .await?;
            objects_observed.observed = true;
            files.push(QueryFile {
                date: file.date().into(),
                hour: file.hour(),
                rows: file.rows(),
                decoded_bytes: file.decoded_bytes(),
                object,
            });
        }
        let manifest = QueryManifest {
            schema_version: 1,
            storage_schema_version: 1,
            stream_id: self.scope.stream,
            normalizer_revision: draft.normalizer_revision.clone(),
            first_sequence: batch.first_sequence(),
            last_sequence: batch.last_sequence(),
            events: batch.event_count(),
            previous,
            files,
        };
        let request = PublicationInput {
            schema_version: 1,
            id: draft.id,
            previous: draft.previous,
            first_sequence: manifest.first_sequence,
            last_sequence: manifest.last_sequence,
            manifest: manifest
                .encode(self.limits, self.scope.stream)
                .map_err(|_| ControlError::Invalid)?,
            rule_revision: draft.rule_revision,
            normalizer_revision: draft.normalizer_revision,
            states: draft.states,
            findings: draft.findings,
            work: draft.work,
            receipts: draft.receipts,
        };
        request.validate(&self.scope)?;
        context.check()?;
        self.prepared.fetch_add(1, Ordering::Relaxed);
        observation.failed = false;
        Ok(PreparedPublication {
            request,
            token,
            context,
            binding: self.binding.clone(),
            _seat: seat,
            objects_observed,
        })
    }
    pub async fn prepare_scoped(
        &self,
        token: LeaseToken,
        rows: &[StoredEvent],
        draft: crate::shared_scoped::ScopedPublicationDraft,
        context: ControlContext,
    ) -> Result<ScopedPreparedPublication, SharedError> {
        context.check()?;
        self.token(&token)?;
        draft.validate(rows, &self.scope)?;
        let prepared = self.prepare(token, rows, draft.render()?, context).await?;
        let request = draft.attach(prepared.request().clone())?;
        prepared.context.check()?;
        Ok(ScopedPreparedPublication { prepared, request })
    }
    pub async fn commit_scoped(
        &self,
        prepared: ScopedPreparedPublication,
    ) -> Result<PublicationResult, SharedError> {
        let mut observation = Observation {
            rejected: &self.rejected,
            failed: true,
        };
        let mut p = prepared.prepared;
        p.context.check()?;
        self.token(&p.token)?;
        if !Arc::ptr_eq(&p.binding, &self.binding) {
            return Err(ControlError::Fenced.into());
        }
        prepared.request.validate(&self.scope)?;
        let result = self
            .control
            .publish_scoped(p.token, prepared.request, p.context.clone())
            .await?;
        p.context.check().map_err(|_| ControlError::Uncertain)?;
        p.objects_observed.confirmed = true;
        self.committed.fetch_add(1, Ordering::Relaxed);
        observation.failed = false;
        Ok(result)
    }
    pub async fn resolve_scoped(
        &self,
        token: LeaseToken,
        request: signal_control::ScopedPublicationInput,
        context: ControlContext,
    ) -> Result<PublicationResult, SharedError> {
        let mut observation = Observation {
            rejected: &self.rejected,
            failed: true,
        };
        context.check()?;
        self.token(&token)?;
        request.validate(&self.scope)?;
        let result = self
            .control
            .resolve_scoped_publication(token, request, context.clone())
            .await?;
        context.check()?;
        observation.failed = false;
        Ok(result)
    }
    /// Only this database result can precede a caller's WAL checkpoint decision.
    /// Uncertainty is returned unchanged; this method never retries with a new ID.
    pub async fn commit(
        &self,
        mut prepared: PreparedPublication,
    ) -> Result<PublicationResult, SharedError> {
        let mut observation = Observation {
            rejected: &self.rejected,
            failed: true,
        };
        prepared.context.check()?;
        self.token(&prepared.token)?;
        if !Arc::ptr_eq(&prepared.binding, &self.binding) {
            return Err(ControlError::Fenced.into());
        }
        let result = self
            .control
            .publish(prepared.token, prepared.request, prepared.context.clone())
            .await?;
        prepared
            .context
            .check()
            .map_err(|_| ControlError::Uncertain)?;
        self.committed.fetch_add(1, Ordering::Relaxed);
        prepared.objects_observed.confirmed = true;
        observation.failed = false;
        Ok(result)
    }
    /// Current lease plus exact persisted request resolves metadata commitment.
    /// It is not a protected-custody or source-ACK witness.
    pub async fn resolve(
        &self,
        token: LeaseToken,
        request: PublicationInput,
        context: ControlContext,
    ) -> Result<PublicationResult, SharedError> {
        let mut observation = Observation {
            rejected: &self.rejected,
            failed: true,
        };
        context.check()?;
        self.token(&token)?;
        let result = self
            .control
            .resolve_publication(token, request, context.clone())
            .await?;
        context.check()?;
        observation.failed = false;
        Ok(result)
    }
    /// Physical codec/object workers drain before their resources are released.
    /// The host closes its shared control client after all server components stop.
    pub async fn shutdown(&self, context: ControlContext) -> Result<(), SharedError> {
        self.closed.store(true, Ordering::Release);
        self.codec.shutdown(operation(&context)?).await?;
        self.io.shutdown(operation(&context)?).await?;
        Ok(())
    }
}
