//! Exact canonical inputs from a live committed catalog, not new source authority.
use crate::{
    CanonicalObjectRef, CatalogPin, ControlClient, ControlContext, ControlError, LeaseToken,
    ObjectControlState, RetentionKind, RetentionPinInput, Scope,
};
use sha2::{Digest, Sha256};
use signal_storage::{
    OperationContext, StoredEvent,
    object_codec::ObjectCodec,
    object_io::{ObjectIo, ObjectIoError},
    object_manifest::{ManifestLimits, QueryFile, QueryManifest},
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
#[derive(Clone, Copy)]
pub struct CanonicalRecoveryLimits {
    pub backend: Uuid,
    pub files: usize,
    pub object_bytes: u64,
    pub decoded_bytes: u64,
    pub scanned_rows: usize,
    pub result_bytes: usize,
}
impl CanonicalRecoveryLimits {
    pub fn validate(self) -> Result<(), ControlError> {
        if self.backend.is_nil()
            || !(1..=128).contains(&self.files)
            || !(1..=268_435_456).contains(&self.object_bytes)
            || !(1..=268_435_456).contains(&self.decoded_bytes)
            || !(1..=65536).contains(&self.scanned_rows)
            || !(1..=16_777_216).contains(&self.result_bytes)
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}
struct Size {
    used: usize,
    limit: usize,
}
impl std::io::Write for Size {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.used) {
            return Err(std::io::Error::other("canonical recovery byte capacity"));
        }
        self.used += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Nonserializable original catalog/object proof; cloning bytes grants no pin.
pub struct RecoveredCanonicalInputs {
    rows: Vec<StoredEvent>,
    objects: Vec<signal_storage::object_manifest::QueryObjectRef>,
    scope: Scope,
    backend: Uuid,
    deadline: tokio::time::Instant,
}
impl RecoveredCanonicalInputs {
    pub fn rows(&self) -> Result<&[StoredEvent], ControlError> {
        self.check()?;
        Ok(&self.rows)
    }
    fn check(&self) -> Result<(), ControlError> {
        if tokio::time::Instant::now() >= self.deadline {
            Err(ControlError::SnapshotExpired)
        } else {
            Ok(())
        }
    }
}
enum ReplayPinProfile {
    General,
    Window,
    Sensor,
}
/// Pin before the original catalog capability expires. Partial/uncertain work
/// must retain its installed pins; release needs a separate explicit decision.
pub async fn retain_canonical_inputs(
    client: &ControlClient,
    token: LeaseToken,
    inputs: &RecoveredCanonicalInputs,
    state_key: &str,
    rule_revision: [u8; 32],
    metadata_sha256: [u8; 32],
    context: ControlContext,
) -> Result<Vec<Uuid>, ControlError> {
    retain_inputs(
        client,
        token,
        inputs,
        state_key,
        rule_revision,
        metadata_sha256,
        context,
        ReplayPinProfile::General,
    )
    .await
}
/// Exact committed Window-only replay pins through the restricted producer grant.
pub async fn retain_window_canonical_inputs(
    client: &ControlClient,
    token: LeaseToken,
    inputs: &RecoveredCanonicalInputs,
    state_key: &str,
    rule_revision: [u8; 32],
    metadata_sha256: [u8; 32],
    context: ControlContext,
) -> Result<Vec<Uuid>, ControlError> {
    retain_inputs(
        client,
        token,
        inputs,
        state_key,
        rule_revision,
        metadata_sha256,
        context,
        ReplayPinProfile::Window,
    )
    .await
}
/// Exact committed sensor replay pins through the restricted producer grant.
pub async fn retain_sensor_canonical_inputs(
    client: &ControlClient,
    token: LeaseToken,
    inputs: &RecoveredCanonicalInputs,
    state_key: &str,
    rule_revision: [u8; 32],
    metadata_sha256: [u8; 32],
    context: ControlContext,
) -> Result<Vec<Uuid>, ControlError> {
    retain_inputs(
        client,
        token,
        inputs,
        state_key,
        rule_revision,
        metadata_sha256,
        context,
        ReplayPinProfile::Sensor,
    )
    .await
}
#[allow(clippy::too_many_arguments)] // Same bounded proof, two explicit authority profiles.
async fn retain_inputs(
    client: &ControlClient,
    token: LeaseToken,
    inputs: &RecoveredCanonicalInputs,
    state_key: &str,
    rule_revision: [u8; 32],
    metadata_sha256: [u8; 32],
    context: ControlContext,
    profile: ReplayPinProfile,
) -> Result<Vec<Uuid>, ControlError> {
    token.validate()?;
    context.check()?;
    inputs.check()?;
    if token.scope != inputs.scope
        || state_key.is_empty()
        || state_key.len() > 256
        || state_key.chars().any(char::is_control)
    {
        return Err(ControlError::Fenced);
    }
    let context = context.limited_to(inputs.deadline);
    let mut retained = Vec::with_capacity(inputs.objects.len());
    for source in &inputs.objects {
        inputs.check()?;
        context.check()?;
        let object = CanonicalObjectRef {
            schema_version: 1,
            backend_id: inputs.backend,
            key: source.key.clone(),
            version: source.version.clone().ok_or(ControlError::Corrupt)?,
        };
        let reference = serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"scope":inputs.scope,"state_key":state_key,
            "rule_revision":rule_revision,"metadata_sha256":metadata_sha256,"object":object,
            "object_bytes":source.bytes,"object_sha256":source.sha256}),
        )
        .map_err(|_| ControlError::Invalid)?
        .into_boxed_slice()
        .into_vec();
        if reference.len() > 4096 {
            return Err(ControlError::Full);
        }
        let identity: [u8; 32] = Sha256::digest(&reference).into();
        let id = Uuid::new_v5(&Uuid::from_bytes(*b"SIGNAL-STATEPIN1"), &identity);
        let input = RetentionPinInput {
            schema_version: 1,
            id,
            object,
            kind: RetentionKind::Replay,
            reference,
        };
        let result = match profile {
            ReplayPinProfile::Window => {
                client
                    .pin_window_object(token.clone(), input, context.clone())
                    .await?
            }
            ReplayPinProfile::Sensor => {
                client
                    .pin_sensor_object(token.clone(), input, context.clone())
                    .await?
            }
            ReplayPinProfile::General => {
                client
                    .pin_object(token.clone(), input, context.clone())
                    .await?
            }
        };
        if result.state != ObjectControlState::Retained {
            return Err(ControlError::Corrupt);
        }
        retained.push(id);
    }
    inputs.check()?;
    context.check()?;
    Ok(retained)
}
pub async fn recover_canonical_rows(
    pin: &CatalogPin,
    io: &ObjectIo,
    codec: &ObjectCodec,
    ids: &[Uuid],
    limits: CanonicalRecoveryLimits,
    context: ControlContext,
) -> Result<Vec<StoredEvent>, ControlError> {
    let recovered = recover_canonical_inputs(pin, io, codec, ids, limits, context.clone()).await?;
    context.check()?;
    recovered.check()?;
    Ok(recovered.rows)
}
pub async fn recover_canonical_inputs(
    pin: &CatalogPin,
    io: &ObjectIo,
    codec: &ObjectCodec,
    ids: &[Uuid],
    limits: CanonicalRecoveryLimits,
    context: ControlContext,
) -> Result<RecoveredCanonicalInputs, ControlError> {
    recover_inputs(pin, io, codec, ids, None, limits, context).await
}
/// Recover the original protected ID/sequence pairs. Exact retries at other
/// sequences are tolerated; changed canonical content is still refused.
pub async fn recover_canonical_inputs_at(
    pin: &CatalogPin,
    io: &ObjectIo,
    codec: &ObjectCodec,
    references: &BTreeMap<Uuid, u64>,
    limits: CanonicalRecoveryLimits,
    context: ControlContext,
) -> Result<RecoveredCanonicalInputs, ControlError> {
    if references.len() > 4096
        || references.values().any(|s| *s == 0 || *s > i64::MAX as u64)
        || references.values().collect::<BTreeSet<_>>().len() != references.len()
    {
        return Err(ControlError::Invalid);
    }
    let ids = references.keys().copied().collect::<Vec<_>>();
    recover_inputs(pin, io, codec, &ids, Some(references), limits, context).await
}
async fn recover_inputs(
    pin: &CatalogPin,
    io: &ObjectIo,
    codec: &ObjectCodec,
    ids: &[Uuid],
    sequences: Option<&BTreeMap<Uuid, u64>>,
    limits: CanonicalRecoveryLimits,
    context: ControlContext,
) -> Result<RecoveredCanonicalInputs, ControlError> {
    context.check()?;
    limits.validate()?;
    let checkpoint = pin.checkpoint()?;
    if sequences.is_some_and(|r| r.values().any(|s| *s > checkpoint)) {
        return Err(ControlError::Invalid);
    }
    if ids.len() > 4096 || ids.iter().any(Uuid::is_nil) {
        return Err(ControlError::Invalid);
    }
    let wanted: BTreeSet<_> = ids.iter().copied().collect();
    if wanted.len() != ids.len() {
        return Err(ControlError::Invalid);
    }
    if pin.backend()? != limits.backend {
        return Err(ControlError::Fenced);
    }
    let snapshot = pin.snapshot()?;
    let context = context.limited_to(snapshot.deadline());
    context.check()?;
    if wanted.is_empty() {
        snapshot.check()?;
        return Ok(RecoveredCanonicalInputs {
            rows: Vec::new(),
            objects: Vec::new(),
            scope: snapshot.scope().clone(),
            backend: limits.backend,
            deadline: context.deadline(),
        });
    }

    let mut files = BTreeMap::<String, (QueryFile, u64, u64)>::new();
    let mut object_bytes = 0u64;
    let mut decoded_bytes = 0u64;
    let mut rows = 0usize;
    for retained in snapshot.manifests()? {
        context.check()?;
        snapshot.check()?;
        let manifest: QueryManifest =
            serde_json::from_slice(&retained.bytes).map_err(|_| ControlError::Corrupt)?;
        manifest
            .validate(
                ManifestLimits {
                    events: 4096,
                    ..Default::default()
                },
                snapshot.scope().stream,
            )
            .map_err(|_| ControlError::Corrupt)?;
        if manifest.last_sequence > pin.checkpoint()? {
            return Err(ControlError::Corrupt);
        }
        for file in manifest.files {
            if file.object.version.is_none() {
                return Err(ControlError::Corrupt);
            }
            if let Some((old, _, _)) = files.get(&file.object.key) {
                if old != &file {
                    return Err(ControlError::Conflict);
                }
                continue;
            }
            object_bytes = object_bytes
                .checked_add(file.object.bytes)
                .ok_or(ControlError::Full)?;
            decoded_bytes = decoded_bytes
                .checked_add(file.decoded_bytes)
                .ok_or(ControlError::Full)?;
            rows = rows.checked_add(file.rows).ok_or(ControlError::Full)?;
            if files.len() == limits.files
                || object_bytes > limits.object_bytes
                || decoded_bytes > limits.decoded_bytes
                || rows > limits.scanned_rows
            {
                return Err(ControlError::Full);
            }
            files.insert(
                file.object.key.clone(),
                (file, manifest.first_sequence, manifest.last_sequence),
            );
        }
    }
    let mut found = BTreeMap::new();
    let mut observed = BTreeMap::new();
    let mut objects = Vec::new();
    let mut size = Size {
        used: 0,
        limit: limits.result_bytes,
    };
    // Scan the complete bounded selection, including after finding all IDs, so
    // duplicate canonical identities in another immutable file cannot hide.
    for (_, (file, first, last)) in files {
        context.check()?;
        snapshot.check()?;
        let operation = || OperationContext {
            deadline: context.deadline(),
            cancellation: context.cancellation_token(),
        };
        let body = io
            .read_exact(&file.object, operation())
            .await
            .map_err(|error| match error {
                ObjectIoError::Cancelled => ControlError::Cancelled,
                ObjectIoError::Timeout => ControlError::Timeout,
                ObjectIoError::Full => ControlError::Full,
                ObjectIoError::Corrupt | ObjectIoError::Condition => ControlError::Corrupt,
                _ => ControlError::Unavailable,
            })?;
        context.check()?;
        snapshot.check()?;
        let decoded = codec
            .inspect(&file, body.bytes(), first, last, operation())
            .await
            .map_err(|_| ControlError::Corrupt)?;
        let mut needed = false;
        for row in decoded.rows() {
            context.check()?;
            snapshot.check()?;
            if wanted.contains(&row.event.id) {
                if let Some(references) = sequences {
                    let digest = canonical_hash(&row.event)?;
                    if observed
                        .insert(row.event.id, digest)
                        .is_some_and(|old| old != digest)
                    {
                        return Err(ControlError::Conflict);
                    }
                    if references.get(&row.event.id) != Some(&row.sequence) {
                        continue;
                    }
                }
                if found.contains_key(&row.event.id) {
                    return Err(ControlError::Conflict);
                }
                serde_json::to_writer(&mut size, &row.event).map_err(|_| ControlError::Full)?;
                needed = true;
                found.insert(row.event.id, row.clone());
            }
        }
        if needed {
            objects.push(file.object);
        }
    }
    context.check()?;
    snapshot.check()?;
    if found.len() != wanted.len() {
        return Err(ControlError::Unavailable);
    }
    let rows = ids
        .iter()
        .map(|id| found.remove(id).ok_or(ControlError::Corrupt))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RecoveredCanonicalInputs {
        rows,
        objects,
        scope: snapshot.scope().clone(),
        backend: limits.backend,
        deadline: context.deadline(),
    })
}

fn canonical_hash(event: &impl serde::Serialize) -> Result<[u8; 32], ControlError> {
    struct Hash(Sha256);
    impl std::io::Write for Hash {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut hash = Hash(Sha256::new());
    serde_json::to_writer(&mut hash, event).map_err(|_| ControlError::Corrupt)?;
    Ok(hash.0.finalize().into())
}
