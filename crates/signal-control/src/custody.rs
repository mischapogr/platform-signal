//! Generic retained-object coordination, separate from M2 admission and M3 policy.
//! Trusted embedding adapters own actual provider retention and archive isolation.
use crate::{
    CanonicalObjectRef, ControlClient, ControlContext, ControlError, LeaseToken, ReceiptInput,
    ReceiptResult, Scope,
};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin};
use uuid::Uuid;

pub type CustodyFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ControlError>> + Send + 'a>>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectCustodyDescription {
    pub schema_version: u32,
    pub id: Uuid,
    pub scope: Scope,
    pub object: CanonicalObjectRef,
    pub bytes: u64,
    pub sha256: [u8; 32],
    pub retain_until: DateTime<Utc>,
}
impl From<&ObjectCustodyDescription> for signal_protocol::object_custody::Description {
    fn from(d: &ObjectCustodyDescription) -> Self {
        Self {
            schema_version: d.schema_version,
            id: d.id,
            scope: signal_protocol::object_custody::Scope {
                schema_version: d.scope.schema_version,
                store_id: d.scope.store_id,
                generation: d.scope.generation,
                tenant: d.scope.tenant.clone(),
                stream: d.scope.stream,
                partition_id: d.scope.partition_id,
            },
            object: signal_protocol::object_custody::ObjectReference {
                schema_version: d.object.schema_version,
                backend_id: d.object.backend_id,
                key: d.object.key.clone(),
                version: d.object.version.clone(),
            },
            bytes: d.bytes,
            sha256: d.sha256,
            retain_until: d.retain_until,
        }
    }
}
impl TryFrom<signal_protocol::object_custody::Description> for ObjectCustodyDescription {
    type Error = ControlError;
    fn try_from(d: signal_protocol::object_custody::Description) -> Result<Self, ControlError> {
        d.validate().map_err(|_| ControlError::Invalid)?;
        let result = Self {
            schema_version: d.schema_version,
            id: d.id,
            scope: Scope {
                schema_version: d.scope.schema_version,
                store_id: d.scope.store_id,
                generation: d.scope.generation,
                tenant: d.scope.tenant,
                stream: d.scope.stream,
                partition_id: d.scope.partition_id,
            },
            object: CanonicalObjectRef {
                schema_version: d.object.schema_version,
                backend_id: d.object.backend_id,
                key: d.object.key,
                version: d.object.version,
            },
            bytes: d.bytes,
            sha256: d.sha256,
            retain_until: d.retain_until,
        };
        result.validate()?;
        Ok(result)
    }
}
impl ObjectCustodyDescription {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.scope.validate()?;
        self.object.validate()?;
        if self.schema_version != 1
            || self.id.is_nil()
            || matches!(self.object.version.as_str(), "null" | "*")
            || self.bytes == 0
            || self.bytes > 64 * 1024 * 1024
            || self.sha256 == [0; 32]
            || !(1..=9999).contains(&self.retain_until.year())
            || self.retain_until.timestamp_subsec_nanos() >= 1_000_000_000
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32], ControlError> {
        self.validate()?;
        Ok(Sha256::digest(crate::publication::encode(self)?).into())
    }
    pub(crate) fn input(&self) -> Result<ReceiptInput, ControlError> {
        self.validate()?;
        #[derive(Serialize)]
        struct Reference<'a> {
            kind: &'static str,
            description: &'a ObjectCustodyDescription,
        }
        let input = ReceiptInput {
            schema_version: 1,
            id: self.id,
            prepared_count: 0,
            source_record_count: 0,
            reference: crate::publication::encode(&Reference {
                kind: "object_custody_v1",
                description: self,
            })?,
        };
        input.wire()?;
        Ok(input)
    }
}

/// Trusted host adapter observation; never deserialize a producer's assertion.
pub struct RetainedObjectObservation {
    pub description_sha256: [u8; 32],
    pub authority_revision: [u8; 32],
    pub observed_at: DateTime<Utc>,
    pub retained_until: DateTime<Utc>,
}
pub trait ObjectCustodyVerifier: Send + Sync {
    /// Verify exact bytes/version, current credentials and guaranteed retention.
    /// Own physical work under the supplied context even when its future drops.
    fn verify<'a>(
        &'a self,
        description: &'a ObjectCustodyDescription,
        context: ControlContext,
    ) -> CustodyFuture<'a, RetainedObjectObservation>;
}
pub trait ObjectCustodyRecorder: Send + Sync {
    /// Commit/reconcile the exact record under current generation/owner checks.
    fn record<'a>(
        &'a self,
        token: LeaseToken,
        input: ReceiptInput,
        context: ControlContext,
    ) -> CustodyFuture<'a, ReceiptResult>;
}
impl ObjectCustodyRecorder for ControlClient {
    fn record<'a>(
        &'a self,
        token: LeaseToken,
        input: ReceiptInput,
        context: ControlContext,
    ) -> CustodyFuture<'a, ReceiptResult> {
        Box::pin(self.record_receipt(token, input, context))
    }
}

/// Trusted existing-only restored lineage adapter. Resolution must check the
/// current owner and sealed origin generation; it must never insert a receipt.
pub trait RestoredObjectCustodyResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        token: LeaseToken,
        description: ObjectCustodyDescription,
        context: ControlContext,
    ) -> CustodyFuture<'a, ReceiptResult>;
}
impl RestoredObjectCustodyResolver for ControlClient {
    fn resolve<'a>(
        &'a self,
        token: LeaseToken,
        description: ObjectCustodyDescription,
        context: ControlContext,
    ) -> CustodyFuture<'a, ReceiptResult> {
        Box::pin(self.resolve_restored_custody(token, description, context))
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectCustodyReceipt {
    pub schema_version: u32,
    pub description: ObjectCustodyDescription,
    pub description_sha256: [u8; 32],
}
impl ObjectCustodyReceipt {
    /// Checks metadata integrity only; never reconstructs a release permit.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 1 || self.description.digest()? != self.description_sha256 {
            return Err(ControlError::Corrupt);
        }
        Ok(())
    }
}
/// Ephemeral confirmation, never a serialized or replayable release authority.
pub struct ObjectCustodyPermit {
    receipt: ObjectCustodyReceipt,
    context: ControlContext,
}
impl ObjectCustodyPermit {
    pub fn checked_receipt(&self) -> Result<&ObjectCustodyReceipt, ControlError> {
        self.context.check()?;
        if self.receipt.description.retain_until <= Utc::now() {
            return Err(ControlError::Fenced);
        }
        Ok(&self.receipt)
    }
}

async fn bounded<T>(
    context: &ControlContext,
    mutating: bool,
    future: CustodyFuture<'_, T>,
) -> Result<T, ControlError> {
    context.check()?;
    let cancellation = context.cancellation_token();
    let result = tokio::select! { biased;
        _ = cancellation.cancelled() => Err(if mutating { ControlError::Uncertain } else { ControlError::Cancelled }),
        result = tokio::time::timeout_at(context.deadline(), future) =>
            result.map_err(|_| if mutating { ControlError::Uncertain } else { ControlError::Timeout })?,
    };
    if result.is_ok() {
        context.check().map_err(|error| {
            if mutating {
                ControlError::Uncertain
            } else {
                error
            }
        })?;
    }
    result.map_err(|error| match error {
        ControlError::Cancelled | ControlError::Timeout if mutating => ControlError::Uncertain,
        other => other,
    })
}
async fn verify(
    verifier: &dyn ObjectCustodyVerifier,
    description: &ObjectCustodyDescription,
    authority_revision: [u8; 32],
    context: &ControlContext,
) -> Result<(), ControlError> {
    let began = Utc::now();
    let observation = bounded(
        context,
        false,
        verifier.verify(description, context.clone()),
    )
    .await?;
    let now = Utc::now();
    if observation.description_sha256 != description.digest()?
        || observation.authority_revision != authority_revision
        || observation.observed_at < began
        || observation.observed_at > now
        || observation.retained_until < description.retain_until
        || description.retain_until <= now
    {
        return Err(ControlError::Fenced);
    }
    Ok(())
}
fn confirmation(result: ReceiptResult, id: Uuid) -> Result<(), ControlError> {
    if result.schema_version != 1
        || result.id != id
        || result.prepared_count != 0
        || result.source_record_count != 0
        || result.verified_prefix != 0
    {
        return Err(ControlError::Corrupt);
    }
    Ok(())
}

/// No permit on PUT alone, uncertain COMMIT, stale authority or expired context.
pub async fn coordinate_object_custody(
    recorder: &dyn ObjectCustodyRecorder,
    verifier: &dyn ObjectCustodyVerifier,
    token: LeaseToken,
    description: ObjectCustodyDescription,
    authority_revision: [u8; 32],
    context: ControlContext,
) -> Result<ObjectCustodyPermit, ControlError> {
    context.check()?;
    token.validate()?;
    description.validate()?;
    if token.scope != description.scope
        || authority_revision == [0; 32]
        || description.retain_until <= Utc::now()
    {
        return Err(ControlError::Fenced);
    }
    let input = description.input()?;
    verify(verifier, &description, authority_revision, &context).await?;
    confirmation(
        bounded(
            &context,
            true,
            recorder.record(token.clone(), input.clone(), context.clone()),
        )
        .await?,
        description.id,
    )?;
    verify(verifier, &description, authority_revision, &context).await?;
    confirmation(
        bounded(
            &context,
            true,
            recorder.record(token, input, context.clone()),
        )
        .await?,
        description.id,
    )?;
    let permit = ObjectCustodyPermit {
        receipt: ObjectCustodyReceipt {
            schema_version: 1,
            description_sha256: description.digest()?,
            description,
        },
        context,
    };
    permit.checked_receipt()?;
    Ok(permit)
}

/// Fresh restored confirmation retains the original description and digest.
/// An existing current-owner lineage record must resolve before either retained
/// read and again after the last read. Metadata alone cannot mint this permit.
pub async fn coordinate_restored_object_custody(
    resolver: &dyn RestoredObjectCustodyResolver,
    verifier: &dyn ObjectCustodyVerifier,
    token: LeaseToken,
    description: ObjectCustodyDescription,
    authority_revision: [u8; 32],
    context: ControlContext,
) -> Result<ObjectCustodyPermit, ControlError> {
    context.check()?;
    crate::restored_custody::validate(&crate::restored_custody::Action::Resolve {
        token: token.clone(),
        description: Box::new(description.clone()),
    })?;
    if authority_revision == [0; 32] || description.retain_until <= Utc::now() {
        return Err(ControlError::Fenced);
    }
    for read in 0..=2 {
        confirmation(
            bounded(
                &context,
                false,
                resolver.resolve(token.clone(), description.clone(), context.clone()),
            )
            .await?,
            description.id,
        )?;
        if read < 2 {
            verify(verifier, &description, authority_revision, &context).await?;
        }
    }
    let permit = ObjectCustodyPermit {
        receipt: ObjectCustodyReceipt {
            schema_version: 1,
            description_sha256: description.digest()?,
            description,
        },
        context,
    };
    permit.checked_receipt()?;
    Ok(permit)
}

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;
