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
impl ObjectCustodyDescription {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.scope.validate()?;
        self.object.validate()?;
        if self.schema_version != 1
            || self.id.is_nil()
            || self.object.version == "null"
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
    fn input(&self) -> Result<ReceiptInput, ControlError> {
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

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;
