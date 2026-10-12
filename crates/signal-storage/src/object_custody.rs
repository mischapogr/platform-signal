//! Explicit retained-version read capability, separate from query publication.
use crate::{OperationContext, object_io::ObjectIoError, object_manifest::QueryObjectRef};
use chrono::{DateTime, Datelike, Utc};

/// Host-selected adapter running only on ObjectIo's fixed physical worker.
/// Read the entire exact version, check length/hash and non-bypassable provider
/// retention. This observation is not a control receipt or release permit.
#[async_trait::async_trait]
pub trait RetainedVersionRead: Send + Sync {
    async fn verify_retained(
        &self,
        reference: &QueryObjectRef,
        retain_until: DateTime<Utc>,
        context: &OperationContext,
    ) -> Result<DateTime<Utc>, ObjectIoError>;
}
pub(crate) fn validate(
    reference: &QueryObjectRef,
    retain_until: DateTime<Utc>,
    maximum: u64,
) -> Result<(), ObjectIoError> {
    reference
        .validate(maximum)
        .map_err(|_| ObjectIoError::Corrupt)?;
    if reference.sha256 == [0; 32]
        || reference.bytes == 0
        || reference.bytes > 64 * 1024 * 1024
        || !(1..=9999).contains(&retain_until.year())
        || retain_until.timestamp_subsec_nanos() >= 1_000_000_000
        || reference
            .version
            .as_deref()
            .is_none_or(|v| v == "null" || v == "*")
        || retain_until <= Utc::now()
    {
        return Err(ObjectIoError::Condition);
    }
    Ok(())
}
