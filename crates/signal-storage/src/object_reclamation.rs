//! Explicit exact-version capability. Never substitute a path-only delete.
use crate::{OperationContext, object_io::ObjectIoError, object_manifest::QueryObjectRef};
use uuid::Uuid;

/// Host-selected backend capability, executed only on ObjectIo's fixed worker.
/// Implementations must enforce version and ETag atomically, honor the original
/// context, and never bypass retention or fall back to unversioned deletion.
/// This is not a retirement plan, source ACK, custody or distributed fencing.
#[async_trait::async_trait]
pub trait ExactVersionDelete: Send + Sync {
    async fn remove_exact(
        &self,
        reference: &QueryObjectRef,
        context: &OperationContext,
    ) -> Result<(), ObjectIoError>;
}

pub(crate) fn validate(
    reference: &QueryObjectRef,
    stream: Uuid,
    maximum: u64,
) -> Result<(), ObjectIoError> {
    reference
        .validate(maximum)
        .map_err(|_| ObjectIoError::Corrupt)?;
    if stream.is_nil() || reference.sha256 == [0; 32] {
        return Err(ObjectIoError::Corrupt);
    }
    let version = reference
        .version
        .as_deref()
        .ok_or(ObjectIoError::Condition)?;
    if version == "null" || version == "*" || !version.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ObjectIoError::Condition);
    }
    etag(reference.etag.as_deref().ok_or(ObjectIoError::Condition)?)?;
    let prefix = format!("query/{stream}/data/");
    let relative = reference
        .key
        .strip_prefix(&prefix)
        .ok_or(ObjectIoError::Condition)?;
    let mut parts = relative.split('/');
    let date = parts
        .next()
        .and_then(|s| s.strip_prefix("date="))
        .ok_or(ObjectIoError::Corrupt)?;
    let parsed =
        chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").map_err(|_| ObjectIoError::Corrupt)?;
    if parsed.format("%Y-%m-%d").to_string() != date {
        return Err(ObjectIoError::Corrupt);
    }
    let hour = parts
        .next()
        .and_then(|s| s.strip_prefix("hour="))
        .ok_or(ObjectIoError::Corrupt)?;
    let hour: u8 = hour.parse().map_err(|_| ObjectIoError::Corrupt)?;
    if hour > 23
        || parts.next().is_none()
        || parts.next().is_some()
        || crate::object_manifest::data_key(stream, date, hour, reference.sha256) != reference.key
    {
        return Err(ObjectIoError::Corrupt);
    }
    Ok(())
}

pub(crate) fn etag(value: &str) -> Result<String, ObjectIoError> {
    let inner = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        &value[1..value.len() - 1]
    } else {
        value
    };
    if inner.is_empty()
        || value.len() > 256
        || !inner
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'*' | b',' | b'\\'))
    {
        return Err(ObjectIoError::Condition);
    }
    Ok(format!("\"{inner}\""))
}

/// Finite conditional deletion acknowledgements. Missing retired copies are
/// separately observed; this is not proof of original evidence custody or ACK.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ReclamationReport {
    pub schema_version: u16,
    pub stream_id: Uuid,
    pub retired_through: u64,
    pub acknowledged_versions: usize,
    pub acknowledged_bytes: u64,
    pub observed_absent_versions: usize,
    pub observed_absent_bytes: u64,
}
