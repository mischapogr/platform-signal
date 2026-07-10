//! Small's exact query-manifest control witness. This is not source custody.
use crate::object_manifest::{PreviousManifest, manifest_key};
use crate::{OperationContext, StorageError, check_context};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) const HEAD_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeadRecord {
    pub schema_version: u16,
    pub stream_id: Uuid,
    pub backend_id: Uuid,
    pub previous: Option<PreviousManifest>,
    pub current: PreviousManifest,
}

pub(crate) fn validate_reference(
    head: &PreviousManifest,
    stream: Uuid,
) -> Result<(), StorageError> {
    if head.first_sequence == 0
        || head.last_sequence < head.first_sequence
        || head.object.key != manifest_key(stream, head.first_sequence)
        || head.object.sha256 == [0; 32]
    {
        return Err(StorageError::Corrupt("Small query head reference"));
    }
    head.object
        .validate(crate::object_manifest::MAX_MANIFEST_BYTES as u64)
        .map_err(|_| StorageError::Corrupt("Small query head reference"))
}

impl HeadRecord {
    pub(crate) fn new(
        stream_id: Uuid,
        backend_id: Uuid,
        previous: Option<&PreviousManifest>,
        current: &PreviousManifest,
    ) -> Result<Self, StorageError> {
        // Validate logical field lengths before copying caller-owned strings.
        validate_reference(current, stream_id)?;
        if let Some(previous) = previous {
            validate_reference(previous, stream_id)?;
            if previous.last_sequence >= current.first_sequence {
                return Err(StorageError::Corrupt("Small query head transition"));
            }
        }
        if stream_id.is_nil() || backend_id.is_nil() {
            return Err(StorageError::Config("Small query head binding"));
        }
        Ok(Self {
            schema_version: 1,
            stream_id,
            backend_id,
            previous: previous.cloned(),
            current: current.clone(),
        })
    }
    pub(crate) fn validate(&self, stream: Uuid, backend: Uuid) -> Result<(), StorageError> {
        if self.schema_version != 1 || self.stream_id != stream || self.backend_id != backend {
            return Err(StorageError::StreamMismatch);
        }
        validate_reference(&self.current, stream)?;
        if let Some(previous) = &self.previous {
            validate_reference(previous, stream)?;
            if previous.last_sequence >= self.current.first_sequence {
                return Err(StorageError::Corrupt("Small query head transition"));
            }
        }
        Ok(())
    }
    pub(crate) fn encode(&self, context: &OperationContext) -> Result<Vec<u8>, StorageError> {
        check_context(Some(context))?;
        self.validate(self.stream_id, self.backend_id)?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| StorageError::Corrupt("Small query head"))?;
        if bytes.len() > HEAD_BYTES {
            return Err(StorageError::Full);
        }
        check_context(Some(context))?;
        Ok(bytes)
    }
    pub(crate) fn decode(
        bytes: &[u8],
        stream: Uuid,
        backend: Uuid,
        context: &OperationContext,
    ) -> Result<Self, StorageError> {
        check_context(Some(context))?;
        if bytes.len() > HEAD_BYTES {
            return Err(StorageError::Full);
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|_| StorageError::Corrupt("Small query head encoding"))?;
        record.validate(stream, backend)?;
        check_context(Some(context))?;
        Ok(record)
    }
}
