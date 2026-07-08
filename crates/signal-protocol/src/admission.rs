//! Shared v1 admission-response verification. A verified prefix acknowledges
//! local WAL admission only, never protected evidence or completed processing.
use crate::{API_SCHEMA_VERSION, ErrorCode, IngestResponse};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionDisposition {
    Complete,
    Retry,
    Permanent,
    ReduceBatch,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionOutcome {
    pub accepted: usize,
    pub disposition: AdmissionDisposition,
}
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("invalid admission response")]
pub struct InvalidAdmissionResponse;

pub fn verify_admission_response(
    status: u16,
    response: IngestResponse,
    event_ids: &[Uuid],
) -> Result<AdmissionOutcome, InvalidAdmissionResponse> {
    let invalid = || InvalidAdmissionResponse;
    if response.schema_version != API_SCHEMA_VERSION
        || response.accepted > event_ids.len()
        || response.event_ids.len() != response.accepted
        || !response
            .event_ids
            .iter()
            .zip(event_ids)
            .all(|(id, event)| id == event)
    {
        return Err(invalid());
    }
    if status == 202 {
        if response.accepted != event_ids.len()
            || response.rejected != 0
            || response.error.is_some()
        {
            return Err(invalid());
        }
        return Ok(AdmissionOutcome {
            accepted: response.accepted,
            disposition: AdmissionDisposition::Complete,
        });
    }
    let error = response.error.ok_or_else(invalid)?;
    let disposition = match (status, error.code) {
        (429, ErrorCode::Full)
        | (408, ErrorCode::RequestTimeout)
        | (503, ErrorCode::Unavailable | ErrorCode::Stopping) => AdmissionDisposition::Retry,
        (413, ErrorCode::BatchTooLarge | ErrorCode::PayloadTooLarge) => {
            AdmissionDisposition::ReduceBatch
        }
        (401, ErrorCode::Unauthorized)
        | (
            400,
            ErrorCode::InvalidJson
            | ErrorCode::InvalidEvent
            | ErrorCode::UnsupportedVersion
            | ErrorCode::EmptyBatch,
        )
        | (404, ErrorCode::NotFound)
        | (405, ErrorCode::MethodNotAllowed)
        | (415, ErrorCode::UnsupportedMediaType) => AdmissionDisposition::Permanent,
        _ => return Err(invalid()),
    };
    let known_total = response.accepted.checked_add(response.rejected) == Some(event_ids.len());
    // The server cannot know batch count before auth/body parsing/concurrency checks.
    let unknown_total = response.accepted == 0 && response.rejected == 0 && error.index.is_none();
    if !known_total && !unknown_total {
        return Err(invalid());
    }
    if response.accepted != 0 {
        if disposition != AdmissionDisposition::Retry
            || response.accepted == event_ids.len()
            || error.index != Some(response.accepted)
        {
            return Err(invalid());
        }
    } else if let Some(index) = error.index
        && (index >= event_ids.len()
            || (disposition == AdmissionDisposition::Retry
                && error.code != ErrorCode::RequestTimeout
                && index != 0))
    {
        return Err(invalid());
    }
    Ok(AdmissionOutcome {
        accepted: response.accepted,
        disposition,
    })
}
