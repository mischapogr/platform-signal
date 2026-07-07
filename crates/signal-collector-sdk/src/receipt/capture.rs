use super::*;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;

/// Authenticated transport failures, never source contents or credentials.
#[derive(Debug, Error)]
pub enum CaptureFailure {
    #[error("source permission denied")]
    Denied,
    #[error("requested source version is unavailable")]
    MissingVersion,
    #[error("source version awaits archive restore")]
    RestorePending,
    #[error("source throttled collection")]
    Throttled,
    #[error("source transport unavailable")]
    Unavailable,
    #[error("invalid source response")]
    Malformed,
}
#[derive(Debug, Error)]
pub enum CaptureError {
    #[error(transparent)]
    Source(#[from] CaptureFailure),
    #[error(transparent)]
    Operation(#[from] ReceiptError),
    #[error("source response version does not match discovery")]
    VersionMismatch,
    #[error("captured source bytes exceed bounds or are empty")]
    Limit,
    #[error("source read failed: {0:?}")]
    Read(std::io::ErrorKind),
}
/// Transport must bound headers and own/cancel its stream on drop. The version
/// comes from the actual authenticated response, not a copy of the request.
pub struct CaptureStream {
    pub version_id: String,
    pub etag: Option<String>,
    pub body: Box<dyn AsyncRead + Unpin + Send>,
}
/// Credentials and endpoints belong to the application. It must request exactly
/// bucket/key/version, enforce expected_bucket_owner and avoid transparent gzip
/// decompression or redirect to untrusted endpoints. No access is inferred from
/// notification ownerIdentity. Dropping open/stream must cancel its owned I/O.
#[async_trait]
pub trait CaptureTransport: Send + Sync {
    async fn open(
        &self,
        discovery: &ObjectDiscovery,
        context: &ExtensionContext,
    ) -> Result<CaptureStream, CaptureFailure>;
}
/// Exact bounded compressed capture, constructed only after complete source EOF.
/// Retaining multiple captures needs an application aggregate work budget.
pub struct CapturedObject {
    discovery: ObjectDiscovery,
    bytes: Vec<u8>,
    etag: Option<String>,
}
impl CapturedObject {
    pub fn original_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn discovery(&self) -> &ObjectDiscovery {
        &self.discovery
    }
    pub(super) fn into_plan(
        self,
        pins: CapturePreparation,
        fresh: &ReceiptBinding,
    ) -> Result<(Vec<u8>, ReceiptPreparation), ReceiptError> {
        if self.discovery.binding() != fresh {
            return Err(ReceiptError::Scope);
        }
        let plan = ReceiptPreparation {
            receipt_id: pins.receipt_id,
            binding: fresh.clone(),
            original: OriginalCapture {
                bucket: self.discovery.bucket().to_owned(),
                key: self.discovery.key().to_owned(),
                version_id: self.discovery.version_id().to_owned(),
                etag: self.etag,
                captured_at: pins.captured_at,
                discovery_sha256: self.discovery.sha256(),
                delivery_id: pins.delivery_id,
            },
            prepared_at: pins.prepared_at,
            normalizer_sha256: pins.normalizer_sha256,
            retention: pins.retention,
            event_ids: pins.event_ids,
        };
        preparation::validate_plan_bounds(&plan).map_err(preparation::receipt_error)?;
        Ok((self.bytes, plan))
    }
}
/// Fixed application pins; event IDs map all native ordinals. Capture identity
/// cannot be replaced by caller-supplied original metadata.
pub struct CapturePreparation {
    pub receipt_id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub prepared_at: DateTime<Utc>,
    pub normalizer_sha256: [u8; 32],
    pub retention: ReceiptRetention,
    pub event_ids: Vec<Uuid>,
    pub delivery_id: String,
}
/// One bounded invocation, no queue, worker or retry loop. Caller refreshes
/// authenticated authority immediately before invocation and again before
/// publication. Every open/read uses the same finite context. Uncertain source
/// capture is not M1 and never authorizes a message delete.
pub async fn capture_object(
    transport: &dyn CaptureTransport,
    discovery: ObjectDiscovery,
    fresh: &ReceiptBinding,
    ctx: ExtensionContext,
) -> Result<CapturedObject, CaptureError> {
    check(&ctx)?;
    if discovery.binding() != fresh {
        return Err(ReceiptError::Scope.into());
    }
    let mut stream = tokio::select! {
        biased;
        _ = ctx.cancellation().cancelled() => return Err(ReceiptError::Cancelled.into()),
        _ = tokio::time::sleep_until(ctx.deadline()) => return Err(ReceiptError::Timeout.into()),
        stream = transport.open(&discovery, &ctx) => stream?,
    };
    check(&ctx)?;
    if stream.version_id != discovery.version_id() || stream.version_id.len() > 1024 {
        return Err(CaptureError::VersionMismatch);
    }
    if stream
        .etag
        .as_ref()
        .is_some_and(|s| s.is_empty() || s.len() > 1024)
    {
        return Err(CaptureFailure::Malformed.into());
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        check(&ctx)?;
        let count = tokio::select! {
            biased;
            _ = ctx.cancellation().cancelled() => return Err(ReceiptError::Cancelled.into()),
            _ = tokio::time::sleep_until(ctx.deadline()) => return Err(ReceiptError::Timeout.into()),
            result = stream.body.read(&mut chunk) => result.map_err(|e|CaptureError::Read(e.kind()))?,
        };
        if count == 0 {
            break;
        }
        let needed = bytes.len().checked_add(count).ok_or(CaptureError::Limit)?;
        if needed > MAX_CAPTURE_BYTES {
            return Err(CaptureError::Limit);
        }
        if needed > bytes.capacity() {
            let capacity = (bytes.capacity().max(65536) * 2)
                .min(MAX_CAPTURE_BYTES)
                .max(needed);
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .map_err(|_| CaptureError::Limit)?;
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    check(&ctx)?;
    if bytes.is_empty() {
        return Err(CaptureError::Limit);
    }
    Ok(CapturedObject {
        discovery,
        bytes,
        etag: stream.etag,
    })
}
