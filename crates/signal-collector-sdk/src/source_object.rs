//! Shared bounded complete-gzip decoding for native source object adapters.
use crate::ExtensionContext;
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};
use std::io::Read;
use thiserror::Error;
pub const MAX_COMPRESSED_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DECODED_BYTES: usize = 32 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DecodeError {
    #[error("compressed source object byte limit")]
    CaptureLimit,
    #[error("invalid gzip member, CRC or trailing input")]
    InvalidCompression,
    #[error("decoded source object byte limit")]
    DecodedLimit,
    #[error("source object operation cancelled")]
    Cancelled,
    #[error("source object operation deadline")]
    Timeout,
}
pub struct DecodedObject {
    pub(crate) bytes: Vec<u8>,
    pub(crate) original_sha256: [u8; 32],
}
impl DecodedObject {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn original_sha256(&self) -> &[u8; 32] {
        &self.original_sha256
    }
}
pub(crate) fn check(ctx: &ExtensionContext) -> Result<(), DecodeError> {
    if ctx.cancellation().is_cancelled() {
        return Err(DecodeError::Cancelled);
    }
    if tokio::time::Instant::now() >= ctx.deadline() {
        return Err(DecodeError::Timeout);
    }
    Ok(())
}
/// Bounded CPU work on an owned blocking worker. Validate the entire single
/// gzip member before exposing bytes; no transport, custody or coverage grant.
pub fn decode_gzip(original: &[u8], ctx: &ExtensionContext) -> Result<DecodedObject, DecodeError> {
    check(ctx)?;
    if original.is_empty() || original.len() > MAX_COMPRESSED_BYTES {
        return Err(DecodeError::CaptureLimit);
    }
    let mut hash = Sha256::new();
    for chunk in original.chunks(65536) {
        check(ctx)?;
        hash.update(chunk);
    }
    let mut gzip = GzDecoder::new(original);
    let mut decoded = Vec::new();
    let mut chunk = [0; 65536];
    loop {
        check(ctx)?;
        let n = gzip
            .read(&mut chunk)
            .map_err(|_| DecodeError::InvalidCompression)?;
        if n == 0 {
            break;
        }
        if decoded
            .len()
            .checked_add(n)
            .is_none_or(|n| n > MAX_DECODED_BYTES)
        {
            return Err(DecodeError::DecodedLimit);
        }
        if decoded.len() + n > decoded.capacity() {
            let capacity = (decoded.capacity().max(65536) * 2)
                .min(MAX_DECODED_BYTES)
                .max(decoded.len() + n);
            decoded
                .try_reserve_exact(capacity - decoded.len())
                .map_err(|_| DecodeError::DecodedLimit)?;
        }
        decoded.extend_from_slice(&chunk[..n]);
    }
    check(ctx)?;
    if !gzip.into_inner().is_empty() {
        return Err(DecodeError::InvalidCompression);
    }
    Ok(DecodedObject {
        bytes: decoded,
        original_sha256: hash.finalize().into(),
    })
}
