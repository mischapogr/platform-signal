use super::{MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_RECORD_BYTES, NormalizeError, decode_json};
use crate::ExtensionContext;
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};
use std::{io::Read, ops::Range};
use thiserror::Error;
const COMPRESSED_LIMIT: usize = 8 * 1024 * 1024;
const DECODED_LIMIT: usize = 32 * 1024 * 1024;
const COUNT_LIMIT: usize = 1024;

#[derive(Debug, Error)]
pub enum ObjectReadError {
    #[error("compressed source capture exceeds bounds")]
    CaptureLimit,
    #[error("invalid gzip member, CRC or trailing input")]
    InvalidCompression,
    #[error("invalid complete CloudTrail JSON object")]
    InvalidObjectJson,
    #[error("decoded object, record, count or nesting exceeds bounds")]
    ObjectLimitsExceeded,
    #[error("unsupported CloudTrail object envelope")]
    UnsupportedObject,
    #[error("CloudTrail Records array is empty")]
    EmptyRecords,
    #[error("object operation cancelled")]
    Cancelled,
    #[error("object deadline expired")]
    Timeout,
}
/// One bounded decoded object plus native byte spans; no whole-object DOM.
/// This proves parsing only, never source credentials, scope or completeness.
/// Aggregate caller buffering/active work needs its own single-owner budget.
pub struct CloudTrailObject {
    decoded: Vec<u8>,
    records: Vec<Range<usize>>,
    original_sha256: [u8; 32],
}
impl CloudTrailObject {
    pub fn decoded_length(&self) -> usize {
        self.decoded.len()
    }
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
    pub fn original_sha256(&self) -> &[u8; 32] {
        &self.original_sha256
    }
    pub fn record(&self, index: usize) -> Option<&[u8]> {
        self.records.get(index).map(|r| &self.decoded[r.clone()])
    }
    pub fn span(&self, index: usize) -> Option<Range<usize>> {
        self.records.get(index).cloned()
    }
}
fn check(ctx: &ExtensionContext) -> Result<(), ObjectReadError> {
    if ctx.cancellation().is_cancelled() {
        return Err(ObjectReadError::Cancelled);
    }
    if tokio::time::Instant::now() >= ctx.deadline() {
        return Err(ObjectReadError::Timeout);
    }
    Ok(())
}
/// Synchronous bounded CPU work for an owned blocking worker, not async I/O.
/// Context checks surround gzip reads and bounded record parsing. Nothing is
/// exposed until the trailer and every native record have been validated.
pub fn read_object(
    original: &[u8],
    ctx: &ExtensionContext,
) -> Result<CloudTrailObject, ObjectReadError> {
    check(ctx)?;
    if original.is_empty() || original.len() > COMPRESSED_LIMIT {
        return Err(ObjectReadError::CaptureLimit);
    }
    let mut hash = Sha256::new();
    for chunk in original.chunks(65536) {
        check(ctx)?;
        hash.update(chunk);
    }
    let original_sha256 = hash.finalize().into();
    let mut gzip = GzDecoder::new(original);
    check(ctx)?;
    let mut decoded = Vec::new();
    let mut chunk = [0; 65536];
    loop {
        check(ctx)?;
        let n = gzip
            .read(&mut chunk)
            .map_err(|_| ObjectReadError::InvalidCompression)?;
        if n == 0 {
            break;
        }
        if decoded
            .len()
            .checked_add(n)
            .is_none_or(|n| n > DECODED_LIMIT)
        {
            return Err(ObjectReadError::ObjectLimitsExceeded);
        }
        // Geometric growth cannot exceed the explicit decoded byte ceiling.
        if decoded.len() + n > decoded.capacity() {
            let capacity = (decoded.capacity().max(65536) * 2)
                .min(DECODED_LIMIT)
                .max(decoded.len() + n);
            decoded
                .try_reserve_exact(capacity - decoded.len())
                .map_err(|_| ObjectReadError::ObjectLimitsExceeded)?;
        }
        decoded.extend_from_slice(&chunk[..n]);
    }
    check(ctx)?;
    if !gzip.into_inner().is_empty() {
        return Err(ObjectReadError::InvalidCompression);
    }
    std::str::from_utf8(&decoded).map_err(|_| ObjectReadError::InvalidObjectJson)?;
    let records = records(&decoded, ctx)?;
    check(ctx)?;
    Ok(CloudTrailObject {
        decoded,
        records,
        original_sha256,
    })
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Cursor<'_> {
    fn ws(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.at += 1;
        }
    }
    fn take(&mut self, expected: u8) -> Result<(), ObjectReadError> {
        self.ws();
        if self.bytes.get(self.at) != Some(&expected) {
            return Err(ObjectReadError::InvalidObjectJson);
        }
        self.at += 1;
        Ok(())
    }
    fn native_end(&mut self, ctx: &ExtensionContext) -> Result<usize, ObjectReadError> {
        let start = self.at;
        let mut stack = [0; MAX_JSON_DEPTH - 2];
        let mut depth = 0;
        let mut quoted = false;
        let mut escaped = false;
        while let Some(&b) = self.bytes.get(self.at) {
            if (self.at - start).is_multiple_of(1024) {
                check(ctx)?;
            }
            if self.at - start >= MAX_RECORD_BYTES {
                return Err(ObjectReadError::ObjectLimitsExceeded);
            }
            if quoted {
                self.at += 1;
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    quoted = false;
                    if depth == 0 {
                        return Ok(self.at);
                    }
                }
                continue;
            }
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    if depth == stack.len() {
                        return Err(ObjectReadError::ObjectLimitsExceeded);
                    }
                    stack[depth] = if b == b'{' { b'}' } else { b']' };
                    depth += 1;
                }
                b'}' | b']' => {
                    if depth == 0 {
                        break;
                    }
                    if stack[depth - 1] != b {
                        return Err(ObjectReadError::InvalidObjectJson);
                    }
                    depth -= 1;
                    if depth == 0 {
                        self.at += 1;
                        return Ok(self.at);
                    }
                }
                b',' | b' ' | b'\n' | b'\r' | b'\t' if depth == 0 => break,
                _ => {}
            }
            self.at += 1;
        }
        if quoted || depth != 0 || self.at == start {
            return Err(ObjectReadError::InvalidObjectJson);
        }
        Ok(self.at)
    }
}
fn records(decoded: &[u8], ctx: &ExtensionContext) -> Result<Vec<Range<usize>>, ObjectReadError> {
    let mut c = Cursor {
        bytes: decoded,
        at: 0,
    };
    c.take(b'{')?;
    c.ws();
    let key_start = c.at;
    if c.bytes.get(c.at) != Some(&b'"') {
        return Err(ObjectReadError::UnsupportedObject);
    }
    let end = c.native_end(ctx)?;
    if end - key_start > 128 {
        return Err(ObjectReadError::UnsupportedObject);
    }
    let key = decode_json(&decoded[key_start..end], 128, 1, 1)
        .map_err(|_| ObjectReadError::InvalidObjectJson)?;
    if key.as_str() != Some("Records") {
        return Err(ObjectReadError::UnsupportedObject);
    }
    c.take(b':')?;
    c.take(b'[')?;
    c.ws();
    let mut spans = Vec::new();
    if c.bytes.get(c.at) != Some(&b']') {
        loop {
            check(ctx)?;
            if spans.len() == COUNT_LIMIT {
                return Err(ObjectReadError::ObjectLimitsExceeded);
            }
            c.ws();
            let start = c.at;
            let end = c.native_end(ctx)?;
            decode_json(
                &decoded[start..end],
                MAX_RECORD_BYTES,
                MAX_JSON_DEPTH - 2,
                MAX_JSON_NODES,
            )
            .map_err(|e| match e {
                NormalizeError::RecordBytesExceeded
                | NormalizeError::JsonDepthExceeded
                | NormalizeError::JsonNodesExceeded => ObjectReadError::ObjectLimitsExceeded,
                _ => ObjectReadError::InvalidObjectJson,
            })?;
            check(ctx)?;
            spans.push(start..end);
            c.ws();
            match c.bytes.get(c.at) {
                Some(b',') => {
                    c.at += 1;
                }
                Some(b']') => break,
                _ => return Err(ObjectReadError::InvalidObjectJson),
            }
        }
    }
    c.take(b']')?;
    c.take(b'}')?;
    c.ws();
    if c.at != decoded.len() {
        return Err(ObjectReadError::InvalidObjectJson);
    }
    if spans.is_empty() {
        return Err(ObjectReadError::EmptyRecords);
    }
    Ok(spans)
}
