//! Local fixed-frontier scan contracts. Cursor checksums are consistency checks, not grants.
use crate::{AuthorizedBinding, CoverageConfig, CoverageError as Error, Receipt, format};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

pub const MAX_SCAN_CURSOR_TOKEN_BYTES: usize = 2 * (format::MAX_BINDING_BYTES + 256);
pub const MAX_SCAN_RESPONSE_BYTES: u64 = format::MAX_ENTRY_BYTES as u64;
pub const SCAN_PAGE_HEADER_BYTES: u64 = 4096;
pub const SCAN_RECORD_ALLOWANCE_BYTES: u64 = 8192;
pub const SCAN_WORK_ALLOWANCE_BYTES: u64 = 4096;
const DOMAIN: &[u8] = b"SIGNAL-COVERAGE-SCAN-V1\0";
const FIXED_CURSOR_BYTES: usize = 152;
// One bounded incoming token, the full grant and envelopes share the operation's
// existing two-entry reserve with its retained page. Decoding and row scratch
// use the separately configured worker reserve.
const MAX_SCAN_COMMAND_BYTES: u64 =
    2 * format::MAX_BINDING_BYTES as u64 + 8192 + MAX_SCAN_CURSOR_TOKEN_BYTES as u64 + 16_384;
const _: () =
    assert!(MAX_SCAN_COMMAND_BYTES + MAX_SCAN_RESPONSE_BYTES <= 2 * format::MAX_ENTRY_BYTES as u64);
const MAX_SCAN_ROW_BYTES: u64 = (format::MAX_METADATA_BYTES
    + format::MAX_RAW_BYTES
    + format::MAX_BINDING_BYTES
    + format::MAX_PROFILE_BYTES) as u64
    + SCAN_WORK_ALLOWANCE_BYTES;

/// Independent page/result/work bounds. Bytes are conservative local charges, not HTTP sizes.
#[derive(Clone, Copy, Debug)]
pub struct ScanBudget {
    pub max_records: u64,
    pub max_response_bytes: u64,
    pub max_scanned_records: u64,
    pub max_scanned_bytes: u64,
}
impl ScanBudget {
    pub(crate) fn validate(&self, config: &CoverageConfig) -> Result<(), Error> {
        let work_cap = config
            .max_identities
            .checked_mul(MAX_SCAN_ROW_BYTES)
            .ok_or(Error::Invalid("scan budget overflow"))?
            .min(config.max_ledger_bytes);
        if self.max_records == 0
            || self.max_records > config.max_identities
            || !(SCAN_PAGE_HEADER_BYTES..=MAX_SCAN_RESPONSE_BYTES)
                .contains(&self.max_response_bytes)
            || self.max_scanned_records == 0
            || self.max_scanned_records > config.max_identities
            || self.max_scanned_bytes == 0
            || self.max_scanned_bytes > work_cap
        {
            return Err(Error::Invalid("finite scan budget"));
        }
        Ok(())
    }
}

/// Bounded availability only. These positions confer no current-health or unseen-suffix claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanAvailability {
    pub history_id: Uuid,
    pub committed_sequence: u64,
    pub payload_pruned_through: u64,
    pub identity_pruned_through: u64,
}

/// Opaque canonical version-1 token. A fresh exact authorization grant is still required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanCursor {
    token: String,
}
impl ScanCursor {
    /// Validate syntax, finite length, canonical binding and checksum before copying the token.
    pub fn parse(token: &str) -> Result<Self, Error> {
        CursorState::decode(token)?;
        Ok(Self {
            token: token.to_owned(),
        })
    }
    pub fn as_str(&self) -> &str {
        &self.token
    }
    pub(crate) fn state(&self) -> Result<CursorState, Error> {
        CursorState::decode(&self.token)
    }
}

pub(crate) struct CursorState {
    pub history_id: Uuid,
    pub binding: Vec<u8>,
    pub frontier: u64,
    pub frontier_prefix: [u8; 32],
    pub last: u64,
    pub last_prefix: [u8; 32],
    pub payload_marker: u64,
    pub identity_marker: u64,
}
impl CursorState {
    pub fn encode(&self) -> Result<ScanCursor, Error> {
        if self.binding.len() > format::MAX_BINDING_BYTES {
            return Err(Error::InvalidCursor);
        }
        let mut bytes = Vec::with_capacity(DOMAIN.len() + FIXED_CURSOR_BYTES + self.binding.len());
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(self.history_id.as_bytes());
        let length = u32::try_from(self.binding.len()).map_err(|_| Error::InvalidCursor)?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&self.binding);
        bytes.extend_from_slice(&self.frontier.to_be_bytes());
        bytes.extend_from_slice(&self.frontier_prefix);
        bytes.extend_from_slice(&self.last.to_be_bytes());
        bytes.extend_from_slice(&self.last_prefix);
        bytes.extend_from_slice(&self.payload_marker.to_be_bytes());
        bytes.extend_from_slice(&self.identity_marker.to_be_bytes());
        bytes.extend_from_slice(&format::sha256(&bytes));
        if bytes.len() > MAX_SCAN_CURSOR_TOKEN_BYTES / 2 {
            return Err(Error::InvalidCursor);
        }
        Ok(ScanCursor {
            token: format::hex(&bytes),
        })
    }
    fn decode(token: &str) -> Result<Self, Error> {
        if token.len() > MAX_SCAN_CURSOR_TOKEN_BYTES
            || token.len() < 2 * (DOMAIN.len() + FIXED_CURSOR_BYTES)
            || !token.len().is_multiple_of(2)
            || !token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidCursor);
        }
        let mut bytes = Vec::with_capacity(token.len() / 2);
        for pair in token.as_bytes().chunks_exact(2) {
            fn nibble(b: u8) -> u8 {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b - b'a' + 10
                }
            }
            bytes.push((nibble(pair[0]) << 4) | nibble(pair[1]));
        }
        let checksum_at = bytes.len().checked_sub(32).ok_or(Error::InvalidCursor)?;
        if format::sha256(&bytes[..checksum_at]) != bytes[checksum_at..] {
            return Err(Error::InvalidCursor);
        }
        let mut reader = Reader(&bytes[..checksum_at]);
        if reader.take(DOMAIN.len())? != DOMAIN || reader.u32()? != 1 {
            return Err(Error::InvalidCursor);
        }
        let history_id = Uuid::from_slice(reader.take(16)?).map_err(|_| Error::InvalidCursor)?;
        if history_id.is_nil() {
            return Err(Error::InvalidCursor);
        }
        let binding_len = reader.u32()? as usize;
        if binding_len == 0 || binding_len > format::MAX_BINDING_BYTES {
            return Err(Error::InvalidCursor);
        }
        let binding = reader.take(binding_len)?;
        format::HistoryBinding::decode(binding).map_err(|_| Error::InvalidCursor)?;
        let state = Self {
            history_id,
            binding: binding.to_vec(),
            frontier: reader.u64()?,
            frontier_prefix: reader.hash()?,
            last: reader.u64()?,
            last_prefix: reader.hash()?,
            payload_marker: reader.u64()?,
            identity_marker: reader.u64()?,
        };
        if !reader.0.is_empty()
            || state.identity_marker > state.payload_marker
            || state.payload_marker > state.frontier
            || state.identity_marker > state.last
            || state.last > state.frontier
        {
            return Err(Error::InvalidCursor);
        }
        Ok(state)
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error::InvalidCursor);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::InvalidCursor)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::InvalidCursor)?,
        ))
    }
    fn hash(&mut self) -> Result<[u8; 32], Error> {
        self.take(32)?.try_into().map_err(|_| Error::InvalidCursor)
    }
}

pub(crate) fn page_header_bytes(authority: &AuthorizedBinding) -> u64 {
    SCAN_PAGE_HEADER_BYTES
        + (2 * (DOMAIN.len() + FIXED_CURSOR_BYTES + authority.binding.encoded().len())) as u64
}

/// Matching historical bytes and immutable receipt. Scope and pins are not duplicated per row.
#[derive(Debug)]
pub struct ScanRecord {
    pub receipt: Receipt,
    pub raw: Option<Vec<u8>>,
}

/// A bounded retained response. Drop it to release its operation slot; it cannot be cloned.
#[derive(Debug)]
pub struct ScanPage {
    pub(crate) records: Vec<ScanRecord>,
    pub(crate) continuation: Option<ScanCursor>,
    pub(crate) availability: ScanAvailability,
    pub(crate) frontier: u64,
    pub(crate) scanned_records: u64,
    pub(crate) scanned_bytes: u64,
    pub(crate) response_bytes: u64,
    pub(crate) permit: Option<Arc<OwnedSemaphorePermit>>,
}
impl ScanPage {
    pub fn records(&self) -> &[ScanRecord] {
        &self.records
    }
    pub fn continuation(&self) -> Option<&ScanCursor> {
        self.continuation.as_ref()
    }
    pub fn availability(&self) -> ScanAvailability {
        self.availability
    }
    pub fn frontier(&self) -> u64 {
        self.frontier
    }
    pub fn scanned_records(&self) -> u64 {
        self.scanned_records
    }
    pub fn scanned_bytes(&self) -> u64 {
        self.scanned_bytes
    }
    pub fn response_bytes(&self) -> u64 {
        self.response_bytes
    }
}
