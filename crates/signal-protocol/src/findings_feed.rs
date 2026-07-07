//! Bounded append-prefix references, never credentials or consumer acknowledgements.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Largest empty version-1 envelope: 76 ASCII cursor bytes and `has_more:false`.
pub const FINDINGS_FEED_EMPTY_BYTES: usize = 144;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FeedQueryError {
    #[error("invalid feed query")]
    InvalidQuery,
    #[error("invalid findings cursor")]
    InvalidCursor,
    #[error("unsupported findings cursor version")]
    UnsupportedCursorVersion,
}

/// Exact consumed prefix of one retained append-only journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingsCursor {
    stream: Uuid,
    position: u64,
    digest: [u8; 32],
}
impl FindingsCursor {
    pub fn initial(stream: Uuid) -> Result<Self, FeedQueryError> {
        if stream.is_nil() {
            return Err(FeedQueryError::InvalidCursor);
        }
        let mut hash = Sha256::new();
        hash.update(b"SIGNAL-FINDINGS-CURSOR-V1");
        hash.update(stream.as_bytes());
        Ok(Self {
            stream,
            position: 0,
            digest: hash.finalize().into(),
        })
    }
    /// Hash original first-occurrence payload bytes, without reserialization.
    pub fn advance(self, payload: &[u8]) -> Result<Self, FeedQueryError> {
        let position = self
            .position
            .checked_add(1)
            .ok_or(FeedQueryError::InvalidCursor)?;
        let length = u32::try_from(payload.len()).map_err(|_| FeedQueryError::InvalidCursor)?;
        let mut hash = Sha256::new();
        hash.update(b"SIGNAL-FINDINGS-RECORD-V1");
        hash.update(self.digest);
        hash.update(position.to_be_bytes());
        hash.update(length.to_be_bytes());
        hash.update(payload);
        Ok(Self {
            stream: self.stream,
            position,
            digest: hash.finalize().into(),
        })
    }
    pub fn stream(self) -> Uuid {
        self.stream
    }
    pub fn position(self) -> u64 {
        self.position
    }
    pub fn encode(self) -> String {
        let mut bytes = [0; 57];
        bytes[0] = 1;
        bytes[1..17].copy_from_slice(self.stream.as_bytes());
        bytes[17..25].copy_from_slice(&self.position.to_be_bytes());
        bytes[25..].copy_from_slice(&self.digest);
        URL_SAFE_NO_PAD.encode(bytes)
    }
    pub fn decode(token: &str) -> Result<Self, FeedQueryError> {
        if token.len() != 76 {
            return Err(FeedQueryError::InvalidCursor);
        }
        let mut bytes = [0; 57];
        let length = URL_SAFE_NO_PAD
            .decode_slice(token, &mut bytes)
            .map_err(|_| FeedQueryError::InvalidCursor)?;
        if length != 57 || URL_SAFE_NO_PAD.encode(bytes) != token {
            return Err(FeedQueryError::InvalidCursor);
        }
        if bytes[0] != 1 {
            return Err(FeedQueryError::UnsupportedCursorVersion);
        }
        let stream = Uuid::from_slice(&bytes[1..17]).map_err(|_| FeedQueryError::InvalidCursor)?;
        if stream.is_nil() {
            return Err(FeedQueryError::InvalidCursor);
        }
        let position = u64::from_be_bytes(
            bytes[17..25]
                .try_into()
                .map_err(|_| FeedQueryError::InvalidCursor)?,
        );
        let digest = bytes[25..]
            .try_into()
            .map_err(|_| FeedQueryError::InvalidCursor)?;
        Ok(Self {
            stream,
            position,
            digest,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingsAfter {
    Begin,
    Cursor(FindingsCursor),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingsFeedQuery {
    pub after: FindingsAfter,
    pub limit: usize,
}

/// Caller checks authorization before parsing; no filters or implicit tail bootstrap.
pub fn parse_findings_feed_query(
    raw: &str,
    max_limit: usize,
) -> Result<FindingsFeedQuery, FeedQueryError> {
    if raw.len() > 16_384 || max_limit == 0 || raw.split('&').any(str::is_empty) {
        return Err(FeedQueryError::InvalidQuery);
    }
    // serde_urlencoded replaces malformed UTF-8; validate exact percent decoding first.
    let mut decoded = Vec::with_capacity(raw.len());
    let input = raw.as_bytes();
    let mut n = 0;
    while n < input.len() {
        if input[n] == b'%' {
            if n + 2 >= input.len()
                || !input[n + 1].is_ascii_hexdigit()
                || !input[n + 2].is_ascii_hexdigit()
            {
                return Err(FeedQueryError::InvalidQuery);
            }
            decoded.push(
                u8::from_str_radix(&raw[n + 1..n + 3], 16)
                    .map_err(|_| FeedQueryError::InvalidQuery)?,
            );
            n += 3;
        } else {
            decoded.push(input[n]);
            n += 1;
        }
    }
    std::str::from_utf8(&decoded).map_err(|_| FeedQueryError::InvalidQuery)?;
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(raw).map_err(|_| FeedQueryError::InvalidQuery)?;
    let mut after = None;
    let mut limit = None;
    for (key, value) in pairs {
        match key.as_str() {
            "after" if after.is_none() && !value.is_empty() => {
                after = Some(if value == "begin" {
                    FindingsAfter::Begin
                } else {
                    FindingsAfter::Cursor(FindingsCursor::decode(&value)?)
                });
            }
            "limit"
                if limit.is_none()
                    && !value.is_empty()
                    && value.bytes().all(|b| b.is_ascii_digit()) =>
            {
                let number: usize = value.parse().map_err(|_| FeedQueryError::InvalidQuery)?;
                if number == 0 || number > max_limit {
                    return Err(FeedQueryError::InvalidQuery);
                }
                limit = Some(number);
            }
            _ => return Err(FeedQueryError::InvalidQuery),
        }
    }
    Ok(FindingsFeedQuery {
        after: after.ok_or(FeedQueryError::InvalidQuery)?,
        limit: limit.unwrap_or(100.min(max_limit)),
    })
}

/// Generic wire envelope avoids a protocol dependency on the findings engine.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingsFeedResponse<T> {
    pub schema_version: u16,
    pub findings: Vec<T>,
    pub next_cursor: String,
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_cursor_vector_and_strict_encoding() -> Result<(), Box<dyn std::error::Error>> {
        let zero = FindingsCursor::initial(Uuid::from_bytes([1; 16]))?;
        assert_eq!(zero.encode().len(), 76);
        assert_eq!(FindingsCursor::decode(&zero.encode())?, zero);
        let next = zero.advance(b"raw exact bytes")?;
        assert_ne!(zero, next);
        assert_eq!(next.position(), 1);
        // Independent Python hashlib vector retained in the task evidence.
        assert_eq!(
            next.encode(),
            "AQEBAQEBAQEBAQEBAQEBAQEAAAAAAAAAAZG1vkhhrCu4RiZK6ofjLcYffnHBBi7cHak_8LRC4r_I"
        );
        for token in [
            format!("{}=", zero.encode()),
            zero.encode()[1..].into(),
            "!".repeat(76),
            " ".repeat(76),
        ] {
            assert_eq!(
                FindingsCursor::decode(&token),
                Err(FeedQueryError::InvalidCursor)
            );
        }
        let mut bytes = [0; 57];
        bytes[0] = 2;
        bytes[1..17].fill(1);
        assert_eq!(
            FindingsCursor::decode(&URL_SAFE_NO_PAD.encode(bytes)),
            Err(FeedQueryError::UnsupportedCursorVersion)
        );
        bytes[0] = 1;
        bytes[1..17].fill(0);
        assert_eq!(
            FindingsCursor::decode(&URL_SAFE_NO_PAD.encode(bytes)),
            Err(FeedQueryError::InvalidCursor)
        );
        let overflow = FindingsCursor {
            position: u64::MAX,
            ..zero
        };
        assert!(overflow.advance(b"x").is_err());
        Ok(())
    }
    #[test]
    fn feed_query_requires_explicit_progress_and_rejects_extra_or_duplicate_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(parse_findings_feed_query("after=begin", 10)?.limit, 10);
        let cursor = FindingsCursor::initial(Uuid::from_bytes([1; 16]))?;
        assert_eq!(
            parse_findings_feed_query(&format!("after={}&limit=1", cursor.encode()), 100)?.after,
            FindingsAfter::Cursor(cursor)
        );
        for raw in [
            "",
            "limit=1",
            "after=",
            "after=begin&after=begin",
            "after=begin&%61fter=begin",
            "after=begin&limit=0",
            "after=begin&limit=101",
            "after=begin&limit=%2B1",
            "after=begin&limit=1&limit=2",
            "after=%FF",
            "after=%",
            "after=begin&from=x",
            "after=begin&",
        ] {
            assert!(parse_findings_feed_query(raw, 100).is_err(), "{raw}");
        }
        assert!(parse_findings_feed_query(&"a".repeat(16385), 100).is_err());
        Ok(())
    }
}
