//! Bounded RFC6587 octet counting and selected FortiGate default key/value projection.
//! These helpers grant no transport authentication, source ACK or coverage.
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use signal_event::{IngestEvent, SignalEvent, Source};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_FRAME_BYTES: usize = 65536;
pub const MAX_FIELDS: usize = 256;
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid or oversized syslog frame")]
    Frame,
    #[error("invalid selected FortiGate record")]
    Record,
    #[error("invalid pinned source context")]
    Context,
}
/// One bounded pending frame, no internal completed-frame queue. The receiver
/// must consume the returned frame durably before accepting further input.
#[derive(Default)]
pub struct OctetDecoder {
    length: usize,
    digits: usize,
    body: Option<Vec<u8>>,
    failed: bool,
}
impl OctetDecoder {
    pub fn buffered_bytes(&self) -> usize {
        self.body.as_ref().map_or(self.digits, Vec::len)
    }
    pub fn capacity_bytes(&self) -> usize {
        MAX_FRAME_BYTES + 5
    }
    /// Return consumed input bytes and at most one complete frame. A caller must
    /// retain unconsumed input; malformed framing permanently poisons this stream.
    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<Vec<u8>>), Error> {
        if self.failed {
            return Err(Error::Frame);
        }
        for (index, byte) in input.iter().copied().enumerate() {
            if let Some(body) = &mut self.body {
                body.push(byte);
                if body.len() == self.length {
                    let completed = self.body.take();
                    self.length = 0;
                    self.digits = 0;
                    return Ok((index + 1, completed));
                }
            } else if byte.is_ascii_digit()
                && self.digits < 5
                && !(self.digits == 0 && byte == b'0')
            {
                self.length = self.length * 10 + usize::from(byte - b'0');
                self.digits += 1;
                if self.length > MAX_FRAME_BYTES {
                    self.failed = true;
                    return Err(Error::Frame);
                }
            } else if byte == b' ' && self.digits > 0 {
                self.body = Some(Vec::with_capacity(self.length));
            } else {
                self.failed = true;
                return Err(Error::Frame);
            }
        }
        Ok((input.len(), None))
    }
    /// EOF never promotes an incomplete frame to a message.
    pub fn finish(&self) -> Result<(), Error> {
        if self.failed || self.digits != 0 || self.body.is_some() {
            Err(Error::Frame)
        } else {
            Ok(())
        }
    }
}
fn fields(raw: &str) -> Result<Map<String, Value>, Error> {
    let bytes = raw.as_bytes();
    let mut pos = 0;
    let mut out = Map::new();
    while pos < bytes.len() {
        while bytes.get(pos) == Some(&b' ') {
            pos += 1;
        }
        if pos == bytes.len() {
            break;
        }
        let start = pos;
        while bytes
            .get(pos)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        {
            pos += 1;
        }
        if pos == start || pos - start > 64 || bytes.get(pos) != Some(&b'=') {
            return Err(Error::Record);
        }
        let key = &raw[start..pos];
        pos += 1;
        let mut value = Vec::new();
        if bytes.get(pos) == Some(&b'"') {
            pos += 1;
            let mut closed = false;
            while let Some(&b) = bytes.get(pos) {
                pos += 1;
                if b == b'"' {
                    closed = true;
                    break;
                }
                if b == b'\\' {
                    let escaped = *bytes.get(pos).ok_or(Error::Record)?;
                    if escaped != b'"' && escaped != b'\\' {
                        return Err(Error::Record);
                    }
                    pos += 1;
                    value.push(escaped);
                } else {
                    value.push(b);
                }
            }
            if !closed || bytes.get(pos).is_some_and(|b| *b != b' ') {
                return Err(Error::Record);
            }
        } else {
            while let Some(&b) = bytes.get(pos) {
                if b == b' ' {
                    break;
                }
                if b == b'"' || b == b'\\' {
                    return Err(Error::Record);
                }
                value.push(b);
                pos += 1;
            }
            if value.is_empty() {
                return Err(Error::Record);
            }
        }
        let value = String::from_utf8(value).map_err(|_| Error::Record)?;
        if value.chars().any(char::is_control)
            || out.len() >= MAX_FIELDS
            || matches!(
                key.to_ascii_lowercase().as_str(),
                "password" | "passwd" | "token" | "secret" | "authorization"
            )
            || out.insert(key.into(), Value::String(value)).is_some()
        {
            return Err(Error::Record);
        }
    }
    Ok(out)
}
/// Nanosecond eventtime is explicitly selected, never inferred from magnitude.
/// Device IDs and native fields are assertions. Trusted connection/source scope
/// must be supplied by a separate adapter; source is never derived from devid.
pub fn normalize_fortigate_ns(
    frame: &[u8],
    source: Source,
    event_id: Uuid,
    observed_at: DateTime<Utc>,
) -> Result<SignalEvent, Error> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(Error::Frame);
    }
    if event_id.is_nil() {
        return Err(Error::Context);
    }
    let mut raw = std::str::from_utf8(frame).map_err(|_| Error::Record)?;
    let mut priority = None;
    if raw.starts_with('<') {
        let end = raw.find('>').filter(|n| *n <= 4).ok_or(Error::Record)?;
        let digits = &raw[1..end];
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Record);
        }
        let pri: u16 = digits.parse().map_err(|_| Error::Record)?;
        if pri > 191 {
            return Err(Error::Record);
        }
        priority = Some(pri);
        raw = &raw[end + 1..];
    }
    let native = fields(raw)?;
    for required in ["devid", "eventtime", "level", "logid", "type", "subtype"] {
        if native
            .get(required)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(Error::Record);
        }
    }
    let eventtime = native["eventtime"].as_str().ok_or(Error::Record)?;
    if !eventtime.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Record);
    }
    let ns: u64 = eventtime.parse().map_err(|_| Error::Record)?;
    let timestamp =
        DateTime::<Utc>::from_timestamp((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as u32)
            .ok_or(Error::Record)?;
    let severity = match native["level"].as_str().ok_or(Error::Record)? {
        "emergency" | "alert" | "critical" => "critical",
        "error" => "error",
        "warning" => "warn",
        "notice" | "information" => "info",
        "debug" => "debug",
        _ => return Err(Error::Record),
    };
    let input: IngestEvent = serde_json::from_value(serde_json::json!({
        "timestamp":timestamp,"source":source,"severity":severity,
        "message":"FortiGate syslog record",
        "attributes":{"fortigate":native,"syslog":{"priority":priority,"identity_basis":"native_assertion"},
            "normalizer":{"id":"fortigate-default-ns","revision":"v1"},
            "coverage":{"completeness":"not_assessed"}}
    })).map_err(|_| Error::Record)?;
    let mut event = input.normalize(observed_at).map_err(|_| Error::Context)?;
    event.id = event_id;
    Ok(event)
}
