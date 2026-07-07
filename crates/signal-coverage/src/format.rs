//! ADR-015 version-1 codecs. Canonical profile/binding bytes differ from original report bytes.
use crate::CoverageError as Error;
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize, de};
use sha2::{Digest, Sha256};
use signal_collector_sdk::coverage::CoverageProfile;
use std::{collections::BTreeMap, fmt};
use uuid::Uuid;

pub const MAX_RAW_BYTES: usize = 65_536;
pub const MAX_BINDING_BYTES: usize = 65_536;
pub const MAX_PROFILE_BYTES: usize = 8_192;
pub const MAX_METADATA_BYTES: usize = 73_728;
pub const MAX_ENTRY_BYTES: usize = 397_312;
pub(crate) const ROOT_CHARGE: u64 = 16_384;
const PROFILE: &[u8] = b"SIGNAL-COVERAGE-PROFILE-V1\0";
const BINDING: &[u8] = b"SIGNAL-COVERAGE-BINDING-V1\0";
const HISTORY: &[u8] = b"SIGNAL-COVERAGE-HISTORY-V1\0";
const COMMIT: &[u8] = b"SIGNAL-COVERAGE-COMMIT-V1\0";
const PREFIX: &[u8] = b"SIGNAL-COVERAGE-PREFIX-V1\0";
const STATE: &[u8] = b"SIGNAL-COVERAGE-STATE-V1\0";

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
pub fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}
pub fn genesis(history: Uuid) -> Result<[u8; 32], Error> {
    non_nil(history)?;
    let mut data = HISTORY.to_vec();
    data.extend_from_slice(history.as_bytes());
    Ok(sha256(&data))
}
pub fn prefix(previous: [u8; 32], metadata: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREFIX);
    hasher.update(previous);
    hasher.update(sha256(metadata));
    hasher.finalize().into()
}
pub fn identity(history: Uuid) -> Result<Vec<u8>, Error> {
    non_nil(history)?;
    let mut data = b"SIGCOV01".to_vec();
    data.extend_from_slice(history.as_bytes());
    data.extend_from_slice(&sha256(&data));
    Ok(data)
}
pub(crate) fn read_identity(data: &[u8]) -> Result<Uuid, Error> {
    if data.len() != 56 || &data[..8] != b"SIGCOV01" || sha256(&data[..24]) != data[24..] {
        return Err(Error::Corrupt("identity file"));
    }
    let id = Uuid::from_slice(&data[8..24]).map_err(|_| Error::Corrupt("identity UUID"))?;
    non_nil(id)?;
    Ok(id)
}
pub(crate) fn non_nil(id: Uuid) -> Result<(), Error> {
    if id.is_nil() {
        Err(Error::Invalid("nil UUID"))
    } else {
        Ok(())
    }
}
fn checked_text(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 1024 {
        Err(Error::Invalid("text byte bound"))
    } else {
        Ok(())
    }
}
fn blob(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let len = u32::try_from(bytes.len()).map_err(|_| Error::Invalid("blob bound"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn text(out: &mut Vec<u8>, value: &str) -> Result<(), Error> {
    checked_text(value)?;
    blob(out, value.as_bytes())
}
fn bounded_json<T: de::DeserializeOwned>(data: &[u8], maximum: usize) -> Result<T, Error> {
    if data.is_empty() || data.len() > maximum {
        return Err(Error::Invalid("JSON byte bound"));
    }
    serde_json::from_slice(data).map_err(|_| Error::Invalid("JSON structure"))
}

/// Validated UTC time, encoded as exactly 30 ASCII bytes; no epoch-nanosecond narrowing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp([u8; 30]);
impl Timestamp {
    pub fn parse(value: &str) -> Result<Self, Error> {
        let b = value.as_bytes();
        if !value.is_ascii()
            || !(20..=30).contains(&b.len())
            || b.last() != Some(&b'Z')
            || b[4] != b'-'
            || b[7] != b'-'
            || b[10] != b'T'
            || b[13] != b':'
            || b[16] != b':'
            || (b.len() != 20
                && (b.len() < 22
                    || b[19] != b'.'
                    || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit)))
        {
            return Err(Error::Invalid("UTC time syntax"));
        }
        let parsed =
            DateTime::parse_from_rfc3339(value).map_err(|_| Error::Invalid("calendar time"))?;
        if !(1..=9999).contains(&parsed.year()) || parsed.nanosecond() >= 1_000_000_000 {
            return Err(Error::Invalid("calendar time range"));
        }
        let result = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            parsed.year(),
            parsed.month(),
            parsed.day(),
            parsed.hour(),
            parsed.minute(),
            parsed.second(),
            parsed.nanosecond()
        );
        Ok(Self(
            result
                .as_bytes()
                .try_into()
                .map_err(|_| Error::Invalid("time width"))?,
        ))
    }
    pub fn encoded(&self) -> &[u8; 30] {
        &self.0
    }
    pub(crate) fn datetime(&self) -> Result<DateTime<Utc>, Error> {
        let s = std::str::from_utf8(&self.0).map_err(|_| Error::Corrupt("time encoding"))?;
        Ok(DateTime::parse_from_rfc3339(s)
            .map_err(|_| Error::Corrupt("time encoding"))?
            .with_timezone(&Utc))
    }
}
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Construction admits only ASCII; formatting avoids an invariant panic.
        f.write_str(std::str::from_utf8(&self.0).map_err(|_| fmt::Error)?)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileWire {
    schema_version: u32,
    id: String,
    revision: String,
    required_components: Vec<String>,
    requires_checkpoint: bool,
    max_interval_seconds: u32,
    max_verification_age_seconds: u32,
    max_clock_skew_seconds: u32,
}
/// Opaque validated profile with its frozen canonical definition and SDK representation.
#[derive(Clone, Debug)]
pub struct ProfileDefinition {
    wire: ProfileWire,
    pub(crate) sdk: CoverageProfile,
    bytes: Vec<u8>,
}
impl ProfileDefinition {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let sdk = CoverageProfile::parse(data).map_err(Error::Coverage)?;
        let wire: ProfileWire = bounded_json(data, MAX_RAW_BYTES)?;
        let mut bytes = PROFILE.to_vec();
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        text(&mut bytes, &wire.id)?;
        text(&mut bytes, &wire.revision)?;
        let mut mask = 0;
        for c in &wire.required_components {
            mask |= match c.as_str() {
                "configuration" => 1,
                "scope" => 2,
                "continuity" => 4,
                "source_integrity" => 8,
                _ => return Err(Error::Invalid("component")),
            };
        }
        bytes.extend_from_slice(&[mask, u8::from(wire.requires_checkpoint)]);
        for n in [
            wire.max_interval_seconds,
            wire.max_verification_age_seconds,
            wire.max_clock_skew_seconds,
        ] {
            bytes.extend_from_slice(&n.to_be_bytes());
        }
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(Error::Invalid("profile encoded bound"));
        }
        Ok(Self { wire, sdk, bytes })
    }
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }
    pub fn fingerprint(&self) -> [u8; 32] {
        sha256(&self.bytes)
    }
    pub fn id(&self) -> &str {
        &self.wire.id
    }
    pub fn revision(&self) -> &str {
        &self.wire.revision
    }
    /// The retained validated v1 definition, independent of today's catalog.
    pub fn definition_bytes(&self) -> Result<Vec<u8>, Error> {
        self.sdk.definition_bytes().map_err(Error::Coverage)
    }
    pub(crate) fn skew(&self) -> u32 {
        self.wire.max_clock_skew_seconds
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(Error::Corrupt("profile bound"));
        }
        let mut c = Cursor::new(bytes);
        c.magic(PROFILE)?;
        if c.u32()? != 1 {
            return Err(Error::Corrupt("profile version"));
        }
        let id = c.text()?;
        let revision = c.text()?;
        let mask = c.u8()?;
        let checkpoint = c.u8()?;
        if ![7, 15].contains(&mask) || checkpoint > 1 {
            return Err(Error::Corrupt("profile flags"));
        }
        let wire = ProfileWire {
            schema_version: 1,
            id,
            revision,
            required_components: [
                (1, "configuration"),
                (2, "scope"),
                (4, "continuity"),
                (8, "source_integrity"),
            ]
            .into_iter()
            .filter(|(bit, _)| mask & bit != 0)
            .map(|(_, name)| name.to_owned())
            .collect(),
            requires_checkpoint: checkpoint == 1,
            max_interval_seconds: c.u32()?,
            max_verification_age_seconds: c.u32()?,
            max_clock_skew_seconds: c.u32()?,
        };
        c.end()?;
        let json = serde_json::to_vec(&wire).map_err(|_| Error::Corrupt("profile JSON"))?;
        let p = Self::parse(&json)?;
        if p.encoded() != bytes {
            return Err(Error::Corrupt("profile canonical bytes"));
        }
        Ok(p)
    }
}

fn attributes<'de, D: de::Deserializer<'de>>(d: D) -> Result<BTreeMap<String, String>, D::Error> {
    struct Visitor;
    impl<'de> de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded unique attributes")
        }
        fn visit_map<M: de::MapAccess<'de>>(self, mut m: M) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some(k) = m.next_key::<String>()? {
                if result.len() >= 16 || result.contains_key(&k) {
                    return Err(de::Error::custom("attribute bound/duplicate"));
                }
                result.insert(k, m.next_value()?);
            }
            Ok(result)
        }
    }
    d.deserialize_map(Visitor)
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Scope {
    kind: String,
    id: String,
    #[serde(default, deserialize_with = "attributes")]
    attributes: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProfileRef {
    id: String,
    revision: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct BindingWire {
    source_id: String,
    collector_id: String,
    resource_scope: Scope,
    expected_stream: String,
    coverage_profile: ProfileRef,
    collection_config_revision: String,
    observer_id: String,
}
/// An exact full key, including observer identity. This type grants no authorization.
#[derive(Clone, Debug)]
pub struct HistoryBinding {
    wire: BindingWire,
    bytes: Vec<u8>,
}
impl HistoryBinding {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        Self::from_wire(bounded_json(data, MAX_BINDING_BYTES)?)
    }
    fn from_wire(wire: BindingWire) -> Result<Self, Error> {
        let mut bytes = BINDING.to_vec();
        for s in [
            &wire.source_id,
            &wire.collector_id,
            &wire.resource_scope.kind,
            &wire.resource_scope.id,
        ] {
            text(&mut bytes, s)?;
        }
        bytes.extend_from_slice(&(wire.resource_scope.attributes.len() as u32).to_be_bytes());
        for (k, v) in &wire.resource_scope.attributes {
            text(&mut bytes, k)?;
            text(&mut bytes, v)?;
        }
        for s in [
            &wire.expected_stream,
            &wire.coverage_profile.id,
            &wire.coverage_profile.revision,
            &wire.collection_config_revision,
            &wire.observer_id,
        ] {
            text(&mut bytes, s)?;
        }
        if bytes.len() > MAX_BINDING_BYTES {
            return Err(Error::Invalid("binding encoded bound"));
        }
        Ok(Self { wire, bytes })
    }
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }
    pub fn observer_id(&self) -> &str {
        &self.wire.observer_id
    }
    /// Check configured profile identity; retained definition conflicts still
    /// require physical history validation before accepting new writes.
    pub fn profile_matches(&self, p: &ProfileDefinition) -> bool {
        self.wire.coverage_profile.id == p.id()
            && self.wire.coverage_profile.revision == p.revision()
    }
    pub(crate) fn from_record(data: &[u8]) -> Result<(Self, RecordTimes), Error> {
        #[derive(Deserialize)]
        struct Provenance {
            observer_id: String,
            observed_at: String,
        }
        #[derive(Deserialize)]
        struct Projection {
            source_id: String,
            collector_id: String,
            resource_scope: Scope,
            expected_stream: String,
            coverage_profile: ProfileRef,
            collection_config_revision: String,
            provenance: Provenance,
            record_id: Uuid,
            coverage_start: String,
            coverage_end: String,
            last_verified_at: String,
        }
        let p: Projection = bounded_json(data, MAX_RAW_BYTES)?;
        let times = RecordTimes {
            id: p.record_id,
            verified: Timestamp::parse(&p.last_verified_at)?,
            observed: Timestamp::parse(&p.provenance.observed_at)?,
            start: Timestamp::parse(&p.coverage_start)?,
            end: Timestamp::parse(&p.coverage_end)?,
        };
        let b = Self::from_wire(BindingWire {
            source_id: p.source_id,
            collector_id: p.collector_id,
            resource_scope: p.resource_scope,
            expected_stream: p.expected_stream,
            coverage_profile: p.coverage_profile,
            collection_config_revision: p.collection_config_revision,
            observer_id: p.provenance.observer_id,
        })?;
        Ok((b, times))
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BINDING_BYTES {
            return Err(Error::Corrupt("binding bound"));
        }
        let mut c = Cursor::new(bytes);
        c.magic(BINDING)?;
        let source_id = c.text()?;
        let collector_id = c.text()?;
        let kind = c.text()?;
        let id = c.text()?;
        let count = c.u32()?;
        if count > 16 {
            return Err(Error::Corrupt("attribute count"));
        }
        let mut attributes = BTreeMap::new();
        let mut last = None;
        for _ in 0..count {
            let k = c.text()?;
            if last.as_ref().is_some_and(|v| v >= &k) {
                return Err(Error::Corrupt("attribute ordering"));
            }
            let v = c.text()?;
            last = Some(k.clone());
            attributes.insert(k, v);
        }
        let wire = BindingWire {
            source_id,
            collector_id,
            resource_scope: Scope {
                kind,
                id,
                attributes,
            },
            expected_stream: c.text()?,
            coverage_profile: ProfileRef {
                id: c.text()?,
                revision: c.text()?,
            },
            collection_config_revision: c.text()?,
            observer_id: c.text()?,
        };
        c.end()?;
        let b = Self::from_wire(wire)?;
        if b.encoded() != bytes {
            return Err(Error::Corrupt("binding canonical bytes"));
        }
        Ok(b)
    }
}
pub(crate) struct RecordTimes {
    pub id: Uuid,
    pub verified: Timestamp,
    pub observed: Timestamp,
    pub start: Timestamp,
    pub end: Timestamp,
}

/// Immutable commit fields. Encoding alone is not a valid source assertion or admission.
#[derive(Clone, Debug)]
pub struct CommitMetadata {
    pub history_id: Uuid,
    pub sequence: u64,
    pub record_id: Uuid,
    pub raw_length: u32,
    pub content_sha256: [u8; 32],
    pub binding: HistoryBinding,
    pub profile_fingerprint: [u8; 32],
    pub authority_revision: String,
    pub accepted_at: Timestamp,
    pub replay_until: Timestamp,
    pub identity_until: Timestamp,
    pub correction_of: Option<Uuid>,
}
impl CommitMetadata {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        non_nil(self.history_id)?;
        non_nil(self.record_id)?;
        if self.sequence == 0
            || self.raw_length == 0
            || self.raw_length as usize > MAX_RAW_BYTES
            || self.accepted_at >= self.replay_until
            || self.replay_until > self.identity_until
        {
            return Err(Error::Invalid("commit bounds/deadlines"));
        }
        let mut out = COMMIT.to_vec();
        out.extend_from_slice(self.history_id.as_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(self.record_id.as_bytes());
        out.extend_from_slice(&self.raw_length.to_be_bytes());
        out.extend_from_slice(&self.content_sha256);
        blob(&mut out, self.binding.encoded())?;
        out.extend_from_slice(&self.profile_fingerprint);
        text(&mut out, &self.authority_revision)?;
        for t in [self.accepted_at, self.replay_until, self.identity_until] {
            out.extend_from_slice(t.encoded());
        }
        match self.correction_of {
            None => out.push(0),
            Some(id) => {
                non_nil(id)?;
                out.push(1);
                out.extend_from_slice(id.as_bytes());
            }
        }
        if out.len() > MAX_METADATA_BYTES {
            return Err(Error::Invalid("commit metadata bound"));
        }
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(Error::Corrupt("commit metadata bound"));
        }
        let mut c = Cursor::new(bytes);
        c.magic(COMMIT)?;
        let history_id = c.uuid()?;
        let sequence = c.u64()?;
        let record_id = c.uuid()?;
        let raw_length = c.u32()?;
        let content_sha256 = c.fixed()?;
        let binding = HistoryBinding::decode(c.blob(MAX_BINDING_BYTES)?)?;
        let profile_fingerprint = c.fixed()?;
        let authority_revision = c.text()?;
        let accepted_at = c.time()?;
        let replay_until = c.time()?;
        let identity_until = c.time()?;
        let correction_of = match c.u8()? {
            0 => None,
            1 => Some(c.uuid()?),
            _ => return Err(Error::Corrupt("correction flag")),
        };
        c.end()?;
        let m = Self {
            history_id,
            sequence,
            record_id,
            raw_length,
            content_sha256,
            binding,
            profile_fingerprint,
            authority_revision,
            accepted_at,
            replay_until,
            identity_until,
            correction_of,
        };
        if m.encode()? != bytes {
            return Err(Error::Corrupt("commit canonical bytes"));
        }
        Ok(m)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct State {
    pub history_id: Uuid,
    pub committed_sequence: u64,
    pub committed_prefix: [u8; 32],
    pub payload_pruned_through: u64,
    pub payload_anchor: [u8; 32],
    pub identity_pruned_through: u64,
    pub identity_anchor: [u8; 32],
    pub clock_floor: Timestamp,
    pub payload_count: u64,
    pub identity_count: u64,
    pub binding_count: u64,
    pub profile_count: u64,
    pub ledger_charge: u64,
}
impl State {
    pub fn empty(history_id: Uuid, clock_floor: Timestamp) -> Result<Self, Error> {
        let h = genesis(history_id)?;
        Ok(Self {
            history_id,
            committed_sequence: 0,
            committed_prefix: h,
            payload_pruned_through: 0,
            payload_anchor: h,
            identity_pruned_through: 0,
            identity_anchor: h,
            clock_floor,
            payload_count: 0,
            identity_count: 0,
            binding_count: 0,
            profile_count: 0,
            ledger_charge: ROOT_CHARGE,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        non_nil(self.history_id)?;
        if self.identity_pruned_through > self.payload_pruned_through
            || self.payload_pruned_through > self.committed_sequence
            || self.payload_count != self.committed_sequence - self.payload_pruned_through
            || self.identity_count != self.committed_sequence - self.identity_pruned_through
            || self.ledger_charge < ROOT_CHARGE
        {
            return Err(Error::Corrupt("state positions/counts"));
        }
        let positions = [
            (self.committed_sequence, self.committed_prefix),
            (self.payload_pruned_through, self.payload_anchor),
            (self.identity_pruned_through, self.identity_anchor),
        ];
        for (i, (position, anchor)) in positions.iter().enumerate() {
            if (*position == 0 && *anchor != genesis(self.history_id)?)
                || positions[..i]
                    .iter()
                    .any(|(p, a)| p == position && a != anchor)
            {
                return Err(Error::Corrupt("state anchors"));
            }
        }
        let mut out = STATE.to_vec();
        out.extend_from_slice(&1_u32.to_be_bytes());
        out.extend_from_slice(self.history_id.as_bytes());
        for (position, anchor) in positions {
            out.extend_from_slice(&position.to_be_bytes());
            out.extend_from_slice(&anchor);
        }
        out.extend_from_slice(self.clock_floor.encoded());
        for n in [
            self.payload_count,
            self.identity_count,
            self.binding_count,
            self.profile_count,
            self.ledger_charge,
        ] {
            if n > i64::MAX as u64 {
                return Err(Error::Corrupt("state counter range"));
            }
            out.extend_from_slice(&n.to_be_bytes());
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(bytes);
        c.magic(STATE)?;
        if c.u32()? != 1 {
            return Err(Error::Corrupt("state version"));
        }
        let s = Self {
            history_id: c.uuid()?,
            committed_sequence: c.u64()?,
            committed_prefix: c.fixed()?,
            payload_pruned_through: c.u64()?,
            payload_anchor: c.fixed()?,
            identity_pruned_through: c.u64()?,
            identity_anchor: c.fixed()?,
            clock_floor: c.time()?,
            payload_count: c.u64()?,
            identity_count: c.u64()?,
            binding_count: c.u64()?,
            profile_count: c.u64()?,
            ledger_charge: c.u64()?,
        };
        c.end()?;
        if s.encode()? != bytes {
            return Err(Error::Corrupt("state canonical bytes"));
        }
        Ok(s)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or(Error::Corrupt("codec offset"))?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::Corrupt("codec truncation"))?;
        self.offset = end;
        Ok(result)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Corrupt("codec width"))
    }
    fn magic(&mut self, expected: &[u8]) -> Result<(), Error> {
        if self.take(expected.len())? != expected {
            return Err(Error::Corrupt("codec domain"));
        }
        Ok(())
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn uuid(&mut self) -> Result<Uuid, Error> {
        let id = Uuid::from_bytes(self.fixed()?);
        non_nil(id)?;
        Ok(id)
    }
    fn blob(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let len = self.u32()? as usize;
        if len > maximum {
            return Err(Error::Corrupt("codec blob bound"));
        }
        self.take(len)
    }
    fn text(&mut self) -> Result<String, Error> {
        let bytes = self.blob(1024)?;
        let s = std::str::from_utf8(bytes).map_err(|_| Error::Corrupt("codec UTF-8"))?;
        checked_text(s)?;
        Ok(s.to_owned())
    }
    fn time(&mut self) -> Result<Timestamp, Error> {
        let bytes = self.take(30)?;
        let s = std::str::from_utf8(bytes).map_err(|_| Error::Corrupt("codec time"))?;
        let t = Timestamp::parse(s)?;
        if t.encoded() != bytes {
            return Err(Error::Corrupt("canonical time"));
        }
        Ok(t)
    }
    fn end(&self) -> Result<(), Error> {
        if self.offset != self.bytes.len() {
            Err(Error::Corrupt("codec trailing bytes"))
        } else {
            Ok(())
        }
    }
}
