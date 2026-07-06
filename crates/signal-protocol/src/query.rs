//! Version 1 event-query contracts. The public HTTP query syntax is URL parameters.

use std::collections::HashSet;

use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use signal_event::{Severity, SignalEvent};
use thiserror::Error;

use crate::API_SCHEMA_VERSION;

/// Bounds apply to both URL input and programmatically constructed queries.
pub const MAX_QUERY_BYTES: usize = 16 * 1024;
pub const MAX_ATTRIBUTE_FILTERS: usize = 32;
pub const MAX_ATTRIBUTE_PATH_BYTES: usize = 512;
pub const MAX_ATTRIBUTE_PATH_DEPTH: usize = 16;
pub const MAX_FILTER_BYTES: usize = 4096;
const MAX_ATTRIBUTE_VALUE_DEPTH: usize = 32;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventQuery {
    pub schema_version: u16,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub contains: Option<String>,
    pub severity: Option<Severity>,
    /// Compatibility alias for source_type.
    pub source: Option<String>,
    /// Compatibility alias for resource_id.
    pub resource: Option<String>,
    #[serde(default)]
    pub source_type: Option<String>,
    #[serde(default)]
    pub source_name: Option<String>,
    #[serde(default)]
    pub resource_kind: Option<String>,
    #[serde(default)]
    pub resource_id: Option<String>,
    pub account: Option<String>,
    pub attributes: Vec<AttributeFilter>,
    pub limit: usize,
    pub order: QueryOrder,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttributeFilter {
    /// Relative path inside attributes. Dotted map keys take precedence over traversal.
    pub path: String,
    pub value: Value,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryOrder {
    #[default]
    Asc,
    Desc,
}

impl Default for EventQuery {
    fn default() -> Self {
        Self {
            schema_version: API_SCHEMA_VERSION,
            from: None,
            to: None,
            contains: None,
            severity: None,
            source: None,
            resource: None,
            source_type: None,
            source_name: None,
            resource_kind: None,
            resource_id: None,
            account: None,
            attributes: Vec::new(),
            limit: 100,
            order: QueryOrder::Asc,
        }
    }
}

/// Safe validation diagnostics never interpolate caller-supplied keys or values.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum QueryValidationError {
    #[error("query exceeds the supported complexity limits")]
    TooComplex,
    #[error("query filter exceeds the supported size limit")]
    InvalidFilter,
    #[error("query encoding is invalid")]
    InvalidEncoding,
    #[error("query parameter is unknown")]
    UnknownParameter,
    #[error("query parameter is repeated")]
    DuplicateParameter,
    #[error("query timestamp must be full RFC3339 with nanosecond precision or less")]
    InvalidTimestamp,
    #[error("query time range must have from before to")]
    InvalidTimeRange,
    #[error("query severity is invalid")]
    InvalidSeverity,
    #[error("query order must be asc or desc")]
    InvalidOrder,
    #[error("query limit must be positive and within the configured maximum")]
    InvalidLimit,
    #[error("query alias conflicts with its explicit field")]
    ConflictingAlias,
    #[error("attribute path must have nonempty dot-separated components")]
    InvalidAttributePath,
    #[error("unsupported query schema version")]
    UnsupportedVersion,
}

impl EventQuery {
    pub fn source_type_filter(&self) -> Option<&str> {
        self.source_type.as_deref().or(self.source.as_deref())
    }

    pub fn resource_id_filter(&self) -> Option<&str> {
        self.resource_id.as_deref().or(self.resource.as_deref())
    }

    /// Also validate programmatically constructed queries before opening data files.
    pub fn validate(&self, max_limit: usize) -> Result<(), QueryValidationError> {
        if self.schema_version != API_SCHEMA_VERSION {
            return Err(QueryValidationError::UnsupportedVersion);
        }
        if self.limit == 0 || self.limit > max_limit {
            return Err(QueryValidationError::InvalidLimit);
        }
        if self.from.zip(self.to).is_some_and(|(from, to)| from >= to) {
            return Err(QueryValidationError::InvalidTimeRange);
        }
        if self
            .from
            .into_iter()
            .chain(self.to)
            .any(|t| !(0..=9999).contains(&t.year()))
        {
            return Err(QueryValidationError::InvalidTimestamp);
        }
        for (alias, explicit) in [
            (&self.source, &self.source_type),
            (&self.resource, &self.resource_id),
        ] {
            if alias
                .as_ref()
                .zip(explicit.as_ref())
                .is_some_and(|(a, b)| a != b)
            {
                return Err(QueryValidationError::ConflictingAlias);
            }
        }
        if self.attributes.len() > MAX_ATTRIBUTE_FILTERS {
            return Err(QueryValidationError::TooComplex);
        }
        let mut total_bytes = 0;
        for value in [
            &self.contains,
            &self.source,
            &self.resource,
            &self.source_type,
            &self.source_name,
            &self.resource_kind,
            &self.resource_id,
            &self.account,
        ]
        .into_iter()
        .flatten()
        {
            if value.len() > MAX_FILTER_BYTES {
                return Err(QueryValidationError::InvalidFilter);
            }
            total_bytes += value.len();
        }
        let mut paths = HashSet::new();
        for attribute in &self.attributes {
            validate_path(&attribute.path)?;
            let mut nodes = 0;
            validate_value_shape(&attribute.value, 0, &mut nodes)?;
            let mut counter = BoundedJsonCounter { bytes: 0 };
            serde_json::to_writer(&mut counter, &attribute.value)
                .map_err(|_| QueryValidationError::InvalidFilter)?;
            total_bytes += attribute.path.len() + counter.bytes;
            if total_bytes > MAX_QUERY_BYTES {
                return Err(QueryValidationError::TooComplex);
            }
            if !paths.insert(attribute.path.as_str()) {
                return Err(QueryValidationError::DuplicateParameter);
            }
        }
        if total_bytes > MAX_QUERY_BYTES {
            return Err(QueryValidationError::TooComplex);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EventQueryResponse {
    pub schema_version: u16,
    pub events: Vec<SignalEvent>,
    pub metadata: QueryMetadata,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryMetadata {
    pub duration_ms: u64,
    pub scanned_files: usize,
    pub candidate_partitions: usize,
}

/// Parse application/x-www-form-urlencoded parameters, preserving JSON attribute types.
/// Time bounds use UTC [from, to). Unknown and repeated parameters fail closed.
pub fn parse_event_query(raw: &str, max_limit: usize) -> Result<EventQuery, QueryValidationError> {
    if raw.len() > MAX_QUERY_BYTES {
        return Err(QueryValidationError::TooComplex);
    }
    validate_encoding(raw)?;
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(raw).map_err(|_| QueryValidationError::InvalidEncoding)?;
    let mut query = EventQuery {
        limit: 100.min(max_limit),
        ..Default::default()
    };
    let mut seen = HashSet::new();
    for (key, value) in pairs {
        if !seen.insert(key.clone()) {
            return Err(QueryValidationError::DuplicateParameter);
        }
        match key.as_str() {
            "from" => query.from = Some(parse_timestamp(&value)?),
            "to" => query.to = Some(parse_timestamp(&value)?),
            "contains" => query.contains = Some(value),
            "severity" => {
                query.severity = Some(match value.as_str() {
                    "trace" => Severity::Trace,
                    "debug" => Severity::Debug,
                    "info" => Severity::Info,
                    "warn" => Severity::Warn,
                    "error" => Severity::Error,
                    "critical" => Severity::Critical,
                    _ => return Err(QueryValidationError::InvalidSeverity),
                })
            }
            "source" => query.source = Some(value),
            "resource" => query.resource = Some(value),
            "source_type" => query.source_type = Some(value),
            "source_name" => query.source_name = Some(value),
            "resource_kind" => query.resource_kind = Some(value),
            "resource_id" => query.resource_id = Some(value),
            "account" => query.account = Some(value),
            "limit" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(QueryValidationError::InvalidLimit);
                }
                query.limit = value
                    .parse()
                    .map_err(|_| QueryValidationError::InvalidLimit)?;
            }
            "order" => {
                query.order = match value.as_str() {
                    "asc" => QueryOrder::Asc,
                    "desc" => QueryOrder::Desc,
                    _ => return Err(QueryValidationError::InvalidOrder),
                }
            }
            _ => {
                let path = key
                    .strip_prefix("attribute.")
                    .ok_or(QueryValidationError::UnknownParameter)?;
                validate_path(path)?;
                if query.attributes.len() >= MAX_ATTRIBUTE_FILTERS {
                    return Err(QueryValidationError::TooComplex);
                }
                if value.len() > MAX_FILTER_BYTES {
                    return Err(QueryValidationError::InvalidFilter);
                }
                query.attributes.push(AttributeFilter {
                    path: path.to_owned(),
                    value: serde_json::from_str(&value).unwrap_or(Value::String(value)),
                });
            }
        }
    }
    query.validate(max_limit)?;
    Ok(query)
}

fn validate_path(path: &str) -> Result<(), QueryValidationError> {
    if path.len() > MAX_ATTRIBUTE_PATH_BYTES || path.split('.').count() > MAX_ATTRIBUTE_PATH_DEPTH {
        return Err(QueryValidationError::TooComplex);
    }
    if path.split('.').any(str::is_empty) {
        return Err(QueryValidationError::InvalidAttributePath);
    }
    Ok(())
}

/// Parse a bounded full RFC3339 query timestamp using the event-query wire contract.
pub fn parse_query_timestamp(value: &str) -> Result<DateTime<Utc>, QueryValidationError> {
    if value.len() > 64 {
        return Err(QueryValidationError::InvalidTimestamp);
    }
    parse_timestamp(value)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, QueryValidationError> {
    let bytes = value.as_bytes();
    // Chrono accepts some relaxed ISO8601 spellings. The API requires the full RFC3339 shape.
    if bytes.len() < 20
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(QueryValidationError::InvalidTimestamp);
    }
    let mut zone = 19;
    if bytes.get(zone) == Some(&b'.') {
        zone += 1;
        let start = zone;
        while bytes.get(zone).is_some_and(u8::is_ascii_digit) {
            zone += 1;
        }
        if zone == start || zone - start > 9 {
            return Err(QueryValidationError::InvalidTimestamp);
        }
    }
    let valid_zone = match &bytes[zone..] {
        [b'Z' | b'z'] => true,
        [b'+' | b'-', a, b, b':', c, d] => [a, b, c, d].iter().all(|b| b.is_ascii_digit()),
        _ => false,
    };
    if !valid_zone {
        return Err(QueryValidationError::InvalidTimestamp);
    }
    let timestamp = DateTime::parse_from_rfc3339(value)
        .map_err(|_| QueryValidationError::InvalidTimestamp)?
        .with_timezone(&Utc);
    if !(0..=9999).contains(&timestamp.year()) {
        return Err(QueryValidationError::InvalidTimestamp);
    }
    Ok(timestamp)
}

fn validate_encoding(raw: &str) -> Result<(), QueryValidationError> {
    // URL decoders can replace malformed UTF-8; reject it instead of changing equality values.
    for component in raw.split(['&', '=']) {
        let mut decoded = Vec::with_capacity(component.len());
        let mut bytes = component.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let a = bytes
                    .next()
                    .and_then(hex_digit)
                    .ok_or(QueryValidationError::InvalidEncoding)?;
                let b = bytes
                    .next()
                    .and_then(hex_digit)
                    .ok_or(QueryValidationError::InvalidEncoding)?;
                decoded.push(a * 16 + b);
            } else {
                decoded.push(byte);
            }
        }
        std::str::from_utf8(&decoded).map_err(|_| QueryValidationError::InvalidEncoding)?;
    }
    Ok(())
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// Count serialized bytes without creating another copy of arbitrary caller values.
struct BoundedJsonCounter {
    bytes: usize,
}

impl std::io::Write for BoundedJsonCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_FILTER_BYTES.saturating_sub(self.bytes) {
            return Err(std::io::Error::other("filter size limit"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_value_shape(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), QueryValidationError> {
    *nodes += 1;
    if depth > MAX_ATTRIBUTE_VALUE_DEPTH || *nodes > MAX_FILTER_BYTES {
        return Err(QueryValidationError::TooComplex);
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_value_shape(value, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_value_shape(value, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}
