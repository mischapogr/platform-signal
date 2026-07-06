//! Version 1 events, independent of transport and async runtime.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let input: signal_event::IngestEvent = serde_json::from_str(r#"{
//!   "timestamp":"2026-10-06T12:00:00Z",
//!   "source":{"type":"application"}, "message":"hello"
//! }"#)?;
//! let event = input.normalize(chrono::Utc::now())?;
//! assert_eq!(event.schema_version, 1);
//! # Ok(()) }
//! ```

pub mod path;
pub use path::lookup_attribute_path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;

/// Serialized event contract version, independent of the crate version.
pub const SCHEMA_VERSION: u16 = 1;

/// Log severity; detection severity is a separate contract.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Critical,
}

/// Source identity within the version 1 event contract.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    #[serde(rename = "type")]
    pub source_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Optional generic resource identity within the version 1 event contract.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// Input defaults apply here; [`SignalEvent`] always has ID and observed time.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IngestEvent {
    #[serde(default = "schema_version")]
    pub schema_version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub timestamp: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_timestamp"
    )]
    pub observed_at: Option<DateTime<Utc>>,
    pub source: Source,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub attributes: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

const fn schema_version() -> u16 {
    SCHEMA_VERSION
}

impl IngestEvent {
    /// Fill input defaults exactly once and validate before admission.
    pub fn normalize(self, observed_at: DateTime<Utc>) -> Result<SignalEvent, ValidationError> {
        let event = SignalEvent {
            schema_version: self.schema_version,
            id: self.id.unwrap_or_else(Uuid::new_v4),
            timestamp: self.timestamp,
            observed_at: self.observed_at.unwrap_or(observed_at),
            source: self.source,
            severity: self.severity,
            message: self.message,
            attributes: self.attributes,
            resource: self.resource,
            trace_id: self.trace_id,
            span_id: self.span_id,
            tags: self.tags,
        };
        event.validate()?;
        Ok(event)
    }
}

/// Canonical versioned event. Deserialized/programmatically created values need validation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignalEvent {
    pub schema_version: u16,
    pub id: Uuid,
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub timestamp: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub observed_at: DateTime<Utc>,
    pub source: Source,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub attributes: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    pub tags: Vec<String>,
}

/// Semantic errors use field names only, never supplied values.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("unsupported event schema version")]
    UnsupportedVersion,
    #[error("event ID must not be nil")]
    NilId,
    #[error("{0} must not be blank")]
    BlankField(&'static str),
    #[error("a nonblank message or structured attributes are required")]
    MissingContent,
    #[error("{0} must be a nonzero hexadecimal correlation ID")]
    InvalidCorrelationId(&'static str),
    #[error("span_id requires trace_id")]
    SpanWithoutTrace,
}

impl SignalEvent {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedVersion);
        }
        if self.id.is_nil() {
            return Err(ValidationError::NilId);
        }
        nonblank(&self.source.source_type, "source.type")?;
        if let Some(name) = &self.source.name {
            nonblank(name, "source.name")?;
        }
        if self.message.as_ref().is_none_or(|m| m.trim().is_empty()) && self.attributes.is_empty() {
            return Err(ValidationError::MissingContent);
        }
        if let Some(resource) = &self.resource {
            nonblank(&resource.kind, "resource.kind")?;
            nonblank(&resource.id, "resource.id")?;
            if let Some(account) = &resource.account_id {
                nonblank(account, "resource.account_id")?;
            }
            if let Some(region) = &resource.region {
                nonblank(region, "resource.region")?;
            }
        }
        for tag in &self.tags {
            nonblank(tag, "tags")?;
        }
        if let Some(trace) = &self.trace_id {
            correlation(trace, 32, "trace_id")?;
        }
        if let Some(span) = &self.span_id {
            correlation(span, 16, "span_id")?;
            if self.trace_id.is_none() {
                return Err(ValidationError::SpanWithoutTrace);
            }
        }
        Ok(())
    }
}

fn nonblank(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        Err(ValidationError::BlankField(field))
    } else {
        Ok(())
    }
}

fn correlation(value: &str, length: usize, field: &'static str) -> Result<(), ValidationError> {
    if value.len() != length
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
        || value.bytes().all(|b| b == b'0')
    {
        Err(ValidationError::InvalidCorrelationId(field))
    } else {
        Ok(())
    }
}

fn deserialize_timestamp<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<DateTime<Utc>, D::Error> {
    let text = String::deserialize(deserializer)?;
    DateTime::parse_from_rfc3339(&text)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| serde::de::Error::custom("timestamp must be RFC3339"))
}
fn deserialize_optional_timestamp<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<DateTime<Utc>>, D::Error> {
    let text = Option::<String>::deserialize(deserializer)?;
    text.map(|text| {
        DateTime::parse_from_rfc3339(&text)
            .map(|time| time.with_timezone(&Utc))
            .map_err(|_| serde::de::Error::custom("observed_at must be RFC3339"))
    })
    .transpose()
}
