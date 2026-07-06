//! Version 1 storage rows. JSON is authoritative; typed projections are checked on read.

use std::sync::Arc;

use arrow::array::{
    Array, ArrayRef, Int64Array, StringArray, UInt16Array, UInt32Array, UInt64Array,
};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use signal_event::Severity;

use crate::{StorageError, StoredEvent};

/// Independent from the canonical event schema version.
pub const STORAGE_SCHEMA_VERSION: u16 = 1;

/// Lossless timestamps use RFC3339 plus seconds/nanos for subsequent query comparisons.
pub fn schema() -> Arc<Schema> {
    use DataType::{Int64, UInt16, UInt32, UInt64, Utf8};
    Arc::new(Schema::new(vec![
        Field::new("storage_schema_version", UInt16, false),
        Field::new("wal_sequence", UInt64, false),
        Field::new("event_json", Utf8, false),
        Field::new("id", Utf8, false),
        Field::new("timestamp", Utf8, false),
        Field::new("observed_at", Utf8, false),
        Field::new("timestamp_seconds", Int64, false),
        Field::new("timestamp_nanos", UInt32, false),
        Field::new("source_type", Utf8, false),
        Field::new("source_name", Utf8, true),
        Field::new("severity", Utf8, false),
        Field::new("message", Utf8, true),
        Field::new("attributes_json", Utf8, false),
        Field::new("resource_kind", Utf8, true),
        Field::new("resource_id", Utf8, true),
        Field::new("resource_account_id", Utf8, true),
        Field::new("resource_region", Utf8, true),
        Field::new("trace_id", Utf8, true),
        Field::new("span_id", Utf8, true),
        Field::new("tags_json", Utf8, false),
    ]))
}

/// Encode one caller-bounded batch without flattening JSON attributes or optional fields.
pub fn encode(events: &[StoredEvent]) -> Result<RecordBatch, StorageError> {
    let mut json = Vec::with_capacity(events.len());
    let mut ids = Vec::with_capacity(events.len());
    let mut timestamps = Vec::with_capacity(events.len());
    let mut observed = Vec::with_capacity(events.len());
    let mut attributes = Vec::with_capacity(events.len());
    let mut tags = Vec::with_capacity(events.len());
    for stored in events {
        let event = &stored.event;
        event.validate().map_err(|_| StorageError::InvalidBatch)?;
        let canonical = serde_json::to_string(event).map_err(|_| StorageError::InvalidBatch)?;
        // Programmatically created values must survive the existing event wire contract too.
        let restored: signal_event::SignalEvent =
            serde_json::from_str(&canonical).map_err(|_| StorageError::InvalidBatch)?;
        if &restored != event {
            return Err(StorageError::InvalidBatch);
        }
        json.push(canonical);
        ids.push(event.id.to_string());
        timestamps.push(event.timestamp.to_rfc3339());
        observed.push(event.observed_at.to_rfc3339());
        attributes.push(
            serde_json::to_string(&event.attributes).map_err(|_| StorageError::InvalidBatch)?,
        );
        tags.push(serde_json::to_string(&event.tags).map_err(|_| StorageError::InvalidBatch)?);
    }
    let strings = |values: Vec<String>| -> ArrayRef { Arc::new(StringArray::from(values)) };
    let optional = |values: Vec<Option<&str>>| -> ArrayRef { Arc::new(StringArray::from(values)) };
    let columns: Vec<ArrayRef> = vec![
        Arc::new(UInt16Array::from(vec![
            STORAGE_SCHEMA_VERSION;
            events.len()
        ])),
        Arc::new(UInt64Array::from(
            events.iter().map(|s| s.sequence).collect::<Vec<_>>(),
        )),
        strings(json),
        strings(ids),
        strings(timestamps),
        strings(observed),
        Arc::new(Int64Array::from(
            events
                .iter()
                .map(|s| s.event.timestamp.timestamp())
                .collect::<Vec<_>>(),
        )),
        Arc::new(UInt32Array::from(
            events
                .iter()
                .map(|s| s.event.timestamp.timestamp_subsec_nanos())
                .collect::<Vec<_>>(),
        )),
        optional(
            events
                .iter()
                .map(|s| Some(s.event.source.source_type.as_str()))
                .collect(),
        ),
        optional(
            events
                .iter()
                .map(|s| s.event.source.name.as_deref())
                .collect(),
        ),
        optional(
            events
                .iter()
                .map(|s| Some(severity(s.event.severity)))
                .collect(),
        ),
        optional(events.iter().map(|s| s.event.message.as_deref()).collect()),
        strings(attributes),
        optional(
            events
                .iter()
                .map(|s| s.event.resource.as_ref().map(|r| r.kind.as_str()))
                .collect(),
        ),
        optional(
            events
                .iter()
                .map(|s| s.event.resource.as_ref().map(|r| r.id.as_str()))
                .collect(),
        ),
        optional(
            events
                .iter()
                .map(|s| {
                    s.event
                        .resource
                        .as_ref()
                        .and_then(|r| r.account_id.as_deref())
                })
                .collect(),
        ),
        optional(
            events
                .iter()
                .map(|s| s.event.resource.as_ref().and_then(|r| r.region.as_deref()))
                .collect(),
        ),
        optional(events.iter().map(|s| s.event.trace_id.as_deref()).collect()),
        optional(events.iter().map(|s| s.event.span_id.as_deref()).collect()),
        strings(tags),
    ];
    RecordBatch::try_new(schema(), columns).map_err(|_| StorageError::InvalidBatch)
}

/// Fail closed on malformed rows, unsupported versions and stale/tampered projections.
pub fn decode(batch: &RecordBatch) -> Result<Vec<StoredEvent>, StorageError> {
    if batch.schema().as_ref() != schema().as_ref() {
        return Err(StorageError::Corrupt("invalid storage batch"));
    }
    for (field, column) in batch.schema().fields().iter().zip(batch.columns()) {
        if !field.is_nullable() && column.null_count() != 0 {
            return Err(StorageError::Corrupt("invalid storage batch"));
        }
    }
    let versions = typed::<UInt16Array>(batch, 0)?;
    let sequences = typed::<UInt64Array>(batch, 1)?;
    let json = typed::<StringArray>(batch, 2)?;
    let mut events = Vec::with_capacity(batch.num_rows());
    for row in 0..batch.num_rows() {
        if versions.value(row) != STORAGE_SCHEMA_VERSION {
            return Err(StorageError::Corrupt("invalid storage batch"));
        }
        let event: signal_event::SignalEvent = serde_json::from_str(json.value(row))
            .map_err(|_| StorageError::Corrupt("invalid storage batch"))?;
        event
            .validate()
            .map_err(|_| StorageError::Corrupt("invalid storage batch"))?;
        events.push(StoredEvent {
            sequence: sequences.value(row),
            event,
        });
    }
    let expected = encode(&events).map_err(|_| StorageError::Corrupt("invalid storage batch"))?;
    if expected
        .columns()
        .iter()
        .zip(batch.columns())
        .any(|(left, right)| left.to_data() != right.to_data())
    {
        return Err(StorageError::Corrupt("invalid storage batch"));
    }
    Ok(events)
}

fn typed<T: 'static>(batch: &RecordBatch, column: usize) -> Result<&T, StorageError> {
    batch
        .column(column)
        .as_any()
        .downcast_ref::<T>()
        .ok_or(StorageError::Corrupt("invalid storage batch"))
}

fn severity(value: Severity) -> &'static str {
    match value {
        Severity::Trace => "trace",
        Severity::Debug => "debug",
        Severity::Info => "info",
        Severity::Warn => "warn",
        Severity::Error => "error",
        Severity::Critical => "critical",
    }
}
