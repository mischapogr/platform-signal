use std::sync::Arc;

use arrow::array::{ArrayRef, StringArray, UInt16Array};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use chrono::{DateTime, Utc};
use signal_event::{IngestEvent, Resource};
use signal_storage::{StorageError, StoredEvent, codec};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn sample(sequence: u64) -> Result<StoredEvent> {
    let input: IngestEvent = serde_json::from_str(
        r#"{
        "timestamp":"1969-12-31T23:59:59.123456789Z",
        "source":{"type":"application","name":"collector"},
        "attributes":{"nested":{"array":[null,true,{"huge":1844674407370955161600001,"negative":-1844674407370955161600001,"fraction":1.234567890123456789}]},"empty":{}},
        "trace_id":"0123456789abcdef0123456789abcdef",
        "span_id":"0123456789abcdef", "tags":["one","two"]
    }"#,
    )?;
    Ok(StoredEvent {
        sequence,
        event: input.normalize(Utc::now())?,
    })
}

#[test]
fn roundtrip_preserves_nested_numbers_optionals_and_negative_nanosecond_time() -> Result {
    let mut first = sample(1)?;
    first.event.resource = Some(Resource {
        kind: "host".into(),
        id: "host-one".into(),
        account_id: Some("account".into()),
        region: Some("region".into()),
    });
    let mut second = sample(2)?;
    second.event.source.name = None;
    second.event.trace_id = None;
    second.event.span_id = None;
    second.event.message = Some(String::new());
    second.event.tags.clear();
    let mut third = sample(3)?;
    third.event.resource = Some(Resource {
        kind: "host".into(),
        id: "host-two".into(),
        account_id: None,
        region: None,
    });
    third.event.message = Some("message".into());
    let events = vec![first, second, third];
    let decoded = codec::decode(&codec::encode(&events)?)?;
    assert_eq!(events, decoded);
    assert_eq!(
        serde_json::to_string(&events[0].event.attributes)?,
        serde_json::to_string(&decoded[0].event.attributes)?
    );
    Ok(())
}

#[test]
fn roundtrip_rfc3339_boundary_years_and_leap_seconds() -> Result {
    for timestamp in [
        "0000-01-01T00:00:00.000000001Z",
        "9999-12-31T23:59:59.999999999Z",
        "2016-12-31T23:59:60.123456789Z",
    ] {
        let mut event = sample(1)?;
        event.event.timestamp = DateTime::parse_from_rfc3339(timestamp)?.with_timezone(&Utc);
        event.event.observed_at = event.event.timestamp;
        assert_eq!(
            codec::decode(&codec::encode(&[event.clone()])?)?,
            vec![event]
        );
    }
    Ok(())
}

#[test]
fn extended_chrono_years_fail_before_persistence_if_event_wire_rejects_them() -> Result {
    for timestamp in [DateTime::<Utc>::MIN_UTC, DateTime::<Utc>::MAX_UTC] {
        let mut stored = sample(1)?;
        stored.event.timestamp = timestamp;
        let wire = serde_json::to_string(&stored.event)?;
        assert!(serde_json::from_str::<signal_event::SignalEvent>(&wire).is_err());
        assert!(matches!(
            codec::encode(&[stored]),
            Err(StorageError::InvalidBatch)
        ));
    }
    Ok(())
}

#[test]
fn empty_batch_has_schema_and_roundtrips() -> Result {
    let batch = codec::encode(&[])?;
    assert_eq!(batch.num_rows(), 0);
    assert_eq!(batch.schema(), codec::schema());
    assert!(codec::decode(&batch)?.is_empty());
    Ok(())
}

fn replace(batch: &RecordBatch, column: usize, replacement: ArrayRef) -> Result<RecordBatch> {
    let mut columns = batch.columns().to_vec();
    columns[column] = replacement;
    Ok(RecordBatch::try_new(batch.schema(), columns)?)
}

#[test]
fn corrupt_rows_versions_json_and_projections_are_rejected() -> Result {
    let batch = codec::encode(&[sample(1)?])?;
    for bad in [
        replace(&batch, 0, Arc::new(UInt16Array::from(vec![2])))?,
        replace(
            &batch,
            2,
            Arc::new(StringArray::from(vec!["private secret malformed payload"])),
        )?,
        replace(&batch, 3, Arc::new(StringArray::from(vec!["wrong-id"])))?,
        replace(&batch, 11, Arc::new(StringArray::from(vec![Some("")])))?,
    ] {
        let error = codec::decode(&bad).err().ok_or("expected corruption")?;
        assert!(matches!(error, StorageError::Corrupt(_)));
        assert!(!error.to_string().contains("private secret"));
    }
    let mut event = sample(1)?;
    event.event.schema_version = 2;
    let bad = replace(
        &batch,
        2,
        Arc::new(StringArray::from(vec![serde_json::to_string(
            &event.event,
        )?])),
    )?;
    assert!(matches!(codec::decode(&bad), Err(StorageError::Corrupt(_))));
    Ok(())
}

#[test]
fn malformed_schema_and_required_null_are_rejected() -> Result {
    let batch = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new("wrong", DataType::Utf8, true)])),
        vec![Arc::new(StringArray::from(vec![None::<&str>]))],
    )?;
    assert!(matches!(
        codec::decode(&batch),
        Err(StorageError::Corrupt(_))
    ));
    // Arrow rejects required nulls on batch construction, so loosening schema must fail decode.
    let correct = codec::encode(&[sample(1)?])?;
    let mut fields: Vec<Field> = correct
        .schema()
        .fields()
        .iter()
        .map(|field| field.as_ref().clone())
        .collect();
    fields[2] = Field::new("event_json", DataType::Utf8, true);
    let mut columns = correct.columns().to_vec();
    columns[2] = Arc::new(StringArray::from(vec![None::<&str>]));
    let nullable = RecordBatch::try_new(Arc::new(Schema::new(fields)), columns)?;
    assert!(matches!(
        codec::decode(&nullable),
        Err(StorageError::Corrupt(_))
    ));
    Ok(())
}

#[test]
fn invalid_canonical_events_cannot_be_encoded() -> Result {
    let mut event = sample(1)?;
    event.event.source.source_type.clear();
    assert!(matches!(
        codec::encode(&[event]),
        Err(StorageError::InvalidBatch)
    ));
    Ok(())
}
