use super::*;
use crate::object_manifest::{QueryObjectRef, data_key};
use signal_event::IngestEvent;
use std::time::Duration;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> OperationContext {
    OperationContext::new(Duration::from_secs(5))
}
fn rows() -> Result<Vec<StoredEvent>> {
    ["2026-07-10T19:30:00Z","2026-07-10T20:30:00Z"].into_iter().enumerate().map(|(i,t)| {
        let input: IngestEvent=serde_json::from_value(serde_json::json!({"timestamp":t,"source":{"type":"synthetic"},"message":"preserved","attributes":{"nested":{"values":[1,true,null]}}}))?;
        Ok(StoredEvent {sequence:7+i as u64*2,event:input.normalize(chrono::Utc::now())?})
    }).collect()
}
fn codec() -> Result<ObjectCodec> {
    Ok(ObjectCodec::new(
        StorageConfig::default(),
        ManifestLimits::default(),
    )?)
}
fn file(value: &PreparedQueryFile) -> QueryFile {
    let stream = Uuid::new_v4();
    QueryFile {
        date: value.date().into(),
        hour: value.hour(),
        rows: value.rows(),
        decoded_bytes: value.decoded_bytes(),
        object: QueryObjectRef {
            key: data_key(stream, value.date(), value.hour(), value.sha256()),
            version: Some("synthetic-v1".into()),
            etag: None,
            bytes: value.bytes().len() as u64,
            sha256: value.sha256(),
        },
    }
}
#[tokio::test]
async fn exact_prepared_partition_bytes_and_retained_result_admission() -> Result {
    let codec = codec()?;
    let original = rows()?;
    let batch = codec.prepare(&original, context()).await?;
    assert_eq!(
        (
            batch.first_sequence(),
            batch.last_sequence(),
            batch.event_count()
        ),
        (7, 9, 2)
    );
    assert_eq!(batch.files().len(), 2);
    assert_eq!(codec.metrics().depth, 1);
    assert_eq!(codec.metrics().running, 0);
    assert!(matches!(
        codec.prepare(&original, context()).await,
        Err(StorageError::Full)
    ));
    assert_eq!(codec.metrics().rejected, 1);
    let exports = batch
        .files()
        .iter()
        .map(|f| (file(f), f.bytes().to_vec()))
        .collect::<Vec<_>>();
    drop(batch);
    for ((file, body), expected) in exports.into_iter().zip(original) {
        for _ in 0..100 {
            let result = codec.inspect(&file, &body, 7, 9, context()).await?;
            assert_eq!(result.rows(), std::slice::from_ref(&expected));
            drop(result);
        }
    }
    codec.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn unpolled_error_reply_retains_admission_until_consumed() -> Result {
    let codec = codec()?;
    let mut ctx = context();
    let permit = codec.admit(&mut ctx)?;
    let (reply, receive) = oneshot::channel();
    codec
        .sender
        .lock()
        .map_err(|_| "sender lock")?
        .as_ref()
        .ok_or("sender")?
        .try_send(Command {
            work: Work::Encode(b"invalid internal wire".to_vec()),
            context: ctx,
            permit,
            reply,
        })
        .map_err(|_| "command admission")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while codec.metrics().processed == 0 || codec.metrics().running != 0 {
        if Instant::now() >= deadline {
            return Err("worker completion timeout".into());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(codec.metrics().depth, 1);
    assert!(matches!(
        codec.prepare(&rows()?, context()).await,
        Err(StorageError::Full)
    ));
    let completed = receive.await?;
    assert!(completed.result.is_err());
    assert_eq!(codec.metrics().depth, 1);
    drop(completed);
    assert_eq!(codec.metrics().depth, 0);
    let prepared = codec.prepare(&rows()?, context()).await?;
    drop(prepared);
    codec.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn checksum_rows_partition_sequence_and_decoded_budget_fail_closed() -> Result {
    let codec = codec()?;
    let batch = codec.prepare(&rows()?, context()).await?;
    let base = file(&batch.files()[0]);
    let bytes = batch.files()[0].bytes().to_vec();
    drop(batch);
    let mut wrong = bytes.clone();
    wrong[0] ^= 1;
    assert!(codec.inspect(&base, &wrong, 7, 9, context()).await.is_err());
    let mut variants = vec![];
    let mut f = base.clone();
    f.rows += 1;
    variants.push(f);
    let mut f = base.clone();
    f.hour += 1;
    variants.push(f);
    let mut f = base.clone();
    f.decoded_bytes -= 1;
    variants.push(f);
    for f in variants {
        assert!(codec.inspect(&f, &bytes, 7, 9, context()).await.is_err());
    }
    assert!(codec.inspect(&base, &bytes, 8, 9, context()).await.is_err());
    let mut unordered = rows()?;
    unordered.reverse();
    assert!(codec.prepare(&unordered, context()).await.is_err());
    assert_eq!(codec.metrics().rejected, 6);
    codec.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn quota_precancel_and_physical_timeout_do_not_refund_worker_or_reply() -> Result {
    let tiny = ObjectCodec::new(
        StorageConfig::default(),
        ManifestLimits {
            object_bytes: 1,
            batch_object_bytes: 1,
            ..Default::default()
        },
    )?;
    assert!(matches!(
        tiny.prepare(&rows()?, context()).await,
        Err(StorageError::Full)
    ));
    assert_eq!(tiny.metrics().rejected, 1);
    tiny.shutdown(context()).await?;
    let intake = ObjectCodec::new(
        StorageConfig {
            max_batch_bytes: 1,
            max_event_bytes: 1,
            ..Default::default()
        },
        ManifestLimits::default(),
    )?;
    let oversized = vec![0; 1024 * 1024 + 5];
    let reference = QueryFile {
        date: "2026-07-10".into(),
        hour: 19,
        rows: 1,
        decoded_bytes: 1,
        object: QueryObjectRef {
            key: data_key(Uuid::new_v4(), "2026-07-10", 19, [0; 32]),
            version: Some("synthetic".into()),
            etag: None,
            bytes: oversized.len() as u64,
            sha256: [0; 32],
        },
    };
    assert!(matches!(
        intake
            .inspect(&reference, &oversized, 7, 9, context())
            .await,
        Err(StorageError::Full)
    ));
    assert_eq!(intake.metrics().processed, 0);
    assert_eq!(intake.metrics().rejected, 1);
    intake.shutdown(context()).await?;
    let codec = Arc::new(codec()?);
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        codec.prepare(&rows()?, cancelled).await,
        Err(StorageError::Cancelled)
    ));
    let (entered, receive) = oneshot::channel();
    let (release, wait) = std::sync::mpsc::sync_channel(0);
    let child = codec.clone();
    let request = tokio::spawn(async move {
        let mut context = OperationContext::new(Duration::from_millis(50));
        let permit = child.admit(&mut context)?;
        child
            .request(Work::Pause(entered, wait), context, permit)
            .await
    });
    receive.await?;
    assert!(matches!(request.await?, Err(StorageError::Timeout)));
    assert_eq!(codec.metrics().running, 1);
    assert_eq!(codec.metrics().depth, 1);
    assert!(matches!(
        codec.prepare(&rows()?, context()).await,
        Err(StorageError::Full)
    ));
    assert!(matches!(
        codec
            .shutdown(OperationContext::new(Duration::from_millis(10)))
            .await,
        Err(StorageError::Timeout)
    ));
    release.send(())?;
    codec.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn borrowed_intake_bounds_depth_and_wire_without_transferring_caller_spare_capacity() -> Result
{
    let codec = codec()?;
    let mut values = rows()?;
    values.reserve_exact(4096);
    if let Some(message) = values[0].event.message.as_mut() {
        message.reserve_exact(1024 * 1024);
    }
    let batch = codec.prepare(&values, context()).await?;
    assert!(batch.files().iter().map(|f| f.bytes().len()).sum::<usize>() < 65536);
    drop(batch);
    let before = codec.metrics().processed;
    let mut deep = serde_json::Value::Null;
    for _ in 0..4096 {
        deep = serde_json::Value::Array(vec![deep]);
    }
    values[0].event.attributes.insert("deep".into(), deep);
    assert!(matches!(
        codec.prepare(&values, context()).await,
        Err(StorageError::Full)
    ));
    assert_eq!(codec.metrics().processed, before);
    assert_eq!(codec.metrics().rejected, 1);
    assert_eq!(codec.metrics().depth, 0);
    // Borrowed invalid input remains with its owner. Test dismantles it iteratively.
    let mut deep = values[0]
        .event
        .attributes
        .remove("deep")
        .ok_or("deep fixture")?;
    while let serde_json::Value::Array(mut array) = deep {
        deep = array.pop().ok_or("nested fixture")?;
    }
    codec.shutdown(context()).await?;
    Ok(())
}
#[tokio::test]
async fn decoded_metadata_budget_rejects_before_any_corrupt_page_header_is_examined() -> Result {
    let codec = codec()?;
    let batch = codec.prepare(&rows()?, context()).await?;
    let mut reference = file(&batch.files()[0]);
    let mut bytes = batch.files()[0].bytes().to_vec();
    drop(batch);
    let builder = ::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
        Bytes::copy_from_slice(&bytes),
    )?;
    let offset = builder.metadata().row_group(0).column(0).data_page_offset() as usize;
    bytes[offset] = 0xff;
    reference.object.sha256 = crate::object_manifest::sha256(&bytes);
    reference.decoded_bytes = 1;
    let result = codec.inspect(&reference, &bytes, 7, 9, context()).await;
    assert!(matches!(
        result,
        Err(StorageError::Corrupt("object decoded size"))
    ));
    codec.shutdown(context()).await?;
    let tiny = ObjectCodec::new(
        StorageConfig::default(),
        ManifestLimits {
            decoded_bytes: 1,
            ..Default::default()
        },
    )?;
    assert!(matches!(
        tiny.prepare(&rows()?, context()).await,
        Err(StorageError::Corrupt("object decoded size"))
    ));
    tiny.shutdown(context()).await?;
    Ok(())
}

#[tokio::test]
async fn untrusted_parquet_json_nodes_are_bounded_before_value_allocation() -> Result {
    let codec = codec()?;
    let mut original = rows()?;
    original.truncate(1);
    original[0].event.attributes.insert(
        "wide".into(),
        serde_json::Value::Array(vec![serde_json::Value::Null; 140000]),
    );
    let batch = crate::codec::encode(&original)?;
    let props = ::parquet::file::properties::WriterProperties::builder()
        .set_dictionary_enabled(false)
        .set_max_row_group_row_count(Some(128))
        .build();
    let mut writer =
        ::parquet::arrow::ArrowWriter::try_new(Vec::new(), crate::codec::schema(), Some(props))?;
    writer.write(&batch)?;
    let bytes = writer.into_inner()?;
    let reader = ::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
        Bytes::copy_from_slice(&bytes),
    )?;
    let decoded = reader
        .metadata()
        .row_groups()
        .iter()
        .flat_map(|g| g.columns())
        .map(|c| c.uncompressed_size() as u64)
        .sum();
    let sha = crate::object_manifest::sha256(&bytes);
    let scope = Uuid::new_v4();
    let reference = QueryFile {
        date: "2026-07-10".into(),
        hour: 19,
        rows: 1,
        decoded_bytes: decoded,
        object: QueryObjectRef {
            key: data_key(scope, "2026-07-10", 19, sha),
            version: Some("synthetic-wide-v1".into()),
            etag: None,
            bytes: bytes.len() as u64,
            sha256: sha,
        },
    };
    assert!(matches!(
        codec.inspect(&reference, &bytes, 7, 9, context()).await,
        Err(StorageError::Corrupt("object JSON bounds"))
    ));
    assert_eq!(codec.metrics().depth, 0);
    codec.shutdown(context()).await?;
    Ok(())
}
