//! Streaming filesystem acceptance gate, intentionally excluded from normal tests.
//! Run: cargo run --release -p signal-storage --example million-roundtrip

use chrono::{DateTime, Utc};
use serde_json::{Map, json};
use signal_event::{Resource, SCHEMA_VERSION, Severity, SignalEvent, Source};
use signal_storage::{OperationContext, ParquetStore, StorageConfig, StoredEvent};
use std::{
    error::Error,
    io,
    path::Path,
    time::{Duration, Instant},
};
use uuid::Uuid;

type GateResult<T> = Result<T, Box<dyn Error>>;
const DEFAULT_COUNT: u64 = 1_000_000;
const MAX_COUNT: u64 = 10_000_000;
const BATCH_ROWS: usize = 1_000;
const BATCH_BYTES: usize = 2 * 1024 * 1024;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::main]
async fn main() -> GateResult<()> {
    let mut arguments = std::env::args().skip(1);
    let count = arguments
        .next()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(DEFAULT_COUNT);
    if arguments.next().is_some() || count == 0 || count > MAX_COUNT {
        return Err(failure(
            "usage: million-roundtrip [count between 1 and 10000000]",
        ));
    }
    let directory = tempfile::tempdir()?;
    let config = StorageConfig {
        directory: directory.path().join("events"),
        max_batch_events: BATCH_ROWS,
        max_batch_bytes: BATCH_BYTES,
        max_event_bytes: 16 * 1024,
        max_disk_bytes: 4 * 1024 * 1024 * 1024,
        operation_timeout: OPERATION_TIMEOUT,
        ..StorageConfig::default()
    };
    let stream_id = Uuid::new_v4();
    println!("filesystem Parquet acceptance gate; excludes HTTP, WAL, query and rules");
    println!(
        "config: count={count} batch_rows={BATCH_ROWS} batch_bytes={BATCH_BYTES} compression={:?} disk_capacity={} file_capacity={} timeout_seconds={}",
        config.compression,
        config.max_disk_bytes,
        config.max_files,
        OPERATION_TIMEOUT.as_secs()
    );
    let store = ParquetStore::open(config.clone(), stream_id).await?;
    let write_start = Instant::now();
    let mut next_sequence = 1;
    while next_sequence <= count {
        let mut batch = Vec::with_capacity(BATCH_ROWS);
        let mut batch_bytes = 0;
        while batch.len() < BATCH_ROWS && next_sequence <= count {
            let event = generated_event(next_sequence)?;
            let bytes = serde_json::to_vec(&event)?.len();
            if bytes > config.max_event_bytes {
                return Err(failure(
                    "generated event exceeds configured event byte limit",
                ));
            }
            if bytes > BATCH_BYTES - batch_bytes {
                break;
            }
            batch_bytes += bytes;
            batch.push(StoredEvent {
                sequence: next_sequence,
                event,
            });
            next_sequence += 1;
        }
        if batch.is_empty() {
            return Err(failure(
                "generated event exceeds configured batch byte limit",
            ));
        }
        let first_sequence = next_sequence - batch.len() as u64;
        let rows = batch.len();
        let receipt = store
            .append(batch, context())
            .await
            .map_err(|error| failure(format!("append at sequence {first_sequence}: {error}")))?;
        if receipt.first_sequence != first_sequence
            || receipt.last_sequence != next_sequence - 1
            || receipt.new_count != rows
            || receipt.replay_count != 0
        {
            return Err(failure(format!(
                "unexpected append receipt at sequence {first_sequence}"
            )));
        }
    }
    store.flush(context()).await?;
    let write_elapsed = write_start.elapsed();
    let metrics = store.metrics();
    if metrics.persisted != count || metrics.high_water != count || metrics.replayed != 0 {
        return Err(failure(
            "persisted storage metrics do not match generated count",
        ));
    }
    store.shutdown(context()).await?;
    drop(store);

    // Reopen with the original stream identity; compare an independently regenerated
    // event for each sequence, rather than retaining the original event corpus.
    let reopen_start = Instant::now();
    let store = ParquetStore::open(config.clone(), stream_id).await?;
    let reopen_elapsed = reopen_start.elapsed();
    let read_start = Instant::now();
    let mut after_sequence = 0;
    loop {
        let batch = store
            .read_batch(after_sequence, BATCH_ROWS, BATCH_BYTES, context())
            .await
            .map_err(|error| failure(format!("read after sequence {after_sequence}: {error}")))?;
        if batch.is_empty() {
            break;
        }
        if batch.len() > BATCH_ROWS {
            return Err(failure("read batch exceeds configured row bound"));
        }
        let mut batch_bytes = 0;
        for row in batch {
            let expected_sequence = after_sequence + 1;
            if row.sequence != expected_sequence || row.sequence > count {
                return Err(failure(format!(
                    "missing, duplicated or unexpected sequence at {expected_sequence}"
                )));
            }
            let expected = generated_event(expected_sequence)?;
            if row.event.id != expected.id
                || row.event.timestamp != expected.timestamp
                || row.event.observed_at != expected.observed_at
            {
                return Err(failure(format!(
                    "ID or nanosecond timestamp mismatch at sequence {expected_sequence}"
                )));
            }
            if row.event != expected {
                return Err(failure(format!(
                    "canonical event mismatch at sequence {expected_sequence}"
                )));
            }
            batch_bytes += serde_json::to_vec(&row.event)?.len();
            if batch_bytes > BATCH_BYTES {
                return Err(failure("read batch exceeds configured byte bound"));
            }
            after_sequence = row.sequence;
        }
    }
    let read_elapsed = read_start.elapsed();
    if after_sequence != count {
        return Err(failure(format!(
            "expected {count} records, read {after_sequence}"
        )));
    }
    let (files, parquet_files, disk_bytes) = disk_usage(&config.directory)?;
    store.shutdown(context()).await?;
    println!(
        "verified: records={after_sequence} exact IDs/timestamps/canonical events; no missing or duplicated sequences"
    );
    println!(
        "disk: regular_files={files} parquet_files={parquet_files} bytes={disk_bytes} storage_metric_bytes={} storage_entries_including_directories={}",
        metrics.disk_bytes, metrics.files
    );
    println!(
        "write: seconds={:.3} events_per_second={:.1}",
        write_elapsed.as_secs_f64(),
        count as f64 / write_elapsed.as_secs_f64()
    );
    println!("reopen: seconds={:.3}", reopen_elapsed.as_secs_f64());
    println!(
        "read_and_verify: seconds={:.3} events_per_second={:.1}",
        read_elapsed.as_secs_f64(),
        count as f64 / read_elapsed.as_secs_f64()
    );
    println!(
        "temporary gate data cleaned after completion; timings are storage acceptance evidence, not an end-to-end benchmark"
    );
    directory.close()?;
    Ok(())
}

fn context() -> OperationContext {
    OperationContext::new(OPERATION_TIMEOUT)
}

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

fn generated_event(sequence: u64) -> GateResult<SignalEvent> {
    let timestamp = DateTime::<Utc>::from_timestamp(
        1_767_225_599 + (sequence / 10) as i64,
        (sequence % 1_000_000_000) as u32,
    )
    .ok_or_else(|| failure("generated timestamp is out of range"))?;
    let observed_at = timestamp + chrono::Duration::nanoseconds(987_654_321);
    let mut attributes = Map::new();
    attributes.insert("sequence".into(), json!(sequence));
    attributes.insert("nested".into(), json!({"user": {"name": format!("user-{}", sequence % 17), "enabled": sequence.is_multiple_of(2)}, "values": [null, true, {"maximum": u64::MAX, "minimum": i64::MIN}], "empty": {}}));
    attributes.insert("literal.key".into(), json!(["unicode-雪", sequence % 7]));
    let severity = match sequence % 6 {
        0 => Severity::Trace,
        1 => Severity::Debug,
        2 => Severity::Info,
        3 => Severity::Warn,
        4 => Severity::Error,
        _ => Severity::Critical,
    };
    Ok(SignalEvent {
        schema_version: SCHEMA_VERSION,
        id: Uuid::from_u128(
            (0x1234_5678_9abc_4def_8000_0000_0000_0000_u128) | u128::from(sequence),
        ),
        timestamp,
        observed_at,
        source: Source {
            source_type: "acceptance-gate".into(),
            name: (sequence.is_multiple_of(2)).then(|| "generated".into()),
        },
        severity,
        message: (!sequence.is_multiple_of(3)).then(|| format!("generated event {sequence}")),
        attributes,
        resource: (sequence.is_multiple_of(2)).then(|| Resource {
            kind: "test-resource".into(),
            id: format!("resource-{}", sequence % 11),
            account_id: Some("test-account".into()),
            region: Some("test-region".into()),
        }),
        trace_id: (sequence.is_multiple_of(2)).then(|| format!("{sequence:032x}")),
        span_id: (sequence.is_multiple_of(2)).then(|| format!("{sequence:016x}")),
        tags: if sequence.is_multiple_of(3) {
            Vec::new()
        } else {
            vec!["generated".into(), "roundtrip".into()]
        },
    })
}

// The tree depth is fixed by the date/hour partition layout; read_dir stays
// streaming and this walk never collects all file paths.
fn disk_usage(directory: &Path) -> GateResult<(u64, u64, u64)> {
    let mut files = 0;
    let mut parquet_files = 0;
    let mut bytes = 0;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            let (nested_files, nested_parquet, nested_bytes) = disk_usage(&entry.path())?;
            files += nested_files;
            parquet_files += nested_parquet;
            bytes += nested_bytes;
        } else if metadata.is_file() {
            files += 1;
            bytes += metadata.len();
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "parquet")
            {
                parquet_files += 1;
            }
        }
    }
    Ok((files, parquet_files, bytes))
}
