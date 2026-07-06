//! Real filesystem mutation and checkpoint properties; seed 0x51a10e04.
use signal_buffer::{BufferConfig, BufferError, DurableBuffer};
use signal_event::{IngestEvent, SignalEvent};
use signal_protocol::EventSink;
use std::{fs, path::Path, time::Duration};
use tempfile::TempDir;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn config(directory: &TempDir) -> BufferConfig {
    BufferConfig {
        directory: directory.path().join("wal"),
        max_events: 8,
        max_memory_bytes: 16384,
        max_record_bytes: 2048,
        segment_bytes: 8192,
        max_wal_bytes: 32768,
        max_segments: 8,
        operation_timeout: Duration::from_secs(2),
        ..BufferConfig::default()
    }
}
fn event(index: usize) -> Result<SignalEvent> {
    Ok(serde_json::from_value::<IngestEvent>(
        serde_json::json!({"timestamp":"2026-10-06T12:00:00Z",
        "source":{"type":"property"},"message":format!("event-{index}"),
        "attributes":{"number":184467440737095516160000u128,"nested":[null,true]}}),
    )?
    .normalize("2026-10-06T12:00:01Z".parse()?)?)
}
fn segment(config: &BufferConfig) -> Result<std::path::PathBuf> {
    let mut paths = fs::read_dir(&config.directory)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| path.extension().is_some_and(|extension| extension == "wal"));
    assert_eq!(paths.len(), 1);
    paths.pop().ok_or_else(|| "missing segment".into())
}
fn copy_fixture(source: &Path, target: &Path) -> Result {
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        fs::copy(entry.path(), target.join(entry.file_name()))?;
    }
    Ok(())
}
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[tokio::test]
async fn seeded_crc_and_checkpoint_mutations_fail_without_destroying_evidence() -> Result {
    let original = TempDir::new()?;
    let baseline = config(&original);
    let buffer = DurableBuffer::open(baseline.clone()).await?;
    let first = event(0)?;
    let payload = serde_json::to_vec(&first)?.len();
    buffer.admit(first).await?;
    buffer.admit(event(1)?).await?;
    buffer.admit(event(2)?).await?;
    buffer.shutdown().await?;
    let mut seed = 0x51a10e04;
    // Header bytes plus 64 seeded positions in the first record's actual payload.
    let positions = (0..40)
        .chain((0..64).map(|_| 40 + next(&mut seed) as usize % payload))
        .collect::<Vec<_>>();
    println!("CAMPAIGN wal_record_mutations={}", positions.len());
    for offset in positions {
        let damaged = TempDir::new()?;
        let candidate = config(&damaged);
        copy_fixture(&baseline.directory, &candidate.directory)?;
        let path = segment(&candidate)?;
        let mut bytes = fs::read(&path)?;
        assert!(bytes.len() <= 65536);
        bytes[offset] ^= 1;
        fs::write(&path, &bytes)?;
        assert!(
            matches!(
                DurableBuffer::open(candidate).await,
                Err(BufferError::Corrupt(_))
            ),
            "offset {offset}"
        );
        assert_eq!(
            fs::read(&path)?,
            bytes,
            "recovery must not truncate corrupt interior evidence"
        );
    }
    let checkpoint = fs::read(baseline.directory.join("checkpoint"))?;
    println!("CAMPAIGN wal_checkpoint_mutations={}", checkpoint.len());
    for offset in 0..checkpoint.len() {
        let damaged = TempDir::new()?;
        let candidate = config(&damaged);
        copy_fixture(&baseline.directory, &candidate.directory)?;
        let path = candidate.directory.join("checkpoint");
        let mut bytes = checkpoint.clone();
        bytes[offset] ^= 1;
        fs::write(&path, &bytes)?;
        assert!(matches!(
            DurableBuffer::open(candidate).await,
            Err(BufferError::Corrupt(_))
        ));
        assert_eq!(fs::read(path)?, bytes);
    }
    Ok(())
}

#[tokio::test]
async fn every_final_record_cut_preserves_complete_prefix_and_reuses_sequence() -> Result {
    let original = TempDir::new()?;
    let baseline = config(&original);
    let buffer = DurableBuffer::open(baseline.clone()).await?;
    let expected = [event(0)?, event(1)?];
    for event in &expected {
        buffer.admit(event.clone()).await?;
    }
    let path = segment(&baseline)?;
    let prefix = fs::metadata(&path)?.len();
    buffer.admit(event(2)?).await?;
    buffer.shutdown().await?;
    let bytes = fs::read(&path)?;
    let tail = bytes.len() - prefix as usize;
    assert!(bytes.len() <= 65536);
    // Enumerate every incomplete final-frame position, including partial record headers.
    println!("CAMPAIGN wal_tail_cuts={tail}");
    for cut in 0..tail {
        let truncated = TempDir::new()?;
        let candidate = config(&truncated);
        copy_fixture(&baseline.directory, &candidate.directory)?;
        let path = segment(&candidate)?;
        fs::write(&path, &bytes[..prefix as usize + cut])?;
        let replay = DurableBuffer::open(candidate).await?;
        let records = replay.read_batch(8, 16384).await?;
        assert_eq!(
            records
                .iter()
                .map(|record| &record.event)
                .collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>(),
            "cut {cut}"
        );
        assert_eq!(fs::metadata(path)?.len(), prefix);
        assert_eq!(replay.snapshot().checkpoint, 0);
        let replacement = event(3)?;
        replay.admit(replacement.clone()).await?;
        let replaced = replay.read_batch(8, 16384).await?;
        assert_eq!(replaced[2].sequence, 3);
        assert_eq!(replaced[2].event, replacement);
        replay.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ack_prefix_replay_and_reclaim_match_durable_sequence_model() -> Result {
    for ack in 0..=8 {
        let directory = TempDir::new()?;
        let config = config(&directory);
        let events = (0..8).map(event).collect::<Result<Vec<_>>>()?;
        let buffer = DurableBuffer::open(config.clone()).await?;
        for event in &events {
            buffer.admit(event.clone()).await?;
        }
        assert!(matches!(buffer.ack(1).await, Err(BufferError::InvalidAck)));
        assert_eq!(buffer.read_batch(8, 16384).await?.len(), 8);
        if ack > 0 {
            buffer.ack(ack as u64).await?;
        }
        buffer.shutdown().await?;
        let replay = DurableBuffer::open(config).await?;
        let batch = replay.read_batch(8, 16384).await?;
        assert_eq!(
            batch.iter().map(|record| &record.event).collect::<Vec<_>>(),
            events[ack..].iter().collect::<Vec<_>>()
        );
        assert_eq!(replay.snapshot().checkpoint, ack as u64);
        assert_eq!(replay.snapshot().depth, 8 - ack);
        if ack < 8 {
            replay.ack(8).await?;
        }
        assert_eq!(replay.snapshot().depth, 0);
        assert_eq!(replay.snapshot().wal_segments, 0);
        replay.shutdown().await?;
    }
    Ok(())
}
