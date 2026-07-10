use super::*;
use crate::{
    StoredEvent,
    object_io::{ObjectIo, ObjectIoLimits, SmallOwnerConfig},
    object_publication::{ObjectPublisher, PublicationConfig},
};
use object_store::{ObjectStore, ObjectStoreExt, PutOptions, memory::InMemory};
use std::{sync::Arc, time::Duration};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> OperationContext {
    OperationContext::new(Duration::from_secs(5))
}
fn policy() -> RetentionPolicy {
    RetentionPolicy {
        schema_version: 1,
        raw_seconds: Some(7200),
        query_seconds: 3600,
        index_seconds: Some(1800),
        replay_seconds: 1800,
        evidence_reference_seconds: 7200,
        reader_seconds: 600,
        orphan_grace_seconds: 1800,
    }
}
fn limits() -> ReportLimits {
    ReportLimits {
        max_objects: 10,
        max_bytes: 64 * 1024,
    }
}
fn reference(stream: Uuid) -> QueryObjectRef {
    QueryObjectRef {
        key: format!(
            "query/{stream}/data/date=2026-07-10/hour=19/{}.parquet",
            "a".repeat(64)
        ),
        version: Some("immutable-v1".into()),
        etag: Some("opaque-etag".into()),
        bytes: 13,
        sha256: [1; 32],
    }
}
#[test]
fn retention_horizons_are_explicit_and_reject_reference_replay_or_index_conflicts() -> Result {
    policy().validate()?;
    let mut p = policy();
    p.raw_seconds = None;
    p.validate()?;
    for field in 0..8 {
        let mut p = policy();
        match field {
            0 => p.query_seconds = 0,
            1 => p.raw_seconds = Some(3600),
            2 => p.query_seconds = 900,
            3 => p.index_seconds = Some(7200),
            4 => p.orphan_grace_seconds = 300,
            5 => p.reader_seconds = 7200,
            6 => p.schema_version = 2,
            _ => p.replay_seconds = u64::MAX,
        };
        assert!(matches!(p.validate(), Err(StorageError::Config(_))));
    }
    let mut json = serde_json::to_value(policy())?;
    json["unknown"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<RetentionPolicy>(json).is_err());
    Ok(())
}
#[test]
fn reachability_preflight_rejects_foreign_duplicate_and_unbounded_references() -> Result {
    let stream = Uuid::new_v4();
    let r = reference(stream);
    let mut seen = BTreeSet::new();
    let mut bytes = 0;
    preflight(&r, stream, &mut seen, &mut bytes, limits(), &context())?;
    assert!(matches!(
        preflight(&r, stream, &mut seen, &mut bytes, limits(), &context()),
        Err(StorageError::Corrupt(_))
    ));
    for mode in 0..4 {
        let mut input = r.clone();
        let mut l = limits();
        let ctx = context();
        match mode {
            0 => input.key = format!("protected/{stream}/native/original"),
            1 => l.max_bytes = 1,
            2 => input.version = Some("v".repeat(257)),
            _ => ctx.cancellation.cancel(),
        };
        let result = preflight(&input, stream, &mut BTreeSet::new(), &mut 0, l, &ctx);
        if mode == 3 {
            assert!(matches!(result, Err(StorageError::Cancelled)));
        } else {
            assert!(result.is_err());
        }
    }
    let mut held = BTreeSet::new();
    let mut weight = 0;
    assert!(matches!(
        preflight(
            &r,
            stream,
            &mut held,
            &mut weight,
            ReportLimits {
                max_bytes: 1,
                ..limits()
            },
            &context()
        ),
        Err(StorageError::Full)
    ));
    assert!(held.is_empty());
    assert_eq!(weight, 0);
    Ok(())
}
#[tokio::test]
async fn actual_committed_snapshot_reports_holds_without_mutation_or_delete_authority() -> Result {
    let temp = tempfile::TempDir::new()?;
    let stream = Uuid::new_v4();
    let backend = Arc::new(InMemory::new());
    let io = ObjectIo::open_small_remote(
        &SmallOwnerConfig {
            directory: temp.path().into(),
            stream_id: stream,
            backend_id: Uuid::new_v4(),
        },
        backend.clone(),
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
        context(),
    )
    .await?;
    let publisher = ObjectPublisher::new(
        io,
        tokio::runtime::Handle::current(),
        PublicationConfig::default(),
    )?;
    let now = DateTime::parse_from_rfc3339("2026-07-10T21:00:00Z")?.with_timezone(&Utc);
    let empty = publisher.snapshot(context()).await?;
    assert!(matches!(
        RetentionReport::assess(
            &empty,
            &policy(),
            stream,
            0,
            now,
            ReportLimits {
                max_bytes: 1,
                ..limits()
            },
            &context()
        ),
        Err(StorageError::Full)
    ));
    assert!(
        RetentionReport::assess(&empty, &policy(), stream, 0, now, limits(), &context())?
            .objects
            .is_empty()
    );
    drop(empty);
    let mut events = Vec::new();
    for (sequence, timestamp) in [(7, "2026-07-10T19:30:00Z"), (9, "2026-07-10T20:30:00Z")] {
        let input: signal_event::IngestEvent = serde_json::from_value(
            serde_json::json!({"timestamp":timestamp,"source":{"type":"retention-fixture"},"message":"query copy"}),
        )?;
        events.push(StoredEvent {
            sequence,
            event: input.normalize(Utc::now())?,
        });
    }
    publisher.append(&events, context()).await?;
    let orphan = object_store::path::Path::from(format!(
        "query/{stream}/data/date=2026-07-10/hour=18/{}.parquet",
        "b".repeat(64)
    ));
    backend
        .put_opts(
            &orphan,
            b"unknown orphan".to_vec().into(),
            PutOptions::default(),
        )
        .await?;
    let snapshot = publisher.snapshot(context()).await?;
    let held = RetentionReport::assess(&snapshot, &policy(), stream, 7, now, limits(), &context())?;
    assert_eq!(held.objects.len(), 4);
    assert_eq!(
        held.objects
            .iter()
            .filter(|o| o.decision == RetentionDecision::ReplayBlocked)
            .count(),
        1
    );
    assert_eq!(
        held.objects
            .iter()
            .filter(|o| o.decision == RetentionDecision::UnknownOrphanAge)
            .count(),
        1
    );
    let aged = RetentionReport::assess(&snapshot, &policy(), stream, 9, now, limits(), &context())?;
    assert_eq!(
        aged.objects
            .iter()
            .filter(|o| o.decision == RetentionDecision::RequiresRetirementCommit)
            .count(),
        1
    );
    assert_eq!(
        aged.objects
            .iter()
            .filter(|o| o.decision == RetentionDecision::KeepCommitted)
            .count(),
        2
    );
    let wire = aged.encode(64 * 1024, &context())?;
    let parsed: serde_json::Value = serde_json::from_slice(&wire)?;
    assert_eq!(parsed["schema_version"], 1);
    assert!(matches!(
        aged.encode(1, &context()),
        Err(StorageError::Full)
    ));
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        aged.encode(64 * 1024, &cancelled),
        Err(StorageError::Cancelled)
    ));
    assert!(matches!(
        RetentionReport::assess(
            &snapshot,
            &policy(),
            Uuid::new_v4(),
            9,
            now,
            limits(),
            &context()
        ),
        Err(StorageError::StreamMismatch)
    ));
    for l in [
        ReportLimits {
            max_objects: 2,
            ..limits()
        },
        ReportLimits {
            max_bytes: 1,
            ..limits()
        },
    ] {
        assert!(matches!(
            RetentionReport::assess(&snapshot, &policy(), stream, 9, now, l, &context()),
            Err(StorageError::Full)
        ));
    }
    assert!(matches!(
        RetentionReport::assess(
            &snapshot,
            &policy(),
            stream,
            9,
            DateTime::<Utc>::MIN_UTC,
            limits(),
            &context()
        ),
        Err(StorageError::Config(_))
    ));
    assert_eq!(publisher.metrics().high_water, 9);
    assert_eq!(publisher.metrics().depth, 1);
    assert!(backend.head(&orphan).await.is_ok());
    drop(snapshot);
    publisher.shutdown(context()).await?;
    Ok(())
}
