use signal_control::{ControlClient, ControlError, LeaseToken, SnapshotInput};
use std::time::Duration;
use tokio_postgres::Client;
use uuid::Uuid;
type Error = Box<dyn std::error::Error>;
fn request(ids: Vec<Uuid>, pin_ms: u32) -> SnapshotInput {
    SnapshotInput {
        schema_version: 1,
        id: Uuid::new_v4(),
        manifest_ids: ids,
        pin_ms,
    }
}
async fn witness(db: &Client) -> Result<serde_json::Value, Error> {
    Ok(db.query_one("SELECT jsonb_build_object('store',(SELECT to_jsonb(s) FROM signal_control.store s),'snapshots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signal_control.snapshots s))",&[]).await?.try_get(0)?)
}
pub async fn qualify(
    db: &Client,
    runtime: &ControlClient,
    token: &LeaseToken,
) -> Result<(), Error> {
    eprintln!("phase: bounded-snapshot-exact-replay-and-expiry");
    let rows=db.query("SELECT id,manifest FROM signal_control.commits WHERE partition_id=$1 ORDER BY first_sequence",&[&token.scope.partition_id]).await?;
    assert_eq!(rows.len(), 4);
    let ids: Vec<Uuid> = rows.iter().map(|r| r.get(0)).collect();
    let input = request(ids.clone(), 5000);
    let pin = runtime
        .read_snapshot(token.scope.clone(), input.clone(), super::context()?)
        .await?;
    assert_eq!(pin.id(), input.id);
    assert_eq!(pin.scope(), &token.scope);
    assert_eq!(pin.manifests()?.len(), 4);
    for (p, row) in pin.manifests()?.iter().zip(&rows) {
        assert_eq!(p.bytes, row.get::<_, Vec<u8>>(1));
    }
    let first = witness(db).await?;
    let expiry = db
        .query_one(
            "SELECT expires_at::text FROM signal_control.snapshots WHERE id=$1",
            &[&input.id],
        )
        .await?
        .get::<_, String>(0);
    let replay = runtime
        .read_snapshot(token.scope.clone(), input.clone(), super::context()?)
        .await?;
    assert_eq!(replay.manifests()?, pin.manifests()?);
    assert_eq!(witness(db).await?, first);
    let mut changed = input.clone();
    changed.manifest_ids.reverse();
    assert!(matches!(
        runtime
            .read_snapshot(token.scope.clone(), changed, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    let mut changed = input.clone();
    changed.pin_ms = 4999;
    assert!(matches!(
        runtime
            .read_snapshot(token.scope.clone(), changed, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, first);
    let mut foreign = token.scope.clone();
    foreign.tenant = "foreign".into();
    assert!(matches!(
        runtime
            .read_snapshot(foreign, input.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let mut old = token.scope.clone();
    old.generation = Uuid::new_v4();
    assert!(matches!(
        runtime
            .read_snapshot(old, input.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let missing = request(vec![ids[0], Uuid::new_v4()], 5000);
    assert!(matches!(
        runtime
            .read_snapshot(token.scope.clone(), missing, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, first);
    db.execute("UPDATE signal_control.commits SET manifest=manifest||decode('20','hex') WHERE partition_id=$1 AND id=$2",&[&token.scope.partition_id,&ids[0]]).await?;
    assert!(matches!(
        runtime
            .read_snapshot(
                token.scope.clone(),
                request(vec![ids[0]], 5000),
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    db.execute(
        "UPDATE signal_control.commits SET manifest=$3 WHERE partition_id=$1 AND id=$2",
        &[
            &token.scope.partition_id,
            &ids[0],
            &rows[0].get::<_, Vec<u8>>(1),
        ],
    )
    .await?;
    assert_eq!(witness(db).await?, first);
    db.batch_execute("UPDATE signal_control.store SET max_rows=used_rows")
        .await?;
    let exhausted = witness(db).await?;
    assert!(matches!(
        runtime
            .read_snapshot(
                token.scope.clone(),
                request(ids.clone(), 5000),
                super::context()?
            )
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(witness(db).await?, exhausted);
    db.batch_execute("UPDATE signal_control.store SET max_rows=65536,max_bytes=used_bytes")
        .await?;
    let exhausted = witness(db).await?;
    assert!(matches!(
        runtime
            .read_snapshot(
                token.scope.clone(),
                request(ids.clone(), 5000),
                super::context()?
            )
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(witness(db).await?, exhausted);
    db.batch_execute("UPDATE signal_control.store SET max_bytes=67108864")
        .await?;
    eprintln!("phase: snapshot-short-pin-and-compaction");
    let short = request(vec![ids[0]], 500);
    let expired = runtime
        .read_snapshot(token.scope.clone(), short.clone(), super::context()?)
        .await?;
    let mut selection = expired.bind_query_selection(signal_storage::FileSelection::default())?;
    assert_eq!(selection.deadline(), Some(expired.deadline()));
    selection.restrict_deadline(expired.deadline() + Duration::from_secs(60));
    assert_eq!(selection.deadline(), Some(expired.deadline()));
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert!(matches!(
        expired.manifests(),
        Err(ControlError::SnapshotExpired)
    ));
    assert!(matches!(
        runtime
            .read_snapshot(token.scope.clone(), short.clone(), super::context()?)
            .await,
        Err(ControlError::SnapshotExpired)
    ));
    assert!(matches!(
        selection.check_lifetime(),
        Err(signal_storage::StorageError::Timeout)
    ));
    assert!(matches!(
        expired.bind_query_selection(signal_storage::FileSelection::default()),
        Err(ControlError::SnapshotExpired)
    ));
    eprintln!("phase: shared-query-selection-pin-expiry-qualified");
    let reclaimed = runtime
        .read_snapshot(
            token.scope.clone(),
            request(vec![ids[1]], 5000),
            super::context()?,
        )
        .await?;
    reclaimed.check()?;
    let marker = db
        .query_one(
            "SELECT octet_length(manifest_ids) FROM signal_control.snapshots WHERE id=$1",
            &[&short.id],
        )
        .await?;
    assert_eq!(marker.get::<_, i32>(0), 1);
    assert!(matches!(
        runtime
            .read_snapshot(token.scope.clone(), short, super::context()?)
            .await,
        Err(ControlError::SnapshotExpired)
    ));
    assert_eq!(
        db.query_one(
            "SELECT expires_at::text FROM signal_control.snapshots WHERE id=$1",
            &[&input.id]
        )
        .await?
        .get::<_, String>(0),
        expiry
    );
    // No lease is required for trusted reads, but generation and principal are mandatory.
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&token.scope.partition_id]).await?;
    let read = runtime
        .read_snapshot(
            token.scope.clone(),
            request(vec![ids[0]], 5000),
            super::context()?,
        )
        .await?;
    read.check()?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()+interval '60 seconds' WHERE id=$1",&[&token.scope.partition_id]).await?;
    eprintln!("phase: snapshot-object-reply-bounds-and-isolation");
    // Administrative synthetic corruption exercises SQL bounds before any pin is written.
    let mut manifest: serde_json::Value = serde_json::from_slice(&rows[0].get::<_, Vec<u8>>(1))?;
    let file = manifest["files"][0].clone();
    manifest["files"] = serde_json::Value::Array(vec![file; 129]);
    let oversized = serde_json::to_vec(&manifest)?;
    db.execute("UPDATE signal_control.commits SET manifest=$3,manifest_sha256=sha256($3),objects_sha256=signal_control.commit_object_seal(backend_id,sha256($3),object_hashes) WHERE partition_id=$1 AND id=$2",&[&token.scope.partition_id,&ids[0],&oversized]).await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .read_snapshot(
                token.scope.clone(),
                request(vec![ids[0]], 5000),
                super::context()?
            )
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(witness(db).await?, before);
    db.execute("UPDATE signal_control.commits SET manifest=$3,manifest_sha256=sha256($3),objects_sha256=signal_control.commit_object_seal(backend_id,sha256($3),object_hashes) WHERE partition_id=$1 AND id=$2",&[&token.scope.partition_id,&ids[0],&rows[0].get::<_,Vec<u8>>(1)]).await?;
    for row in &rows {
        let mut padded = row.get::<_, Vec<u8>>(1);
        padded.resize(150000, b' ');
        db.execute("UPDATE signal_control.commits SET manifest=$3,manifest_sha256=sha256($3),objects_sha256=signal_control.commit_object_seal(backend_id,sha256($3),object_hashes) WHERE partition_id=$1 AND id=$2",&[&token.scope.partition_id,&row.get::<_,Uuid>(0),&padded]).await?;
    }
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .read_snapshot(
                token.scope.clone(),
                request(ids.clone(), 5000),
                super::context()?
            )
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(witness(db).await?, before);
    for row in &rows {
        db.execute("UPDATE signal_control.commits SET manifest=$3,manifest_sha256=sha256($3),objects_sha256=signal_control.commit_object_seal(backend_id,sha256($3),object_hashes) WHERE partition_id=$1 AND id=$2",&[&token.scope.partition_id,&row.get::<_,Uuid>(0),&row.get::<_,Vec<u8>>(1)]).await?;
    }
    let (schema, routines) = signal_control::schema_identity();
    let scope = serde_json::to_value(&token.scope)?;
    let identity = Uuid::new_v4();
    db.batch_execute("SET SESSION AUTHORIZATION signal_runtime")
        .await?;
    let rejected = db
        .query_one(
            "SELECT signal_control.read_snapshot($1,$2,$3,$4,$5,$6)",
            &[
                &scope,
                &identity,
                &ids,
                &5000_i32,
                &schema.as_slice(),
                &routines.as_slice(),
            ],
        )
        .await;
    db.batch_execute("RESET SESSION AUTHORIZATION").await?;
    let error = rejected.err().ok_or("unisolated snapshot must fail")?;
    assert_eq!(
        error.as_db_error().map(|e| e.message()),
        Some("SIGNAL_INVALID")
    );
    assert!(runtime.metrics().snapshot_expired >= 2);
    // An update committed after the repeatable-read view was established fails
    // the entire transaction, followed by a fresh bounded whole-operation retry.
    eprintln!("phase: snapshot-concurrent-update-whole-operation-failure");
    let before = witness(db).await?;
    db.batch_execute(
        "BEGIN; UPDATE signal_control.store SET feed_position=feed_position WHERE singleton",
    )
    .await?;
    let client = runtime.clone();
    let scope = token.scope.clone();
    let selected = ids.clone();
    let contender = tokio::spawn(async move {
        client
            .read_snapshot(scope, request(selected, 5000), super::context()?)
            .await
    });
    tokio::time::timeout(Duration::from_millis(400),async {
        loop {
            db.batch_execute("SELECT pg_stat_clear_snapshot()").await?;
            let waiting=db.query_one("SELECT count(*)>0 FROM pg_stat_activity WHERE usename='signal_runtime' AND wait_event_type='Lock' AND query LIKE 'SELECT signal_control.read_snapshot%'",&[]).await?;
            if waiting.get::<_,bool>(0) { break; }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok::<(),tokio_postgres::Error>(())
    }).await??;
    db.batch_execute("COMMIT").await?;
    contender.await??.check()?;
    assert!(runtime.metrics().snapshot_retries >= 1);
    assert_ne!(witness(db).await?, before);
    // A nontransactional synthetic sequence proves all three aborted rounds execute
    // and no fourth round, counter change or partial snapshot survives exhaustion.
    db.batch_execute("CREATE SEQUENCE public.synthetic_snapshot_round; GRANT USAGE ON SEQUENCE public.synthetic_snapshot_round TO signal_control_owner; CREATE FUNCTION public.synthetic_snapshot_retry() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('public.synthetic_snapshot_round'); RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='synthetic serialization failure'; END $$; CREATE TRIGGER synthetic_snapshot_retry BEFORE INSERT ON signal_control.snapshots FOR EACH ROW EXECUTE FUNCTION public.synthetic_snapshot_retry()").await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .read_snapshot(
                token.scope.clone(),
                request(ids.clone(), 5000),
                super::context()?
            )
            .await,
        Err(ControlError::Retryable)
    ));
    assert_eq!(
        db.query_one(
            "SELECT last_value FROM public.synthetic_snapshot_round",
            &[]
        )
        .await?
        .get::<_, i64>(0),
        3
    );
    assert_eq!(witness(db).await?, before);
    db.batch_execute("DROP TRIGGER synthetic_snapshot_retry ON signal_control.snapshots; DROP FUNCTION public.synthetic_snapshot_retry(); DROP SEQUENCE public.synthetic_snapshot_round").await?;
    // Permanent rows and compacted payloads remain charged exactly.
    let counters=db.query_one("SELECT used_rows = ((SELECT count(*) FROM signal_control.commits)+(SELECT count(*) FROM signal_control.receipts)+(SELECT count(*) FROM signal_control.state)+(SELECT count(*) FROM signal_control.findings)+(SELECT count(*) FROM signal_control.outbox)+(SELECT count(*) FROM signal_control.snapshots)), used_bytes = ((SELECT coalesce(sum(512+octet_length(request)+octet_length(manifest)+octet_length(normalizer_revision)+32*cardinality(object_hashes)),0) FROM signal_control.commits)+(SELECT coalesce(sum(256+octet_length(reference)+octet_length(retained_request)),0) FROM signal_control.receipts)+(SELECT coalesce(sum(192+octet_length(key)+octet_length(value)),0) FROM signal_control.state)+(SELECT coalesce(sum(256+octet_length(content)),0) FROM signal_control.findings)+(SELECT coalesce(sum(256+octet_length(plan)),0) FROM signal_control.outbox)+(SELECT coalesce(sum(320+octet_length(manifest_ids)+32*cardinality(object_hashes)),0) FROM signal_control.snapshots)) FROM signal_control.store",&[]).await?;
    assert!(counters.get::<_, bool>(0));
    assert!(counters.get::<_, bool>(1));
    eprintln!("matrix-case:snapshot_expired passed");
    eprintln!("phase: bounded-snapshot-qualification-complete");
    Ok(())
}
