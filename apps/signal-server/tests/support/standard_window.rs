//! Owner-only provisioning and stopped-state oracle for the actual WINDOW Main fixture.
use super::{Result, context};
use signal_buffer::{BufferConfig, DurableBuffer};
use signal_control::Scope;
use signal_server::shared_recovery::RECOVERY_BYTES;
use std::{fs, path::Path};
use uuid::Uuid;

pub async fn prepare(db: &tokio_postgres::Client, scope: &Scope, generation: Uuid) -> Result {
    prepare_modules(db, scope, generation, true).await
}
pub async fn prepare_modules(
    db: &tokio_postgres::Client,
    scope: &Scope,
    generation: Uuid,
    window: bool,
) -> Result {
    install_modules(db, window).await?;
    db.execute("INSERT INTO signal_multi_event.profile(singleton,scope_generation,max_rows,max_bytes) VALUES(true,$1,128,1048576)", &[&generation]).await?;
    if window {
        db.execute("INSERT INTO signal_window_history.profile(partition_id,state_key,scope_generation,max_rows,max_bytes,retention_ms) VALUES($1,'standard-window',$2,32,262144,60000)", &[&scope.partition_id,&generation]).await?;
    }
    Ok(())
}

pub async fn install_modules(db: &tokio_postgres::Client, window: bool) -> Result {
    db.batch_execute("SET ROLE signal_control_owner").await?;
    for source in [
        include_str!("../../../../schemas/shared-control/009-state-read.sql"),
        include_str!("../../../../schemas/shared-control/010-multi-event-publication.sql"),
        include_str!("../../../../schemas/shared-control/011-replay-pin-transfer.sql"),
        include_str!("../../../../schemas/shared-control/012-window-history.sql"),
        include_str!("../../../../schemas/shared-control/013-window-history-read.sql"),
        include_str!("../../../../schemas/shared-control/014-obsolete-replay-pin.sql"),
        include_str!("../../../../schemas/shared-control/015-window-profile.sql"),
        include_str!("../../../../schemas/shared-control/016-known-findings.sql"),
        include_str!("../../../../schemas/shared-control/017-window-replay-pin.sql"),
    ] {
        db.batch_execute(source).await?;
    }
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_state_read,signal_multi_event,signal_replay_transfer,signal_replay_release,signal_finding_lookup TO signal_standard_producer; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_state_read,signal_multi_event,signal_replay_transfer,signal_replay_release,signal_finding_lookup TO signal_standard_producer; GRANT USAGE ON SCHEMA signal_multi_event TO signal_standard_reader; GRANT SELECT ON ALL TABLES IN SCHEMA signal_multi_event TO signal_standard_reader; GRANT SELECT ON signal_control.commits TO signal_standard_reader").await?;
    if window {
        db.batch_execute("GRANT USAGE ON SCHEMA signal_window_history_read,signal_window_profile,signal_window_pin TO signal_standard_producer; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_window_history_read,signal_window_profile,signal_window_pin TO signal_standard_producer").await?;
    }
    Ok(())
}

pub async fn verify(db: &tokio_postgres::Client, root: &Path) -> Result {
    let expected: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("window-expected.json"))?)?;
    let checkpoint = expected["checkpoint"].as_u64().ok_or("checkpoint")?;
    let row = db.query_one("SELECT (SELECT checkpoint FROM signal_control.partitions WHERE kind='pipeline'),(SELECT count(*) FROM signal_control.findings),(SELECT count(*) FROM signal_multi_event.facts),(SELECT count(*) FROM signal_window_history.assessments WHERE convert_from(payload,'UTF8')::jsonb#>>'{assessment,outcome}'='match'),(SELECT count(*) FROM signal_control.object_pins WHERE state='retained' AND kind='replay')", &[]).await?;
    assert_eq!(row.get::<_, i64>(0), checkpoint as i64);
    assert_eq!(row.get::<_, i64>(1), 3);
    assert_eq!(row.get::<_, i64>(2), 3);
    assert_eq!(row.get::<_, i64>(3), 1);
    if checkpoint >= 5 {
        assert!(row.get::<_, i64>(4) > 0);
    }
    let state: Vec<u8> = db
        .query_one(
            "SELECT value FROM signal_control.state WHERE key='standard-window'",
            &[],
        )
        .await?
        .try_get(0)?;
    let state: serde_json::Value = serde_json::from_slice(&state)?;
    let ids = expected["event_ids"].as_array().ok_or("event IDs")?;
    for (index, id) in ids.iter().enumerate() {
        assert_eq!(
            state["canonical_sequences"][id.as_str().ok_or("event ID")?],
            (index + 1) as u64
        );
    }
    let rows = db
        .query(
            "SELECT id,content FROM signal_control.findings ORDER BY id",
            &[],
        )
        .await?;
    let findings = rows
        .iter()
        .map(|r| serde_json::json!({"id":r.get::<_,Uuid>(0),"bytes":r.get::<_,Vec<u8>>(1)}))
        .collect::<Vec<_>>();
    let baseline = root.join("window-original-findings.json");
    if checkpoint == 4 {
        fs::write(&baseline, serde_json::to_vec(&findings)?)?;
    } else {
        assert_eq!(
            findings,
            serde_json::from_slice::<Vec<serde_json::Value>>(&fs::read(baseline)?)?
        );
    }
    let wal = DurableBuffer::open_with_recovery(
        BufferConfig {
            directory: root.join("server/wal"),
            ..Default::default()
        },
        RECOVERY_BYTES,
    )
    .await?;
    assert_eq!(wal.snapshot().checkpoint, checkpoint);
    assert_eq!(wal.snapshot().last_sequence, checkpoint);
    assert!(wal.read_recovery(context()?.deadline()).await?.is_none());
    wal.shutdown().await?;
    println!("phase: actual-Standard-WINDOW-original-sequences-findings-history-DB-WAL-qualified");
    Ok(())
}

/// Oracle binds the actual synced slot to the original SQL bytes after restart.
pub async fn recovery(db: &tokio_postgres::Client, root: &Path, recovered: bool) -> Result {
    use sha2::{Digest, Sha256};
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("window-crash-entry.json"))?)?;
    let request: signal_control::MultiEventPublicationInput =
        serde_json::from_value(saved["phase"]["request"].clone())?;
    assert_eq!(saved["schema_version"], 3);
    assert_eq!(saved["first"], 6);
    assert_eq!(saved["last"], 6);
    let publication = request.publication();
    let wal = DurableBuffer::open_with_recovery(
        BufferConfig {
            directory: root.join("server/wal"),
            ..Default::default()
        },
        RECOVERY_BYTES,
    )
    .await?;
    let expected = if recovered { 6 } else { 5 };
    assert_eq!(wal.snapshot().checkpoint, expected);
    assert_eq!(wal.snapshot().last_sequence, 6);
    let slot = wal.read_recovery(context()?.deadline()).await?;
    let rows = db
        .query(
            "SELECT request,request_sha256,manifest FROM signal_control.commits WHERE id=$1",
            &[&publication.id],
        )
        .await?;
    if recovered {
        assert!(slot.is_none());
        assert_eq!(rows.len(), 1);
        let raw = request.encode_sql_publication()?;
        assert_eq!(rows[0].get::<_, Vec<u8>>(0), raw);
        assert_eq!(rows[0].get::<_, Vec<u8>>(1), Sha256::digest(&raw).to_vec());
        assert_eq!(rows[0].get::<_, Vec<u8>>(2), publication.manifest);
        let claims: Vec<u8> = db
            .query_one(
                "SELECT claims FROM signal_multi_event.requests WHERE commit_id=$1",
                &[&publication.id],
            )
            .await?
            .try_get(0)?;
        assert_eq!(claims, request.encode_sql_claims()?);
        for finding in &publication.findings {
            let bytes: Vec<u8> = db
                .query_one(
                    "SELECT content FROM signal_control.findings WHERE id=$1",
                    &[&finding.id],
                )
                .await?
                .try_get(0)?;
            assert_eq!(bytes, finding.bytes);
        }
    } else {
        assert!(rows.is_empty());
        let slot = slot.ok_or("original Window recovery slot missing")?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&slot.bytes)?,
            saved
        );
    }
    let checkpoint: i64 = db
        .query_one(
            "SELECT checkpoint FROM signal_control.partitions WHERE kind='pipeline'",
            &[],
        )
        .await?
        .try_get(0)?;
    assert_eq!(checkpoint, expected as i64);
    let baseline: Vec<serde_json::Value> =
        serde_json::from_slice(&fs::read(root.join("window-original-findings.json"))?)?;
    for original in baseline {
        let id: Uuid = serde_json::from_value(original["id"].clone())?;
        let bytes: Vec<u8> = db
            .query_one(
                "SELECT content FROM signal_control.findings WHERE id=$1",
                &[&id],
            )
            .await?
            .try_get(0)?;
        assert_eq!(
            bytes,
            serde_json::from_value::<Vec<u8>>(original["bytes"].clone())?
        );
    }
    wal.shutdown().await?;
    println!(
        "phase: actual-Standard-WINDOW-original-prepared-crash-request-claims-DB-WAL-qualified"
    );
    Ok(())
}
