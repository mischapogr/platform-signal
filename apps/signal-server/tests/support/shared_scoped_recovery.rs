//! Synthetic host claims, actual owned PostgreSQL/WAL/process loss. No AWS proof.
use super::{Fixture, Result, context, database, draft, recovery_support, versions};
use signal_buffer::{BufferConfig, DurableBuffer};
use signal_control::{
    AdministrativeScope, ConnectionSettings, ControlAdministrator, ControlClient, ControlError,
    FindingScopeAdministrator, FindingScopeLimits, FindingScopeProfile, InitializeInput,
    MigrationInput, ProducerEnrollment, Scope, schema_identity,
};
use signal_protocol::EventSink;
use signal_server::{
    shared_recovery::{RECOVERY_BYTES, RecoveryError, SharedRecovery},
    shared_scoped::ScopedPublicationDraft,
};
use std::sync::Arc;
use uuid::Uuid;
const DB: &str = "signal_shared_scoped_recovery";
pub(super) fn connection(f: &Fixture) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
        f.port,
        DB.into(),
        "signal_runtime".into(),
        f.password.as_bytes().to_vec(),
    )
}
fn claims(
    producer: &ProducerEnrollment,
    rows: &[signal_storage::StoredEvent],
    previous: Option<Uuid>,
) -> Result<ScopedPublicationDraft> {
    let row = rows.first().ok_or("original WAL row missing")?;
    let finding = signal_findings::Finding::for_event(
        "scoped-recovery",
        &row.event,
        signal_findings::DetectionSeverity::High,
        "Recovery",
    )?;
    // This fixture supplies a synthetic trusted-host report. Native authenticated
    // HTTP admission remains a separate required application qualification.
    let sealed = signal_findings::DerivedFinding::from_event(finding, &row.event, true)?
        .into_scoped(producer.scope_generation)?;
    let mut plan = draft();
    plan.previous = previous;
    Ok(ScopedPublicationDraft::from_host(
        plan,
        producer,
        rows,
        vec![(row.sequence, sealed)],
    )?)
}
pub(super) async fn qualify(f: &Fixture) -> Result {
    let root = tempfile::tempdir()?;
    let cfg = BufferConfig {
        directory: root.path().join("wal"),
        ..Default::default()
    };
    let initial = DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?;
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::from_u128(0xfa00),
        generation: Uuid::from_u128(0xfa01),
        tenant: "synthetic-scoped-recovery".into(),
        stream: initial.snapshot().stream_id,
        partition_id: Uuid::from_u128(0xfa03),
    };
    initial.shutdown().await?;
    let (root_db, root_driver) = database(f, "postgres").await?;
    root_db
        .batch_execute(&format!("CREATE DATABASE {DB}"))
        .await?;
    root_db
        .batch_execute(&format!(
            "GRANT CREATE ON DATABASE {DB} TO signal_control_owner"
        ))
        .await?;
    drop(root_db);
    root_driver.await??;
    let migrator = ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse()?,
        f.port,
        DB.into(),
        "signal_migrator".into(),
        f.password.as_bytes().to_vec(),
    )?;
    let installer = ControlAdministrator::new(migrator.clone(), "signal_control_owner".into())?;
    let authority = AdministrativeScope {
        schema_version: 1,
        store_id: scope.store_id,
        generation: scope.generation,
    };
    installer
        .initialize(
            InitializeInput {
                scope: authority.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            context()?,
        )
        .await?;
    installer
        .migrate_catalog(
            MigrationInput {
                scope: authority.clone(),
                source_revision: 2,
                source_sha256: schema_identity().1,
            },
            context()?,
        )
        .await?;
    installer.shutdown(context()?).await?;
    let (db, driver) = database(f, DB).await?;
    let backend = Uuid::from_u128(0xfa04);
    db.execute(
        "INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,$2,$3,'pipeline')",
        &[&scope.partition_id, &scope.tenant, &scope.stream],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.principals VALUES('signal_runtime',$1,$2,$3)",
        &[&scope.tenant, &scope.stream, &scope.partition_id],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_backends VALUES($1,'owned-scoped-recovery-versions')",
        &[&backend],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_scopes VALUES($1,$2,$3)",
        &[
            &scope.partition_id,
            &backend,
            &format!("query/{}/", scope.stream),
        ],
    )
    .await?;
    db.batch_execute("SET ROLE signal_control_owner").await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/007-finding-scope.sql"
    ))
    .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/008-scoped-publication.sql"
    ))
    .await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_control,signal_finding_scope TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) TO signal_runtime").await?;
    let admin = FindingScopeAdministrator::new(
        migrator,
        "signal_control_owner".into(),
        FindingScopeProfile::Catalog4Scoped,
    )?;
    let mut producer = ProducerEnrollment {
        scope: scope.clone(),
        scope_generation: Uuid::from_u128(0xfa05),
        startup: Uuid::new_v4(),
        wal_floor: 0,
    };
    admin
        .activate(
            authority,
            producer.scope_generation,
            FindingScopeLimits {
                producers: 1,
                rows: 128,
                bytes: 131072,
            },
            context()?,
        )
        .await?;
    admin.enroll(producer.clone(), context()?).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    let control = ControlClient::catalog(connection(f)?)?;
    let mut token = control
        .acquire(scope.clone(), Uuid::new_v4(), 60000, context()?)
        .await?;
    control.shutdown(context()?).await?;
    let objects = Arc::new(versions::Versions(object_store::memory::InMemory::new()));
    let mut previous = None;
    for (offset, mode) in [
        "scoped-draft",
        "scoped-before-commit",
        "scoped-after-commit",
        "scoped-after-ack",
    ]
    .into_iter()
    .enumerate()
    {
        let sequence = offset as u64 + 1;
        let wal = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
        let input: signal_event::IngestEvent = serde_json::from_value(serde_json::json!({
            "timestamp":chrono::Utc::now().to_rfc3339(),"source":{"type":"audit"},"message":"scoped recovery",
            "attributes":{"account":"spoof"},"resource":{"kind":"host","id":"fixture","account_id":"canonical"}
        }))?;
        wal.admit(input.normalize(chrono::Utc::now())?).await?;
        let rows: Vec<_> = wal
            .read_batch(1, 8 * 1024 * 1024)
            .await?
            .into_iter()
            .map(|r| signal_storage::StoredEvent {
                sequence: r.sequence,
                event: r.event,
            })
            .collect();
        assert_eq!(rows[0].sequence, sequence);
        let plan = claims(&producer, &rows, previous)?;
        let control = Arc::new(ControlClient::catalog(connection(f)?)?);
        let publisher = recovery_support::publisher(control.clone(), &scope, backend, &objects)?;
        let recovery = SharedRecovery::new(publisher.clone(), wal.clone())?;
        let mut prepared = if mode == "scoped-draft" {
            db.batch_execute("UPDATE signal_control.store SET ready=false")
                .await?;
            assert!(matches!(
                recovery
                    .prepare_scoped(token.clone(), plan, 1, context()?)
                    .await,
                Err(RecoveryError::Shared(super::SharedError::Control(
                    ControlError::Fenced
                )))
            ));
            db.batch_execute("UPDATE signal_control.store SET ready=true")
                .await?;
            None
        } else {
            Some(
                recovery
                    .prepare_scoped(token.clone(), plan, 1, context()?)
                    .await?,
            )
        };
        if let Some(p) = &prepared {
            assert!(p.scoped_request().is_some());
        }
        let retained = wal
            .read_recovery(context()?.deadline())
            .await?
            .ok_or("original scoped slot missing")?;
        let value: serde_json::Value = serde_json::from_slice(&retained.bytes)?;
        assert_eq!(value["schema_version"], 2);
        let claim_value = if mode == "scoped-draft" {
            &value["phase"]["draft"]["claims"]["claims"]
        } else {
            &value["phase"]["request"]["claims"]
        };
        assert_eq!(
            claim_value["startup"],
            serde_json::to_value(producer.startup)?
        );
        assert_eq!(claim_value["wal_floor"], producer.wal_floor);
        drop(prepared.take());
        drop(recovery);
        publisher.shutdown(context()?).await?;
        control.shutdown(context()?).await?;
        wal.shutdown().await?;
        drop(publisher);
        drop(control);
        drop(wal);
        recovery_support::kill_worker(root.path(), mode, &cfg.directory, &token).await?;
        let wal = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
        assert_eq!(
            wal.read_recovery(context()?.deadline()).await?,
            Some(retained.clone())
        );
        assert_eq!(
            wal.snapshot().checkpoint,
            if mode == "scoped-after-ack" {
                sequence
            } else {
                sequence - 1
            }
        );
        if mode == "scoped-after-commit" || mode == "scoped-after-ack" {
            // Current host startup changes after the old operation committed.
            // Recovery must resolve the old original claims, never regenerate them.
            db.batch_execute("UPDATE signal_control.store SET ready=false")
                .await?;
            producer.startup = Uuid::new_v4();
            producer.wal_floor = sequence;
            admin.enroll(producer.clone(), context()?).await?;
            db.batch_execute("UPDATE signal_control.store SET ready=true")
                .await?;
            assert_eq!(
                wal.read_recovery(context()?.deadline()).await?,
                Some(retained)
            );
        }
        let control = Arc::new(ControlClient::catalog(connection(f)?)?);
        db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", &[&scope.partition_id]).await?;
        token = control
            .acquire(scope.clone(), Uuid::new_v4(), 60000, context()?)
            .await?;
        let publisher = recovery_support::publisher(control.clone(), &scope, backend, &objects)?;
        let recovery = SharedRecovery::new(publisher.clone(), wal.clone())?;
        let result = recovery
            .resume(token.clone(), context()?)
            .await?
            .ok_or("scoped resolution missing")?;
        assert_eq!(result.last_sequence, sequence);
        assert_eq!(wal.snapshot().checkpoint, sequence);
        assert!(wal.read_recovery(context()?.deadline()).await?.is_none());
        assert_eq!(
            db.query_one("SELECT count(*) FROM signal_finding_scope.facts", &[])
                .await?
                .get::<_, i64>(0),
            sequence as i64
        );
        assert_eq!(
            db.query_one("SELECT count(*) FROM signal_finding_scope.requests", &[])
                .await?
                .get::<_, i64>(0),
            sequence as i64
        );
        if mode != "scoped-draft" {
            let expected: signal_control::ScopedPublicationInput =
                serde_json::from_value(value["phase"]["request"].clone())?;
            let fact = expected
                .publication()
                .findings
                .first()
                .ok_or("original finding missing")?;
            let actual: Vec<u8> = db
                .query_one(
                    "SELECT content FROM signal_control.findings WHERE id=$1",
                    &[&fact.id],
                )
                .await?
                .get(0);
            assert_eq!(actual, fact.bytes);
        }
        previous = Some(result.id);
        drop(recovery);
        publisher.shutdown(context()?).await?;
        control.shutdown(context()?).await?;
        wal.shutdown().await?;
    }
    // A missing old operation after startup replacement cannot be recreated or
    // acknowledged. Its original bytes and WAL checkpoint remain held.
    let wal = Arc::new(DurableBuffer::open_with_recovery(cfg, RECOVERY_BYTES).await?);
    let input: signal_event::IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":chrono::Utc::now().to_rfc3339(),"source":{"type":"audit"},"message":"held original","attributes":{}}),
    )?;
    wal.admit(input.normalize(chrono::Utc::now())?).await?;
    let rows: Vec<_> = wal
        .read_batch(1, 8 * 1024 * 1024)
        .await?
        .into_iter()
        .map(|r| signal_storage::StoredEvent {
            sequence: r.sequence,
            event: r.event,
        })
        .collect();
    let control = Arc::new(ControlClient::catalog(connection(f)?)?);
    let publisher = recovery_support::publisher(control.clone(), &scope, backend, &objects)?;
    let recovery = SharedRecovery::new(publisher.clone(), wal.clone())?;
    let prepared = recovery
        .prepare_scoped(
            token.clone(),
            claims(&producer, &rows, previous)?,
            1,
            context()?,
        )
        .await?;
    drop(prepared);
    let original = wal
        .read_recovery(context()?.deadline())
        .await?
        .ok_or("held slot missing")?;
    db.batch_execute("UPDATE signal_control.store SET ready=false")
        .await?;
    producer.startup = Uuid::new_v4();
    producer.wal_floor = 5;
    admin.enroll(producer, context()?).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    assert!(matches!(
        recovery.resume(token, context()?).await,
        Err(RecoveryError::Shared(super::SharedError::Control(
            ControlError::Fenced
        )))
    ));
    assert_eq!(wal.snapshot().checkpoint, 4);
    assert_eq!(
        wal.read_recovery(context()?.deadline()).await?,
        Some(original)
    );
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_control.commits", &[])
            .await?
            .get::<_, i64>(0),
        4
    );
    drop(recovery);
    publisher.shutdown(context()?).await?;
    control.shutdown(context()?).await?;
    wal.shutdown().await?;
    admin.shutdown(context()?).await?;
    drop(db);
    driver.await??;
    eprintln!(
        "phase: actual-server-scoped-wal-original-claims-crash-and-startup-fencing-qualified"
    );
    Ok(())
}
