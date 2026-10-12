//! Application boundary regressions: rejected input never reaches DB or object I/O.
use signal_control::{
    ConnectionSettings, ControlClient, ControlContext, ControlError, LeaseToken, Scope,
};
use signal_server::shared::{PublicationDraft, SharedError, SharedPublisher};
use signal_server::shared_startup::{CatalogProfile, SharedStartup};
use signal_storage::{
    StorageConfig, StoredEvent,
    object_io::{ObjectIo, ObjectIoLimits},
    object_manifest::ManifestLimits,
};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[path = "support/shared_custody.rs"]
mod custody;
fn context() -> std::result::Result<ControlContext, ControlError> {
    ControlContext::new(Duration::from_secs(5))
}
fn draft() -> PublicationDraft {
    PublicationDraft {
        schema_version: 1,
        id: Uuid::new_v4(),
        previous: None,
        rule_revision: [1; 32],
        normalizer_revision: "synthetic-v1".into(),
        states: vec![],
        findings: vec![],
        work: vec![],
        receipts: vec![],
    }
}
#[tokio::test]
async fn startup_rejects_foreign_wal_loss_policy_and_closed_buffer_before_connect() -> Result {
    let directory = tempfile::tempdir()?;
    let wal = Arc::new(
        signal_buffer::DurableBuffer::open(signal_buffer::BufferConfig {
            directory: directory.path().join("wal"),
            ..Default::default()
        })
        .await?,
    );
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        tenant: "synthetic-startup".into(),
        stream: wal.snapshot().stream_id,
        partition_id: Uuid::new_v4(),
    };
    let connection = || {
        ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
            1,
            "unreachable".into(),
            "unreachable".into(),
            b"synthetic-not-a-secret".to_vec(),
        )
    };
    let backend = Uuid::new_v4();
    let mut foreign = scope.clone();
    foreign.stream = Uuid::new_v4();
    assert!(matches!(
        SharedStartup::new(
            connection()?,
            CatalogProfile::Catalog4,
            foreign,
            backend,
            wal.clone()
        ),
        Err(ControlError::Fenced)
    ));
    let lossy = Arc::new(
        signal_buffer::DurableBuffer::open(signal_buffer::BufferConfig {
            directory: directory.path().join("lossy"),
            policy: signal_buffer::Policy::DropOldest,
            ..Default::default()
        })
        .await?,
    );
    let mut lossy_scope = scope.clone();
    lossy_scope.stream = lossy.snapshot().stream_id;
    assert!(matches!(
        SharedStartup::new(
            connection()?,
            CatalogProfile::Catalog4,
            lossy_scope,
            backend,
            lossy.clone()
        ),
        Err(ControlError::Invalid)
    ));
    lossy.shutdown().await?;
    let startup = SharedStartup::new(
        connection()?,
        CatalogProfile::Catalog4,
        scope.clone(),
        backend,
        wal.clone(),
    )?;
    let cancelled = context()?;
    cancelled.cancel();
    assert!(matches!(
        startup.verify(cancelled).await,
        Err(ControlError::Cancelled)
    ));
    assert_eq!(startup.metrics().queue_depth, 0);
    startup.shutdown(context()?).await?;
    wal.shutdown().await?;
    assert!(matches!(
        SharedStartup::new(connection()?, CatalogProfile::Catalog4, scope, backend, wal),
        Err(ControlError::Unavailable)
    ));
    Ok(())
}
#[tokio::test]
async fn hostile_scope_gaps_metadata_and_cancellation_fail_before_any_io() -> Result {
    // No database listens here. Getting as far as a SQL call would return a
    // different error and make this regression fail.
    let control = Arc::new(ControlClient::catalog(
        ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse()?,
            1,
            "unreachable".into(),
            "unreachable".into(),
            b"synthetic-not-a-secret".to_vec(),
        )?,
    )?);
    let io = ObjectIo::remote(
        Arc::new(object_store::memory::InMemory::new()),
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
    )?;
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        tenant: "synthetic".into(),
        stream: Uuid::new_v4(),
        partition_id: Uuid::new_v4(),
    };
    let publisher = SharedPublisher::new(
        control.clone(),
        scope.clone(),
        Uuid::new_v4(),
        io,
        StorageConfig::default(),
        ManifestLimits::default(),
    )?;
    let token = LeaseToken {
        scope,
        owner: Uuid::new_v4(),
        epoch: 1,
    };
    let input: signal_event::IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":chrono::Utc::now().to_rfc3339(),"source":{"type":"synthetic"},"message":"owned test","attributes":{}}),
    )?;
    let rows = vec![StoredEvent {
        sequence: 1,
        event: input.normalize(chrono::Utc::now())?,
    }];
    let mut foreign = token.clone();
    foreign.scope.stream = Uuid::new_v4();
    assert!(matches!(
        publisher.prepare(foreign, &rows, draft(), context()?).await,
        Err(SharedError::Control(ControlError::Fenced))
    ));
    let mut invalid = draft();
    invalid.id = Uuid::nil();
    assert!(matches!(
        publisher
            .prepare(token.clone(), &rows, invalid, context()?)
            .await,
        Err(SharedError::Control(ControlError::Invalid))
    ));
    let mut gap = rows.clone();
    gap.push(StoredEvent {
        sequence: 3,
        event: rows[0].event.clone(),
    });
    assert!(matches!(
        publisher
            .prepare(token.clone(), &gap, draft(), context()?)
            .await,
        Err(SharedError::Control(ControlError::Invalid))
    ));
    let mut oversized = draft();
    oversized.work = Vec::with_capacity(129);
    assert!(matches!(
        publisher
            .prepare(token.clone(), &rows, oversized, context()?)
            .await,
        Err(SharedError::Control(ControlError::Invalid))
    ));
    let cancelled = context()?;
    cancelled.cancel();
    assert!(matches!(
        publisher
            .prepare(token.clone(), &rows, draft(), cancelled)
            .await,
        Err(SharedError::Control(ControlError::Cancelled))
    ));
    let metrics = publisher.metrics();
    assert_eq!(metrics.rejected, 5);
    assert_eq!(metrics.prepared, 0);
    assert_eq!(metrics.active, 0);
    assert_eq!(metrics.objects.processed, 0);
    assert_eq!(metrics.codec.processed, 0);
    assert_eq!(control.metrics().queue_depth, 0);
    publisher.shutdown(context()?).await?;
    assert!(publisher.metrics().closed);
    assert!(matches!(
        publisher.prepare(token, &rows, draft(), context()?).await,
        Err(SharedError::Control(ControlError::Unavailable))
    ));
    control.shutdown(context()?).await?;
    Ok(())
}

#[path = "support/shared_recovery.rs"]
mod recovery_support;
#[path = "support/shared_scoped_recovery.rs"]
mod scoped_recovery_support;
#[path = "support/versions.rs"]
mod versions;
#[tokio::test]
async fn recovery_schema_downgrade_or_unknown_version_holds_original_slot_before_io() -> Result {
    use signal_buffer::{BufferConfig, DurableBuffer};
    use signal_control::ProducerEnrollment;
    use signal_protocol::EventSink;
    use signal_server::{
        shared_recovery::{RECOVERY_BYTES, RecoveryError, SharedRecovery},
        shared_scoped::ScopedPublicationDraft,
    };
    let directory = tempfile::tempdir()?;
    let wal = Arc::new(
        DurableBuffer::open_with_recovery(
            BufferConfig {
                directory: directory.path().join("wal"),
                ..Default::default()
            },
            RECOVERY_BYTES,
        )
        .await?,
    );
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        tenant: "synthetic".into(),
        stream: wal.snapshot().stream_id,
        partition_id: Uuid::new_v4(),
    };
    let token = LeaseToken {
        scope: scope.clone(),
        owner: Uuid::new_v4(),
        epoch: 1,
    };
    let backend = Uuid::new_v4();
    let control = Arc::new(ControlClient::catalog(
        ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse()?,
            1,
            "unreachable".into(),
            "unreachable".into(),
            b"synthetic-not-a-secret".to_vec(),
        )?,
    )?);
    let publisher = Arc::new(SharedPublisher::new(
        control.clone(),
        scope.clone(),
        backend,
        ObjectIo::remote(
            Arc::new(object_store::memory::InMemory::new()),
            tokio::runtime::Handle::current(),
            ObjectIoLimits::default(),
        )?,
        StorageConfig::default(),
        ManifestLimits::default(),
    )?);
    let recovery = SharedRecovery::new(publisher.clone(), wal.clone())?;
    let input: signal_event::IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":chrono::Utc::now().to_rfc3339(),"source":{"type":"synthetic"},"message":"original retained","attributes":{}}),
    )?;
    let event = input.normalize(chrono::Utc::now())?;
    wal.admit(event.clone()).await?;
    let rows = [StoredEvent { sequence: 1, event }];
    let producer = ProducerEnrollment {
        scope: scope.clone(),
        scope_generation: Uuid::new_v4(),
        startup: Uuid::new_v4(),
        wal_floor: 0,
    };
    let scoped = ScopedPublicationDraft::from_host(draft(), &producer, &rows, vec![])?;
    for (version, phase) in [
        (2, serde_json::json!({"state":"draft","draft":draft()})),
        (
            1,
            serde_json::json!({"state":"scoped_draft","draft":scoped.clone()}),
        ),
        (
            3,
            serde_json::json!({"state":"scoped_draft","draft":scoped.clone()}),
        ),
    ] {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"schema_version":version,"scope":scope,"backend":backend,"first":1,"last":1,"rows_sha256":vec![0u8;32],"phase":phase}),
        )?;
        let retained = wal
            .replace_recovery(None, Some(bytes), context()?.deadline())
            .await?
            .ok_or("test record missing")?;
        assert!(matches!(
            recovery.resume(token.clone(), context()?).await,
            Err(RecoveryError::Control(ControlError::Fenced))
        ));
        assert_eq!(wal.snapshot().checkpoint, 0);
        assert_eq!(
            wal.read_recovery(context()?.deadline()).await?,
            Some(retained.clone())
        );
        assert_eq!(publisher.metrics().objects.processed, 0);
        assert_eq!(publisher.metrics().codec.processed, 0);
        assert_eq!(control.metrics().queue_depth, 0);
        // Explicit owned fixture cleanup; runtime never clears a refused record.
        wal.replace_recovery(Some(retained.sha256), None, context()?.deadline())
            .await?;
    }
    drop(recovery);
    publisher.shutdown(context()?).await?;
    control.shutdown(context()?).await?;
    wal.shutdown().await?;
    Ok(())
}
#[tokio::test]
#[ignore = "owned PostgreSQL recovery child, launched only by the server fixture"]
async fn postgres_shared_recovery_crash_worker() -> Result {
    recovery_support::worker().await
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    port: u16,
    password: String,
    root_der: String,
    wrong_der: String,
}
const DATABASE: &str = "signal_shared_server_publication";
async fn database(
    f: &Fixture,
    name: &str,
) -> Result<(
    tokio_postgres::Client,
    tokio::task::JoinHandle<std::result::Result<(), tokio_postgres::Error>>,
)> {
    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(f.port)
        .user("postgres")
        .password(&f.password)
        .dbname(name)
        .application_name("signal-shared-server-owned-fixture")
        .connect_timeout(Duration::from_secs(5));
    let (client, connection) = tokio::time::timeout(
        Duration::from_secs(5),
        config.connect(tokio_postgres::NoTls),
    )
    .await??;
    Ok((client, tokio::spawn(connection)))
}
fn settings(f: &Fixture, user: &str) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
        f.port,
        DATABASE.into(),
        user.into(),
        f.password.as_bytes().to_vec(),
    )
}
fn io(store: Arc<versions::Versions>) -> Result<ObjectIo> {
    Ok(ObjectIo::remote(
        store,
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
    )?)
}
#[tokio::test]
#[ignore = "owned PostgreSQL fixture only, invoked by check-shared-runtime.py --server"]
async fn postgres_server_publication_and_actual_query() -> Result {
    use signal_control::{
        AdministrativeScope, ControlAdministrator, FindingInput, InitializeInput, MigrationInput,
        SharedQuerySource, schema_identity,
    };
    use signal_storage::{
        OperationContext,
        object_cache::MaterializationConfig,
        object_selection::{ObjectSelection, SelectionConfig},
    };
    let fixture_path = std::env::var("SIGNAL_CONTROL_FIXTURE")?;
    let bytes = std::fs::read(fixture_path)?;
    if bytes.len() > 16384 {
        return Err("fixture bounds".into());
    }
    let f: Fixture = serde_json::from_slice(&bytes)?;
    if f.port == 0
        || f.password.is_empty()
        || f.password.len() > 128
        || f.root_der.is_empty()
        || f.wrong_der.is_empty()
    {
        return Err("fixture fields".into());
    }
    let (root, root_driver) = database(&f, "postgres").await?;
    root.batch_execute(&format!("CREATE DATABASE {DATABASE}"))
        .await?;
    root.batch_execute(&format!(
        "GRANT CREATE ON DATABASE {DATABASE} TO signal_control_owner"
    ))
    .await?;
    drop(root);
    root_driver.await??;
    let wal_directory = tempfile::tempdir()?;
    let wal = Arc::new(
        signal_buffer::DurableBuffer::open(signal_buffer::BufferConfig {
            directory: wal_directory.path().join("wal"),
            ..Default::default()
        })
        .await?,
    );
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::from_u128(0xe100),
        generation: Uuid::from_u128(0xe101),
        tenant: "synthetic-shared-server".into(),
        stream: wal.snapshot().stream_id,
        partition_id: Uuid::from_u128(0xe103),
    };
    let admin_scope = AdministrativeScope {
        schema_version: 1,
        store_id: scope.store_id,
        generation: scope.generation,
    };
    let admin = ControlAdministrator::new(
        settings(&f, "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    admin
        .initialize(
            InitializeInput {
                scope: admin_scope.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            context()?,
        )
        .await?;
    admin
        .migrate_catalog(
            MigrationInput {
                scope: admin_scope,
                source_revision: 2,
                source_sha256: schema_identity().1,
            },
            context()?,
        )
        .await?;
    admin.shutdown(context()?).await?;
    let (db, db_driver) = database(&f, DATABASE).await?;
    let backend = Uuid::from_u128(0xe104);
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
        "INSERT INTO signal_control.object_backends VALUES($1,'owned-shared-server-versions')",
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
    db.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    let startup = SharedStartup::new(
        settings(&f, "signal_runtime")?,
        CatalogProfile::Catalog4,
        scope.clone(),
        backend,
        wal.clone(),
    )?;
    assert_eq!(
        startup.verify(context()?).await?.catalog()?.checkpoint()?,
        0
    );
    for (profile, mut candidate_scope, candidate_backend) in [
        (CatalogProfile::RestoredCatalog5, scope.clone(), backend),
        (CatalogProfile::Catalog4, scope.clone(), Uuid::new_v4()),
        (CatalogProfile::Catalog4, scope.clone(), backend),
    ] {
        if profile == CatalogProfile::Catalog4 && candidate_backend == backend {
            candidate_scope.generation = Uuid::new_v4();
        }
        let wrong = SharedStartup::new(
            settings(&f, "signal_runtime")?,
            profile,
            candidate_scope,
            candidate_backend,
            wal.clone(),
        )?;
        let denied = wrong.verify(context()?).await;
        if profile == CatalogProfile::RestoredCatalog5 {
            assert!(matches!(denied, Err(ControlError::Corrupt)));
        } else {
            assert!(matches!(denied, Err(ControlError::Fenced)));
        }
        wrong.shutdown(context()?).await?;
    }
    db.batch_execute("UPDATE signal_control.store SET ready=false")
        .await?;
    assert!(matches!(
        startup.verify(context()?).await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    let control = startup.control();
    let token = control
        .acquire(scope.clone(), Uuid::new_v4(), 15000, context()?)
        .await?;
    let objects = Arc::new(versions::Versions(object_store::memory::InMemory::new()));
    let publisher = SharedPublisher::new(
        control.clone(),
        scope.clone(),
        backend,
        io(objects.clone())?,
        StorageConfig::default(),
        ManifestLimits::default(),
    )?;
    let input: signal_event::IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":chrono::Utc::now().to_rfc3339(),"source":{"type":"synthetic-server"},"message":"actual server shared publication","attributes":{"nested":{"flag":true}}}),
    )?;
    let event = input.normalize(chrono::Utc::now())?;
    let rules = signal_rules::RuleSet::from_yaml_documents(
        [
            "apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: synthetic.server\n  name: Owned test\nspec:\n  severity: high\n  match:\n    all:\n      - field: message\n        contains: shared publication\n  finding:\n    title: Owned test finding\n",
        ],
        signal_rules::RuleLimits::default(),
    )?;
    let mut revision = Vec::new();
    rules.write_revision(
        &mut revision,
        65536,
        &signal_rules::RuleContext::new(Duration::from_secs(5)),
    )?;
    use sha2::Digest;
    let rule_sha: [u8; 32] = sha2::Sha256::digest(&revision).into();
    let findings = rules.evaluate(&event)?;
    assert_eq!(findings.len(), 1);
    let finding = findings[0].clone();
    let finding_bytes = serde_json::to_vec(&finding)?;
    let rows = vec![StoredEvent {
        sequence: 1,
        event: event.clone(),
    }];
    let first_id = Uuid::new_v4();
    let mut first_draft = draft();
    first_draft.id = first_id;
    first_draft.rule_revision = rule_sha;
    first_draft.findings = vec![FindingInput {
        id: finding.id,
        bytes: finding_bytes.clone(),
    }];
    let abandoned = publisher
        .prepare(token.clone(), &rows, draft(), context()?)
        .await?;
    assert_eq!(publisher.metrics().orphan_candidate_results, 0);
    drop(abandoned);
    assert_eq!(publisher.metrics().active, 0);
    assert_eq!(publisher.metrics().orphan_candidate_results, 1);
    let prepared = publisher
        .prepare(token.clone(), &rows, first_draft, context()?)
        .await?;
    let first_request = prepared.request().clone();
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_control.commits", &[])
            .await?
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_control.findings", &[])
            .await?
            .get::<_, i64>(0),
        0
    );
    assert_eq!(publisher.metrics().active, 1);
    assert!(matches!(
        publisher
            .prepare(token.clone(), &rows, draft(), context()?)
            .await,
        Err(SharedError::Control(ControlError::Full))
    ));
    let first = publisher.commit(prepared).await?;
    assert_eq!(first.id, first_id);
    assert_eq!(publisher.metrics().active, 0);
    assert_eq!(publisher.metrics().orphan_candidate_results, 1);
    // A DB commit cannot bless a WAL that lacks the admitted sequence. Once
    // present, its committed but unacknowledged prefix remains replayable.
    assert!(matches!(
        startup.verify(context()?).await,
        Err(ControlError::Corrupt)
    ));
    use signal_protocol::EventSink;
    wal.admit(event.clone()).await?;
    let verified = startup.verify(context()?).await?;
    assert_eq!(verified.catalog()?.checkpoint()?, 1);
    assert_eq!(wal.snapshot().checkpoint, 0);
    let original = context()?;
    let cancelled_start = startup.verify(original.clone()).await?;
    original.cancel();
    assert!(matches!(
        cancelled_start.catalog(),
        Err(ControlError::Cancelled)
    ));
    let short = ControlContext::new(Duration::from_secs(1))?;
    let expiry = short.deadline();
    let expiring = startup.verify(short).await?;
    tokio::time::sleep_until(expiry + Duration::from_millis(1)).await;
    assert!(matches!(expiring.catalog(), Err(ControlError::Timeout)));
    assert_eq!(wal.read_batch(4, 65536).await?.len(), 1);
    wal.ack(1).await?;
    let second_rows = vec![StoredEvent {
        sequence: 2,
        event: event.clone(),
    }];
    let mut second_draft = draft();
    second_draft.previous = Some(first_id);
    second_draft.rule_revision = rule_sha;
    second_draft.findings = vec![FindingInput {
        id: finding.id,
        bytes: finding_bytes.clone(),
    }];
    let prepared = publisher
        .prepare(token.clone(), &second_rows, second_draft, context()?)
        .await?;
    let second = publisher.commit(prepared).await?;
    assert_eq!(verified.catalog()?.checkpoint()?, 1); // never silently rediscover
    wal.admit(event.clone()).await?;
    assert_eq!(
        startup.verify(context()?).await?.catalog()?.checkpoint()?,
        2
    );
    assert_ne!(second.id, first.id);
    assert_eq!(second.cursor, first.cursor); // global first-occurrence finding preserved
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_control.findings", &[])
            .await?
            .get::<_, i64>(0),
        1
    );
    let mut replay = draft();
    replay.id = first_id;
    replay.rule_revision = rule_sha;
    replay.findings = vec![FindingInput {
        id: finding.id,
        bytes: finding_bytes.clone(),
    }];
    let prepared = publisher
        .prepare(token.clone(), &rows, replay, context()?)
        .await?;
    assert_eq!(prepared.request(), &first_request);
    assert_eq!(publisher.commit(prepared).await?, first);
    assert_eq!(
        publisher
            .resolve(token.clone(), first_request, context()?)
            .await?,
        first
    );
    let cache = tempfile::tempdir()?;
    let selection = ObjectSelection::new(
        io(objects.clone())?,
        tokio::runtime::Handle::current(),
        SelectionConfig {
            stream: scope.stream,
            backend,
            storage: StorageConfig::default(),
            manifests: ManifestLimits::default(),
            cache: MaterializationConfig {
                directory: cache.path().join("derived"),
                max_files: 128,
                max_disk_bytes: 64 * 1024 * 1024,
            },
        },
    )?;
    let source = Arc::new(SharedQuerySource::new(
        control.clone(),
        scope.clone(),
        selection,
    )?);
    let engine = signal_query::QueryEngine::with_source(
        signal_query::QueryConfig::default(),
        source.clone(),
    )?;
    let response = engine
        .execute(
            signal_protocol::EventQuery::default(),
            OperationContext::new(Duration::from_secs(5)),
        )
        .await?;
    assert_eq!(response.events.len(), 2);
    assert!(
        response
            .events
            .iter()
            .all(|e| e.message.as_deref() == Some("actual server shared publication"))
    );
    engine
        .shutdown(OperationContext::new(Duration::from_secs(5)))
        .await?;
    drop(engine);
    source
        .shutdown(OperationContext::new(Duration::from_secs(5)))
        .await?;
    drop(source);
    // Uploaded data remains orphan-only when its original operation is cancelled.
    let third_rows = vec![StoredEvent { sequence: 3, event }];
    let mut third = draft();
    third.previous = Some(second.id);
    let budget = context()?;
    let prepared = publisher
        .prepare(token.clone(), &third_rows, third, budget.clone())
        .await?;
    budget.cancel();
    assert!(matches!(
        publisher.commit(prepared).await,
        Err(SharedError::Control(ControlError::Cancelled))
    ));
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_control.commits", &[])
            .await?
            .get::<_, i64>(0),
        2
    );
    let mut stale = draft();
    stale.previous = Some(second.id);
    let prepared = publisher
        .prepare(token, &third_rows, stale, context()?)
        .await?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&scope.partition_id]).await?;
    assert!(matches!(
        publisher.commit(prepared).await,
        Err(SharedError::Control(ControlError::Fenced))
    ));
    assert_eq!(
        db.query_one(
            "SELECT checkpoint FROM signal_control.partitions WHERE id=$1",
            &[&scope.partition_id]
        )
        .await?
        .get::<_, i64>(0),
        2
    );
    // Observe an actual deferred COMMIT before cancelling the caller. A late
    // reply must remain uncertain and resolve only the exact retained request.
    let current = control
        .acquire(scope.clone(), Uuid::new_v4(), 15000, context()?)
        .await?;
    let mut uncertain_draft = draft();
    uncertain_draft.previous = Some(second.id);
    uncertain_draft.rule_revision = rule_sha;
    uncertain_draft.findings = vec![FindingInput {
        id: finding.id,
        bytes: finding_bytes,
    }];
    let budget = context()?;
    let prepared = publisher
        .prepare(
            current.clone(),
            &third_rows,
            uncertain_draft,
            budget.clone(),
        )
        .await?;
    let retained = prepared.request().clone();
    db.batch_execute("CREATE FUNCTION public.synthetic_shared_commit_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(.5); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_shared_commit_pause AFTER INSERT ON signal_control.commits DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_shared_commit_pause()").await?;
    let observer = async {
        tokio::time::timeout(Duration::from_secs(4),async {
            loop {
                let active:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND query='COMMIT' AND wait_event='PgSleep')",&[&DATABASE]).await?.get(0);
                if active { budget.cancel(); return Ok::<(),tokio_postgres::Error>(()); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await
    };
    let (result, observed) = tokio::join!(publisher.commit(prepared), observer);
    observed??;
    assert!(matches!(
        result,
        Err(SharedError::Control(ControlError::Uncertain))
    ));
    let resolved = publisher
        .resolve(current, retained.clone(), context()?)
        .await?;
    assert_eq!(resolved.id, retained.id);
    assert_eq!(resolved.last_sequence, 3);
    assert_eq!(resolved.cursor, first.cursor);
    // An acknowledged local prefix beyond the committed catalog is rejected,
    // even when a host incorrectly acknowledged an extra synthetic WAL row.
    wal.admit(third_rows[0].event.clone()).await?;
    wal.admit(third_rows[0].event.clone()).await?;
    assert_eq!(wal.read_batch(4, 65536).await?.len(), 3);
    wal.ack(4).await?;
    assert!(matches!(
        startup.verify(context()?).await,
        Err(ControlError::Corrupt)
    ));
    db.batch_execute("DROP TRIGGER synthetic_shared_commit_pause ON signal_control.commits; DROP FUNCTION public.synthetic_shared_commit_pause()").await?;
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_control.commits", &[])
            .await?
            .get::<_, i64>(0),
        3
    );
    // Explicit fixture-only global SELECT enrollment; producer EXECUTE rights
    // alone do not authorize the shared reader adapter.
    db.batch_execute("GRANT SELECT ON signal_control.store,signal_control.migrations,signal_control.findings TO signal_runtime").await?;
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let policy = signal_protocol::access::AccessPolicy {
        schema_version: 1,
        roles: vec![signal_protocol::access::Role {
            id: "synthetic-feed".into(),
            permissions: vec![signal_protocol::access::Permission {
                operation: signal_protocol::access::Operation::ReadFindingsFeed,
                scope: signal_protocol::access::ResourceScope::all(),
            }],
        }],
        bindings: vec![signal_protocol::access::SubjectBinding {
            issuer: "synthetic".into(),
            subject: "reader".into(),
            roles: vec!["synthetic-feed".into()],
        }],
    }
    .compile()?;
    let grant = Arc::new(policy.grant(
        signal_protocol::access::AuthenticatedIdentity::from_verified_backend(
            "synthetic".into(),
            "reader".into(),
            at,
            at + 60,
        )?,
        at,
    )?);
    let feed = signal_server::shared_feed::SharedFindingsFeed::new(
        control.clone(),
        scope.store_id,
        scope.generation,
        1,
        65536,
    )?;
    let query = signal_protocol::findings_feed::FindingsFeedQuery {
        after: signal_protocol::findings_feed::FindingsAfter::Begin,
        limit: 1,
    };
    let bytes = feed.read(query, grant.clone(), context()?).await?;
    let response: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(response["next_cursor"], first.cursor);
    assert_eq!(response["has_more"], false);
    let original: Vec<u8> = db
        .query_one(
            "SELECT content FROM signal_control.findings ORDER BY position LIMIT 1",
            &[],
        )
        .await?
        .try_get(0)?;
    assert!(bytes.windows(original.len()).any(|chunk| chunk == original));
    let tiny = signal_server::shared_feed::SharedFindingsFeed::new(
        control.clone(),
        scope.store_id,
        scope.generation,
        1,
        signal_protocol::findings_feed::FINDINGS_FEED_EMPTY_BYTES,
    )?;
    assert!(matches!(
        tiny.read(query, grant.clone(), context()?).await,
        Err(signal_server::shared_feed::SharedFeedError::PageBudget)
    ));
    assert_eq!(tiny.metrics().rejected, 1);
    assert_eq!(tiny.metrics().active_callers, 0);
    let mut foreign = query;
    foreign.after = signal_protocol::findings_feed::FindingsAfter::Cursor(
        signal_protocol::findings_feed::FindingsCursor::initial(Uuid::new_v4())?,
    );
    assert!(matches!(
        feed.read(foreign, grant, context()?).await,
        Err(signal_server::shared_feed::SharedFeedError::CursorStreamMismatch)
    ));
    assert_eq!(feed.metrics().rejected, 1);
    assert_eq!(feed.metrics().active_callers, 0);
    eprintln!("phase: actual-server-shared-findings-feed-wire-qualified");
    publisher.shutdown(context()?).await?;
    startup.shutdown(context()?).await?;
    wal.shutdown().await?;
    drop(db);
    db_driver.await??;
    recovery_support::qualify(&f).await?;
    scoped_recovery_support::qualify(&f).await?;
    eprintln!("phase: actual-server-explicit-startup-wal-authority-qualified");
    eprintln!("phase: actual-server-shared-publication-replay-query-and-orphan-fencing-qualified");
    Ok(())
}

#[tokio::test]
async fn rejected_publisher_retains_exact_codec_and_io_for_host_drain() -> Result {
    let control = Arc::new(ControlClient::catalog(
        ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse()?,
            1,
            "unreachable".into(),
            "unreachable".into(),
            b"synthetic-not-a-secret".to_vec(),
        )?,
    )?);
    let storage = StorageConfig::default();
    let limits = ManifestLimits::default();
    let io = Arc::new(ObjectIo::remote(
        Arc::new(object_store::memory::InMemory::new()),
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
    )?);
    let codec = Arc::new(signal_storage::object_codec::ObjectCodec::new(
        storage.clone(),
        limits,
    )?);
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::new_v4(),
        generation: Uuid::new_v4(),
        tenant: "synthetic".into(),
        stream: Uuid::new_v4(),
        partition_id: Uuid::new_v4(),
    };
    let mut mismatch = limits;
    mismatch.events -= 1;
    assert!(matches!(
        SharedPublisher::with_workers(
            control.clone(),
            scope.clone(),
            Uuid::new_v4(),
            io.clone(),
            codec.clone(),
            storage.clone(),
            mismatch
        ),
        Err(SharedError::Control(ControlError::Invalid))
    ));
    assert!(!io.metrics().closed);
    assert!(!codec.metrics().closed);
    assert_eq!(Arc::strong_count(&io), 1);
    assert_eq!(Arc::strong_count(&codec), 1);
    let publisher = SharedPublisher::with_workers(
        control.clone(),
        scope,
        Uuid::new_v4(),
        io.clone(),
        codec.clone(),
        storage,
        limits,
    )?;
    publisher.shutdown(context()?).await?;
    codec
        .shutdown(signal_storage::OperationContext::new(Duration::from_secs(
            5,
        )))
        .await?;
    io.shutdown(signal_storage::OperationContext::new(Duration::from_secs(
        5,
    )))
    .await?;
    control.shutdown(context()?).await?;
    assert!(codec.metrics().closed);
    assert!(io.metrics().closed);
    Ok(())
}
