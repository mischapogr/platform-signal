//! Actual native admitted rows, owner PostgreSQL and WAL; emulated object versions.
use super::{DB, Fixture, Result, context, versions};
use signal_buffer::{BufferConfig, DurableBuffer};
use signal_control::{ConnectionSettings, ControlClient, ControlError, ProducerEnrollment};
use signal_findings::DerivedFinding;
use signal_server::{
    shared::{PublicationDraft, SharedPublisher},
    shared_recovery::{RECOVERY_BYTES, SharedRecovery},
    shared_scoped::ScopedPublicationDraft,
};
use signal_storage::{
    StorageConfig, StoredEvent,
    object_io::{ObjectIo, ObjectIoLimits},
    object_manifest::ManifestLimits,
};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
use uuid::Uuid;

fn connection(f: &Fixture) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
        f.port,
        DB.into(),
        "signal_runtime".into(),
        f.password.as_bytes().to_vec(),
    )
}
fn publisher(
    control: Arc<ControlClient>,
    producer: &ProducerEnrollment,
    backend: Uuid,
    objects: &Arc<versions::Versions>,
) -> Result<Arc<SharedPublisher>> {
    Ok(Arc::new(SharedPublisher::new(
        control,
        producer.scope.clone(),
        backend,
        ObjectIo::remote(
            objects.clone(),
            tokio::runtime::Handle::current(),
            ObjectIoLimits::default(),
        )?,
        StorageConfig::default(),
        ManifestLimits::default(),
    )?))
}

pub(super) async fn qualify(
    f: &Fixture,
    producer: &ProducerEnrollment,
    identity: &signal_ingest::identity::IdentityBackend,
    wal: Arc<DurableBuffer>,
    cfg: BufferConfig,
) -> Result {
    let rows: Vec<StoredEvent> = wal
        .read_batch(2, 65536)
        .await?
        .into_iter()
        .map(|row| StoredEvent {
            sequence: row.sequence,
            event: row.event,
        })
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].sequence, producer.wal_floor);
    assert_eq!(rows[1].sequence, producer.wal_floor + 1);
    // The parent established exclusive native admission above the original floor
    // using the real configured provider. Neither persisted attributes nor the
    // freshly reopened WAL itself supplies authentication evidence.
    let rules = signal_rules::RuleSet::from_yaml_documents(
        [
            "apiVersion: signal.dev/v1\nkind: Rule\nmetadata:\n  id: native.scope\n  name: Native scope fixture\nspec:\n  severity: high\n  match:\n    all:\n      - field: message\n        contains: native admission\n  finding:\n    title: Native scope fixture\n",
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
    let findings = rows
        .iter()
        .map(|row| rules.evaluate(&row.event))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert!(findings.iter().all(|f| f.len() == 1));
    let legacy = &findings[0][0];
    let native = &findings[1][0];
    let legacy_bytes = serde_json::to_vec(legacy)?;
    let plan = PublicationDraft {
        schema_version: 1,
        id: Uuid::new_v4(),
        previous: None,
        rule_revision: sha2::Sha256::digest(revision).into(),
        normalizer_revision: "native-fixture-v1".into(),
        states: vec![],
        findings: vec![signal_control::FindingInput {
            id: legacy.id,
            bytes: legacy_bytes.clone(),
        }],
        work: vec![],
        receipts: vec![],
    };
    // Even a host attempting to claim the old row cannot cross the original floor.
    let old = DerivedFinding::from_event(legacy.clone(), &rows[0].event, true)?
        .into_scoped(producer.scope_generation)?;
    assert!(
        ScopedPublicationDraft::from_host(
            plan.clone(),
            producer,
            &rows,
            vec![(rows[0].sequence, old)]
        )
        .is_err()
    );
    let mut spoofed = rows[1].event.clone();
    spoofed
        .resource
        .as_mut()
        .ok_or("resource missing")?
        .account_id = Some("b".into());
    let spoofed = DerivedFinding::from_event(native.clone(), &spoofed, true)?
        .into_scoped(producer.scope_generation)?;
    assert!(
        ScopedPublicationDraft::from_host(
            plan.clone(),
            producer,
            &rows,
            vec![(rows[1].sequence, spoofed)]
        )
        .is_err()
    );
    let sealed = DerivedFinding::from_event(native.clone(), &rows[1].event, true)?
        .into_scoped(producer.scope_generation)?;
    let plan =
        ScopedPublicationDraft::from_host(plan, producer, &rows, vec![(rows[1].sequence, sealed)])?;
    assert_eq!(wal.snapshot().checkpoint, 0);
    assert!(wal.read_recovery(context()?.deadline()).await?.is_none());

    let mut pg = tokio_postgres::Config::new();
    pg.host("127.0.0.1")
        .port(f.port)
        .dbname(DB)
        .user("postgres")
        .password(&f.password);
    let (db, driver) = timeout(Duration::from_secs(2), pg.connect(tokio_postgres::NoTls)).await??;
    let driver = tokio::spawn(driver);
    let result: Result = async {
        let backend = Uuid::new_v4();
        timeout(Duration::from_secs(2), db.execute(
            "INSERT INTO signal_control.principals VALUES('signal_runtime',$1,$2,$3)",
            &[&producer.scope.tenant, &producer.scope.stream, &producer.scope.partition_id],
        )).await??;
        timeout(Duration::from_secs(2), db.execute(
            "INSERT INTO signal_control.object_backends VALUES($1,'owned-native-fixture-versions')", &[&backend],
        )).await??;
        timeout(Duration::from_secs(2), db.execute(
            "INSERT INTO signal_control.object_scopes VALUES($1,$2,$3)",
            &[&producer.scope.partition_id, &backend, &format!("query/{}/", producer.scope.stream)],
        )).await??;
        // Explicit fixture readiness for the existing library. This is never a
        // claim that Standard Main has performed its complete startup ceremony.
        timeout(Duration::from_secs(2), db.batch_execute(
            "GRANT USAGE ON SCHEMA signal_control,signal_finding_scope TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) TO signal_runtime; UPDATE signal_control.store SET ready=true"
        )).await??;
        let control = Arc::new(ControlClient::catalog(connection(f)?)?);
        let token = control.acquire(producer.scope.clone(), Uuid::new_v4(), 60000, context()?).await?;
        let objects = Arc::new(versions::Versions(object_store::memory::InMemory::new()));
        let recovery = SharedRecovery::new(publisher(control.clone(), producer, backend, &objects)?, wal.clone())?;
        let prepared = recovery.prepare_scoped(token.clone(), plan, 2, context()?).await?;
        let original = prepared.scoped_request().ok_or("scoped request missing")?.clone();
        assert_eq!(original.publication().findings.len(), 2);
        let original_json = serde_json::to_value(&original)?;
        assert_eq!(original_json["claims"]["startup"], serde_json::json!(producer.startup));
        assert_eq!(original_json["claims"]["wal_floor"], 1);
        assert_eq!(original_json["claims"]["findings"].as_array().ok_or("claims missing")?.len(), 1);
        assert_eq!(original_json["claims"]["findings"][0]["sequence"], 2);
        let native_bytes = original.publication().findings.iter().find(|f| f.id == native.id)
            .ok_or("native finding missing")?.bytes.clone();
        let saved = wal.read_recovery(context()?.deadline()).await?.ok_or("original request missing")?;
        assert_eq!(wal.snapshot().checkpoint, 0);
        let empty = timeout(Duration::from_secs(2), db.query_one(
            "SELECT (SELECT count(*) FROM signal_control.findings), (SELECT count(*) FROM signal_finding_scope.facts)", &[]
        )).await??;
        assert_eq!(empty.get::<_, i64>(0), 0);
        assert_eq!(empty.get::<_, i64>(1), 0);
        // Lose the prepared capability and restart the real WAL. Reconciliation
        // uses the retained original request, not regenerated scope metadata.
        drop(prepared);
        drop(recovery);
        control.shutdown(context()?).await?;
        wal.shutdown().await?;
        let reopened = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
        assert_eq!(reopened.read_recovery(context()?.deadline()).await?.ok_or("request lost on reopen")?, saved);
        let control = Arc::new(ControlClient::catalog(connection(f)?)?);
        let recovery = SharedRecovery::new(publisher(control.clone(), producer, backend, &objects)?, reopened.clone())?;
        let committed = recovery.resume(token.clone(), context()?).await?.ok_or("publication not reconciled")?;
        assert_eq!(committed.id, original.publication().id);
        assert_eq!(committed.first_sequence, 1);
        assert_eq!(committed.last_sequence, 2);
        let retained_request = timeout(Duration::from_secs(2), db.query_one(
            "SELECT r.claims,c.manifest FROM signal_finding_scope.requests r JOIN signal_control.commits c ON c.partition_id=r.partition_id AND c.id=r.commit_id WHERE r.partition_id=$1 AND r.commit_id=$2",
            &[&producer.scope.partition_id, &original.publication().id],
        )).await??;
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&retained_request.get::<_, Vec<u8>>(0))?, original_json["claims"]);
        assert_eq!(retained_request.get::<_, Vec<u8>>(1), original.publication().manifest);
        assert_eq!(reopened.snapshot().checkpoint, 2);
        assert!(reopened.read_recovery(context()?.deadline()).await?.is_none());
        assert!(recovery.resume(token, context()?).await?.is_none());
        let retained = timeout(Duration::from_secs(2), db.query(
            "SELECT id,content FROM signal_control.findings ORDER BY position", &[]
        )).await??;
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].get::<_, Uuid>(0), legacy.id);
        assert_eq!(retained[0].get::<_, Vec<u8>>(1), legacy_bytes);
        assert_eq!(retained[1].get::<_, Uuid>(0), native.id);
        assert_eq!(retained[1].get::<_, Vec<u8>>(1), native_bytes);
        let facts = timeout(Duration::from_secs(2), db.query(
            "SELECT finding_id,scope_generation,event_id,source,account,resource FROM signal_finding_scope.facts", &[]
        )).await??;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].get::<_, Uuid>(0), native.id);
        assert_eq!(facts[0].get::<_, Uuid>(1), producer.scope_generation);
        assert_eq!(facts[0].get::<_, Uuid>(2), rows[1].event.id);
        assert_eq!(facts[0].get::<_, String>(3), "audit");
        assert_eq!(facts[0].get::<_, String>(4), "a");
        assert_eq!(facts[0].get::<_, String>(5), "host-a");
        timeout(Duration::from_secs(2), db.batch_execute("SET ROLE signal_runtime")).await??;
        let denied = timeout(Duration::from_secs(2), db.query("SELECT * FROM signal_finding_scope.facts", &[])).await?;
        assert_eq!(denied.err().and_then(|e| e.code().cloned()), Some(tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE));
        timeout(Duration::from_secs(2), db.batch_execute("RESET ROLE")).await??;
        let binding=signal_control::ScopedFindingsBinding {store:producer.scope.store_id,generation:producer.scope.generation,scope_generation:producer.scope_generation,schema_owner:"signal_control_owner".into()};
        let connection=|user:&str| signal_control::ConnectionSettings::fixture_loopback("127.0.0.1".parse().map_err(|_|ControlError::Invalid)?,f.port,super::DB.into(),user.into(),f.password.as_bytes().to_vec());
        let execute_only=signal_control::ControlClient::catalog(connection("signal_runtime")?)?;
        assert!(matches!(execute_only.inspect_existing_finding_scope(producer.scope.clone(),binding.clone(),context()?).await,Err(ControlError::Fenced)));
        execute_only.shutdown(context()?).await?;
        let owner_reader=signal_control::ControlClient::catalog(super::settings(f)?)?;
        assert!(matches!(owner_reader.inspect_existing_finding_scope(producer.scope.clone(),binding.clone(),context()?).await,Err(ControlError::Fenced)));
        owner_reader.shutdown(context()?).await?;
        timeout(Duration::from_secs(2),db.batch_execute("CREATE ROLE signal_bootstrap_reader LOGIN; GRANT USAGE ON SCHEMA signal_control,signal_finding_scope TO signal_bootstrap_reader; GRANT SELECT ON signal_control.store,signal_control.migrations,signal_control.findings,signal_control.partitions,signal_finding_scope.activation,signal_finding_scope.profile,signal_finding_scope.producers,signal_finding_scope.facts,signal_finding_scope.requests TO signal_bootstrap_reader")).await??;
        timeout(Duration::from_secs(2),db.execute("SELECT set_config('signal_fixture.password',$1,false)",&[&f.password])).await??;
        timeout(Duration::from_secs(2),db.batch_execute("DO $$ BEGIN EXECUTE format('ALTER ROLE signal_bootstrap_reader PASSWORD %L',current_setting('signal_fixture.password')); END $$")).await??;
        let inspector=signal_control::ControlClient::catalog(connection("signal_bootstrap_reader")?)?;
        for kind in 0..3 {
            let mut wrong=producer.scope.clone();
            match kind {0=>wrong.tenant="foreign".into(),1=>wrong.stream=Uuid::new_v4(),_=>wrong.partition_id=Uuid::new_v4()};
            assert!(matches!(inspector.inspect_existing_finding_scope(wrong,binding.clone(),context()?).await,Err(ControlError::Fenced)));
        }
        let mut stale=binding.clone();stale.scope_generation=Uuid::new_v4();
        assert!(matches!(inspector.inspect_existing_finding_scope(producer.scope.clone(),stale,context()?).await,Err(ControlError::Fenced)));
        timeout(Duration::from_secs(2),db.batch_execute("GRANT UPDATE ON signal_finding_scope.producers TO signal_bootstrap_reader")).await??;
        assert!(matches!(inspector.inspect_existing_finding_scope(producer.scope.clone(),binding.clone(),context()?).await,Err(ControlError::Fenced)));
        timeout(Duration::from_secs(2),db.batch_execute("REVOKE UPDATE ON signal_finding_scope.producers FROM signal_bootstrap_reader")).await??;
        timeout(Duration::from_secs(2),db.batch_execute("GRANT EXECUTE ON FUNCTION signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) TO signal_bootstrap_reader")).await??;
        assert!(matches!(inspector.inspect_existing_finding_scope(producer.scope.clone(),binding.clone(),context()?).await,Err(ControlError::Fenced)));
        timeout(Duration::from_secs(2),db.batch_execute("REVOKE EXECUTE ON FUNCTION signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) FROM signal_bootstrap_reader")).await??;
        let cancelled=context()?;
        let lost=inspector.inspect_existing_finding_scope(producer.scope.clone(),binding.clone(),cancelled.clone()).await?;
        cancelled.cancel();assert!(matches!(lost.binding(),Err(ControlError::Cancelled)));
        let pin=inspector.inspect_existing_finding_scope(producer.scope.clone(),binding.clone(),context()?).await?;
        println!("phase: read-only-original-enrollment-bootstrap-no-owner-or-mutation-qualified");
        assert_eq!(pin.binding()?.producer.as_ref().ok_or("producer missing")?.wal_floor,1);
        assert_eq!(pin.binding()?.checkpoint,Some(2));
        assert_eq!(reopened.snapshot().last_sequence,2);
        assert_eq!(reopened.snapshot().checkpoint,2);
        assert_eq!(reopened.snapshot().recovery_bytes,0);
        let renewed=signal_server::shared_admission::SharedAdmission::new(reopened.clone(),pin)?;
        assert_eq!(renewed.enrollment().wal_floor,1);
        assert_eq!(renewed.enrollment().startup,producer.startup);
        assert_eq!(renewed.admission_floor(),2);
        use signal_protocol::EventSink;
        let event:signal_event::IngestEvent=serde_json::from_value(super::input(803,"a"))?;
        assert_eq!(renewed.admit(event.clone().normalize(chrono::Utc::now())?).await,Err(signal_protocol::AdmissionError::Unavailable));
        let live=super::grant(identity,"producer").await?;
        renewed.admit_with_grant(event.normalize(chrono::Utc::now())?,&live,std::time::Instant::now()+Duration::from_secs(1)).await?;
        let new_rows=reopened.read_batch(1,65536).await?;
        assert_eq!(new_rows.len(),1);assert_eq!(new_rows[0].sequence,3);assert_eq!(new_rows[0].event.id,Uuid::from_u128(803));
        assert_eq!(reopened.snapshot().checkpoint,2);
        let held=inspector.inspect_existing_finding_scope(producer.scope.clone(),binding.clone(),context()?).await?;
        assert!(matches!(signal_server::shared_admission::SharedAdmission::new(reopened.clone(),held),Err(ControlError::Fenced)));
        inspector.shutdown(context()?).await?;
        println!("phase: fully-reconciled-native-WAL-restart-future-only-admission-qualified");
        super::scoped_read::qualify(f,producer,identity,&db,legacy,native).await?;
        control.shutdown(context()?).await?;
        reopened.shutdown().await?;
        Ok(())
    }.await;
    drop(db);
    timeout(Duration::from_secs(2), driver).await???;
    result?;
    println!(
        "phase: actual-native-http-scoped-publication-legacy-unknown-original-request-resume-qualified"
    );
    Ok(())
}
