//! Offline provisioning/oracle for the actual Standard executable process fixture.
//! Synthetic owned PostgreSQL and persistent S3 protocol simulation, never AWS proof.
use signal_buffer::{BufferConfig, DurableBuffer};
use signal_control::{
    AdministrativeScope, ConnectionSettings, ControlAdministrator, ControlContext,
    FindingScopeAdministrator, FindingScopeLimits, FindingScopeProfile, InitializeInput,
    MigrationInput, ProducerEnrollment, Scope, schema_identity,
};
use signal_server::shared_recovery::RECOVERY_BYTES;
use std::{fs, path::PathBuf, time::Duration};
use tokio::time::timeout;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DB: &str = "signal_standard_main";
#[path = "support/standard_restore.rs"]
mod standard_restore;
#[derive(serde::Deserialize)]
struct Fixture {
    port: u16,
    password: String,
    root_der: String,
}
fn context() -> std::result::Result<ControlContext, signal_control::ControlError> {
    ControlContext::new(Duration::from_secs(5))
}
#[tokio::test]
#[ignore = "owned PostgreSQL TLS, S3 and native provider launched by standard-main-process.py"]
async fn standard_offline_fixture() -> Result {
    let fixture = PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?);
    assert!(fs::metadata(&fixture)?.len() <= 4096);
    let f: Fixture = serde_json::from_slice(&fs::read(fixture)?)?;
    let root = PathBuf::from(std::env::var("SIGNAL_STANDARD_ROOT")?);
    let phase = std::env::var("SIGNAL_STANDARD_PHASE")?;
    let mut pg = tokio_postgres::Config::new();
    pg.host("127.0.0.1")
        .port(f.port)
        .user("postgres")
        .password(&f.password);
    if phase == "prepare" {
        let (db, driver) =
            timeout(Duration::from_secs(2), pg.connect(tokio_postgres::NoTls)).await??;
        let driver = tokio::spawn(driver);
        timeout(
            Duration::from_secs(2),
            db.batch_execute("CREATE DATABASE signal_standard_main"),
        )
        .await??;
        timeout(
            Duration::from_secs(2),
            db.batch_execute(
                "GRANT CREATE ON DATABASE signal_standard_main TO signal_control_owner",
            ),
        )
        .await??;
        drop(db);
        timeout(Duration::from_secs(2), driver).await???;
    }
    pg.dbname(if phase == "verify_restored" {
        "signal_standard_restore"
    } else {
        DB
    });
    let (db, driver) = timeout(Duration::from_secs(2), pg.connect(tokio_postgres::NoTls)).await??;
    let driver = tokio::spawn(driver);
    let result:Result=async {
        if phase=="prepare" && std::env::var("SIGNAL_STANDARD_AUDIT").as_deref()==Ok("true") {
            use std::os::unix::fs::PermissionsExt;
            fs::create_dir(root.join("audit-outbox"))?;
            fs::set_permissions(root.join("audit-outbox"),fs::Permissions::from_mode(0o700))?;
            let context=signal_collector_sdk::ExtensionContext::new(tokio_util::sync::CancellationToken::new(),Duration::from_secs(5))?;
            let outbox=signal_collector_sdk::audit::outbox::AuditOutbox::open(&root.join("audit-outbox"),context).await?;
            drop(outbox);
        }
        if phase=="verify_restored" {
            let row=timeout(Duration::from_secs(2),db.query_one("SELECT (SELECT count(*) FROM signal_control.findings),(SELECT count(*) FROM signal_finding_scope.facts),(SELECT checkpoint FROM signal_control.partitions WHERE kind='pipeline'),(SELECT wal_floor FROM signal_finding_scope.producers),(SELECT feed_position FROM signal_control.partitions WHERE kind='notification')",&[])).await??;
            assert_eq!(row.get::<_,i64>(0),3);assert_eq!(row.get::<_,i64>(1),3);assert_eq!(row.get::<_,i64>(2),3);assert_eq!(row.get::<_,i64>(3),0);assert_eq!(row.get::<_,i64>(4),2);
            let wal=DurableBuffer::open_with_recovery(BufferConfig{directory:root.join("restored-server/wal"),..Default::default()},RECOVERY_BYTES).await?;
            let doc:serde_json::Value=serde_json::from_slice(&fs::read(root.join("restored-shared.json"))?)?;
            assert_eq!(wal.snapshot().stream_id,serde_json::from_value::<Uuid>(doc["scope"]["stream"].clone())?);
            assert_eq!(wal.snapshot().last_sequence,3);assert_eq!(wal.snapshot().checkpoint,3);assert!(wal.read_recovery(context()?.deadline()).await?.is_none());wal.shutdown().await?;
            println!("phase: Standard-restored-native-publication-original-WAL-floor-and-private-cursor-qualified");return Ok(());
        }
        if phase=="restore_scope" {standard_restore::qualify(&db,&f,&root).await?;return Ok(());}
        if phase=="verify_audit_empty" {
            let row=timeout(Duration::from_secs(2),db.query_one("SELECT (SELECT count(*) FROM signal_control.findings),(SELECT count(*) FROM signal_finding_scope.facts),(SELECT checkpoint FROM signal_control.partitions WHERE kind='pipeline'),(SELECT wal_floor FROM signal_finding_scope.producers)",&[])).await??;
            for column in 0..4 {assert_eq!(row.get::<_,i64>(column),0);}
            let wal=DurableBuffer::open_with_recovery(BufferConfig{directory:root.join("server/wal"),..Default::default()},RECOVERY_BYTES).await?;
            assert_eq!(wal.snapshot().last_sequence,0);assert_eq!(wal.snapshot().checkpoint,0);assert!(wal.read_recovery(context()?.deadline()).await?.is_none());wal.shutdown().await?;
            println!("phase: Standard-audit-lifecycle-original-empty-DB-WAL-floor-checkpoint-qualified");return Ok(());
        }
        if phase=="crash_lock" {
            timeout(Duration::from_secs(2),db.batch_execute("BEGIN; LOCK TABLE signal_finding_scope.facts IN ACCESS EXCLUSIVE MODE")).await??;
            let until=tokio::time::Instant::now()+Duration::from_secs(12);
            fs::write(root.join("crash-lock-ready"),b"held")?;
            while tokio::time::Instant::now()<until {
                timeout(Duration::from_secs(1),db.batch_execute("SELECT pg_stat_clear_snapshot()")).await??;
                let row=timeout(Duration::from_secs(1),db.query_one("SELECT count(*) FROM pg_stat_activity WHERE usename='signal_standard_producer' AND wait_event_type='Lock'",&[])).await??;
                if row.get::<_,i64>(0)>0 {fs::write(root.join("crash-commit-blocked"),b"observed")?;break;}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            tokio::time::sleep_until(until).await;
            timeout(Duration::from_secs(2),db.batch_execute("ROLLBACK")).await??;
            println!("phase: Standard-original-publication-owned-lock-released");return Ok(());
        }
        if matches!(phase.as_str(),"verify_crash_saved"|"verify_crash_recovered") {
            let recovered=phase=="verify_crash_recovered";
            let expected=if recovered {3i64}else{2};
            let row=timeout(Duration::from_secs(2),db.query_one("SELECT (SELECT count(*) FROM signal_control.findings),(SELECT count(*) FROM signal_finding_scope.facts),(SELECT checkpoint FROM signal_control.partitions WHERE kind='pipeline'),(SELECT wal_floor FROM signal_finding_scope.producers)",&[])).await??;
            for column in 0..3 {assert_eq!(row.get::<_,i64>(column),expected);}
            assert_eq!(row.get::<_,i64>(3),0);
            let wal=DurableBuffer::open_with_recovery(BufferConfig{directory:root.join("server/wal"),..Default::default()},RECOVERY_BYTES).await?;
            assert_eq!(wal.snapshot().last_sequence,3);assert_eq!(wal.snapshot().checkpoint,expected as u64);
            let record=wal.read_recovery(context()?.deadline()).await?;
            if recovered {
                assert!(record.is_none());
                let saved:serde_json::Value=serde_json::from_slice(&fs::read(root.join("crash-saved.json"))?)?;
                let request:serde_json::Value=saved["entry"]["phase"]["request"]["publication"].clone();
                let id:Uuid=serde_json::from_value(request["id"].clone())?;
                let original:Vec<u8>=serde_json::from_value(request["manifest"].clone())?;
                let rows=timeout(Duration::from_secs(2),db.query("SELECT first_sequence,last_sequence,manifest FROM signal_control.commits WHERE id=$1",&[&id])).await??;
                assert_eq!(rows.len(),1);assert_eq!(rows[0].get::<_,i64>(0),3);assert_eq!(rows[0].get::<_,i64>(1),3);assert_eq!(rows[0].get::<_,Vec<u8>>(2),original);
                println!("phase: Standard-original-saved-request-manifest-once-DB-WAL-checkpoint3-qualified");
            } else {
                let record=record.ok_or("saved original request absent")?;
                let entry:serde_json::Value=serde_json::from_slice(&record.bytes)?;
                assert_eq!(entry["schema_version"],2);assert_eq!(entry["first"],3);assert_eq!(entry["last"],3);assert_eq!(entry["phase"]["state"],"scoped_prepared");
                fs::write(root.join("crash-saved.json"),serde_json::to_vec(&serde_json::json!({"entry":entry,"record_sha256":record.sha256}))?)?;
                println!("phase: Standard-SIGKILL-original-prepared-request-retained-WAL3-DB-checkpoint2-qualified");
            }
            wal.shutdown().await?;return Ok(());
        }
        if matches!(phase.as_str(),"verify_unprepared_before"|"verify_unprepared_after") {
            let row=timeout(Duration::from_secs(2),db.query_one("SELECT (SELECT count(*) FROM signal_control.findings),(SELECT count(*) FROM signal_finding_scope.facts),(SELECT checkpoint FROM signal_control.partitions WHERE kind='pipeline'),(SELECT wal_floor FROM signal_finding_scope.producers)",&[])).await??;
            for column in 0..3 {assert_eq!(row.get::<_,i64>(column),3);}assert_eq!(row.get::<_,i64>(3),0);
            let wal=DurableBuffer::open_with_recovery(BufferConfig{directory:root.join("server/wal"),..Default::default()},RECOVERY_BYTES).await?;
            let snapshot=wal.snapshot();assert_eq!(snapshot.last_sequence,4);assert_eq!(snapshot.checkpoint,3);assert_eq!(snapshot.depth,1);
            assert!(wal.read_recovery(context()?.deadline()).await?.is_none());
            let rows=wal.read_batch_at(1,1048576,context()?.deadline()).await?;assert_eq!(rows.len(),1);assert_eq!(rows[0].sequence,4);
            let retained=serde_json::json!({"stream":snapshot.stream_id,"checkpoint":snapshot.checkpoint,"last_sequence":snapshot.last_sequence,"event":rows[0].event});
            if phase=="verify_unprepared_before" {
                fs::write(root.join("unprepared-before.json"),serde_json::to_vec(&retained)?)?;
                println!("phase: Standard-native-SIGKILL-unprepared-WAL4-checkpoint3-no-recovery-qualified");
            } else {
                let original:serde_json::Value=serde_json::from_slice(&fs::read(root.join("unprepared-before.json"))?)?;assert_eq!(retained,original);
                fs::write(root.join("unprepared-after.json"),serde_json::to_vec(&retained)?)?;
                println!("phase: Standard-unprepared-native-restart-held-original-event-floor-checkpoints-unchanged-qualified");
            }
            wal.shutdown().await?;return Ok(());
        }
        if phase=="restore_scope_stage" {
            use sha2::{Digest,Sha256};
            use signal_control::{CanonicalObjectRef,PostgresStoppedRestore,RestoreConsumers,RestoreDestination,RestoreFuture,RestoreObject,RestoreChallenge,RestoreConsumerCursor,ReconciledConsumers,StoppedRestoreBackend};
            use std::{collections::BTreeMap,sync::Arc};
            struct Consumers;
            impl RestoreConsumers for Consumers {
                fn reconcile<'a>(&'a self,challenge:&'a RestoreChallenge,expected:&'a [RestoreConsumerCursor],ctx:ControlContext)->RestoreFuture<'a,ReconciledConsumers>{Box::pin(async move{ctx.check()?;if !expected.is_empty(){return Err(signal_control::ControlError::Fenced)}Ok(ReconciledConsumers{challenge:challenge.clone(),consumers:vec![]})})}
            }
            let document:serde_json::Value=serde_json::from_slice(&fs::read(root.join("shared.json"))?)?;
            let scope:Scope=serde_json::from_value(document["scope"].clone())?;
            let authority=AdministrativeScope{schema_version:1,store_id:scope.store_id,generation:scope.generation};
            let mut objects=BTreeMap::new();
            for row in timeout(Duration::from_secs(2),db.query("SELECT backend_id,manifest FROM signal_control.commits ORDER BY id",&[])).await?? {
                let backend_id:Uuid=row.get(0);let bytes:Vec<u8>=row.get(1);assert!(bytes.len()<=262144);
                let manifest:signal_storage::object_manifest::QueryManifest=serde_json::from_slice(&bytes)?;
                for reference in manifest.files.iter().map(|file|&file.object).chain(manifest.previous.iter().map(|previous|&previous.object)) {
                    let object=CanonicalObjectRef{schema_version:1,backend_id,key:reference.key.clone(),version:reference.version.clone().ok_or("original object version")?};
                    objects.insert(object.digest()?,RestoreObject{object,sha256:reference.sha256,bytes:reference.bytes});
                }
            }
            assert!(!objects.is_empty());let objects:Vec<_>=objects.into_values().collect();
            let destination=RestoreDestination{id:Uuid::new_v4(),credential_binding_sha256:Sha256::digest(b"separately owned stage-only destination credential").into()};
            let connection=ConnectionSettings::fixture_loopback("127.0.0.1".parse()?,f.port,DB.into(),"signal_migrator".into(),f.password.as_bytes().to_vec())?;
            // Explicit owner quiescence after the parent reaps actual Standard.
            timeout(Duration::from_secs(2),db.batch_execute("UPDATE signal_control.store SET ready=false; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL")).await??;
            let plain=PostgresStoppedRestore::catalog(connection.clone(),"signal_control_owner".into(),authority.clone(),destination.clone(),objects.clone(),Arc::new(Consumers))?;
            assert!(matches!(plain.stage(context()?).await,Err(signal_control::ControlError::Corrupt)));plain.shutdown(context()?).await?;
            let restore=PostgresStoppedRestore::scoped_catalog(connection,"signal_control_owner".into(),authority,destination,objects,Arc::new(Consumers))?;
            let original=restore.stage(context()?).await?;assert_eq!(original.feed_position,2);assert_eq!(original.source_cursors.len(),1);assert_eq!(original.source_cursors[0].checkpoint,2);
            timeout(Duration::from_secs(2),db.batch_execute("UPDATE signal_finding_scope.profile SET used_rows=used_rows+1")).await??;
            assert!(matches!(restore.stage(context()?).await,Err(signal_control::ControlError::Corrupt)));
            timeout(Duration::from_secs(2),db.batch_execute("UPDATE signal_finding_scope.profile SET used_rows=used_rows-1")).await??;
            assert_eq!(restore.stage(context()?).await?,original);
            fs::write(root.join("scoped-restore-stage.json"),serde_json::to_vec(&original)?)?;
            restore.shutdown(context()?).await?;
            timeout(Duration::from_secs(2),db.batch_execute("UPDATE signal_control.store SET ready=true")).await??;
            println!("phase: Standard-populated-scoped-restore-stage-core-only-denial-counter-corruption-qualified");return Ok(());
        }
        if phase=="verify" {
            let row=timeout(Duration::from_secs(2),db.query_one("SELECT (SELECT count(*) FROM signal_control.findings),(SELECT count(*) FROM signal_finding_scope.facts),(SELECT checkpoint FROM signal_control.partitions WHERE kind='pipeline'),(SELECT wal_floor FROM signal_finding_scope.producers)",&[])).await??;
            assert_eq!(row.get::<_,i64>(0),2);assert_eq!(row.get::<_,i64>(1),2);assert_eq!(row.get::<_,i64>(2),2);assert_eq!(row.get::<_,i64>(3),0);
            let wal=DurableBuffer::open_with_recovery(BufferConfig{directory:root.join("server/wal"),..Default::default()},RECOVERY_BYTES).await?;
            assert_eq!(wal.snapshot().last_sequence,2);assert_eq!(wal.snapshot().checkpoint,2);assert!(wal.read_recovery(context()?.deadline()).await?.is_none());wal.shutdown().await?;
            println!("phase: Standard-process-exact-findings-facts-DB-WAL-checkpoint-original-floor-qualified");return Ok(());
        }
        assert_eq!(phase,"prepare");let directory=root.join("server/wal");let wal=DurableBuffer::open_with_recovery(BufferConfig{directory,..Default::default()},RECOVERY_BYTES).await?;
        let scope=Scope{schema_version:1,store_id:Uuid::new_v4(),generation:Uuid::new_v4(),tenant:"synthetic-standard".into(),stream:wal.snapshot().stream_id,partition_id:Uuid::new_v4()};
        let authority=AdministrativeScope{schema_version:1,store_id:scope.store_id,generation:scope.generation};let connection=ConnectionSettings::fixture_loopback("127.0.0.1".parse()?,f.port,DB.into(),"signal_migrator".into(),f.password.as_bytes().to_vec())?;
        let installer=ControlAdministrator::new(connection.clone(),"signal_control_owner".into())?;installer.initialize(InitializeInput{scope:authority.clone(),max_rows:65536,max_bytes:67108864},context()?).await?;installer.migrate_catalog(MigrationInput{scope:authority.clone(),source_revision:2,source_sha256:schema_identity().1},context()?).await?;installer.shutdown(context()?).await?;
        timeout(Duration::from_secs(2),db.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,$2,$3,'pipeline')",&[&scope.partition_id,&scope.tenant,&scope.stream])).await??;
        timeout(Duration::from_secs(2),db.batch_execute("SET ROLE signal_control_owner")).await??;
        timeout(Duration::from_secs(2),db.batch_execute(include_str!("../../../schemas/shared-control/007-finding-scope.sql"))).await??;
        timeout(Duration::from_secs(2),db.batch_execute(include_str!("../../../schemas/shared-control/008-scoped-publication.sql"))).await??;
        timeout(Duration::from_secs(2),db.batch_execute("RESET ROLE")).await??;
        let scope_generation=Uuid::new_v4();let owner=FindingScopeAdministrator::new(connection,"signal_control_owner".into(),FindingScopeProfile::Catalog4Scoped)?;
        owner.activate(authority,scope_generation,FindingScopeLimits{producers:1,rows:128,bytes:1048576},context()?).await?;
        owner.enroll(ProducerEnrollment{scope:scope.clone(),scope_generation,startup:Uuid::new_v4(),wal_floor:0},context()?).await?;owner.shutdown(context()?).await?;wal.shutdown().await?;
        timeout(Duration::from_secs(2),db.batch_execute("CREATE ROLE signal_standard_producer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE signal_standard_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; GRANT USAGE ON SCHEMA signal_control,signal_finding_scope TO signal_standard_producer,signal_standard_reader; GRANT EXECUTE ON FUNCTION signal_control.acquire(jsonb,uuid,integer,bytea,bytea),signal_control.renew(jsonb,integer,bytea,bytea),signal_control.read_catalog_snapshot(jsonb,uuid,integer,bytea,bytea),signal_control.publish(jsonb,bytea,boolean,bytea,bytea),signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) TO signal_standard_producer; GRANT SELECT ON signal_control.store,signal_control.migrations,signal_control.findings,signal_control.partitions,signal_finding_scope.activation,signal_finding_scope.profile,signal_finding_scope.producers,signal_finding_scope.facts,signal_finding_scope.requests TO signal_standard_reader")).await??;
        timeout(Duration::from_secs(2),db.execute("SELECT set_config('signal_fixture.password',$1,false)",&[&f.password])).await??;
        timeout(Duration::from_secs(2),db.batch_execute("DO $$ BEGIN EXECUTE format('ALTER ROLE signal_standard_producer PASSWORD %L',current_setting('signal_fixture.password')); EXECUTE format('ALTER ROLE signal_standard_reader PASSWORD %L',current_setting('signal_fixture.password')); END $$")).await??;
        timeout(Duration::from_secs(2),db.execute("INSERT INTO signal_control.principals VALUES('signal_standard_producer',$1,$2,$3)",&[&scope.tenant,&scope.stream,&scope.partition_id])).await??;
        let backend=Uuid::parse_str(&std::env::var("SIGNAL_STANDARD_BACKEND")?)?;
        timeout(Duration::from_secs(2),db.execute("INSERT INTO signal_control.object_backends VALUES($1,'owned-standard-s3-protocol-fixture')",&[&backend])).await??;
        timeout(Duration::from_secs(2),db.execute("INSERT INTO signal_control.object_scopes VALUES($1,$2,$3)",&[&scope.partition_id,&backend,&format!("query/{}/",scope.stream)])).await??;
        timeout(Duration::from_secs(2),db.batch_execute("UPDATE signal_control.store SET ready=true")).await??;
        let mut roots=rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(fs::read(&f.root_der)?))?;
        let client=|user:&str| -> Result<signal_control::ControlClient> {
            Ok(signal_control::ControlClient::catalog(ConnectionSettings::tls(
                "signal-control.invalid".into(),Some("127.0.0.1".parse()?),f.port,DB.into(),
                user.into(),f.password.as_bytes().to_vec(),roots.clone(),
            )?)?)
        };
        let producer=client("signal_standard_producer")?;
        let mut oversized=String::with_capacity(1024);oversized.push_str("signal_control_owner");
        for invalid in [String::new(),"signal-control-owner".into(),"a".repeat(64),oversized] {
            let rejected=producer.metrics().rejected;
            assert!(matches!(producer.verify_producer_credentials(invalid,context()?).await,Err(signal_control::ControlError::Invalid)));
            assert_eq!(producer.metrics().rejected,rejected);
        }
        producer.verify_producer_credentials("signal_control_owner".into(),context()?).await?;
        for user in ["signal_migrator","signal_standard_reader"] {
            let denied=client(user)?;
            assert!(matches!(denied.verify_producer_credentials("signal_control_owner".into(),context()?).await,Err(signal_control::ControlError::Fenced)));
            denied.shutdown(context()?).await?;
        }
        for (grant,revoke) in [
            ("GRANT UPDATE ON signal_control.partitions TO signal_standard_producer","REVOKE UPDATE ON signal_control.partitions FROM signal_standard_producer"),
            ("GRANT MAINTAIN ON signal_control.partitions TO signal_standard_producer","REVOKE MAINTAIN ON signal_control.partitions FROM signal_standard_producer"),
            ("GRANT UPDATE(checkpoint) ON signal_control.partitions TO signal_standard_producer","REVOKE UPDATE(checkpoint) ON signal_control.partitions FROM signal_standard_producer"),
            ("GRANT CREATE ON DATABASE signal_standard_main TO signal_standard_producer","REVOKE CREATE ON DATABASE signal_standard_main FROM signal_standard_producer"),
            ("GRANT EXECUTE ON FUNCTION signal_control.check_scope(jsonb,boolean,bytea,bytea) TO signal_standard_producer","REVOKE EXECUTE ON FUNCTION signal_control.check_scope(jsonb,boolean,bytea,bytea) FROM signal_standard_producer"),
            ("GRANT UPDATE(checkpoint) ON signal_control.partitions TO PUBLIC","REVOKE UPDATE(checkpoint) ON signal_control.partitions FROM PUBLIC"),
            ("GRANT signal_standard_reader TO signal_standard_producer WITH INHERIT FALSE, SET TRUE","REVOKE signal_standard_reader FROM signal_standard_producer"),
        ] {
            timeout(Duration::from_secs(2),db.batch_execute(grant)).await??;
            assert!(matches!(producer.verify_producer_credentials("signal_control_owner".into(),context()?).await,Err(signal_control::ControlError::Fenced)));
            timeout(Duration::from_secs(2),db.batch_execute(revoke)).await??;
            producer.verify_producer_credentials("signal_control_owner".into(),context()?).await?;
        }
        let cancelled=context()?;cancelled.cancel();
        let rejected=producer.metrics().rejected;
        assert!(matches!(producer.verify_producer_credentials("signal_control_owner".into(),cancelled).await,Err(signal_control::ControlError::Cancelled)));
        assert_eq!(producer.metrics().rejected,rejected);
        producer.shutdown(context()?).await?;
        println!("phase: Standard-producer-verified-TLS-owner-reader-table-column-DDL-precancel-qualification-complete");
        use base64::Engine;
        let document=serde_json::json!({"schema_version":1,"scope":scope,"scope_generation":scope_generation,"schema_owner":"signal_control_owner","backend_id":backend,"catalog_profile":"catalog4","lease_ms":15000,"database":{"host":"signal-control.invalid","address":"127.0.0.1","port":f.port,"database":DB,"producer_user":"signal_standard_producer","producer_password_env":"SIGNAL_STANDARD_PRODUCER_PASSWORD","reader_user":"signal_standard_reader","reader_password_env":"SIGNAL_STANDARD_READER_PASSWORD","roots_der_base64":[base64::engine::general_purpose::STANDARD.encode(fs::read(&f.root_der)?)]}});
        fs::write(root.join("shared.json"),serde_json::to_vec(&document)?)?;
        println!("phase: offline-Standard-owner-enrollment-and-least-privilege-provisioned");Ok(())
    }.await;
    drop(db);
    timeout(Duration::from_secs(2), driver).await???;
    result
}
