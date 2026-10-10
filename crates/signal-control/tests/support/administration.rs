use signal_control::{
    AdministrativeScope, ConnectionSettings, ControlAdministrator, ControlClient, ControlError,
    InitializeInput, MigrationInput, Scope, legacy_identity, schema_identity,
};
use signal_storage::object_manifest::{QueryFile, QueryManifest, QueryObjectRef, data_key};
use std::{net::IpAddr, time::Duration};
use tokio_postgres::Client;
use uuid::Uuid;
type Error = Box<dyn std::error::Error>;
fn settings(f: &super::Fixture, db: &str, user: &str) -> Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        IpAddr::from([127, 0, 0, 1]),
        f.port,
        db.into(),
        user.into(),
        f.password.as_bytes().to_vec(),
    )
}
fn administrator(f: &super::Fixture, db: &str) -> Result<ControlAdministrator, ControlError> {
    ControlAdministrator::new(
        settings(f, db, "signal_migrator")?,
        "signal_control_owner".into(),
    )
}
fn input(scope: &AdministrativeScope) -> MigrationInput {
    MigrationInput {
        scope: scope.clone(),
        source_revision: 1,
        source_sha256: legacy_identity(),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
async fn idle(a: &ControlAdministrator) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(4), async {
        while a.metrics().active != 0 || a.metrics().queue_depth != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}
pub(super) async fn witness(db: &Client) -> Result<serde_json::Value, Error> {
    Ok(db.query_one("SELECT jsonb_build_object('store',(SELECT to_jsonb(s)-'revision'-'routines_sha256' FROM signal_control.store s),'partitions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM signal_control.partitions p),'commits',(SELECT jsonb_agg(to_jsonb(c) ORDER BY partition_id,id) FROM signal_control.commits c),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY partition_id,id) FROM signal_control.receipts r),'state',(SELECT jsonb_agg(to_jsonb(s) ORDER BY partition_id,key) FROM signal_control.state s),'findings',(SELECT jsonb_agg(to_jsonb(f) ORDER BY position) FROM signal_control.findings f),'work',(SELECT jsonb_agg(to_jsonb(w) ORDER BY id) FROM signal_control.outbox w),'snapshots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signal_control.snapshots s),'pins',(SELECT jsonb_agg(to_jsonb(p) ORDER BY partition_id,id) FROM signal_control.object_pins p),'tombs',(SELECT jsonb_agg(to_jsonb(t) ORDER BY partition_id,id) FROM signal_control.tombstones t),'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM signal_control.notification_attempts a))",&[]).await?.get(0))
}
async fn legacy_call(
    db: &Client,
    token: &serde_json::Value,
    raw: serde_json::Value,
    name: &str,
) -> Result<serde_json::Value, Error> {
    let (schema, _) = schema_identity();
    let legacy = legacy_identity();
    let bytes = serde_json::to_vec(&raw)?;
    let query = match name {
        "publish" => "SELECT signal_control.publish($1,$2,false,$3,$4)",
        "receipt" => "SELECT signal_control.record_receipt($1,$2,$3,$4)",
        "notification" => "SELECT signal_control.notification($1,$2,$3,$4)",
        _ => return Err("unknown fixture operation".into()),
    };
    let row = db
        .query_one(
            query,
            &[token, &bytes, &schema.as_slice(), &legacy.as_slice()],
        )
        .await?;
    Ok(row.get(0))
}
async fn seed(db: &Client, scope: &AdministrativeScope) -> Result<(), Error> {
    let (schema, _) = schema_identity();
    let legacy = legacy_identity();
    db.batch_execute(&format!(
        "SET ROLE signal_control_owner; {} {} RESET ROLE;",
        include_str!("../../../../schemas/shared-control/001.sql"),
        include_str!("../../../../schemas/shared-control/002-functions.sql")
    ))
    .await?;
    db.execute("INSERT INTO signal_control.store(singleton,store_id,generation,revision,ready,feed_digest,schema_sha256,routines_sha256,max_rows,max_bytes) VALUES(true,$1,$2,1,true,sha256(convert_to('SIGNAL-FINDINGS-CURSOR-V1','UTF8')||uuid_send($1)),$3,$4,65536,67108864)",&[&scope.store_id,&scope.generation,&schema.as_slice(),&legacy.as_slice()]).await?;
    let part = Uuid::from_u128(0x101);
    let stream = Uuid::from_u128(0x102);
    db.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,'synthetic-migration',$2,'pipeline')",&[&part,&stream]).await?;
    db.execute("INSERT INTO signal_control.principals(role_name,tenant,stream,partition_id) VALUES('signal_runtime','synthetic-migration',$1,$2)",&[&stream,&part]).await?;
    db.execute("INSERT INTO signal_control.object_backends(id,canonical_id) VALUES($1,'synthetic-migration-physical-namespace')",&[&Uuid::from_u128(0x20)]).await?;
    db.execute("INSERT INTO signal_control.object_scopes(partition_id,backend_id,key_prefix) VALUES($1,$2,$3)",&[&part,&Uuid::from_u128(0x20),&format!("query/{stream}/")]).await?;
    db.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_control.acquire(jsonb,uuid,integer,bytea,bytea),signal_control.publish(jsonb,bytea,boolean,bytea,bytea),signal_control.record_receipt(jsonb,bytea,bytea,bytea),signal_control.notification(jsonb,bytea,bytea,bytea) TO signal_runtime; SET SESSION AUTHORIZATION signal_runtime").await?;
    let s = serde_json::json!({"schema_version":1,"store_id":scope.store_id,"generation":scope.generation,"tenant":"synthetic-migration","stream":stream,"partition_id":part});
    let token: serde_json::Value = db
        .query_one(
            "SELECT signal_control.acquire($1,$2,60000,$3,$4)",
            &[
                &s,
                &Uuid::from_u128(0x103),
                &schema.as_slice(),
                &legacy.as_slice(),
            ],
        )
        .await?
        .get(0);
    let receipt = Uuid::from_u128(0x104);
    legacy_call(db,&token,serde_json::json!({"schema_version":1,"id":receipt,"prepared_count":1,"source_record_count":1,"reference":"73796e7468657469632d637573746f6479"}),"receipt").await?;
    let finding = Uuid::from_u128(0x105);
    let work = Uuid::from_u128(0x106);
    let attempt = Uuid::from_u128(0x107);
    let finding_bytes = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"id":finding,"rule_id":"synthetic-migration","created_at":"2026-10-10T00:00:00Z","severity":"high","title":"synthetic-upgrade","event_ids":[Uuid::from_u128(0x108)],"attributes":{}}),
    )?;
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: stream,
        normalizer_revision: "synthetic-v1".into(),
        first_sequence: 1,
        last_sequence: 1,
        events: 1,
        previous: None,
        files: vec![QueryFile {
            date: "2026-10-10".into(),
            hour: 0,
            object: QueryObjectRef {
                key: data_key(stream, "2026-10-10", 0, [1; 32]),
                version: Some("exact-synthetic-v1".into()),
                etag: None,
                bytes: 128,
                sha256: [1; 32],
            },
            rows: 1,
            decoded_bytes: 256,
        }],
    };
    legacy_call(db,&token,serde_json::json!({"schema_version":1,"id":Uuid::from_u128(0x109),"previous":null,"first_sequence":1,"last_sequence":1,"manifest":hex(&serde_json::to_vec(&manifest)?),"rule_revision":hex(&[2;32]),"normalizer_revision":"synthetic-v1","states":[{"key":"synthetic-state","revision":hex(&[2;32]),"bytes":"73796e7468657469632d7374617465"}],"findings":[{"id":finding,"bytes":hex(&finding_bytes)}],"work":[{"id":work,"finding_id":finding,"bytes":"737461626c652d64656c69766572792d6b65792d616e642d706c616e"}],"receipts":[{"id":receipt,"expected_prefix":0,"verified_prefix":1}]}),"publish").await?;
    for (id, outcome) in [
        (attempt, "uncertain"),
        (Uuid::from_u128(0x110), "delivered"),
    ] {
        legacy_call(db,&token,serde_json::json!({"schema_version":1,"operation":"claim","work_id":work,"attempt_id":id}),"notification").await?;
        legacy_call(db,&token,serde_json::json!({"schema_version":1,"operation":"finish","work_id":work,"attempt_id":id,"outcome":outcome,"evidence":"73796e7468657469632d65766964656e6365"}),"notification").await?;
    }
    db.batch_execute("RESET SESSION AUTHORIZATION").await?;
    Ok(())
}
pub async fn qualify(db: &Client, f: &super::Fixture) -> Result<(), Error> {
    eprintln!("phase: explicit-fresh-administrative-initialization");
    for name in [
        "signal_migration_fresh",
        "signal_migration_legacy",
        "signal_migration_upper",
    ] {
        db.batch_execute(&format!("CREATE DATABASE {name}")).await?;
        db.batch_execute(&format!(
            "GRANT CREATE ON DATABASE {name} TO signal_control_owner"
        ))
        .await?;
    }
    let fresh = administrator(f, "signal_migration_fresh")?;
    let scope = AdministrativeScope {
        schema_version: 1,
        store_id: Uuid::from_u128(0x200),
        generation: Uuid::from_u128(0x201),
    };
    let init = InitializeInput {
        scope: scope.clone(),
        max_rows: 65536,
        max_bytes: 67108864,
    };
    let result = fresh.initialize(init.clone(), super::context()?).await?;
    assert_eq!(result.revision, 2);
    assert!(!result.ready);
    assert_eq!(
        fresh.inspect(scope.clone(), super::context()?).await?,
        result
    );
    assert!(matches!(
        fresh.initialize(init, super::context()?).await,
        Err(ControlError::Conflict)
    ));
    let denied = ControlAdministrator::new(
        settings(f, "signal_migration_fresh", "signal_runtime")?,
        "signal_control_owner".into(),
    )?;
    assert!(matches!(
        denied.inspect(scope.clone(), super::context()?).await,
        Err(ControlError::Fenced)
    ));
    denied.shutdown(super::context()?).await?;
    let (fresh_db, fresh_driver) = super::admin_database(f, "signal_migration_fresh").await?;
    assert!(
        !fresh_db
            .query_one(
                "SELECT has_table_privilege('signal_runtime','signal_control.migrations','UPDATE')",
                &[]
            )
            .await?
            .get::<_, bool>(0)
    );
    fresh_db
        .batch_execute("SET search_path=pg_catalog,signal_control,pg_temp")
        .await?;
    let catalog: String = fresh_db
        .query_one(
            include_str!("../../../../schemas/shared-control/catalog-query.sql"),
            &[],
        )
        .await?
        .get(0);
    eprintln!("source2-catalog: {catalog}");
    fresh.shutdown(super::context()?).await?;
    fresh_driver.abort();
    // Owner identity is a raw catalog name, not a quoted regrole display spelling.
    db.batch_execute("CREATE ROLE \"Signal_Migration_Owner\" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; GRANT \"Signal_Migration_Owner\" TO signal_migrator; GRANT CREATE ON DATABASE signal_migration_upper TO \"Signal_Migration_Owner\"").await?;
    let upper = ControlAdministrator::new(
        settings(f, "signal_migration_upper", "signal_migrator")?,
        "Signal_Migration_Owner".into(),
    )?;
    let upper_result = upper
        .initialize(
            InitializeInput {
                scope: scope.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            super::context()?,
        )
        .await?;
    assert!(!upper_result.ready);
    assert_eq!(
        upper.inspect(scope.clone(), super::context()?).await?,
        upper_result
    );
    upper.shutdown(super::context()?).await?;
    eprintln!("phase: populated-supported-source-migration");
    let (legacy, legacy_driver) = super::admin_database(f, "signal_migration_legacy").await?;
    seed(&legacy, &scope).await?;
    let migrator = administrator(f, "signal_migration_legacy")?;
    let migrate = input(&scope);
    // New runtime never upgrades an old installation on open.
    let runtime = ControlClient::new(settings(f, "signal_migration_legacy", "signal_runtime")?)?;
    let runtime_scope = Scope {
        schema_version: 1,
        store_id: scope.store_id,
        generation: scope.generation,
        tenant: "synthetic-migration".into(),
        stream: Uuid::from_u128(0x102),
        partition_id: Uuid::from_u128(0x101),
    };
    let before = witness(&legacy).await?;
    assert!(matches!(
        runtime
            .acquire(
                runtime_scope.clone(),
                Uuid::from_u128(0x120),
                15000,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(&legacy).await?, before);
    legacy
        .batch_execute("UPDATE signal_control.store SET ready=false")
        .await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Fenced)
    ));
    legacy
        .batch_execute("UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL")
        .await?;
    let before = witness(&legacy).await?;
    for sql in [
        "UPDATE signal_control.store SET routines_sha256=decode(repeat('ff',32),'hex')",
        "UPDATE signal_control.store SET feed_digest=decode(repeat('ff',32),'hex')",
    ] {
        let saved = legacy
            .query_one(
                "SELECT routines_sha256,feed_digest FROM signal_control.store",
                &[],
            )
            .await?;
        legacy.batch_execute(sql).await?;
        let corrupt = witness(&legacy).await?;
        assert!(matches!(
            migrator.migrate(migrate.clone(), super::context()?).await,
            Err(ControlError::Corrupt)
        ));
        assert_eq!(witness(&legacy).await?, corrupt);
        legacy
            .execute(
                "UPDATE signal_control.store SET routines_sha256=$1,feed_digest=$2",
                &[&saved.get::<_, Vec<u8>>(0), &saved.get::<_, Vec<u8>>(1)],
            )
            .await?;
    }
    legacy
        .batch_execute("CREATE TABLE signal_control.partial_revision(id integer)")
        .await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    legacy
        .batch_execute("DROP TABLE signal_control.partial_revision")
        .await?;
    // Malformed stored fields return Corrupt and leave worker ownership intact.
    legacy.batch_execute("ALTER TABLE signal_control.store ALTER COLUMN generation DROP NOT NULL; UPDATE signal_control.store SET generation=NULL").await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    legacy
        .execute(
            "UPDATE signal_control.store SET generation=$1",
            &[&scope.generation],
        )
        .await?;
    legacy
        .batch_execute("ALTER TABLE signal_control.store ALTER COLUMN generation SET NOT NULL")
        .await?;
    assert_eq!(witness(&legacy).await?, before);
    // Unknown/newer revision is rejected even when an administrator altered the old CHECK.
    legacy.batch_execute("ALTER TABLE signal_control.store DROP CONSTRAINT store_revision_check; UPDATE signal_control.store SET revision=9").await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(
        legacy
            .query_one("SELECT revision FROM signal_control.store", &[])
            .await?
            .get::<_, i32>(0),
        9
    );
    assert_eq!(witness(&legacy).await?, before);
    legacy.batch_execute("UPDATE signal_control.store SET revision=1; ALTER TABLE signal_control.store ADD CONSTRAINT store_revision_check CHECK(revision=1)").await?;
    assert_eq!(witness(&legacy).await?, before);
    // Incompatible function-source drift is not accepted just because checksums claim success.
    let original=legacy.query_one("SELECT pg_get_functiondef('signal_control.feed_cursor(uuid,bigint,bytea)'::regprocedure)",&[]).await?.get::<_,String>(0);
    legacy.batch_execute("CREATE OR REPLACE FUNCTION signal_control.feed_cursor(store uuid,feed_index bigint,digest bytea) RETURNS text LANGUAGE sql AS $$ SELECT 'tampered'::text $$").await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    legacy.batch_execute(&original).await?;
    // Structural catalog drift is rejected even when stored hashes match.
    legacy
        .batch_execute("ALTER TABLE signal_control.outbox DROP CONSTRAINT outbox_attempts_check")
        .await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    legacy.batch_execute("ALTER TABLE signal_control.outbox ADD CONSTRAINT outbox_attempts_check CHECK(attempts BETWEEN 0 AND 10)").await?;
    legacy
        .batch_execute("ALTER FUNCTION signal_control.feed_cursor(uuid,bigint,bytea) IMMUTABLE")
        .await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    legacy
        .batch_execute("ALTER FUNCTION signal_control.feed_cursor(uuid,bigint,bytea) VOLATILE")
        .await?;
    legacy.batch_execute("CREATE FUNCTION public.synthetic_unexpected_trigger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; CREATE TRIGGER synthetic_unexpected_trigger BEFORE UPDATE ON signal_control.store FOR EACH ROW EXECUTE FUNCTION public.synthetic_unexpected_trigger()").await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    legacy.batch_execute("DROP TRIGGER synthetic_unexpected_trigger ON signal_control.store; DROP FUNCTION public.synthetic_unexpected_trigger()").await?;
    // A held reader/writer lock rejects migration without waiting or partial DDL.
    legacy
        .batch_execute("BEGIN; LOCK TABLE signal_control.outbox IN ACCESS SHARE MODE")
        .await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Retryable)
    ));
    legacy.batch_execute("ROLLBACK").await?;
    eprintln!("phase: migration-ddl-rollback-injection");
    // Inject failure after the first new DDL and prove transactional catalog rollback.
    legacy.batch_execute("CREATE FUNCTION public.synthetic_migration_ddl_failure() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF to_regclass('signal_control.migrations') IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF; END $$; CREATE EVENT TRIGGER synthetic_migration_ddl_failure ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.synthetic_migration_ddl_failure()").await?;
    assert!(matches!(
        migrator.migrate(migrate.clone(), super::context()?).await,
        Err(ControlError::Full)
    ));
    assert_eq!(witness(&legacy).await?, before);
    assert!(
        legacy
            .query_one(
                "SELECT to_regclass('signal_control.migrations') IS NULL",
                &[]
            )
            .await?
            .get::<_, bool>(0)
    );
    legacy.batch_execute("DROP EVENT TRIGGER synthetic_migration_ddl_failure; DROP FUNCTION public.synthetic_migration_ddl_failure()").await?;
    eprintln!("phase: migration-ddl-cancellation-injection");
    // Cancellation during DDL is an uncertain reply, but retained ownership confirms rollback.
    legacy.batch_execute("CREATE FUNCTION public.synthetic_migration_ddl_pause() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF to_regclass('signal_control.migrations') IS NOT NULL THEN PERFORM pg_sleep(1); END IF; END $$; CREATE EVENT TRIGGER synthetic_migration_ddl_pause ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.synthetic_migration_ddl_pause()").await?;
    let c = super::context()?;
    let observer = async {
        let result=tokio::time::timeout(Duration::from_secs(2),async {loop {
            if legacy.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='signal-control' AND datname='signal_migration_legacy' AND wait_event='PgSleep' AND query<>'COMMIT')",&[]).await?.get::<_,bool>(0) {return Ok::<(),tokio_postgres::Error>(());}
            tokio::time::sleep(Duration::from_millis(5)).await;
        }}).await;
        c.cancel();
        result??;
        Ok::<(), Error>(())
    };
    let (result, observed) = tokio::join!(migrator.migrate(migrate.clone(), c.clone()), observer);
    if let Err(error) = observed {
        return Err(
            format!("migration observer failed: {error}; operation result: {result:?}").into(),
        );
    }
    assert!(matches!(result, Err(ControlError::Uncertain)));
    idle(&migrator).await?;
    assert_eq!(witness(&legacy).await?, before);
    assert!(
        legacy
            .query_one(
                "SELECT to_regclass('signal_control.migrations') IS NULL",
                &[]
            )
            .await?
            .get::<_, bool>(0)
    );
    legacy.batch_execute("DROP EVENT TRIGGER synthetic_migration_ddl_pause; DROP FUNCTION public.synthetic_migration_ddl_pause()").await?;
    eprintln!("phase: migration-commit-uncertainty-injection");
    // Cancel only after observing COMMIT: revision and ledger may have committed.
    legacy.batch_execute("CREATE TABLE public.synthetic_migration_commit_signal(id integer); CREATE FUNCTION public.synthetic_migration_commit_signal() RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN IF to_regclass('signal_control.migrations') IS NOT NULL THEN INSERT INTO public.synthetic_migration_commit_signal VALUES(1); END IF; END $$; CREATE EVENT TRIGGER synthetic_migration_commit_signal ON ddl_command_end WHEN TAG IN ('CREATE FUNCTION') EXECUTE FUNCTION public.synthetic_migration_commit_signal(); CREATE FUNCTION public.synthetic_migration_commit_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_migration_commit_pause AFTER INSERT ON public.synthetic_migration_commit_signal DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_migration_commit_pause()").await?;
    let c = super::context()?;
    let (result, observed) = tokio::join!(
        migrator.migrate(migrate.clone(), c.clone()),
        super::cancel_delayed_commit(&legacy, &c)
    );
    if let Err(error) = observed {
        return Err(
            format!("migration observer failed: {error}; operation result: {result:?}").into(),
        );
    }
    assert!(matches!(result, Err(ControlError::Uncertain)));
    idle(&migrator).await?;
    legacy.batch_execute("DROP EVENT TRIGGER synthetic_migration_commit_signal; DROP FUNCTION public.synthetic_migration_commit_signal(); DROP TABLE public.synthetic_migration_commit_signal; DROP FUNCTION public.synthetic_migration_commit_pause()").await?;
    let resolved = migrator.inspect(scope.clone(), super::context()?).await?;
    assert_eq!(resolved.revision, 2);
    assert!(!resolved.ready);
    assert_eq!(witness(&legacy).await?, before);
    assert!(matches!(
        migrator.migrate(migrate, super::context()?).await,
        Err(ControlError::Conflict)
    ));
    // Corrupt ordered history refuses runtime readiness, even with ready manually true.
    legacy.batch_execute("UPDATE signal_control.store SET ready=true; UPDATE signal_control.migrations SET sha256=decode(repeat('ff',32),'hex') WHERE ordinal=2").await?;
    assert!(matches!(
        runtime
            .acquire(
                runtime_scope.clone(),
                Uuid::from_u128(0x120),
                15000,
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    legacy
        .execute(
            "UPDATE signal_control.migrations SET sha256=$1 WHERE ordinal=2",
            &[&legacy_identity().as_slice()],
        )
        .await?;
    let current = runtime
        .acquire(
            runtime_scope,
            Uuid::from_u128(0x120),
            15000,
            super::context()?,
        )
        .await?;
    assert_eq!(current.epoch, 2);
    runtime.shutdown(super::context()?).await?;
    migrator.shutdown(super::context()?).await?;
    legacy_driver.abort();
    // Prepare the original pipeline fixture with the explicit migrator, then the
    // fixture administrator supplies its separate synthetic readiness decision.
    let main = administrator(f, "postgres")?;
    let main_scope = AdministrativeScope {
        schema_version: 1,
        store_id: Uuid::from_u128(1),
        generation: Uuid::from_u128(2),
    };
    assert!(
        !main
            .migrate(input(&main_scope), super::context()?)
            .await?
            .ready
    );
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    main.shutdown(super::context()?).await?;
    eprintln!("matrix-case:unknown_or_newer_schema passed");
    eprintln!("phase: administrative-migration-qualification-complete");
    Ok(())
}
