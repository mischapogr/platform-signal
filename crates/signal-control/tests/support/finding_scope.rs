//! Explicit stopped extension schema; no host authorization/scoped runtime claim.
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio_postgres::Client;
use uuid::Uuid;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DATABASE: &str = "signal_finding_scope_fixture";
const SQL: &str = include_str!("../../../../schemas/shared-control/007-finding-scope.sql");

async fn fingerprint(db: &Client, scope: bool) -> Result<String> {
    let query = include_str!("../../../../schemas/shared-control/catalog-query.sql");
    let query = if scope {
        query.replace(
            "n.nspname='signal_control'",
            "n.nspname='signal_finding_scope'",
        )
    } else {
        query.into()
    };
    db.batch_execute("SET search_path=pg_catalog,signal_control,pg_temp")
        .await?;
    Ok(db.query_one(&query, &[]).await?.try_get(0)?)
}
async fn absent(db: &Client) -> Result {
    let absent: bool = db
        .query_one(
            "SELECT to_regnamespace('signal_finding_scope') IS NULL",
            &[],
        )
        .await?
        .try_get(0)?;
    assert!(absent);
    Ok(())
}
async fn rejected(db: &Client, expected: &str) -> Result {
    let error = db
        .batch_execute(SQL)
        .await
        .err()
        .ok_or("migration unexpectedly accepted")?;
    let error = error.as_db_error().ok_or("non-database rejection")?;
    if expected == "permission" {
        assert_eq!(error.code().code(), "42501");
    } else {
        assert_eq!(error.code().code(), "P0001");
        assert_eq!(error.message(), expected);
    }
    db.batch_execute("ROLLBACK; RESET ROLE").await?;
    absent(db).await
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Witness {
    store: Uuid,
    generation: Uuid,
    scope: Uuid,
    startup: Uuid,
    partition: Uuid,
    stream: Uuid,
    floor: i64,
    position: i64,
    digest: Vec<u8>,
}
fn witness_path() -> Result<PathBuf> {
    Ok(PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?)
        .with_file_name("finding-scope-witness.json"))
}
fn scope_admin(
    f: &super::Fixture,
    database: &str,
    user: &str,
    profile: signal_control::FindingScopeProfile,
) -> Result<signal_control::FindingScopeAdministrator> {
    Ok(signal_control::FindingScopeAdministrator::new(
        signal_control::ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse()?,
            f.port,
            database.into(),
            user.into(),
            f.password.as_bytes().to_vec(),
        )?,
        "signal_control_owner".into(),
        profile,
    )?)
}
pub async fn qualify(root: &Client, f: &super::Fixture) -> Result {
    root.batch_execute(
        "CREATE DATABASE signal_finding_scope_fixture TEMPLATE signal_catalog_profile",
    )
    .await?;
    root.batch_execute(
        "GRANT CREATE ON DATABASE signal_finding_scope_fixture TO signal_control_owner",
    )
    .await?;
    let (db, driver) = super::admin_database(f, DATABASE).await?;
    let original = fingerprint(&db, false).await?;
    assert_eq!(
        original,
        include_str!("../../../../schemas/shared-control/005-catalog.sha256").trim()
    );
    let history: Vec<Vec<u8>> = db
        .query(
            "SELECT content FROM signal_control.findings ORDER BY position",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.try_get(0))
        .collect::<std::result::Result<_, _>>()?;
    db.batch_execute("SET ROLE signal_control_owner").await?;
    rejected(&db, "SIGNAL_FENCED").await?; // A live store is not a migration authority.
    db.batch_execute("UPDATE signal_control.store SET ready=false")
        .await?;
    db.batch_execute("SET ROLE signal_runtime").await?;
    rejected(&db, "permission").await?; // Runtime credentials cannot install the extension.
    db.batch_execute("ALTER TABLE signal_control.findings DROP CONSTRAINT findings_position_key; SET ROLE signal_control_owner").await?;
    rejected(&db, "SIGNAL_CORRUPT").await?; // Matching migration bytes do not hide catalog drift.
    db.batch_execute(
        "ALTER TABLE signal_control.findings ADD CONSTRAINT findings_position_key UNIQUE(position)",
    )
    .await?;
    assert_eq!(fingerprint(&db, false).await?, original);
    db.batch_execute("SET ROLE signal_control_owner").await?;
    // Complete DDL can still roll back; a failed caller cannot leave half a root.
    let (_, body) = SQL.split_once("BEGIN;\n").ok_or("migration begin")?;
    let body = body.strip_suffix("COMMIT;\n").ok_or("migration commit")?;
    db.batch_execute(&format!("BEGIN; {body} ROLLBACK; RESET ROLE"))
        .await?;
    absent(&db).await?;
    db.batch_execute("SET ROLE signal_control_owner").await?;
    db.batch_execute(SQL).await?;
    db.batch_execute("RESET ROLE").await?;
    assert_eq!(fingerprint(&db, false).await?, original);
    let scope_catalog = fingerprint(&db, true).await?;
    println!("scope7-catalog: {scope_catalog}");
    assert_eq!(
        scope_catalog,
        include_str!("../../../../schemas/shared-control/007-finding-scope-catalog.sha256").trim()
    );
    let row = db
        .query_one(
            "SELECT store_id,generation,feed_position,feed_digest,ready FROM signal_control.store",
            &[],
        )
        .await?;
    assert!(!row.try_get::<_, bool>(4)?);
    let part = db.query_one("SELECT id,stream,checkpoint,tenant FROM signal_control.partitions WHERE kind='pipeline' ORDER BY id LIMIT 1", &[]).await?;
    let mut w = Witness {
        store: row.try_get(0)?,
        generation: row.try_get(1)?,
        scope: Uuid::new_v4(),
        startup: Uuid::new_v4(),
        partition: part.try_get(0)?,
        stream: part.try_get(1)?,
        floor: part.try_get(2)?,
        position: row.try_get(2)?,
        digest: row.try_get(3)?,
    };
    use signal_control::{
        AdministrativeScope, ControlError, FindingScopeLimits, FindingScopeProfile,
        ProducerEnrollment, Scope,
    };
    let admin = scope_admin(
        f,
        DATABASE,
        "signal_migrator",
        FindingScopeProfile::Catalog4,
    )?;
    let limits = FindingScopeLimits {
        producers: 1,
        rows: 65536,
        bytes: 4096,
    };
    let admin_scope = AdministrativeScope {
        schema_version: 1,
        store_id: w.store,
        generation: w.generation,
    };
    let pin = admin
        .activate(admin_scope.clone(), w.scope, limits, super::context()?)
        .await?;
    assert_eq!(pin.binding()?.prefix.position(), w.position as u64);
    let replay = admin
        .activate(admin_scope.clone(), w.scope, limits, super::context()?)
        .await?;
    assert_eq!(replay.binding()?.prefix, pin.binding()?.prefix);
    assert!(matches!(
        admin
            .activate(
                admin_scope.clone(),
                Uuid::new_v4(),
                limits,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    let scope = Scope {
        schema_version: 1,
        store_id: w.store,
        generation: w.generation,
        partition_id: w.partition,
        stream: w.stream,
        tenant: part.try_get(3)?,
    };
    let enrollment = ProducerEnrollment {
        scope: scope.clone(),
        scope_generation: w.scope,
        startup: w.startup,
        wal_floor: w.floor as u64,
    };
    let enrolled = admin.enroll(enrollment.clone(), super::context()?).await?;
    assert_eq!(
        enrolled
            .binding()?
            .producer
            .as_ref()
            .ok_or("producer missing")?
            .startup,
        w.startup
    );
    admin.enroll(enrollment.clone(), super::context()?).await?;
    let mut conflict = enrollment.clone();
    conflict.wal_floor += 1;
    assert!(matches!(
        admin.enroll(conflict, super::context()?).await,
        Err(ControlError::Conflict)
    ));
    let mut next = enrollment.clone();
    next.startup = Uuid::new_v4();
    next.wal_floor += 1;
    admin.enroll(next.clone(), super::context()?).await?;
    assert!(matches!(
        admin.enroll(enrollment, super::context()?).await,
        Err(ControlError::Fenced)
    ));
    w.startup = next.startup;
    w.floor = next.wal_floor as i64;
    let second = Uuid::new_v4();
    let second_stream = Uuid::new_v4();
    db.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,'synthetic-second-scope',$2,'pipeline')",&[&second,&second_stream]).await?;
    let second = ProducerEnrollment {
        scope: Scope {
            partition_id: second,
            stream: second_stream,
            tenant: "synthetic-second-scope".into(),
            ..scope.clone()
        },
        scope_generation: w.scope,
        startup: Uuid::new_v4(),
        wal_floor: 0,
    };
    assert!(matches!(
        admin.enroll(second, super::context()?).await,
        Err(ControlError::Full)
    ));
    db.batch_execute("UPDATE signal_finding_scope.profile SET used_bytes=used_bytes+1")
        .await?;
    assert!(matches!(
        admin
            .inspect(scope.clone(), w.scope, super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    db.batch_execute("UPDATE signal_finding_scope.profile SET used_bytes=used_bytes-1")
        .await?;
    let original = super::context()?;
    let cancel = admin
        .inspect(scope.clone(), w.scope, original.clone())
        .await?;
    original.cancel();
    assert!(matches!(cancel.binding(), Err(ControlError::Cancelled)));
    let held = admin
        .inspect(scope.clone(), w.scope, super::context()?)
        .await?;
    let denied = scope_admin(f, DATABASE, "signal_runtime", FindingScopeProfile::Catalog4)?;
    assert!(matches!(
        denied
            .inspect(scope.clone(), w.scope, super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    denied.shutdown(super::context()?).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    assert!(matches!(
        admin.enroll(next, super::context()?).await,
        Err(ControlError::Fenced)
    ));
    admin.inspect(scope, w.scope, super::context()?).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=false")
        .await?;
    admin.shutdown(super::context()?).await?;
    assert!(matches!(held.binding(), Err(ControlError::Cancelled)));
    println!("phase: current-finding-scope-activation-enrollment-counters-and-authority-qualified");
    assert_eq!(
        db.query_one(
            "SELECT artifact_sha256 FROM signal_finding_scope.profile",
            &[]
        )
        .await?
        .try_get::<_, Vec<u8>>(0)?,
        Sha256::digest(SQL.as_bytes()).to_vec()
    );
    // Facts are deliberately empty: legacy original bytes cannot gain provenance
    // just because a new durable authority root exists.
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_finding_scope.facts", &[])
            .await?
            .try_get::<_, i64>(0)?,
        0
    );
    for role in ["signal_runtime", "signal_denied"] {
        db.batch_execute(&format!("SET ROLE {role}")).await?;
        assert!(
            db.query("SELECT * FROM signal_finding_scope.activation", &[])
                .await
                .is_err()
        );
        assert!(db.execute("INSERT INTO signal_finding_scope.producers SELECT * FROM signal_finding_scope.producers",&[]).await.is_err());
        db.batch_execute("RESET ROLE").await?;
    }
    assert!(
        db.execute(
            "UPDATE signal_finding_scope.profile SET used_producers=129",
            &[]
        )
        .await
        .is_err()
    );
    assert!(
        db.execute(
            "UPDATE signal_finding_scope.producers SET wal_floor=-1",
            &[]
        )
        .await
        .is_err()
    );
    assert!(
        db.execute(
            "UPDATE signal_finding_scope.activation SET prefix_digest=decode('01','hex')",
            &[]
        )
        .await
        .is_err()
    );
    let after: Vec<Vec<u8>> = db
        .query(
            "SELECT content FROM signal_control.findings ORDER BY position",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.try_get(0))
        .collect::<std::result::Result<_, _>>()?;
    assert_eq!(history, after);
    let current_producer = super::scoped_publication::qualify(
        &db,
        f,
        ProducerEnrollment {
            scope: Scope {
                schema_version: 1,
                store_id: w.store,
                generation: w.generation,
                tenant: part.try_get(3)?,
                stream: w.stream,
                partition_id: w.partition,
            },
            scope_generation: w.scope,
            startup: w.startup,
            wal_floor: w.floor as u64,
        },
    )
    .await?;
    w.startup = current_producer.startup;
    w.floor = current_producer.wal_floor as i64;
    std::fs::write(witness_path()?, serde_json::to_vec(&w)?)?;
    drop(db);
    driver.await?;
    root.batch_execute("CREATE DATABASE signal_finding_scope_restore_fixture TEMPLATE signal_catalog_restore_destination").await?;
    root.batch_execute(
        "GRANT CREATE ON DATABASE signal_finding_scope_restore_fixture TO signal_control_owner",
    )
    .await?;
    let (restored, restored_driver) =
        super::admin_database(f, "signal_finding_scope_restore_fixture").await?;
    assert_eq!(
        fingerprint(&restored, false).await?,
        include_str!("../../../../schemas/shared-control/006-catalog.sha256").trim()
    );
    restored
        .batch_execute("UPDATE signal_control.store SET ready=false; SET ROLE signal_control_owner")
        .await?;
    restored.batch_execute(SQL).await?;
    restored.batch_execute("RESET ROLE").await?;
    assert_eq!(fingerprint(&restored, true).await?, scope_catalog);
    assert_eq!(
        fingerprint(&restored, false).await?,
        include_str!("../../../../schemas/shared-control/006-catalog.sha256").trim()
    );
    let restored_admin = scope_admin(
        f,
        "signal_finding_scope_restore_fixture",
        "signal_migrator",
        FindingScopeProfile::RestoredCatalog5,
    )?;
    let restored_head = restored
        .query_one("SELECT store_id,generation FROM signal_control.store", &[])
        .await?;
    restored_admin
        .activate(
            AdministrativeScope {
                schema_version: 1,
                store_id: restored_head.try_get(0)?,
                generation: restored_head.try_get(1)?,
            },
            Uuid::new_v4(),
            limits,
            super::context()?,
        )
        .await?;
    restored_admin.shutdown(super::context()?).await?;
    restored
        .batch_execute("SET ROLE signal_control_owner")
        .await?;
    restored
        .batch_execute(include_str!(
            "../../../../schemas/shared-control/008-scoped-publication.sql"
        ))
        .await?;
    restored.batch_execute("RESET ROLE").await?;
    let scoped_admin = scope_admin(
        f,
        "signal_finding_scope_restore_fixture",
        "signal_migrator",
        FindingScopeProfile::RestoredCatalog5Scoped,
    )?;
    let activation: Uuid = restored
        .query_one(
            "SELECT scope_generation FROM signal_finding_scope.activation",
            &[],
        )
        .await?
        .try_get(0)?;
    scoped_admin
        .activate(
            AdministrativeScope {
                schema_version: 1,
                store_id: restored_head.try_get(0)?,
                generation: restored_head.try_get(1)?,
            },
            activation,
            limits,
            super::context()?,
        )
        .await?;
    scoped_admin.shutdown(super::context()?).await?;
    drop(restored);
    restored_driver.await?;
    println!("phase: shared-finding-scope-stopped-schema-and-immutable-prefix-qualified");
    Ok(())
}
pub async fn restart_probe(f: &super::Fixture) -> Result {
    let path = witness_path()?;
    assert!(std::fs::metadata(&path)?.len() <= 4096);
    let w: Witness = serde_json::from_slice(&std::fs::read(path)?)?;
    let (db, driver) = super::admin_database(f, DATABASE).await?;
    assert_eq!(
        fingerprint(&db, true).await?,
        include_str!("../../../../schemas/shared-control/008-scoped-publication-catalog.sha256")
            .trim()
    );
    let row=db.query_one("SELECT a.store_id,a.store_generation,a.scope_generation,a.prefix_position,a.prefix_digest,p.partition_id,p.stream,p.startup_id,p.wal_floor FROM signal_finding_scope.activation a JOIN signal_finding_scope.producers p USING(scope_generation)",&[]).await?;
    assert_eq!(row.try_get::<_, Uuid>(0)?, w.store);
    assert_eq!(row.try_get::<_, Uuid>(1)?, w.generation);
    assert_eq!(row.try_get::<_, Uuid>(2)?, w.scope);
    assert_eq!(row.try_get::<_, i64>(3)?, w.position);
    assert_eq!(row.try_get::<_, Vec<u8>>(4)?, w.digest);
    assert_eq!(row.try_get::<_, Uuid>(5)?, w.partition);
    assert_eq!(row.try_get::<_, Uuid>(6)?, w.stream);
    assert_eq!(row.try_get::<_, Uuid>(7)?, w.startup);
    assert_eq!(row.try_get::<_, i64>(8)?, w.floor);
    let admin = scope_admin(
        f,
        DATABASE,
        "signal_migrator",
        signal_control::FindingScopeProfile::Catalog4Scoped,
    )?;
    let tenant: String = db
        .query_one(
            "SELECT tenant FROM signal_control.partitions WHERE id=$1",
            &[&w.partition],
        )
        .await?
        .try_get(0)?;
    let pin = admin
        .inspect(
            signal_control::Scope {
                schema_version: 1,
                store_id: w.store,
                generation: w.generation,
                tenant,
                stream: w.stream,
                partition_id: w.partition,
            },
            w.scope,
            super::context()?,
        )
        .await?;
    assert_eq!(
        pin.binding()?
            .producer
            .as_ref()
            .ok_or("restarted producer missing")?
            .startup,
        w.startup
    );
    admin.shutdown(super::context()?).await?;
    assert!(matches!(
        pin.binding(),
        Err(signal_control::ControlError::Cancelled)
    ));
    println!("phase: current-finding-scope-original-host-authority-after-restart-qualified");
    drop(db);
    driver.await?;
    println!("phase: shared-finding-scope-persistent-restart-original-authority-qualified");
    Ok(())
}
