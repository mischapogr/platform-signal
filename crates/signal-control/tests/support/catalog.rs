//! Owned populated revision2-to4 migration and dynamic committed catalog.
use sha2::{Digest, Sha256};
use signal_control::*;
use signal_storage::object_manifest::{
    PreviousManifest, QueryFile, QueryManifest, QueryObjectRef, data_key, manifest_key,
};
use std::{net::IpAddr, time::Duration};
use tokio_postgres::Client;
use uuid::Uuid;
type Error = Box<dyn std::error::Error>;
const DATABASE: &str = "signal_catalog_profile";
fn settings(f: &super::Fixture, user: &str) -> Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        IpAddr::from([127, 0, 0, 1]),
        f.port,
        DATABASE.into(),
        user.into(),
        f.password.as_bytes().to_vec(),
    )
}
fn request() -> CatalogInput {
    CatalogInput {
        schema_version: 1,
        id: Uuid::new_v4(),
        pin_ms: 5000,
    }
}
fn scope() -> Scope {
    Scope {
        schema_version: 1,
        store_id: Uuid::from_u128(0x200),
        generation: Uuid::from_u128(0x201),
        tenant: "synthetic-migration".into(),
        stream: Uuid::from_u128(0x102),
        partition_id: Uuid::from_u128(0x101),
    }
}
async fn counts(db: &Client) -> Result<(i64, i64, i64, i64), Error> {
    let row=db.query_one("SELECT used_rows,used_bytes,(SELECT count(*) FROM signal_control.snapshots),(SELECT count(*) FROM signal_control.catalog_snapshots) FROM signal_control.store",&[]).await?;
    Ok((
        row.try_get(0)?,
        row.try_get(1)?,
        row.try_get(2)?,
        row.try_get(3)?,
    ))
}
pub async fn qualify(root: &Client, f: &super::Fixture) -> Result<(), Error> {
    // Copy an exclusively owned fixture whose legacy initialization, populated
    // migration/history and stopped clients were qualified immediately beforehand.
    root.batch_execute("CREATE DATABASE signal_catalog_profile TEMPLATE signal_migration_legacy")
        .await?;
    let (db, driver) = super::admin_database(f, DATABASE).await?;
    let administrator = ControlAdministrator::new(
        settings(f, "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    let s = scope();
    let admin_scope = AdministrativeScope {
        schema_version: 1,
        store_id: s.store_id,
        generation: s.generation,
    };
    let migration = MigrationInput {
        scope: admin_scope.clone(),
        source_revision: 2,
        source_sha256: schema_identity().1,
    };
    assert!(matches!(
        administrator
            .migrate_catalog(migration.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("UPDATE signal_control.store SET ready=false")
        .await?;
    assert!(matches!(
        administrator
            .migrate_catalog(migration.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL")
        .await?;
    let before = super::administration::witness(&db).await?;
    // Fail after the new table/constraint DDL; transaction rollback must restore
    // the exact source catalog and every retained metadata byte.
    db.batch_execute("CREATE FUNCTION public.synthetic_catalog_ddl_failure() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF to_regclass('signal_control.catalog_snapshots') IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF; END $$; CREATE EVENT TRIGGER synthetic_catalog_ddl_failure ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.synthetic_catalog_ddl_failure()").await?;
    assert!(matches!(
        administrator
            .migrate_catalog(migration.clone(), super::context()?)
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(super::administration::witness(&db).await?, before);
    assert!(
        db.query_one(
            "SELECT to_regclass('signal_control.catalog_snapshots') IS NULL",
            &[]
        )
        .await?
        .get::<_, bool>(0)
    );
    db.batch_execute("DROP EVENT TRIGGER synthetic_catalog_ddl_failure; DROP FUNCTION public.synthetic_catalog_ddl_failure()").await?;
    eprintln!("phase: populated-catalog-profile-migration");
    let result = administrator
        .migrate_catalog(migration.clone(), super::context()?)
        .await
        .map_err(|error| format!("catalog migration: {error}"))?;
    assert_eq!(result.revision, 4);
    assert!(!result.ready);
    assert_eq!(super::administration::witness(&db).await?, before);
    assert_eq!(
        administrator
            .inspect_catalog(admin_scope.clone(), super::context()?)
            .await?,
        result
    );
    assert!(matches!(
        administrator
            .migrate_catalog(migration, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert!(matches!(
        administrator
            .inspect(admin_scope.clone(), super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    db.batch_execute("SET search_path=pg_catalog,signal_control,pg_temp")
        .await?;
    let catalog_identity = db
        .query_one(
            include_str!("../../../../schemas/shared-control/catalog-query.sql"),
            &[],
        )
        .await?
        .get::<_, String>(0);
    db.batch_execute("RESET search_path").await?;
    assert_eq!(
        catalog_identity,
        include_str!("../../../../schemas/shared-control/005-catalog.sha256").trim()
    );
    eprintln!("catalog4-catalog: {catalog_identity}");
    db.batch_execute("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    let old = ControlClient::new(settings(f, "signal_runtime")?)?;
    assert!(matches!(
        old.acquire(s.clone(), Uuid::new_v4(), 15000, super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    old.shutdown(super::context()?).await?;
    let restored = ControlClient::restored(settings(f, "signal_runtime")?)?;
    assert!(matches!(
        restored
            .acquire(s.clone(), Uuid::new_v4(), 15000, super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    restored.shutdown(super::context()?).await?;
    let certificate = std::fs::read(&f.root_der)?;
    assert!(certificate.len() <= 65536);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(certificate))?;
    let tls = ConnectionSettings::tls(
        "signal-control.invalid".into(),
        Some(IpAddr::from([127, 0, 0, 1])),
        f.port,
        DATABASE.into(),
        "signal_runtime".into(),
        f.password.as_bytes().to_vec(),
        roots,
    )?;
    let runtime = std::sync::Arc::new(ControlClient::catalog(tls)?);
    let input = CatalogInput {
        id: Uuid::from_u128(0xc01),
        ..request()
    };
    let first = runtime
        .read_catalog_snapshot(s.clone(), input.clone(), super::context()?)
        .await
        .map_err(|error| format!("initial catalog: {error}"))?;
    assert_eq!(first.checkpoint()?, 1);
    assert_eq!(first.head()?, Some(Uuid::from_u128(0x109)));
    assert_eq!(first.backend()?, Uuid::from_u128(0x20));
    assert_eq!(first.snapshot()?.manifests()?.len(), 1);
    let original = first.snapshot()?.manifests()?[0].clone();
    let expiry = db
        .query_one(
            "SELECT expires_at::text FROM signal_control.snapshots WHERE id=$1",
            &[&input.id],
        )
        .await?
        .get::<_, String>(0);
    let token = runtime
        .acquire(s.clone(), Uuid::new_v4(), 15000, super::context()?)
        .await?;
    let next_id = Uuid::new_v4();
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: s.stream,
        normalizer_revision: "synthetic-v1".into(),
        first_sequence: 2,
        last_sequence: 2,
        events: 1,
        previous: Some(PreviousManifest {
            first_sequence: 1,
            last_sequence: 1,
            object: QueryObjectRef {
                key: manifest_key(s.stream, 1),
                version: Some("exact-synthetic-predecessor".into()),
                etag: None,
                bytes: original.bytes.len() as u64,
                sha256: original.sha256,
            },
        }),
        files: vec![QueryFile {
            date: "2026-10-10".into(),
            hour: 0,
            object: QueryObjectRef {
                key: data_key(s.stream, "2026-10-10", 0, [3; 32]),
                version: Some("exact-synthetic-next".into()),
                etag: None,
                bytes: 128,
                sha256: [3; 32],
            },
            rows: 1,
            decoded_bytes: 256,
        }],
    };
    runtime
        .publish(
            token,
            PublicationInput {
                schema_version: 1,
                id: next_id,
                previous: Some(original.id),
                first_sequence: 2,
                last_sequence: 2,
                manifest: serde_json::to_vec(&manifest)?,
                rule_revision: [2; 32],
                normalizer_revision: "synthetic-v1".into(),
                states: vec![],
                findings: vec![],
                work: vec![],
                receipts: vec![],
            },
            super::context()?,
        )
        .await?;
    let replay = runtime
        .read_catalog_snapshot(s.clone(), input.clone(), super::context()?)
        .await
        .map_err(|error| format!("fixed catalog replay: {error}"))?;
    assert_eq!(replay.checkpoint()?, 1);
    assert_eq!(replay.head()?, Some(original.id));
    assert_eq!(
        replay.snapshot()?.manifests()?,
        first.snapshot()?.manifests()?
    );
    assert_eq!(
        db.query_one(
            "SELECT expires_at::text FROM signal_control.snapshots WHERE id=$1",
            &[&input.id]
        )
        .await?
        .get::<_, String>(0),
        expiry
    );
    let fresh = runtime
        .read_catalog_snapshot(s.clone(), request(), super::context()?)
        .await
        .map_err(|error| format!("advanced catalog: {error}"))?;
    assert_eq!(fresh.checkpoint()?, 2);
    assert_eq!(fresh.head()?, Some(next_id));
    assert_eq!(fresh.snapshot()?.manifests()?.len(), 2);
    let explicit = SnapshotInput {
        schema_version: 1,
        id: Uuid::from_u128(0xc21),
        manifest_ids: vec![original.id],
        pin_ms: 5000,
    };
    runtime
        .read_snapshot(s.clone(), explicit.clone(), super::context()?)
        .await?;
    let collision = CatalogInput {
        schema_version: 1,
        id: explicit.id,
        pin_ms: 5000,
    };
    let unchanged = counts(&db).await?;
    assert!(matches!(
        runtime
            .read_catalog_snapshot(s.clone(), collision, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    let mut foreign = s.clone();
    foreign.tenant = "foreign".into();
    assert!(matches!(
        runtime
            .read_catalog_snapshot(foreign, request(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let mut changed = input.clone();
    changed.pin_ms = 4999;
    assert!(matches!(
        runtime
            .read_catalog_snapshot(s.clone(), changed, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(counts(&db).await?, unchanged);
    db.batch_execute("UPDATE signal_control.store SET max_rows=used_rows+1")
        .await?;
    assert!(matches!(
        runtime
            .read_catalog_snapshot(s.clone(), request(), super::context()?)
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(counts(&db).await?, unchanged);
    db.batch_execute("UPDATE signal_control.store SET max_rows=65536")
        .await?;
    let short = CatalogInput {
        pin_ms: 1000,
        ..request()
    };
    runtime
        .read_catalog_snapshot(s.clone(), short.clone(), super::context()?)
        .await
        .map_err(|error| format!("short catalog admission: {error}"))?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(matches!(
        runtime
            .read_catalog_snapshot(s.clone(), short, super::context()?)
            .await,
        Err(ControlError::SnapshotExpired)
    ));
    db.execute("UPDATE signal_control.catalog_snapshots SET seal=decode(repeat('ff',32),'hex') WHERE id=$1",&[&input.id]).await?;
    assert!(matches!(
        runtime
            .read_catalog_snapshot(s.clone(), input.clone(), super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    db.execute("UPDATE signal_control.catalog_snapshots q SET seal=signal_control.catalog_snapshot_seal(q) WHERE id=$1",&[&input.id]).await?;
    let unaffected = counts(&db).await?;
    db.batch_execute("UPDATE signal_control.partitions SET checkpoint=3 WHERE kind='pipeline'")
        .await?;
    assert!(matches!(
        runtime
            .read_catalog_snapshot(s.clone(), request(), super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(counts(&db).await?, unaffected);
    db.batch_execute("UPDATE signal_control.partitions SET checkpoint=2 WHERE kind='pipeline'")
        .await?;
    // A distinct enrolled empty stream still receives a real finite catalog pin.
    let mut empty = s.clone();
    empty.partition_id = Uuid::from_u128(0xc40);
    empty.stream = Uuid::from_u128(0xc41);
    db.execute(
        "INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,$2,$3,'pipeline')",
        &[&empty.partition_id, &empty.tenant, &empty.stream],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.principals VALUES('signal_runtime',$1,$2,$3)",
        &[&empty.tenant, &empty.stream, &empty.partition_id],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_scopes VALUES($1,$2,$3)",
        &[
            &empty.partition_id,
            &Uuid::from_u128(0x20),
            &format!("query/{}/", empty.stream),
        ],
    )
    .await?;
    let empty_pin = runtime
        .read_catalog_snapshot(empty.clone(), request(), super::context()?)
        .await
        .map_err(|error| format!("empty catalog: {error}"))?;
    assert_eq!(empty_pin.checkpoint()?, 0);
    assert_eq!(empty_pin.head()?, None);
    assert!(empty_pin.snapshot()?.manifests()?.is_empty());
    assert!(
        empty_pin
            .snapshot()?
            .bind_query_selection(signal_storage::FileSelection::default())
            .is_ok()
    );
    super::catalog_query::qualify(&db, runtime.clone(), s.clone()).await?;
    // Real fenced publications cross both aggregate object and manifest limits.
    // Catalog admission must reject the whole request, never a visible prefix.
    let mut empty_token = runtime
        .acquire(empty.clone(), Uuid::new_v4(), 15000, super::context()?)
        .await?;
    let mut prior: Option<(Uuid, Vec<u8>)> = None;
    for sequence in 1..=129_u64 {
        if sequence % 16 == 0 {
            empty_token = runtime.renew(empty_token, 15000, super::context()?).await?;
        }
        let id = Uuid::new_v4();
        let manifest = QueryManifest {
            schema_version: 1,
            storage_schema_version: 1,
            stream_id: empty.stream,
            normalizer_revision: "synthetic-v1".into(),
            first_sequence: sequence,
            last_sequence: sequence,
            events: 1,
            previous: prior.as_ref().map(|(_, body)| PreviousManifest {
                first_sequence: sequence - 1,
                last_sequence: sequence - 1,
                object: QueryObjectRef {
                    key: manifest_key(empty.stream, sequence - 1),
                    version: Some("exact-synthetic-limit".into()),
                    etag: None,
                    bytes: body.len() as u64,
                    sha256: Sha256::digest(body).into(),
                },
            }),
            files: vec![QueryFile {
                date: "2026-10-10".into(),
                hour: 0,
                object: QueryObjectRef {
                    key: data_key(empty.stream, "2026-10-10", 0, [sequence as u8; 32]),
                    version: Some("exact-synthetic-limit".into()),
                    etag: None,
                    bytes: 128,
                    sha256: [sequence as u8; 32],
                },
                rows: 1,
                decoded_bytes: 256,
            }],
        };
        let body = serde_json::to_vec(&manifest)?;
        runtime
            .publish(
                empty_token.clone(),
                PublicationInput {
                    schema_version: 1,
                    id,
                    previous: prior.as_ref().map(|(id, _)| *id),
                    first_sequence: sequence,
                    last_sequence: sequence,
                    manifest: body.clone(),
                    rule_revision: [2; 32],
                    normalizer_revision: "synthetic-v1".into(),
                    states: vec![],
                    findings: vec![],
                    work: vec![],
                    receipts: vec![],
                },
                super::context()?,
            )
            .await?;
        prior = Some((id, body));
        if sequence == 65 || sequence == 129 {
            let original_counts = counts(&db).await?;
            assert!(matches!(
                runtime
                    .read_catalog_snapshot(empty.clone(), request(), super::context()?)
                    .await,
                Err(ControlError::Full)
            ));
            assert_eq!(counts(&db).await?, original_counts);
        }
    }
    runtime.shutdown(super::context()?).await?;
    assert_eq!(
        administrator
            .inspect_catalog(admin_scope, super::context()?)
            .await?
            .revision,
        4
    );
    administrator.shutdown(super::context()?).await?;
    driver.abort();
    let _ = driver.await;
    eprintln!("phase: dynamic-catalog-and-stopped-profile-qualification-complete");
    Ok(())
}

pub async fn restart_probe(f: &super::Fixture) -> Result<(), Error> {
    let administrator = ControlAdministrator::new(
        settings(f, "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    let s = scope();
    assert_eq!(
        administrator
            .inspect_catalog(
                AdministrativeScope {
                    schema_version: 1,
                    store_id: s.store_id,
                    generation: s.generation
                },
                super::context()?
            )
            .await?
            .revision,
        4
    );
    let runtime = ControlClient::catalog(settings(f, "signal_runtime")?)?;
    let original = CatalogInput {
        id: Uuid::from_u128(0xc01),
        ..request()
    };
    assert!(matches!(
        runtime
            .read_catalog_snapshot(s.clone(), original, super::context()?)
            .await,
        Err(ControlError::SnapshotExpired)
    ));
    let mut exhausted = s.clone();
    exhausted.stream = Uuid::from_u128(0xc41);
    exhausted.partition_id = Uuid::from_u128(0xc40);
    assert!(matches!(
        runtime
            .read_catalog_snapshot(exhausted, request(), super::context()?)
            .await,
        Err(ControlError::Full)
    ));
    runtime.shutdown(super::context()?).await?;
    administrator.shutdown(super::context()?).await?;
    eprintln!("phase: persistent-catalog-restart-fresh-client-qualified");
    Ok(())
}
