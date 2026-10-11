//! Operational adapter over the actual stopped Standard WAL and restricted TLS
//! maintenance role. Synthetic custody decisions; never provider deletion.
use super::{DB, Fixture, Result, context};
use signal_buffer::BufferConfig;
use signal_control::{
    CanonicalObjectRef, ConnectionSettings, ControlClient, ControlError, ObjectControlState,
    ReleasePinInput, RetentionKind, RetentionPinInput, RetirementInput, Scope,
};
use signal_server::{
    shared_retirement::{StoppedLifecycle, StoppedLifecycleError},
    shared_startup::CatalogProfile,
};
use std::{fs, path::Path, time::Duration};
use tokio::time::timeout;
use tokio_postgres::Client;
use uuid::Uuid;

fn retire(object: CanonicalObjectRef) -> RetirementInput {
    RetirementInput {
        schema_version: 1,
        id: Uuid::new_v4(),
        object,
        reason: b"explicit synthetic orphan retirement decision".to_vec(),
    }
}
pub async fn qualify(db: &Client, fixture: &Fixture, root: &Path, restored: bool) -> Result {
    let doc: serde_json::Value = serde_json::from_slice(&fs::read(root.join(if restored {
        "restored-shared.json"
    } else {
        "shared.json"
    }))?)?;
    let database = if restored {
        "signal_standard_restore"
    } else {
        DB
    };
    let checkpoint = if restored { 3 } else { 2 };
    let profile = if restored {
        CatalogProfile::RestoredCatalog5
    } else {
        CatalogProfile::Catalog4
    };
    let scope: Scope = serde_json::from_value(doc["scope"].clone())?;
    let backend: Uuid = serde_json::from_value(doc["backend_id"].clone())?;
    timeout(Duration::from_secs(2),db.batch_execute("CREATE ROLE signal_standard_maintenance LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; GRANT USAGE ON SCHEMA signal_control TO signal_standard_maintenance; GRANT EXECUTE ON FUNCTION signal_control.acquire(jsonb,uuid,integer,bytea,bytea),signal_control.renew(jsonb,integer,bytea,bytea),signal_control.read_catalog_snapshot(jsonb,uuid,integer,bytea,bytea),signal_control.object_control(jsonb,bytea,bytea,bytea) TO signal_standard_maintenance")).await??;
    timeout(
        Duration::from_secs(2),
        db.execute(
            "SELECT set_config('signal_fixture.password',$1,false)",
            &[&fixture.password],
        ),
    )
    .await??;
    timeout(Duration::from_secs(2),db.batch_execute("DO $$ BEGIN EXECUTE format('ALTER ROLE signal_standard_maintenance PASSWORD %L',current_setting('signal_fixture.password')); END $$")).await??;
    timeout(
        Duration::from_secs(2),
        db.execute(
            "INSERT INTO signal_control.principals VALUES('signal_standard_maintenance',$1,$2,$3)",
            &[&scope.tenant, &scope.stream, &scope.partition_id],
        ),
    )
    .await??;
    let acl = timeout(Duration::from_secs(2),db.query_one("SELECT has_function_privilege('signal_standard_producer','signal_control.object_control(jsonb,bytea,bytea,bytea)','EXECUTE'),has_table_privilege('signal_standard_maintenance','signal_control.partitions','UPDATE'),has_table_privilege('signal_standard_maintenance','signal_control.commits','SELECT')",&[])).await??;
    for index in 0..3 {
        assert!(!acl.get::<_, bool>(index));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(fs::read(
        &fixture.root_der,
    )?))?;
    let connection = || {
        ConnectionSettings::tls(
            "signal-control.invalid".into(),
            Some("127.0.0.1".parse().map_err(|_| ControlError::Invalid)?),
            fixture.port,
            database.into(),
            "signal_standard_maintenance".into(),
            fixture.password.as_bytes().to_vec(),
            roots.clone(),
        )
    };
    let inspector = match profile {
        CatalogProfile::Catalog4 => ControlClient::catalog(connection()?)?,
        CatalogProfile::RestoredCatalog5 => ControlClient::restored_catalog(connection()?)?,
    };
    let inspected: Result = async {
        // The shared credential inspector resolves exact scoped RPC identities;
        // namespace USAGE permits inspection, never execution of those RPCs.
        assert!(matches!(inspector.verify_lifecycle_credentials("signal_control_owner".into(), context()?).await, Err(ControlError::Fenced)));
        timeout(Duration::from_secs(2),db.batch_execute("GRANT USAGE ON SCHEMA signal_finding_scope TO signal_standard_maintenance")).await??;
        inspector.verify_lifecycle_credentials("signal_control_owner".into(), context()?).await.map_err(|error|format!("initial maintenance credentials: {error}"))?;
        for (grant,revoke) in [
            ("GRANT UPDATE ON signal_control.partitions TO signal_standard_maintenance", "REVOKE UPDATE ON signal_control.partitions FROM signal_standard_maintenance"),
            ("GRANT EXECUTE ON FUNCTION signal_control.publish(jsonb,bytea,boolean,bytea,bytea) TO signal_standard_maintenance", "REVOKE EXECUTE ON FUNCTION signal_control.publish(jsonb,bytea,boolean,bytea,bytea) FROM signal_standard_maintenance"),
            ("GRANT SELECT(checkpoint) ON signal_control.partitions TO PUBLIC", "REVOKE SELECT(checkpoint) ON signal_control.partitions FROM PUBLIC"),
        ] {
            timeout(Duration::from_secs(2),db.batch_execute(grant)).await??;
            let denied = inspector.verify_lifecycle_credentials("signal_control_owner".into(), context()?).await;
            timeout(Duration::from_secs(2),db.batch_execute(revoke)).await??;
            assert!(matches!(denied, Err(ControlError::Fenced)));
        }
        inspector.verify_lifecycle_credentials("signal_control_owner".into(), context()?).await.map_err(|error|format!("post-revocation maintenance credentials: {error}"))?;
        Ok(())
    }.await;
    let inspection_drain = inspector.shutdown(context()?).await;
    inspected?;
    inspection_drain?;
    let mut lifecycle = StoppedLifecycle::begin(
        connection()?,
        profile,
        scope.clone(),
        backend,
        BufferConfig {
            directory: root.join(if restored {
                "restored-server/wal"
            } else {
                "server/wal"
            }),
            ..Default::default()
        },
        "signal_control_owner".into(),
    )?;
    let owner = Uuid::new_v4();
    let result: Result = async {
        lifecycle
            .start(owner, 15000, context()?)
            .await
            .map_err(|error| format!("stopped lifecycle startup: {error}"))?;
        assert_eq!(lifecycle.metrics().0.checkpoint, checkpoint);
        assert_eq!(lifecycle.metrics().0.last_sequence, checkpoint);
        // Every current/historical committed data version remains protected.
        for row in timeout(
            Duration::from_secs(2),
            db.query(
                "SELECT manifest FROM signal_control.commits ORDER BY id",
                &[],
            ),
        )
        .await??
        {
            let manifest: signal_storage::object_manifest::QueryManifest =
                serde_json::from_slice(&row.get::<_, Vec<u8>>(0))?;
            for file in manifest.files {
                let object = CanonicalObjectRef {
                    schema_version: 1,
                    backend_id: backend,
                    key: file.object.key,
                    version: file.object.version.ok_or("exact committed version")?,
                };
                assert!(matches!(
                    lifecycle.retire(retire(object), context()?).await,
                    Err(StoppedLifecycleError::Control(ControlError::Conflict))
                ));
            }
        }
        // External policy explicitly registers each hold kind; no hold is
        // inferred from an empty inventory or caller-reported stopped boolean.
        for kind in [
            RetentionKind::Restore,
            RetentionKind::Replay,
            RetentionKind::Evidence,
        ] {
            let object = CanonicalObjectRef {
                schema_version: 1,
                backend_id: backend,
                key: format!("query/{}/orphan/{}", scope.stream, Uuid::new_v4()),
                version: "synthetic-exact-v1".into(),
            };
            let pin = RetentionPinInput {
                schema_version: 1,
                id: Uuid::new_v4(),
                object: object.clone(),
                kind,
                reference: b"explicit synthetic current external hold".to_vec(),
            };
            let held = lifecycle.pin(pin.clone(), context()?).await?;
            assert_eq!(held.state, ObjectControlState::Retained);
            assert_eq!(lifecycle.pin(pin.clone(), context()?).await?, held);
            assert!(matches!(
                lifecycle.retire(retire(object.clone()), context()?).await,
                Err(StoppedLifecycleError::Control(ControlError::Conflict))
            ));
            let release = ReleasePinInput {
                schema_version: 1,
                id: pin.id,
                reason: b"explicit synthetic current external release".to_vec(),
            };
            let released = lifecycle.release_pin(release.clone(), context()?).await?;
            assert_eq!(released.state, ObjectControlState::Released);
            assert_eq!(lifecycle.release_pin(release, context()?).await?, released);
            let request = retire(object);
            let retired = lifecycle.retire(request.clone(), context()?).await?;
            assert_eq!(retired.state, ObjectControlState::Retired);
            assert_eq!(lifecycle.retire(request, context()?).await?, retired);
        }
        lifecycle.renew(15000, context()?).await?;
        let competitor = match profile {
            CatalogProfile::Catalog4 => ControlClient::catalog(connection()?)?,
            CatalogProfile::RestoredCatalog5 => ControlClient::restored_catalog(connection()?)?,
        };
        // Wait for actual DB-clock expiry. Reacquisition by even the same
        // process-owner UUID advances the epoch; no owner/expiry UPDATE is used.
        tokio::time::sleep(Duration::from_secs(16)).await;
        competitor
            .acquire(scope.clone(), owner, 15000, context()?)
            .await?;
        let stale = lifecycle.renew(15000, context()?).await;
        competitor.shutdown(context()?).await?;
        assert!(matches!(
            stale,
            Err(StoppedLifecycleError::Control(ControlError::Fenced))
        ));
        assert_eq!(lifecycle.metrics().0.checkpoint, checkpoint);
        assert_eq!(lifecycle.metrics().0.last_sequence, checkpoint);
        Ok(())
    }
    .await;
    let drained = lifecycle.shutdown(context()?).await;
    result?;
    drained?;
    if restored {
        println!(
            "phase: Standard-restored-stopped-original-WAL-explicit-holds-retirement-stale-fence-qualified"
        );
    } else {
        println!(
            "phase: Standard-stopped-original-WAL-explicit-holds-retirement-stale-fence-qualified"
        );
    }
    Ok(())
}
