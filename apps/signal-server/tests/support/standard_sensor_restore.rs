//! Fresh trusted DDL and original native sensor rows; authority/S3 are synthetic.
use super::{Fixture, Result, context, standard_restore as restore};
use sha2::{Digest, Sha256};
use signal_control::*;
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tokio_postgres::Client;
use uuid::Uuid;

const DEST: &str = "signal_standard_restore";
struct Consumers;
impl RestoreConsumers for Consumers {
    fn reconcile<'a>(
        &'a self,
        challenge: &'a RestoreChallenge,
        expected: &'a [RestoreConsumerCursor],
        c: ControlContext,
    ) -> RestoreFuture<'a, ReconciledConsumers> {
        Box::pin(async move {
            c.check()?;
            if !expected.is_empty() {
                return Err(ControlError::Fenced);
            }
            Ok(ReconciledConsumers {
                challenge: challenge.clone(),
                consumers: vec![],
            })
        })
    }
}

pub async fn qualify(source: &Client, fixture: &Fixture, root: &Path) -> Result {
    tokio::time::timeout(Duration::from_secs(25), run(source, fixture, root)).await?
}
async fn run(source: &Client, f: &Fixture, root: &Path) -> Result {
    source.batch_execute("DROP TRIGGER synthetic_sensor_hold_retirement ON signal_control.state; DROP FUNCTION public.synthetic_sensor_hold_retirement()").await?;
    let mut doc: serde_json::Value = serde_json::from_slice(&fs::read(root.join("shared.json"))?)?;
    let scope: Scope = serde_json::from_value(doc["scope"].clone())?;
    let logical: Uuid = serde_json::from_value(doc["scope_generation"].clone())?;
    let state = source.query_one("SELECT revision,value FROM signal_control.state WHERE partition_id=$1 AND key='standard-sensor'", &[&scope.partition_id]).await?;
    let original = RevisionedState {
        key: "standard-sensor".into(),
        revision: state
            .get::<_, Vec<u8>>(0)
            .try_into()
            .map_err(|_| "revision")?,
        bytes: state.get(1),
    };
    let frame: MultiEventStateEnvelope = serde_json::from_slice(&original.bytes)?;
    assert_eq!(frame.checkpoint, 2);
    assert_eq!(frame.scope_generation, logical);
    assert_eq!(
        frame.metadata["sensor"]["snapshot"]["record"]["outbox"]
            .as_array()
            .ok_or("pending outbox")?
            .len(),
        1
    );
    let original_findings = restore::dump(source, "signal_control", "findings").await?;
    assert_eq!(original_findings.as_array().ok_or("findings")?.len(), 1);
    source.batch_execute("UPDATE signal_control.store SET ready=false; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL").await?;
    let authority_scope = AdministrativeScope {
        schema_version: 1,
        store_id: scope.store_id,
        generation: scope.generation,
    };
    let backend: Uuid = serde_json::from_value(doc["backend_id"].clone())?;
    let mut objects = BTreeMap::new();
    for row in source
        .query(
            "SELECT manifest FROM signal_control.commits ORDER BY id",
            &[],
        )
        .await?
    {
        let manifest: signal_storage::object_manifest::QueryManifest =
            serde_json::from_slice(&row.get::<_, Vec<u8>>(0))?;
        for r in manifest
            .files
            .iter()
            .map(|f| &f.object)
            .chain(manifest.previous.iter().map(|p| &p.object))
        {
            let object = CanonicalObjectRef {
                schema_version: 1,
                backend_id: backend,
                key: r.key.clone(),
                version: r.version.clone().ok_or("version")?,
            };
            objects.insert(
                object.digest()?,
                RestoreObject {
                    object,
                    sha256: r.sha256,
                    bytes: r.bytes,
                },
            );
        }
    }
    let objects: Vec<_> = objects.into_values().collect();
    assert!(!objects.is_empty() && objects.len() <= 8);
    let destination = RestoreDestination {
        id: Uuid::new_v4(),
        credential_binding_sha256: Sha256::digest(Uuid::new_v4().as_bytes()).into(),
    };
    let before = PostgresStoppedRestore::scoped_catalog(
        restore::settings(f, super::DB, "signal_migrator")?,
        "signal_control_owner".into(),
        authority_scope.clone(),
        destination.clone(),
        objects.clone(),
        Arc::new(Consumers),
    )?;
    let inventory = before.stage(context()?).await?;
    assert!(inventory.consumers.is_empty());
    before.shutdown(context()?).await?;
    source
        .batch_execute("CREATE DATABASE signal_standard_restore")
        .await?;
    source
        .batch_execute("GRANT CREATE ON DATABASE signal_standard_restore TO signal_control_owner")
        .await?;
    let owner = ControlAdministrator::new(
        restore::settings(f, DEST, "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    owner
        .initialize(
            InitializeInput {
                scope: authority_scope.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            context()?,
        )
        .await?;
    owner
        .migrate_catalog(
            MigrationInput {
                scope: authority_scope.clone(),
                source_revision: 2,
                source_sha256: schema_identity().1,
            },
            context()?,
        )
        .await?;
    owner.shutdown(context()?).await?;
    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(f.port)
        .user("postgres")
        .password(&f.password)
        .dbname(DEST);
    let (dest, driver) = config.connect(tokio_postgres::NoTls).await?;
    let driver = tokio::spawn(driver);
    let result: Result = async {
        dest.batch_execute("SET ROLE signal_control_owner").await?;
        dest.batch_execute(include_str!("../../../../schemas/shared-control/007-finding-scope.sql")).await?;
        dest.batch_execute(include_str!("../../../../schemas/shared-control/008-scoped-publication.sql")).await?;
        dest.batch_execute("RESET ROLE").await?;
        super::standard_window::install_modules(&dest, false).await?;
        super::standard_sensor::prepare(&dest).await?;
        dest.batch_execute("BEGIN; TRUNCATE signal_control.store,signal_control.migrations CASCADE").await?;
        for table in restore::TABLES {
            let mut rows = restore::dump(source, "signal_control", table).await?;
            if *table == "partitions" { for r in rows.as_array_mut().ok_or("partitions")? { r["head"] = serde_json::Value::Null; } }
            dest.execute(&format!("INSERT INTO signal_control.{table} SELECT * FROM jsonb_populate_recordset(NULL::signal_control.{table},$1)"), &[&rows]).await?;
        }
        dest.batch_execute("UPDATE signal_control.partitions p SET head=c.id FROM signal_control.commits c WHERE c.partition_id=p.id AND c.last_sequence=p.checkpoint").await?;
        for (schema, tables) in [
            ("signal_finding_scope", restore::SCOPE_TABLES),
            ("signal_multi_event", &["profile", "requests", "facts"][..]),
            ("signal_window_history", &["profile", "assessments"][..]),
        ] {
            for table in tables {
                let rows = restore::dump(source, schema, table).await?;
                dest.execute(&format!("INSERT INTO {schema}.{table} SELECT * FROM jsonb_populate_recordset(NULL::{schema}.{table},$1)"), &[&rows]).await?;
                assert_eq!(restore::dump(&dest, schema, table).await?, rows);
            }
        }
        dest.batch_execute("GRANT USAGE ON SCHEMA signal_control,signal_finding_scope TO signal_standard_producer,signal_standard_reader; GRANT EXECUTE ON FUNCTION signal_control.acquire(jsonb,uuid,integer,bytea,bytea),signal_control.renew(jsonb,integer,bytea,bytea),signal_control.read_catalog_snapshot(jsonb,uuid,integer,bytea,bytea),signal_control.publish(jsonb,bytea,boolean,bytea,bytea),signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) TO signal_standard_producer; GRANT SELECT ON ALL TABLES IN SCHEMA signal_control,signal_finding_scope TO signal_standard_reader; COMMIT").await?;
        let restore = PostgresStoppedRestore::scoped_catalog(restore::settings(f, DEST, "signal_migrator")?, "signal_control_owner".into(), authority_scope, destination.clone(), objects, Arc::new(Consumers))?;
        assert_eq!(restore.stage(context()?).await?, inventory);
        let generation = Uuid::new_v4();
        let authority = restore::Authority { inventory: inventory.clone(), destination: destination.clone(), generation, approval: Uuid::new_v4(), allowed: AtomicBool::new(true) };
        let endpoint: serde_json::Value = serde_json::from_slice(&fs::read(root.join("fixture/endpoint.json"))?)?;
        let custody = restore::Custody { client: reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(2)).build()?, endpoint: endpoint["url"].as_str().ok_or("endpoint")?.into(), backend, allowed: AtomicBool::new(true) };
        let receipt = coordinate_stopped_restore(&restore, &authority, &custody, destination.id, generation, context()?).await?;
        assert!(receipt.ready);
        restore.shutdown(context()?).await?;
        dest.batch_execute("UPDATE signal_control.store SET ready=false; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL").await?;
        let mut current = scope.clone(); current.generation = generation;
        let request = StateScopeRebindInput::new(current.clone(), scope.generation, original.clone())?;
        let owner = ControlAdministrator::new(restore::settings(f, DEST, "signal_migrator")?, "signal_control_owner".into())?;
        let mut stale = request.clone(); stale.source.bytes.push(b' ');
        assert!(matches!(owner.rebind_state_scope(stale, context()?).await, Err(ControlError::Conflict)));
        owner.rebind_state_scope(request.clone(), context()?).await?;
        owner.rebind_state_scope(request.clone(), context()?).await?;
        owner.shutdown(context()?).await?;
        assert_eq!(restore::dump(&dest, "signal_control", "findings").await?, original_findings);
        let rebound: Vec<u8> = dest.query_one("SELECT value FROM signal_control.state WHERE key='standard-sensor'", &[]).await?.get(0);
        assert_eq!(rebound, request.target.bytes);
        let target: MultiEventStateEnvelope = serde_json::from_slice(&rebound)?;
        assert_eq!(target.metadata["sensor"], frame.metadata["sensor"]);
        assert_eq!(target.canonical_sequences, frame.canonical_sequences);
        assert_eq!(target.scope_generation, logical);
        dest.batch_execute("UPDATE signal_control.store SET ready=true").await?;
        doc["scope"] = serde_json::to_value(current)?;
        doc["catalog_profile"] = serde_json::json!("restored_catalog5");
        doc["database"]["database"] = serde_json::json!(DEST);
        fs::write(root.join("restored-shared.json"), serde_json::to_vec(&doc)?)?;
        fs::write(root.join("sensor-restore-receipt.json"), serde_json::to_vec(&serde_json::json!({"schema_version":1,"generation":generation,"old_generation":scope.generation,"scope_generation":logical,"checkpoint":frame.checkpoint,"pending_outputs":1,"original_findings":original_findings,"original_state_sha256":Sha256::digest(&original.bytes).iter().map(|b|format!("{b:02x}")).collect::<String>(),"rebound_state_sha256":Sha256::digest(&rebound).iter().map(|b|format!("{b:02x}")).collect::<String>(),"inventory":inventory}))?)?;
        println!("phase: Standard-SENSOR-fresh-trusted-restored-generation-original-pending-known-output-owner-rebind-qualified");
        Ok(())
    }.await;
    drop(dest);
    driver.await??;
    result
}
