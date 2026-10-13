//! Trusted fresh schema + stopped data-only restore, owned fixtures only.
use super::{Fixture, Result, context};
use sha2::{Digest, Sha256};
use signal_control::*;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::timeout;
use tokio_postgres::Client;
use uuid::Uuid;
const DEST: &str = "signal_standard_restore";
const TABLES: &[&str] = &[
    "store",
    "object_backends",
    "partitions",
    "object_scopes",
    "principals",
    "commits",
    "receipts",
    "state",
    "findings",
    "outbox",
    "snapshots",
    "tombstones",
    "object_pins",
    "notification_attempts",
    "catalog_snapshots",
    "migrations",
];
const SCOPE_TABLES: &[&str] = &["profile", "activation", "producers", "facts", "requests"];
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentConsumer {
    schema_version: u16,
    consumer: Uuid,
    stream: Uuid,
    cursor: String,
    findings: usize,
    deliveries: usize,
}
fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut bytes = Vec::new();
    f.by_ref().take(cap as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err("restore fixture bytes".into());
    }
    Ok(bytes)
}
struct Consumers {
    current: PathBuf,
    expected: RestoreConsumerCursor,
    store: Uuid,
    allowed: AtomicBool,
}
impl RestoreConsumers for Consumers {
    fn reconcile<'a>(
        &'a self,
        c: &'a RestoreChallenge,
        expected: &'a [RestoreConsumerCursor],
        ctx: ControlContext,
    ) -> RestoreFuture<'a, ReconciledConsumers> {
        Box::pin(async move {
            ctx.check()?;
            let snapshot: CurrentConsumer = serde_json::from_slice(
                &read(&self.current, 4096).map_err(|_| ControlError::Corrupt)?,
            )
            .map_err(|_| ControlError::Corrupt)?;
            let cursor = signal_protocol::findings_feed::FindingsCursor::from_retained_parts(
                self.store,
                self.expected.position,
                self.expected.digest,
            )
            .map_err(|_| ControlError::Corrupt)?;
            if !self.allowed.load(Ordering::Acquire)
                || snapshot.schema_version != 1
                || snapshot.consumer != self.expected.consumer_id
                || snapshot.stream != self.store
                || snapshot.cursor != cursor.encode()
                || snapshot.findings != 2
                || snapshot.deliveries != 2
                || expected != [self.expected.clone()]
            {
                return Err(ControlError::Fenced);
            }
            ctx.check()?;
            Ok(ReconciledConsumers {
                challenge: c.clone(),
                consumers: expected.to_vec(),
            })
        })
    }
}
struct Authority {
    inventory: RestoreInventory,
    destination: RestoreDestination,
    generation: Uuid,
    approval: Uuid,
    allowed: AtomicBool,
}
impl RestoreAuthority for Authority {
    fn authorize<'a>(
        &'a self,
        c: &'a RestoreChallenge,
        i: &'a RestoreInventory,
        ctx: ControlContext,
    ) -> RestoreFuture<'a, RestoreDecision> {
        Box::pin(async move {
            ctx.check()?;
            if !self.allowed.load(Ordering::Acquire)
                || *i != self.inventory
                || c.destination_id != self.destination.id
                || c.new_generation != self.generation
                || c.inventory_sha256 != self.inventory.digest()?
                || c.checkpoint_sha256 != self.inventory.checkpoint_sha256
            {
                return Err(ControlError::Fenced);
            }
            Ok(RestoreDecision {
                challenge: c.clone(),
                approval_id: self.approval,
                custody_sha256: Sha256::digest(b"independently current owned version custody")
                    .into(),
                credential_binding_sha256: self.destination.credential_binding_sha256,
                expires_at: ctx.deadline(),
            })
        })
    }
}
struct Custody {
    client: reqwest::Client,
    endpoint: String,
    backend: Uuid,
    allowed: AtomicBool,
}
impl RestoreCustody for Custody {
    fn verify<'a>(
        &'a self,
        o: &'a RestoreObject,
        _protected: bool,
        _decision: &'a RestoreDecision,
        ctx: ControlContext,
    ) -> RestoreFuture<'a, ()> {
        Box::pin(async move {
            ctx.check()?;
            if !self.allowed.load(Ordering::Acquire)
                || o.object.backend_id != self.backend
                || o.bytes > 8 * 1024 * 1024
            {
                return Err(ControlError::Fenced);
            }
            let mut url = reqwest::Url::parse(&self.endpoint).map_err(|_| ControlError::Invalid)?;
            url.set_path(&format!("/signal-fixture/{}", o.object.key));
            url.query_pairs_mut()
                .append_pair("versionId", &o.object.version);
            // Synthetic protocol endpoint checks framing only; never an AWS IAM proof.
            let mut response = self
                .client
                .get(url)
                .header(
                    "Authorization",
                    "AWS4-HMAC-SHA256 synthetic-current-custody",
                )
                .header(
                    "x-amz-date",
                    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string(),
                )
                .header("x-amz-expected-bucket-owner", "123456789012")
                .send()
                .await
                .map_err(|_| ControlError::Corrupt)?;
            if response.status() != reqwest::StatusCode::OK
                || response
                    .headers()
                    .get("x-amz-version-id")
                    .and_then(|v| v.to_str().ok())
                    != Some(o.object.version.as_str())
            {
                return Err(ControlError::Corrupt);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| ControlError::Corrupt)? {
                if bytes.len() + chunk.len() > 8 * 1024 * 1024 {
                    return Err(ControlError::Full);
                }
                bytes.extend_from_slice(&chunk);
            }
            if bytes.len() as u64 != o.bytes || <[u8; 32]>::from(Sha256::digest(&bytes)) != o.sha256
            {
                return Err(ControlError::Corrupt);
            }
            ctx.check()
        })
    }
}
fn settings(
    f: &Fixture,
    database: &str,
    user: &str,
) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
        f.port,
        database.into(),
        user.into(),
        f.password.as_bytes().to_vec(),
    )
}
async fn dump(db: &Client, schema: &str, table: &str) -> Result<serde_json::Value> {
    let query = format!(
        "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM {schema}.{table} t"
    );
    let value: serde_json::Value = timeout(Duration::from_secs(2), db.query_one(&query, &[]))
        .await??
        .get(0);
    assert!(serde_json::to_vec(&value)?.len() <= 1024 * 1024);
    Ok(value)
}
async fn idle(restore: &PostgresStoppedRestore) -> Result {
    timeout(Duration::from_secs(4), async {
        while restore.metrics().active != 0 || restore.metrics().queue_depth != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}
// Observe this owned destination's actual SQL wait before cancellation. A clock
// guess, queued request or stale PostgreSQL statistics is not a COMMIT witness.
async fn cancel_observed(db: &Client, c: &ControlContext, commit: bool) -> Result {
    let observed = timeout(Duration::from_secs(2), async {
        loop {
            db.execute("SELECT pg_stat_clear_snapshot()", &[]).await?;
            let count: i64 = db.query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name='signal-control' AND datname=$1 AND state='active' AND wait_event='PgSleep' AND (query='COMMIT')=$2",
                &[&DEST, &commit],
            ).await?.get(0);
            if count == 1 { return Ok::<(), tokio_postgres::Error>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await;
    c.cancel();
    observed??;
    Ok(())
}
pub async fn qualify(source: &Client, f: &Fixture, root: &Path) -> Result {
    let current_path = root.join("private-consumer/current-private-progress.json");
    let current: CurrentConsumer = serde_json::from_slice(&read(&current_path, 4096)?)?;
    assert_eq!(current.schema_version, 1);
    assert_eq!(current.findings, 2);
    assert_eq!(current.deliveries, 2);
    let mut document: serde_json::Value =
        serde_json::from_slice(&read(&root.join("shared.json"), 4096)?)?;
    let scope: Scope = serde_json::from_value(document["scope"].clone())?;
    assert_eq!(scope.store_id, current.stream);
    let cursor = signal_protocol::findings_feed::FindingsCursor::decode(&current.cursor)?;
    assert_eq!(cursor.position(), 2);
    assert_eq!(cursor.stream(), scope.store_id);
    let digest: Vec<u8> = timeout(
        Duration::from_secs(2),
        source.query_one(
            "SELECT cursor_digest FROM signal_control.findings WHERE position=2",
            &[],
        ),
    )
    .await??
    .get(0);
    let expected = RestoreConsumerCursor {
        consumer_id: current.consumer,
        position: 2,
        digest: digest.try_into().map_err(|_| "cursor digest")?,
    };
    assert_eq!(
        signal_protocol::findings_feed::FindingsCursor::from_retained_parts(
            scope.store_id,
            2,
            expected.digest
        )?
        .encode(),
        current.cursor
    );
    timeout(Duration::from_secs(2),source.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind,feed_position) VALUES($1,$2,$1,'notification',2)",&[&current.consumer,&scope.tenant])).await??;
    timeout(Duration::from_secs(2),source.batch_execute("UPDATE signal_control.store SET ready=false; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL")).await??;
    let authority_scope = AdministrativeScope {
        schema_version: 1,
        store_id: scope.store_id,
        generation: scope.generation,
    };
    let mut objects = BTreeMap::new();
    let backend: Uuid = serde_json::from_value(document["backend_id"].clone())?;
    for row in timeout(
        Duration::from_secs(2),
        source.query(
            "SELECT manifest FROM signal_control.commits ORDER BY id",
            &[],
        ),
    )
    .await??
    {
        let manifest: signal_storage::object_manifest::QueryManifest =
            serde_json::from_slice(&row.get::<_, Vec<u8>>(0))?;
        for reference in manifest
            .files
            .iter()
            .map(|f| &f.object)
            .chain(manifest.previous.iter().map(|p| &p.object))
        {
            let object = CanonicalObjectRef {
                schema_version: 1,
                backend_id: backend,
                key: reference.key.clone(),
                version: reference.version.clone().ok_or("object version")?,
            };
            objects.insert(
                object.digest()?,
                RestoreObject {
                    object,
                    sha256: reference.sha256,
                    bytes: reference.bytes,
                },
            );
        }
    }
    let custody_selected = document.get("custody").is_some();
    if custody_selected {
        let d: ObjectCustodyDescription =
            serde_json::from_slice(&read(&root.join("custody-description.json"), 4096)?)?;
        d.validate()?;
        assert_eq!(d.scope, scope);
        objects.insert(
            d.object.digest()?,
            RestoreObject {
                object: d.object,
                sha256: d.sha256,
                bytes: d.bytes,
            },
        );
    }
    let objects: Vec<_> = objects.into_values().collect();
    assert_eq!(objects.len(), if custody_selected { 4 } else { 3 });
    let destination = RestoreDestination {
        id: Uuid::new_v4(),
        credential_binding_sha256: Sha256::digest(Uuid::new_v4().as_bytes()).into(),
    };
    let consumers = Arc::new(Consumers {
        current: current_path,
        expected,
        store: scope.store_id,
        allowed: AtomicBool::new(true),
    });
    let source_restore = PostgresStoppedRestore::scoped_catalog(
        settings(f, super::DB, "signal_migrator")?,
        "signal_control_owner".into(),
        authority_scope.clone(),
        destination.clone(),
        objects.clone(),
        consumers.clone(),
    )?;
    let original = source_restore.stage(context()?).await?;
    assert_eq!(original.consumers.len(), 1);
    source_restore.shutdown(context()?).await?;
    // Fresh compiled DDL; import rows only. No copied functions or credentials.
    timeout(
        Duration::from_secs(2),
        source.batch_execute("CREATE DATABASE signal_standard_restore"),
    )
    .await??;
    timeout(
        Duration::from_secs(2),
        source.batch_execute(
            "GRANT CREATE ON DATABASE signal_standard_restore TO signal_control_owner",
        ),
    )
    .await??;
    let administrator = ControlAdministrator::new(
        settings(f, DEST, "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    administrator
        .initialize(
            InitializeInput {
                scope: authority_scope.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            context()?,
        )
        .await?;
    administrator
        .migrate_catalog(
            MigrationInput {
                scope: authority_scope.clone(),
                source_revision: 2,
                source_sha256: schema_identity().1,
            },
            context()?,
        )
        .await?;
    administrator.shutdown(context()?).await?;
    let mut pg = tokio_postgres::Config::new();
    pg.host("127.0.0.1")
        .port(f.port)
        .user("postgres")
        .password(&f.password)
        .dbname(DEST);
    let (dest, driver) =
        timeout(Duration::from_secs(2), pg.connect(tokio_postgres::NoTls)).await??;
    let driver = tokio::spawn(driver);
    let result:Result=async {
  timeout(Duration::from_secs(2),dest.batch_execute("SET ROLE signal_control_owner")).await??;
  timeout(Duration::from_secs(2),dest.batch_execute(include_str!("../../../../schemas/shared-control/007-finding-scope.sql"))).await??;
  timeout(Duration::from_secs(2),dest.batch_execute(include_str!("../../../../schemas/shared-control/008-scoped-publication.sql"))).await??;
  timeout(Duration::from_secs(2),dest.batch_execute("RESET ROLE; BEGIN; TRUNCATE signal_control.store,signal_control.migrations CASCADE")).await??;
  let mut scope_before=BTreeMap::new();
  for table in TABLES {
   let mut rows=dump(source,"signal_control",table).await?;
   if *table=="partitions"{for row in rows.as_array_mut().ok_or("partition rows")?{row["head"]=serde_json::Value::Null;}}
   timeout(Duration::from_secs(2),dest.execute(&format!("INSERT INTO signal_control.{table} SELECT * FROM jsonb_populate_recordset(NULL::signal_control.{table},$1)"),&[&rows])).await??;
  }
  timeout(Duration::from_secs(2),dest.batch_execute("UPDATE signal_control.partitions p SET head=c.id FROM signal_control.commits c WHERE c.partition_id=p.id AND c.last_sequence=p.checkpoint")).await??;
  for table in SCOPE_TABLES{let rows=dump(source,"signal_finding_scope",table).await?;scope_before.insert(*table,rows.clone());timeout(Duration::from_secs(2),dest.execute(&format!("INSERT INTO signal_finding_scope.{table} SELECT * FROM jsonb_populate_recordset(NULL::signal_finding_scope.{table},$1)"),&[&rows])).await??;}
  timeout(Duration::from_secs(2),dest.batch_execute("GRANT USAGE ON SCHEMA signal_control,signal_finding_scope TO signal_standard_producer,signal_standard_reader; GRANT EXECUTE ON FUNCTION signal_control.acquire(jsonb,uuid,integer,bytea,bytea),signal_control.renew(jsonb,integer,bytea,bytea),signal_control.read_catalog_snapshot(jsonb,uuid,integer,bytea,bytea),signal_control.publish(jsonb,bytea,boolean,bytea,bytea),signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) TO signal_standard_producer; GRANT SELECT ON ALL TABLES IN SCHEMA signal_control,signal_finding_scope TO signal_standard_reader; COMMIT")).await??;
  let restore=PostgresStoppedRestore::scoped_catalog(settings(f,DEST,"signal_migrator")?,"signal_control_owner".into(),authority_scope.clone(),destination.clone(),objects,consumers.clone())?;
  let copied=restore.stage(context()?).await?;assert_eq!(copied,original);
  let generation=Uuid::new_v4();let approval=Authority{inventory:original.clone(),destination:destination.clone(),generation,approval:Uuid::new_v4(),allowed:AtomicBool::new(false)};
  let endpoint:serde_json::Value=serde_json::from_slice(&read(&root.join("fixture/endpoint.json"),4096)?)?;
  let custody=Custody{client:reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(2)).build()?,endpoint:endpoint["url"].as_str().ok_or("current endpoint")?.into(),backend,allowed:AtomicBool::new(true)};
  assert!(matches!(coordinate_stopped_restore(&restore,&approval,&custody,destination.id,generation,context()?).await,Err(ControlError::Fenced)));assert_eq!(restore.stage(context()?).await?,copied);
  approval.allowed.store(true,Ordering::Release);custody.allowed.store(false,Ordering::Release);
  assert!(matches!(coordinate_stopped_restore(&restore,&approval,&custody,destination.id,generation,context()?).await,Err(ControlError::Fenced)));assert_eq!(restore.stage(context()?).await?,copied);
  custody.allowed.store(true,Ordering::Release);consumers.allowed.store(false,Ordering::Release);
  // Owned public fixture hooks stay outside the frozen control/scope catalog.
  timeout(Duration::from_secs(2),dest.batch_execute("CREATE FUNCTION public.synthetic_scoped_restore_fail() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF to_regclass('signal_control.restore_record') IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF; END $$; CREATE EVENT TRIGGER synthetic_scoped_restore_fail ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.synthetic_scoped_restore_fail()")).await??;
  assert!(matches!(coordinate_stopped_restore(&restore,&approval,&custody,destination.id,generation,context()?).await,Err(ControlError::Full)));
  timeout(Duration::from_secs(2),dest.batch_execute("DROP EVENT TRIGGER synthetic_scoped_restore_fail; DROP FUNCTION public.synthetic_scoped_restore_fail()")).await??;
  assert_eq!(restore.stage(context()?).await?,copied);
  for table in SCOPE_TABLES{assert_eq!(dump(&dest,"signal_finding_scope",table).await?,scope_before[table]);}
  // Cancel only once PostgreSQL is executing the actual DDL pause.
  timeout(Duration::from_secs(2),dest.batch_execute("CREATE FUNCTION public.synthetic_scoped_restore_pause() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF to_regclass('signal_control.restore_record') IS NOT NULL THEN PERFORM pg_sleep(1); END IF; END $$; CREATE EVENT TRIGGER synthetic_scoped_restore_pause ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.synthetic_scoped_restore_pause()")).await??;
  let c=context()?;
  let (result,observed)=tokio::join!(coordinate_stopped_restore(&restore,&approval,&custody,destination.id,generation,c.clone()),cancel_observed(&dest,&c,false));
  observed.map_err(|error|format!("scoped DDL observer: {error}; result: {result:?}"))?;
  assert!(matches!(result,Err(ControlError::Uncertain)));idle(&restore).await?;
  timeout(Duration::from_secs(2),dest.batch_execute("DROP EVENT TRIGGER synthetic_scoped_restore_pause; DROP FUNCTION public.synthetic_scoped_restore_pause()")).await??;
  assert_eq!(restore.stage(context()?).await?,copied);
  assert!(timeout(Duration::from_secs(2),dest.query_one("SELECT to_regclass('signal_control.restore_record') IS NULL",&[])).await??.get::<_,bool>(0));
  println!("phase: Standard-scoped-restore-DDL-error-and-observed-cancellation-original-inventory-rollback-qualified");
  // The last replacement queues a deferred pause. Observe COMMIT itself,
  // cancel the original caller, then resolve through a fresh bounded read.
  timeout(Duration::from_secs(2),dest.batch_execute("CREATE TABLE public.synthetic_scoped_restore_commit_signal(id integer); CREATE FUNCTION public.synthetic_scoped_restore_commit_signal() RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN IF EXISTS(SELECT 1 FROM pg_event_trigger_ddl_commands() d JOIN pg_proc p ON p.oid=d.objid WHERE d.classid='pg_proc'::regclass AND p.proname='read_catalog_snapshot') THEN INSERT INTO public.synthetic_scoped_restore_commit_signal VALUES(1); END IF; END $$; CREATE EVENT TRIGGER synthetic_scoped_restore_commit_signal ON ddl_command_end WHEN TAG IN ('CREATE FUNCTION') EXECUTE FUNCTION public.synthetic_scoped_restore_commit_signal(); CREATE FUNCTION public.synthetic_scoped_restore_commit_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_scoped_restore_commit_pause AFTER INSERT ON public.synthetic_scoped_restore_commit_signal DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_scoped_restore_commit_pause()")).await??;
  let c=context()?;
  let (result,observed)=tokio::join!(coordinate_stopped_restore(&restore,&approval,&custody,destination.id,generation,c.clone()),cancel_observed(&dest,&c,true));
  observed.map_err(|error|format!("scoped COMMIT observer: {error}; result: {result:?}"))?;
  assert!(matches!(result,Err(ControlError::Uncertain)));idle(&restore).await?;
  timeout(Duration::from_secs(2),dest.batch_execute("DROP EVENT TRIGGER synthetic_scoped_restore_commit_signal; DROP FUNCTION public.synthetic_scoped_restore_commit_signal(); DROP TABLE public.synthetic_scoped_restore_commit_signal; DROP FUNCTION public.synthetic_scoped_restore_commit_pause()")).await??;
  let held=restore.resolve(context()?).await?;assert!(!held.ready);assert_eq!(held.challenge.new_generation,generation);
  assert!(matches!(resume_stopped_restore(&restore,&approval,&custody,original.clone(),held.clone(),context()?).await,Err(ControlError::Fenced)));
  assert_eq!(restore.resolve(context()?).await?,held);
  println!("phase: Standard-scoped-restore-observed-COMMIT-caller-cancellation-current-resolution-consumer-refusal-qualified");
  consumers.allowed.store(true,Ordering::Release);
  let receipt=resume_stopped_restore(&restore,&approval,&custody,original.clone(),held,context()?).await?;assert!(receipt.ready);
  for table in SCOPE_TABLES {let mut expected=scope_before[table].clone();if *table=="activation"{expected[0]["store_generation"]=serde_json::to_value(generation)?;}assert_eq!(dump(&dest,"signal_finding_scope",table).await?,expected);}
  let owner=FindingScopeAdministrator::new(settings(f,DEST,"signal_migrator")?,"signal_control_owner".into(),FindingScopeProfile::RestoredCatalog5Scoped)?;let scope_generation:Uuid=serde_json::from_value(document["scope_generation"].clone())?;
  assert!(matches!(owner.inspect(scope.clone(),scope_generation,context()?).await,Err(ControlError::Fenced)));let mut current_scope=scope.clone();current_scope.generation=generation;let pin=owner.inspect(current_scope.clone(),scope_generation,context()?).await?;assert_eq!(pin.binding()?.checkpoint,Some(2));assert_eq!(pin.binding()?.producer.as_ref().ok_or("producer")?.wal_floor,0);owner.shutdown(context()?).await?;
  let installer=ControlClient::restored_catalog(settings(f,DEST,"signal_migrator")?)?;
  installer.install_restored_custody("signal_control_owner".into(),context()?).await?;installer.shutdown(context()?).await?;
  let producer=ControlClient::restored_catalog(settings(f,DEST,"signal_standard_producer")?)?;
  assert!(producer.verify_restored_custody_producer_credentials("signal_control_owner".into(),context()?).await.is_err());
  timeout(Duration::from_secs(2),dest.batch_execute("GRANT USAGE ON SCHEMA signal_custody_restore TO signal_standard_producer; GRANT SELECT ON signal_custody_restore.contract TO signal_standard_producer; GRANT EXECUTE ON FUNCTION signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea),signal_control.record_receipt(jsonb,bytea,bytea,bytea) TO signal_standard_producer")).await??;
  producer.verify_restored_custody_producer_credentials("signal_control_owner".into(),context()?).await?;
  assert!(producer.verify_custody_producer_credentials("signal_control_owner".into(),context()?).await.is_err());
  assert!(producer.verify_producer_credentials("signal_control_owner".into(),context()?).await.is_err());
  timeout(Duration::from_secs(2),dest.batch_execute("GRANT UPDATE(artifact_sha256) ON signal_custody_restore.contract TO signal_standard_producer")).await??;
  assert!(producer.verify_restored_custody_producer_credentials("signal_control_owner".into(),context()?).await.is_err());
  timeout(Duration::from_secs(2),dest.batch_execute("REVOKE UPDATE(artifact_sha256) ON signal_custody_restore.contract FROM signal_standard_producer; REVOKE EXECUTE ON FUNCTION signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea),signal_control.record_receipt(jsonb,bytea,bytea,bytea) FROM signal_standard_producer; REVOKE SELECT ON signal_custody_restore.contract FROM signal_standard_producer; REVOKE USAGE ON SCHEMA signal_custody_restore FROM signal_standard_producer")).await??;
  if custody_selected {
      timeout(Duration::from_secs(2),dest.batch_execute("GRANT USAGE ON SCHEMA signal_custody_restore TO signal_standard_producer; GRANT SELECT ON signal_custody_restore.contract TO signal_standard_producer; GRANT EXECUTE ON FUNCTION signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea),signal_control.record_receipt(jsonb,bytea,bytea,bytea) TO signal_standard_producer")).await??;
      producer.verify_restored_custody_producer_credentials("signal_control_owner".into(),context()?).await?;
      document["custody"]["restored_receipts"]=serde_json::json!(true);
  } else {producer.verify_producer_credentials("signal_control_owner".into(),context()?).await?;}
  producer.shutdown(context()?).await?;
  println!("phase: Standard-restored-custody-selected-profile-exact-readonly-grants-ordinary-denial-qualified");
  document["scope"]=serde_json::to_value(current_scope)?;document["catalog_profile"]=serde_json::json!("restored_catalog5");document["database"]["database"]=serde_json::json!(DEST);
  fs::write(root.join("restored-shared.json"),serde_json::to_vec(&document)?)?;fs::write(root.join("scoped-restore-receipt.json"),serde_json::to_vec(&serde_json::json!({"schema_version":1,"generation":generation,"old_generation":scope.generation,"ready":receipt.ready,"inventory":original,"scope_original_bytes_preserved":true,"consumer_current_reconciled":true,"scoped_ddl_error_rollback":true,"scoped_ddl_cancel_rollback":true,"scoped_lost_commit_resolved":true,"scoped_consumer_resume_refused":true}))?)?;
  restore.shutdown(context()?).await?;println!("phase: Standard-fresh-trusted-scoped-restore-current-custody-consumer-gate-generation-original-bytes-qualified");Ok(())
 }.await;
    drop(dest);
    timeout(Duration::from_secs(2), driver).await???;
    result
}
