//! Owned durable version-emulating filesystem objects and actual PostgreSQL
//! catalog restore. Current authority is separately held synthetic fixture state.
use object_store::{ObjectStore, local::LocalFileSystem};
use sha2::{Digest, Sha256};
use signal_control::*;
use signal_storage::{
    OperationContext, StorageConfig, StoredEvent,
    object_cache::MaterializationConfig,
    object_codec::ObjectCodec,
    object_io::{ObjectIo, ObjectIoLimits},
    object_manifest::{ManifestLimits, QueryFile, QueryManifest, data_key},
    object_selection::{ObjectSelection, SelectionConfig},
};
use std::{
    collections::BTreeMap,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio_postgres::Client;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SOURCE: &str = "signal_catalog_restore_source";
const DEST: &str = "signal_catalog_restore_destination";
const TABLES: &[&str] = &[
    "store",
    "partitions",
    "commits",
    "receipts",
    "state",
    "findings",
    "outbox",
    "snapshots",
    "tombstones",
    "principals",
    "object_backends",
    "object_scopes",
    "object_pins",
    "notification_attempts",
    "catalog_snapshots",
    "migrations",
];
fn context() -> OperationContext {
    OperationContext::new(std::time::Duration::from_secs(5))
}
fn settings(
    f: &super::Fixture,
    database: &str,
    user: &str,
) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        IpAddr::from([127, 0, 0, 1]),
        f.port,
        database.into(),
        user.into(),
        f.password.as_bytes().to_vec(),
    )
}
#[derive(Debug)]
struct DurableVersions(LocalFileSystem);
impl std::fmt::Display for DurableVersions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owned durable immutable version fixture")
    }
}
fn object_error() -> object_store::Error {
    object_store::Error::Generic {
        store: "durable version fixture",
        source: std::io::Error::other("invalid fixture operation or object").into(),
    }
}
#[async_trait::async_trait]
impl ObjectStore for DurableVersions {
    async fn put_opts(
        &self,
        p: &object_store::path::Path,
        b: object_store::PutPayload,
        o: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        if !matches!(o.mode, object_store::PutMode::Create) {
            return Err(object_error());
        }
        let mut hash = Sha256::new();
        for bytes in b.iter() {
            hash.update(bytes);
        }
        let tag: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
        let mut result = self.0.put_opts(p, b, o).await?;
        result.version = Some("owned-durable-v1".into());
        result.e_tag = Some(tag);
        Ok(result)
    }
    async fn get_opts(
        &self,
        p: &object_store::path::Path,
        mut o: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        if o.version
            .as_deref()
            .is_some_and(|v| v != "owned-durable-v1")
            || o.range.is_some()
        {
            return Err(object_error());
        }
        o.version = None;
        let condition = o.if_match.take();
        let mut result = self.0.get_opts(p, o).await?;
        if result.meta.size > 64 * 1024 * 1024 {
            return Err(object_error());
        }
        let mut bytes = Vec::new();
        match result.payload {
            object_store::GetResultPayload::File(file, _) => {
                file.take(result.meta.size + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| object_error())?;
            }
            _ => return Err(object_error()),
        }
        if bytes.len() as u64 != result.meta.size {
            return Err(object_error());
        }
        let tag: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if condition.is_some_and(|c| c != tag) {
            return Err(object_error());
        }
        result.meta.version = Some("owned-durable-v1".into());
        result.meta.e_tag = Some(tag);
        result.payload =
            object_store::GetResultPayload::Stream(Box::pin(futures_util::stream::once(async {
                Ok(bytes.into())
            })));
        Ok(result)
    }
    async fn put_multipart_opts(
        &self,
        _: &object_store::path::Path,
        _: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        Err(object_error())
    }
    fn list(
        &self,
        p: Option<&object_store::path::Path>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
    {
        self.0.list(p)
    }
    fn delete_stream(
        &self,
        _: futures_util::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::path::Path>>
    {
        Box::pin(futures_util::stream::once(async { Err(object_error()) }))
    }
    async fn list_with_delimiter(
        &self,
        _: Option<&object_store::path::Path>,
    ) -> object_store::Result<object_store::ListResult> {
        Err(object_error())
    }
    async fn copy_opts(
        &self,
        _: &object_store::path::Path,
        _: &object_store::path::Path,
        _: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        Err(object_error())
    }
}
pub(super) fn io(root: &Path) -> Result<ObjectIo> {
    Ok(ObjectIo::remote(
        Arc::new(DurableVersions(LocalFileSystem::new_with_prefix(root)?)),
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
    )?)
}
struct Authority {
    checkpoint: [u8; 32],
    destination: Uuid,
    binding: [u8; 32],
    approved: AtomicBool,
}
impl RestoreAuthority for Authority {
    fn authorize<'a>(
        &'a self,
        c: &'a RestoreChallenge,
        i: &'a RestoreInventory,
        context: ControlContext,
    ) -> RestoreFuture<'a, RestoreDecision> {
        Box::pin(async move {
            context.check()?;
            if !self.approved.load(Ordering::Acquire)
                || c.destination_id != self.destination
                || i.checkpoint_sha256 != self.checkpoint
                || i.revision != 4
                || i.revisions.iter().any(|r| {
                    r.rule_sha256 != Sha256::digest(b"synthetic exact rule bytes").as_slice()
                        || r.normalizer != "synthetic-exact-v1"
                })
            {
                return Err(ControlError::Fenced);
            }
            Ok(RestoreDecision {
                challenge: c.clone(),
                approval_id: Uuid::from_u128(0xda01),
                custody_sha256: Sha256::digest(b"current separately held owned catalog custody")
                    .into(),
                credential_binding_sha256: self.binding,
                expires_at: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            })
        })
    }
}
struct Consumers(Mutex<Vec<RestoreConsumerCursor>>);
impl RestoreConsumers for Consumers {
    fn reconcile<'a>(
        &'a self,
        c: &'a RestoreChallenge,
        expected: &'a [RestoreConsumerCursor],
        context: ControlContext,
    ) -> RestoreFuture<'a, ReconciledConsumers> {
        Box::pin(async move {
            context.check()?;
            let current = self
                .0
                .lock()
                .map_err(|_| ControlError::Unavailable)?
                .clone();
            if current != expected {
                return Err(ControlError::Fenced);
            }
            Ok(ReconciledConsumers {
                challenge: c.clone(),
                consumers: current,
            })
        })
    }
}
struct Custody {
    io: ObjectIo,
    objects: BTreeMap<[u8; 32], signal_storage::object_manifest::QueryObjectRef>,
    protected: AtomicBool,
}
impl RestoreCustody for Custody {
    fn verify<'a>(
        &'a self,
        o: &'a RestoreObject,
        protected: bool,
        _: &'a RestoreDecision,
        context: ControlContext,
    ) -> RestoreFuture<'a, ()> {
        Box::pin(async move {
            context.check()?;
            if protected && !self.protected.load(Ordering::Acquire) {
                return Err(ControlError::Fenced);
            }
            let reference = self
                .objects
                .get(&o.object.digest()?)
                .ok_or(ControlError::Corrupt)?;
            if o.bytes != reference.bytes
                || o.sha256 != reference.sha256
                || o.object.version != reference.version.as_deref().ok_or(ControlError::Corrupt)?
                || o.object.key != reference.key
            {
                return Err(ControlError::Corrupt);
            }
            let read = self
                .io
                .read_exact(
                    reference,
                    OperationContext {
                        deadline: context.deadline(),
                        cancellation: context.cancellation_token(),
                    },
                )
                .await
                .map_err(|_| ControlError::Corrupt)?;
            if read.bytes().len() as u64 != o.bytes {
                return Err(ControlError::Corrupt);
            }
            context.check()?;
            Ok(())
        })
    }
}
pub(super) async fn initialize(
    f: &super::Fixture,
    name: &str,
    scope: &AdministrativeScope,
) -> Result {
    let admin = ControlAdministrator::new(
        settings(f, name, "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    admin
        .initialize(
            InitializeInput {
                scope: scope.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            super::context()?,
        )
        .await?;
    admin
        .migrate_catalog(
            MigrationInput {
                scope: scope.clone(),
                source_revision: 2,
                source_sha256: schema_identity().1,
            },
            super::context()?,
        )
        .await?;
    admin.shutdown(super::context()?).await?;
    Ok(())
}
async fn checkpoint(db: &Client, skip_store: bool) -> Result<[u8; 32]> {
    let mut rows = Vec::new();
    for table in TABLES
        .iter()
        .copied()
        .filter(|t| !skip_store || *t != "store")
    {
        let bytes:Vec<u8>=db.query_one(&format!("SELECT sha256(convert_to(coalesce(jsonb_agg(h ORDER BY h),'[]'::jsonb)::text,'UTF8')) FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS h FROM signal_control.{table} t) s"),&[]).await?.get(0);
        let digest: [u8; 32] = bytes.try_into().map_err(|_| "checkpoint hash size")?;
        rows.push((table, digest));
    }
    Ok(Sha256::digest(serde_json::to_vec(&rows)?).into())
}
async fn query(f: &super::Fixture, scope: Scope, objects: &Path, cache: &Path) -> Result {
    let control = Arc::new(ControlClient::restored_catalog(settings(
        f,
        DEST,
        "signal_runtime",
    )?)?);
    let selection = ObjectSelection::new(
        io(objects)?,
        tokio::runtime::Handle::current(),
        SelectionConfig {
            stream: scope.stream,
            backend: Uuid::from_u128(0xd105),
            storage: StorageConfig::default(),
            manifests: ManifestLimits::default(),
            cache: MaterializationConfig {
                directory: cache.to_path_buf(),
                max_files: 128,
                max_disk_bytes: 64 * 1024 * 1024,
            },
        },
    )?;
    let source = Arc::new(SharedQuerySource::new(control.clone(), scope, selection)?);
    let engine = signal_query::QueryEngine::with_source(
        signal_query::QueryConfig::default(),
        source.clone(),
    )?;
    let response = engine
        .execute(signal_protocol::EventQuery::default(), context())
        .await?;
    assert_eq!(response.events.len(), 1);
    assert_eq!(
        response.events[0].message.as_deref(),
        Some("catalog restore actual Parquet")
    );
    engine.shutdown(context()).await?;
    drop(engine);
    source.shutdown(context()).await?;
    drop(source);
    control.shutdown(super::context()?).await?;
    Ok(())
}
pub async fn qualify(root: &Client, f: &super::Fixture) -> Result {
    for database in [SOURCE, DEST] {
        root.batch_execute(&format!("CREATE DATABASE {database}"))
            .await?;
        root.batch_execute(&format!(
            "GRANT CREATE ON DATABASE {database} TO signal_control_owner"
        ))
        .await?;
    }
    let scope = AdministrativeScope {
        schema_version: 1,
        store_id: Uuid::from_u128(0xd100),
        generation: Uuid::from_u128(0xd101),
    };
    initialize(f, SOURCE, &scope).await?;
    initialize(f, DEST, &scope).await?;
    let (db, driver) = super::admin_database(f, SOURCE).await?;
    let partition = Uuid::from_u128(0xd102);
    let stream = Uuid::from_u128(0xd103);
    let consumer = Uuid::from_u128(0xd104);
    let backend = Uuid::from_u128(0xd105);
    db.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,'synthetic-catalog-restore',$2,'pipeline'),($3,'synthetic-catalog-restore',$2,'notification')",&[&partition,&stream,&consumer]).await?;
    db.execute("INSERT INTO signal_control.principals VALUES('signal_runtime','synthetic-catalog-restore',$1,$2),('signal_runtime','synthetic-catalog-restore',$1,$3)",&[&stream,&partition,&consumer]).await?;
    db.execute(
        "INSERT INTO signal_control.object_backends VALUES($1,'owned-durable-catalog-fixture')",
        &[&backend],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_scopes VALUES($1,$2,$3)",
        &[&partition, &backend, &format!("query/{stream}/")],
    )
    .await?;
    db.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    let fixture = PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?);
    let retained = fixture
        .parent()
        .ok_or("fixture parent")?
        .join("catalog-restore-objects");
    std::fs::create_dir(&retained)?;
    let writer = io(&retained)?;
    let codec = ObjectCodec::new(StorageConfig::default(), ManifestLimits::default())?;
    let input: signal_event::IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":"2026-10-10T10:00:00Z","source":{"type":"synthetic-catalog-restore"},"message":"catalog restore actual Parquet","attributes":{"nested":{"array":[true,null,42]}}}),
    )?;
    let prepared = codec
        .prepare(
            &[StoredEvent {
                sequence: 1,
                event: input.normalize(chrono::Utc::now())?,
            }],
            context(),
        )
        .await?;
    let file = prepared.files().first().ok_or("prepared file")?;
    let reference = writer
        .create(
            &data_key(stream, file.date(), file.hour(), file.sha256()),
            file.bytes(),
            context(),
        )
        .await?;
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: stream,
        normalizer_revision: "synthetic-exact-v1".into(),
        first_sequence: 1,
        last_sequence: 1,
        events: 1,
        previous: None,
        files: vec![QueryFile {
            date: file.date().into(),
            hour: file.hour(),
            object: reference.clone(),
            rows: file.rows(),
            decoded_bytes: file.decoded_bytes(),
        }],
    };
    drop(prepared);
    let s = Scope {
        schema_version: 1,
        store_id: scope.store_id,
        generation: scope.generation,
        tenant: "synthetic-catalog-restore".into(),
        stream,
        partition_id: partition,
    };
    let runtime = ControlClient::catalog(settings(f, SOURCE, "signal_runtime")?)?;
    let token = runtime
        .acquire(s.clone(), Uuid::new_v4(), 15000, super::context()?)
        .await?;
    let finding = Uuid::from_u128(0xd120);
    let work = Uuid::from_u128(0xd121);
    let attempt = Uuid::from_u128(0xd122);
    let rule: [u8; 32] = Sha256::digest(b"synthetic exact rule bytes").into();
    runtime
        .publish(
            token.clone(),
            PublicationInput {
                schema_version: 1,
                id: Uuid::from_u128(0xd106),
                previous: None,
                first_sequence: 1,
                last_sequence: 1,
                manifest: manifest.encode(ManifestLimits::default(), stream)?,
                rule_revision: Sha256::digest(b"synthetic exact rule bytes").into(),
                normalizer_revision: "synthetic-exact-v1".into(),
                states: vec![RevisionedState {
                    key: "synthetic-catalog-state".into(), revision: rule,
                    bytes: b"original exact detector state".to_vec(),
                }],
                findings: vec![FindingInput { id: finding, bytes: serde_json::to_vec(&serde_json::json!({
                    "schema_version":1,"id":finding,"rule_id":"synthetic-catalog-restore",
                    "created_at":"2026-10-10T00:00:00Z","severity":"high","title":"synthetic-catalog-restore",
                    "event_ids":[Uuid::from_u128(0xd123)],"attributes":{}
                }))? }],
                work: vec![WorkInput {id: work, finding_id: finding, bytes: b"original immutable delivery plan/key".to_vec()}],
                receipts: vec![],
            },
            super::context()?,
        )
        .await?;
    let notification_token = token.clone();
    runtime
        .notification(
            notification_token.clone(),
            NotificationInput {
                schema_version: 1,
                work_id: work,
                attempt_id: attempt,
                action: NotificationAction::Claim {},
            },
            super::context()?,
        )
        .await?;
    runtime
        .notification(
            notification_token.clone(),
            NotificationInput {
                schema_version: 1,
                work_id: work,
                attempt_id: attempt,
                action: NotificationAction::Finish {
                    outcome: NotificationOutcome::Delivered,
                    evidence: b"original delivered evidence".to_vec(),
                },
            },
            super::context()?,
        )
        .await?;
    let history: serde_json::Value = db
        .query_one(
            "SELECT to_jsonb(a) FROM signal_control.notification_attempts a WHERE id=$1",
            &[&attempt],
        )
        .await?
        .get(0);
    let pin_id = Uuid::from_u128(0xd107);
    runtime
        .read_catalog_snapshot(
            s.clone(),
            CatalogInput {
                schema_version: 1,
                id: pin_id,
                pin_ms: 5000,
            },
            super::context()?,
        )
        .await?;
    runtime.shutdown(super::context()?).await?;
    codec.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=false; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL; UPDATE signal_control.partitions SET feed_position=1 WHERE kind='notification'; BEGIN; LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE").await?;
    let expected = checkpoint(&db, false).await?;
    let (destination, dest_driver) = super::admin_database(f, DEST).await?;
    destination
        .batch_execute("BEGIN; TRUNCATE signal_control.store,signal_control.migrations")
        .await?;
    for table in [
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
    ] {
        let expression = if table == "partitions" {
            "to_jsonb(t)||jsonb_build_object('head',NULL)"
        } else {
            "to_jsonb(t)"
        };
        let rows:serde_json::Value=db.query_one(&format!("SELECT coalesce(jsonb_agg({expression}),'[]'::jsonb) FROM signal_control.{table} t"),&[]).await?.get(0);
        destination.execute(&format!("INSERT INTO signal_control.{table} SELECT * FROM jsonb_populate_recordset(NULL::signal_control.{table},$1)"),&[&rows]).await?;
    }
    destination
        .execute(
            "UPDATE signal_control.partitions SET head=$1 WHERE id=$2",
            &[&Uuid::from_u128(0xd106), &partition],
        )
        .await?;
    destination.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; COMMIT").await?;
    db.batch_execute("COMMIT").await?;
    let copied = checkpoint(&destination, false).await?;
    assert_eq!(copied, expected);
    let enrollment = RestoreDestination {
        id: Uuid::from_u128(0xd108),
        credential_binding_sha256: Sha256::digest(
            b"current separately enrolled catalog destination",
        )
        .into(),
    };
    let object = RestoreObject {
        object: CanonicalObjectRef {
            schema_version: 1,
            backend_id: backend,
            key: reference.key.clone(),
            version: reference.version.clone().ok_or("owned version")?,
        },
        bytes: reference.bytes,
        sha256: reference.sha256,
    };
    let consumers = Arc::new(Consumers(Mutex::new(vec![])));
    let restore = PostgresStoppedRestore::catalog(
        settings(f, DEST, "signal_migrator")?,
        "signal_control_owner".into(),
        scope.clone(),
        enrollment.clone(),
        vec![object.clone()],
        consumers.clone(),
    )?;
    let inventory = restore.stage(super::context()?).await?;
    assert_eq!(inventory.revision, 4);
    assert_eq!(inventory.checkpoint_sha256, expected);
    let authority = Authority {
        checkpoint: expected,
        destination: enrollment.id,
        binding: enrollment.credential_binding_sha256,
        approved: AtomicBool::new(false),
    };
    let custody = Custody {
        io: io(&retained)?,
        objects: BTreeMap::from([(object.object.digest()?, reference)]),
        protected: AtomicBool::new(false),
    };
    let generation = Uuid::from_u128(0xd109);
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    authority.approved.store(true, Ordering::Release);
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    custody.protected.store(true, Ordering::Release);
    // Missing and corrupted exact versions cannot authorize a generation barrier.
    let object_path = retained.join(&object.object.key);
    let original = std::fs::read(&object_path)?;
    let hidden = object_path.with_extension("held-for-missing-probe");
    std::fs::rename(&object_path, &hidden)?;
    let missing = coordinate_stopped_restore(
        &restore,
        &authority,
        &custody,
        enrollment.id,
        generation,
        super::context()?,
    )
    .await;
    std::fs::rename(&hidden, &object_path)?;
    assert!(matches!(missing, Err(ControlError::Corrupt)));
    assert_eq!(checkpoint(&destination, false).await?, expected);
    std::fs::write(&object_path, b"corrupt exact-version fixture")?;
    let corrupt = coordinate_stopped_restore(
        &restore,
        &authority,
        &custody,
        enrollment.id,
        generation,
        super::context()?,
    )
    .await;
    std::fs::write(&object_path, &original)?;
    assert!(matches!(corrupt, Err(ControlError::Corrupt)));
    assert_eq!(checkpoint(&destination, false).await?, expected);
    let seal: Vec<u8> = destination
        .query_one(
            "SELECT seal FROM signal_control.catalog_snapshots WHERE id=$1",
            &[&pin_id],
        )
        .await?
        .get(0);
    destination.execute(
        "UPDATE signal_control.catalog_snapshots SET seal=decode(repeat('00',32),'hex') WHERE id=$1", &[&pin_id]
    ).await?;
    let tampered = checkpoint(&destination, false).await?;
    assert_ne!(tampered, expected);
    assert!(matches!(
        restore.stage(super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(checkpoint(&destination, false).await?, tampered);
    destination
        .execute(
            "UPDATE signal_control.catalog_snapshots SET seal=$2 WHERE id=$1",
            &[&pin_id, &seal],
        )
        .await?;
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    // Force a real DDL error after restore_record creation. The entire barrier,
    // migration history and catalog must roll back to the exact source profile.
    destination.batch_execute("CREATE FUNCTION public.synthetic_catalog_restore_fail() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF to_regclass('signal_control.restore_record') IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_FULL'; END IF; END $$; CREATE EVENT TRIGGER synthetic_catalog_restore_fail ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.synthetic_catalog_restore_fail()").await?;
    assert!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await
        .is_err()
    );
    destination.batch_execute("DROP EVENT TRIGGER synthetic_catalog_restore_fail; DROP FUNCTION public.synthetic_catalog_restore_fail()").await?;
    assert_eq!(checkpoint(&destination, false).await?, expected);
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    // Incomplete consumer enrollment cannot enable readiness after the barrier.
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    let receipt = restore.resolve(super::context()?).await?;
    assert!(!receipt.ready);
    assert_eq!(receipt.uncertain_work, 1);
    assert_eq!(
        history,
        destination
            .query_one(
                "SELECT to_jsonb(a) FROM signal_control.notification_attempts a WHERE id=$1",
                &[&attempt]
            )
            .await?
            .get::<_, serde_json::Value>(0)
    );
    assert_eq!(
        destination
            .query_one(
                "SELECT status FROM signal_control.outbox WHERE id=$1",
                &[&work]
            )
            .await?
            .get::<_, String>(0),
        "uncertain"
    );
    assert_eq!(
        destination
            .query_one("SELECT revision FROM signal_control.store", &[])
            .await?
            .get::<_, i32>(0),
        5
    );
    assert_eq!(
        destination
            .query_one(
                "SELECT generation FROM signal_control.catalog_snapshots WHERE id=$1",
                &[&pin_id]
            )
            .await?
            .get::<_, Uuid>(0),
        scope.generation
    );
    *consumers.0.lock().map_err(|_| "consumer mutex")? = inventory.consumers.clone();
    let ready = resume_stopped_restore(
        &restore,
        &authority,
        &custody,
        inventory.clone(),
        receipt.clone(),
        super::context()?,
    )
    .await?;
    assert!(ready.ready);
    let current = ControlClient::restored_catalog(settings(f, DEST, "signal_runtime")?)?;
    assert!(matches!(
        current.renew(token, 15000, super::context()?).await,
        Err(ControlError::Fenced)
    ));
    // Every older compiled runtime identity fails closed on the restored catalog.
    for older in [
        ControlClient::new(settings(f, DEST, "signal_runtime")?)?,
        ControlClient::restored(settings(f, DEST, "signal_runtime")?)?,
        ControlClient::catalog(settings(f, DEST, "signal_runtime")?)?,
    ] {
        let mut new_scope = s.clone();
        new_scope.generation = generation;
        assert!(
            older
                .acquire(new_scope, Uuid::new_v4(), 15000, super::context()?)
                .await
                .is_err()
        );
        older.shutdown(super::context()?).await?;
    }
    assert!(matches!(
        current
            .notification(
                notification_token,
                NotificationInput {
                    schema_version: 1,
                    work_id: work,
                    attempt_id: attempt,
                    action: NotificationAction::Finish {
                        outcome: NotificationOutcome::Delivered,
                        evidence: b"stale completion".to_vec()
                    },
                },
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    super::global_feed::restored(f, DEST, s.store_id, generation, s.generation, true).await?;
    eprintln!("phase: globally-authorized-restored-feed-qualified");
    let mut resumed = s;
    resumed.generation = generation;
    assert!(matches!(
        current
            .read_catalog_snapshot(
                resumed.clone(),
                CatalogInput {
                    schema_version: 1,
                    id: pin_id,
                    pin_ms: 5000
                },
                super::context()?
            )
            .await,
        Err(ControlError::Conflict)
    ));
    current.shutdown(super::context()?).await?;
    query(
        f,
        resumed,
        &retained,
        &fixture
            .parent()
            .ok_or("fixture parent")?
            .join("catalog-restored-query-cache"),
    )
    .await?;
    destination
        .batch_execute("SET search_path=pg_catalog,signal_control,pg_temp")
        .await?;
    let actual: String = destination
        .query_one(
            include_str!("../../../../schemas/shared-control/catalog-query.sql"),
            &[],
        )
        .await?
        .get(0);
    assert_eq!(
        actual,
        include_str!("../../../../schemas/shared-control/006-catalog.sha256").trim()
    );
    eprintln!("catalog5-catalog: {actual}");
    restore.shutdown(super::context()?).await?;
    custody.io.shutdown(context()).await?;
    driver.abort();
    let _ = driver.await;
    dest_driver.abort();
    let _ = dest_driver.await;
    eprintln!("phase: coordinated-catalog-restore-and-actual-query-qualified");
    Ok(())
}
pub async fn restart_probe(f: &super::Fixture) -> Result {
    let root = PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?);
    let root = root.parent().ok_or("fixture parent")?;
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::from_u128(0xd100),
        generation: Uuid::from_u128(0xd109),
        tenant: "synthetic-catalog-restore".into(),
        stream: Uuid::from_u128(0xd103),
        partition_id: Uuid::from_u128(0xd102),
    };
    query(
        f,
        scope.clone(),
        &root.join("catalog-restore-objects"),
        &root.join("catalog-restored-restart-cache"),
    )
    .await?;
    super::global_feed::restored(
        f,
        DEST,
        scope.store_id,
        scope.generation,
        Uuid::from_u128(0xd101),
        false,
    )
    .await?;
    eprintln!("phase: persistent-restored-global-feed-qualified");
    eprintln!("phase: persistent-catalog-restored-query-qualified");
    Ok(())
}
