//! Actual PostgreSQL catalog/Parquet/DataFusion composition with an owned,
//! write-once single-version object fixture. No AWS/versioning qualification.
use object_store::{ObjectStore, memory::InMemory};
use signal_control::*;
use signal_storage::{
    OperationContext, QueryFileSource, StorageConfig, StoredEvent,
    object_cache::MaterializationConfig,
    object_codec::ObjectCodec,
    object_io::{ObjectIo, ObjectIoLimits},
    object_manifest::{
        ManifestLimits, PreviousManifest, QueryFile, QueryManifest, data_key, manifest_key,
    },
    object_selection::{ObjectSelection, SelectionBounds, SelectionConfig},
};
use std::sync::Arc;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn context() -> OperationContext {
    OperationContext::new(std::time::Duration::from_secs(5))
}
fn bounds() -> SelectionBounds {
    SelectionBounds {
        from: None,
        to: None,
        max_files: 128,
        max_decoded_bytes: 256 * 1024 * 1024,
    }
}
#[derive(Debug)]
struct Versions(InMemory);
impl std::fmt::Display for Versions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owned immutable single-version fixture")
    }
}
fn unused() -> object_store::Error {
    object_store::Error::NotImplemented {
        operation: "unused fixture operation".into(),
        implementer: "Versions".into(),
    }
}
#[async_trait::async_trait]
impl ObjectStore for Versions {
    async fn put_opts(
        &self,
        p: &object_store::path::Path,
        b: object_store::PutPayload,
        o: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        if !matches!(o.mode, object_store::PutMode::Create) {
            return Err(unused());
        }
        let mut result = self.0.put_opts(p, b, o).await?;
        result.version = Some("owned-v1".into());
        Ok(result)
    }
    async fn get_opts(
        &self,
        p: &object_store::path::Path,
        mut o: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        if o.version.as_deref().is_some_and(|v| v != "owned-v1") {
            return Err(object_store::Error::NotFound {
                path: p.to_string(),
                source: std::io::Error::other("unavailable fixture version").into(),
            });
        }
        o.version = None;
        let mut result = self.0.get_opts(p, o).await?;
        result.meta.version = Some("owned-v1".into());
        Ok(result)
    }
    async fn put_multipart_opts(
        &self,
        _: &object_store::path::Path,
        _: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        Err(unused())
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
        Box::pin(futures_util::stream::once(async { Err(unused()) }))
    }
    async fn list_with_delimiter(
        &self,
        _: Option<&object_store::path::Path>,
    ) -> object_store::Result<object_store::ListResult> {
        Err(unused())
    }
    async fn copy_opts(
        &self,
        _: &object_store::path::Path,
        _: &object_store::path::Path,
        _: object_store::CopyOptions,
    ) -> object_store::Result<()> {
        Err(unused())
    }
}
async fn publish(
    runtime: &ControlClient,
    io: &ObjectIo,
    codec: &ObjectCodec,
    token: LeaseToken,
    previous: Option<(Uuid, Vec<u8>)>,
    sequence: u64,
) -> Result<(Uuid, Vec<u8>)> {
    let input: signal_event::IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":"2026-10-10T10:00:00Z","source":{"type":"synthetic-query"},"message":format!("shared-query-{sequence}"),"attributes":{"nested":{"array":[true,null,42]}}}),
    )?;
    let prepared = codec
        .prepare(
            &[StoredEvent {
                sequence,
                event: input.normalize(chrono::Utc::now())?,
            }],
            context(),
        )
        .await?;
    let mut files = Vec::new();
    for file in prepared.files() {
        let object = io
            .create(
                &data_key(token.scope.stream, file.date(), file.hour(), file.sha256()),
                file.bytes(),
                context(),
            )
            .await?;
        files.push(QueryFile {
            date: file.date().into(),
            hour: file.hour(),
            object,
            rows: file.rows(),
            decoded_bytes: file.decoded_bytes(),
        });
    }
    drop(prepared);
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: token.scope.stream,
        normalizer_revision: "synthetic-v1".into(),
        first_sequence: sequence,
        last_sequence: sequence,
        events: 1,
        previous: match &previous {
            Some((_, raw)) => Some(PreviousManifest {
                first_sequence: sequence - 1,
                last_sequence: sequence - 1,
                object: io
                    .create(
                        &manifest_key(token.scope.stream, sequence - 1),
                        raw,
                        context(),
                    )
                    .await?,
            }),
            None => None,
        },
        files,
    };
    let raw = manifest.encode(ManifestLimits::default(), token.scope.stream)?;
    let id = Uuid::new_v4();
    runtime
        .publish(
            token,
            PublicationInput {
                schema_version: 1,
                id,
                previous: previous.map(|(id, _)| id),
                first_sequence: sequence,
                last_sequence: sequence,
                manifest: raw.clone(),
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
    Ok((id, raw))
}
pub async fn qualify(
    db: &tokio_postgres::Client,
    runtime: Arc<ControlClient>,
    mut scope: Scope,
) -> Result {
    scope.stream = Uuid::from_u128(0xd01);
    scope.partition_id = Uuid::from_u128(0xd02);
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
        "INSERT INTO signal_control.object_scopes VALUES($1,$2,$3)",
        &[
            &scope.partition_id,
            &Uuid::from_u128(0x20),
            &format!("query/{}/", scope.stream),
        ],
    )
    .await?;
    let root = tempfile::TempDir::new()?;
    let store = Arc::new(Versions(InMemory::new()));
    let writer = ObjectIo::remote(
        store.clone(),
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
    )?;
    let codec = ObjectCodec::new(StorageConfig::default(), ManifestLimits::default())?;
    let token = runtime
        .acquire(scope.clone(), Uuid::new_v4(), 15000, super::context()?)
        .await?;
    let first = publish(&runtime, &writer, &codec, token.clone(), None, 1).await?;
    let pin = runtime
        .read_catalog_snapshot(
            scope.clone(),
            CatalogInput {
                schema_version: 1,
                id: Uuid::new_v4(),
                pin_ms: 5000,
            },
            super::context()?,
        )
        .await?;
    let second = publish(&runtime, &writer, &codec, token, Some(first), 2).await?;
    let config = SelectionConfig {
        stream: scope.stream,
        backend: Uuid::from_u128(0x20),
        storage: StorageConfig::default(),
        manifests: ManifestLimits::default(),
        cache: MaterializationConfig {
            directory: root.path().join("derived"),
            max_files: 128,
            max_disk_bytes: 64 * 1024 * 1024,
        },
    };
    let objects = ObjectSelection::new(
        ObjectIo::remote(
            store.clone(),
            tokio::runtime::Handle::current(),
            ObjectIoLimits::default(),
        )?,
        tokio::runtime::Handle::current(),
        config,
    )?;
    let source = Arc::new(SharedQuerySource::new(
        runtime.clone(),
        scope.clone(),
        objects,
    )?);
    let before: i64 = db
        .query_one("SELECT count(*) FROM signal_control.snapshots", &[])
        .await?
        .get(0);
    assert!(matches!(
        source
            .select_query_files(None, None, 0, 256 * 1024 * 1024, context())
            .await,
        Err(signal_storage::StorageError::InvalidBatch)
    ));
    let cancelled = context();
    cancelled.cancellation.cancel();
    assert!(matches!(
        source
            .select_query_files(None, None, 128, 256 * 1024 * 1024, cancelled)
            .await,
        Err(signal_storage::StorageError::Cancelled)
    ));
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_control.snapshots", &[])
            .await?
            .get::<_, i64>(0),
        before
    );
    let fixed = source.select_pin(&pin, bounds(), context()).await?;
    assert_eq!((fixed.files.len(), fixed.files[0].rows), (1, 1));
    assert_eq!(fixed.deadline(), Some(pin.snapshot()?.deadline()));
    drop(fixed);
    let engine = signal_query::QueryEngine::with_source(
        signal_query::QueryConfig::default(),
        source.clone(),
    )?;
    let response = engine
        .execute(signal_protocol::EventQuery::default(), context())
        .await?;
    assert_eq!(response.events.len(), 2);
    assert_eq!(
        response.events[0].attributes.get("nested"),
        Some(&serde_json::json!({"array":[true,null,42]}))
    );
    let current = runtime
        .read_catalog_snapshot(
            scope.clone(),
            CatalogInput {
                schema_version: 1,
                id: Uuid::new_v4(),
                pin_ms: 5000,
            },
            super::context()?,
        )
        .await?;
    assert_eq!(current.head()?, Some(second.0));
    let wrong = SelectionConfig {
        stream: scope.stream,
        backend: Uuid::from_u128(0xdead),
        storage: StorageConfig::default(),
        manifests: ManifestLimits::default(),
        cache: MaterializationConfig {
            directory: root.path().join("wrong-backend"),
            max_files: 128,
            max_disk_bytes: 64 * 1024 * 1024,
        },
    };
    let wrong_source = SharedQuerySource::new(
        runtime.clone(),
        scope.clone(),
        ObjectSelection::new(
            ObjectIo::remote(
                store,
                tokio::runtime::Handle::current(),
                ObjectIoLimits::default(),
            )?,
            tokio::runtime::Handle::current(),
            wrong,
        )?,
    )?;
    assert!(matches!(
        wrong_source.select_pin(&current, bounds(), context()).await,
        Err(signal_storage::StorageError::Corrupt(
            "shared query scope/backend"
        ))
    ));
    assert_eq!(wrong_source.metrics().objects.processed, 0);
    assert_eq!(wrong_source.metrics().rejected, 1);
    assert!(!root.path().join("wrong-backend").exists());
    wrong_source.shutdown(context()).await?;
    let expired_id = Uuid::new_v4();
    let expired = runtime
        .read_catalog_snapshot(
            scope,
            CatalogInput {
                schema_version: 1,
                id: expired_id,
                pin_ms: 1000,
            },
            super::context()?,
        )
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(matches!(
        source.select_pin(&expired, bounds(), context()).await,
        Err(signal_storage::StorageError::Timeout)
    ));
    engine.shutdown(context()).await?;
    drop(engine);
    source.shutdown(context()).await?;
    drop(source);
    codec.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    eprintln!("phase: shared-catalog-actual-parquet-query-composition-complete");
    Ok(())
}
