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
    canonical: Option<signal_event::SignalEvent>,
) -> Result<(Uuid, Vec<u8>)> {
    let input: signal_event::IngestEvent = serde_json::from_value(
        serde_json::json!({"timestamp":"2026-10-10T10:00:00Z","source":{"type":"synthetic-query"},"message":format!("shared-query-{sequence}"),"attributes":{"nested":{"array":[true,null,42]}}}),
    )?;
    let mut event = input.normalize(chrono::Utc::now())?;
    event.id = Uuid::from_u128(u128::from(sequence));
    let event = canonical.unwrap_or(event);
    let prepared = codec
        .prepare(&[StoredEvent { sequence, event }], context())
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
    let first = publish(&runtime, &writer, &codec, token.clone(), None, 1, None).await?;
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
    let second = publish(
        &runtime,
        &writer,
        &codec,
        token.clone(),
        Some(first),
        2,
        None,
    )
    .await?;
    let recovery = CanonicalRecoveryLimits {
        backend: pin.backend()?,
        files: 128,
        object_bytes: 64 * 1024 * 1024,
        decoded_bytes: 64 * 1024 * 1024,
        scanned_rows: 4096,
        result_bytes: 65536,
    };
    let retained_inputs = recover_canonical_inputs(
        &pin,
        &writer,
        &codec,
        &[Uuid::from_u128(1)],
        recovery,
        super::context()?,
    )
    .await?;
    assert_eq!(retained_inputs.rows()?.len(), 1);
    let original_event = retained_inputs.rows()?[0].event.clone();
    let held = retain_canonical_inputs(
        &runtime,
        token.clone(),
        &retained_inputs,
        "fixture-window",
        [2; 32],
        [3; 32],
        super::context()?,
    )
    .await?;
    assert_eq!(held.len(), 1);
    assert_eq!(
        retain_canonical_inputs(
            &runtime,
            token.clone(),
            &retained_inputs,
            "fixture-window",
            [2; 32],
            [3; 32],
            super::context()?
        )
        .await?,
        held
    );
    let mut foreign = token.clone();
    foreign.scope.tenant = "foreign-fixture".into();
    assert!(matches!(
        retain_canonical_inputs(
            &runtime,
            foreign,
            &retained_inputs,
            "fixture-window",
            [2; 32],
            [3; 32],
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    let row=db.query_one("SELECT state,kind,request FROM signal_control.object_pins WHERE partition_id=$1 AND id=$2",&[&scope.partition_id,&held[0]]).await?;
    assert_eq!(row.try_get::<_, String>(0)?, "retained");
    assert_eq!(row.try_get::<_, String>(1)?, "replay");
    let raw: Vec<u8> = row.try_get(2)?;
    let request: serde_json::Value = serde_json::from_slice(&raw)?;
    let object: CanonicalObjectRef = serde_json::from_value(request["object"].clone())?;
    assert!(matches!(
        runtime
            .retire_object(
                token.clone(),
                RetirementInput {
                    schema_version: 1,
                    id: Uuid::new_v4(),
                    object,
                    reason: b"owned fixture retirement attempt".to_vec()
                },
                super::context()?
            )
            .await,
        Err(ControlError::Conflict)
    ));
    eprintln!("phase: recovered-state-object-retention-replay-and-fencing-qualified");
    let recovered = recover_canonical_rows(
        &pin,
        &writer,
        &codec,
        &[Uuid::from_u128(1)],
        recovery,
        super::context()?,
    )
    .await?;
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].sequence, 1);
    assert_eq!(
        recovered[0].event.attributes.get("nested"),
        Some(&serde_json::json!({"array":[true,null,42]}))
    );
    assert!(matches!(
        recover_canonical_rows(
            &pin,
            &writer,
            &codec,
            &[Uuid::from_u128(2)],
            recovery,
            super::context()?
        )
        .await,
        Err(ControlError::Unavailable)
    ));
    assert!(
        recover_canonical_rows(
            &pin,
            &writer,
            &codec,
            &[Uuid::from_u128(1), Uuid::from_u128(1)],
            recovery,
            super::context()?
        )
        .await
        .is_err()
    );
    let mut quota = recovery;
    quota.result_bytes = 1;
    assert!(matches!(
        recover_canonical_rows(
            &pin,
            &writer,
            &codec,
            &[Uuid::from_u128(1)],
            quota,
            super::context()?
        )
        .await,
        Err(ControlError::Full)
    ));
    let cancelled = super::context()?;
    cancelled.cancel();
    assert!(matches!(
        recover_canonical_rows(
            &pin,
            &writer,
            &codec,
            &[Uuid::from_u128(1)],
            recovery,
            cancelled
        )
        .await,
        Err(ControlError::Cancelled)
    ));
    eprintln!("phase: pinned-canonical-recovery-bounds-and-missing-evidence-qualified");

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
            scope.clone(),
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
    // Actual Parquet copies at distinct WAL positions must recover the original
    // protected pair, while the legacy ID-only API remains deliberately strict.
    let third = publish(
        &runtime,
        &writer,
        &codec,
        token.clone(),
        Some(second),
        3,
        Some(original_event.clone()),
    )
    .await?;
    let repeated = runtime
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
    for sequence in [1, 3] {
        let recovered = recover_canonical_inputs_at(
            &repeated,
            &writer,
            &codec,
            &std::collections::BTreeMap::from([(original_event.id, sequence)]),
            recovery,
            super::context()?,
        )
        .await?;
        assert_eq!(recovered.rows()?[0].sequence, sequence);
        assert_eq!(recovered.rows()?[0].event, original_event);
    }
    assert!(matches!(
        recover_canonical_inputs(
            &repeated,
            &writer,
            &codec,
            &[original_event.id],
            recovery,
            super::context()?
        )
        .await,
        Err(ControlError::Conflict)
    ));
    assert!(matches!(
        recover_canonical_inputs_at(
            &repeated,
            &writer,
            &codec,
            &std::collections::BTreeMap::from([(original_event.id, 2)]),
            recovery,
            super::context()?
        )
        .await,
        Err(ControlError::Unavailable)
    ));
    let mut changed = original_event.clone();
    changed.message = Some("conflicting retry".into());
    publish(
        &runtime,
        &writer,
        &codec,
        token,
        Some(third),
        4,
        Some(changed),
    )
    .await?;
    let conflicting = runtime
        .read_catalog_snapshot(
            scope,
            CatalogInput {
                schema_version: 1,
                id: Uuid::new_v4(),
                pin_ms: 5000,
            },
            super::context()?,
        )
        .await?;
    assert!(matches!(
        recover_canonical_inputs_at(
            &conflicting,
            &writer,
            &codec,
            &std::collections::BTreeMap::from([(original_event.id, 1)]),
            recovery,
            super::context()?
        )
        .await,
        Err(ControlError::Conflict)
    ));
    codec.shutdown(context()).await?;
    writer.shutdown(context()).await?;
    eprintln!("phase: shared-catalog-actual-parquet-query-composition-complete");
    Ok(())
}
