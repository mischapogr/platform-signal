//! Monolithic backend selection. Query copies never confer source custody.
use crate::config::{ConfigError, Settings};
use signal_storage::{
    FileSelection, OperationContext, ParquetStore, QueryFileSource, StorageConfig, StorageError,
    StorageMetrics, StoreFuture, StoreReceipt, StoredEvent,
};
use std::sync::Arc;
use uuid::Uuid;

pub enum Backend {
    Local(Arc<ParquetStore>),
    #[cfg(feature = "s3-query")]
    Object(Arc<signal_storage::object_publication::ObjectPublisher>),
}
impl Backend {
    pub fn local(store: ParquetStore) -> Self {
        Self::Local(Arc::new(store))
    }
    pub async fn open(
        settings: &Settings,
        config: StorageConfig,
        stream: Uuid,
    ) -> Result<Self, StorageError> {
        let kind = settings
            .optional("SIGNAL_STORAGE_TYPE")
            .map_err(setting_error)?;
        match kind.as_deref().unwrap_or("parquet") {
            "parquet" => {
                // Typographical or unused object settings must not silently select local storage.
                for key in OBJECT_SETTINGS {
                    if settings.optional(key).map_err(setting_error)?.is_some() {
                        return Err(StorageError::Config("S3 settings require s3 storage type"));
                    }
                }
                Ok(Self::local(ParquetStore::open(config, stream).await?))
            }
            "s3" => Self::open_object(settings, config, stream).await,
            _ => Err(StorageError::Config("storage type")),
        }
    }
    #[cfg(not(feature = "s3-query"))]
    async fn open_object(_: &Settings, _: StorageConfig, _: Uuid) -> Result<Self, StorageError> {
        Err(StorageError::Config(
            "s3 storage requires s3-query build feature",
        ))
    }
    #[cfg(feature = "s3-query")]
    async fn open_object(
        settings: &Settings,
        config: StorageConfig,
        stream: Uuid,
    ) -> Result<Self, StorageError> {
        use signal_storage::{
            object_cache::MaterializationConfig,
            object_io::{ObjectIo, ObjectIoLimits, SmallOwnerConfig},
            object_publication::{ObjectPublisher, PublicationConfig},
            object_s3::{self, S3Config, S3Credentials},
        };
        let required = |name| {
            settings
                .optional(name)
                .map_err(setting_error)?
                .ok_or(StorageError::Config("required S3 setting missing"))
        };
        let id = required("SIGNAL_S3_BACKEND_ID")?;
        let backend_id =
            Uuid::parse_str(&id).map_err(|_| StorageError::Config("S3 backend UUID"))?;
        if backend_id.is_nil() || backend_id.to_string() != id {
            return Err(StorageError::Config("S3 backend UUID"));
        }
        let allow_loopback_http = match settings
            .optional("SIGNAL_S3_ALLOW_LOOPBACK_HTTP")
            .map_err(setting_error)?
            .as_deref()
        {
            None | Some("false") => false,
            Some("true") => true,
            _ => return Err(StorageError::Config("S3 loopback HTTP setting")),
        };
        let object_bytes = settings
            .number("SIGNAL_S3_OBJECT_BYTES", 64 * 1024 * 1024)
            .map_err(setting_error)?;
        let credentials = S3Credentials {
            access_key: settings
                .secret_environment("SIGNAL_S3_ACCESS_KEY")
                .map_err(setting_error)?,
            secret_key: settings
                .secret_environment("SIGNAL_S3_SECRET_KEY")
                .map_err(setting_error)?,
            session_token: settings
                .optional("SIGNAL_S3_SESSION_TOKEN")
                .map_err(setting_error)?,
        };
        let s3_config = S3Config {
            endpoint: required("SIGNAL_S3_ENDPOINT")?,
            region: required("SIGNAL_S3_REGION")?,
            bucket: required("SIGNAL_S3_BUCKET")?,
            max_object_bytes: object_bytes,
            allow_loopback_http,
        };
        let publication = PublicationConfig {
            materialization: Some(MaterializationConfig {
                directory: required("SIGNAL_S3_CACHE_DIR")?.into(),
                max_files: settings
                    .number("SIGNAL_S3_CACHE_FILES", 1024)
                    .map_err(setting_error)?,
                max_disk_bytes: settings
                    .number("SIGNAL_S3_CACHE_BYTES", 1_073_741_824)
                    .map_err(setting_error)? as u64,
            }),
            inventory_objects: settings
                .number("SIGNAL_S3_INVENTORY_OBJECTS", 10_000)
                .map_err(setting_error)?,
            catalog_bytes: settings
                .number("SIGNAL_S3_CATALOG_BYTES", 16 * 1024 * 1024)
                .map_err(setting_error)?,
            storage: config.clone(),
            ..Default::default()
        };
        // Validate all finite policy before acquiring an owner or making a request.
        publication.validate()?;
        let (remote, _) = object_s3::build(&s3_config, &credentials)
            .map_err(|_| StorageError::Config("bounded S3 adapter"))?;
        let context = OperationContext::new(config.operation_timeout);
        let io = ObjectIo::open_small_remote(
            &SmallOwnerConfig {
                directory: config.directory.clone(),
                stream_id: stream,
                backend_id,
            },
            Arc::new(remote),
            tokio::runtime::Handle::current(),
            ObjectIoLimits {
                bytes: object_bytes,
                entries: publication.inventory_objects,
                timeout: config.operation_timeout,
            },
            context.clone(),
        )
        .await
        .map_err(StorageError::ObjectIo)?;
        let store = Arc::new(ObjectPublisher::new(
            io,
            tokio::runtime::Handle::current(),
            publication,
        )?);
        // Read and authenticate the bounded committed chain before readiness/frontier checks.
        if let Err(error) = store.snapshot(context).await.map(drop) {
            let _ = store
                .shutdown(OperationContext::new(config.operation_timeout))
                .await;
            return Err(error);
        }
        Ok(Self::Object(store))
    }
    pub fn metrics(&self) -> StorageMetrics {
        match self {
            Self::Local(store) => store.metrics(),
            #[cfg(feature = "s3-query")]
            Self::Object(store) => store.storage_metrics(),
        }
    }
    pub fn retired_through(&self) -> u64 {
        match self {
            Self::Local(_) => 0,
            #[cfg(feature = "s3-query")]
            Self::Object(store) => store.retired_through(),
        }
    }
    pub async fn append(
        &self,
        rows: &[StoredEvent],
        context: OperationContext,
    ) -> Result<StoreReceipt, StorageError> {
        match self {
            Self::Local(store) => store.append(rows.to_vec(), context).await,
            #[cfg(feature = "s3-query")]
            Self::Object(store) => store.append(rows, context).await,
        }
    }
    pub async fn flush(&self, context: OperationContext) -> Result<(), StorageError> {
        match self {
            Self::Local(store) => store.flush(context).await,
            #[cfg(feature = "s3-query")]
            Self::Object(store) => store.snapshot(context).await.map(drop),
        }
    }
    pub async fn shutdown(&self, context: OperationContext) -> Result<(), StorageError> {
        match self {
            Self::Local(store) => store.shutdown(context).await,
            #[cfg(feature = "s3-query")]
            Self::Object(store) => store.shutdown(context).await,
        }
    }
    #[cfg(test)]
    pub async fn read_batch(
        &self,
        after: u64,
        max_events: usize,
        max_bytes: usize,
        context: OperationContext,
    ) -> Result<Vec<StoredEvent>, StorageError> {
        match self {
            Self::Local(store) => {
                store
                    .read_batch(after, max_events, max_bytes, context)
                    .await
            }
            #[cfg(feature = "s3-query")]
            Self::Object(_) => Err(StorageError::QueryUnavailable),
        }
    }
}
impl QueryFileSource for Backend {
    fn select_query_files(
        &self,
        from: Option<chrono::DateTime<chrono::Utc>>,
        to: Option<chrono::DateTime<chrono::Utc>>,
        max_files: usize,
        max_decoded_bytes: u64,
        context: OperationContext,
    ) -> StoreFuture<'_, FileSelection> {
        match self {
            Self::Local(store) => {
                store.select_query_files(from, to, max_files, max_decoded_bytes, context)
            }
            #[cfg(feature = "s3-query")]
            Self::Object(store) => {
                store.select_query_files(from, to, max_files, max_decoded_bytes, context)
            }
        }
    }
}
const OBJECT_SETTINGS: &[&str] = &[
    "SIGNAL_S3_ENDPOINT",
    "SIGNAL_S3_REGION",
    "SIGNAL_S3_BUCKET",
    "SIGNAL_S3_BACKEND_ID",
    "SIGNAL_S3_CACHE_DIR",
    "SIGNAL_S3_CACHE_FILES",
    "SIGNAL_S3_CACHE_BYTES",
    "SIGNAL_S3_OBJECT_BYTES",
    "SIGNAL_S3_INVENTORY_OBJECTS",
    "SIGNAL_S3_CATALOG_BYTES",
    "SIGNAL_S3_ALLOW_LOOPBACK_HTTP",
];
fn setting_error(_: ConfigError) -> StorageError {
    StorageError::Config("storage setting")
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    #[tokio::test]
    async fn strict_selection_rejects_unused_or_invalid_object_configuration() -> Result {
        let temp = tempfile::TempDir::new()?;
        let config = StorageConfig {
            directory: temp.path().join("events"),
            ..Default::default()
        };
        for yaml in [
            "schema_version: 1\nstorage:\n  type: parquet\n  s3_endpoint: https://example.invalid\n",
            "schema_version: 1\nstorage:\n  type: s3\n",
        ] {
            let settings = Settings::for_test(yaml, &[])?;
            assert!(matches!(
                Backend::open(&settings, config.clone(), Uuid::new_v4()).await,
                Err(StorageError::Config(_))
            ));
            assert!(!config.directory.exists());
        }
        let settings = Settings::for_test(
            "schema_version: 1\nstorage:\n  type: parquet\n",
            &[("SIGNAL_STORAGE_TYPE", "unknown")],
        )?;
        assert!(matches!(
            Backend::open(&settings, config, Uuid::new_v4()).await,
            Err(StorageError::Config(_))
        ));
        Ok(())
    }
    #[test]
    fn storage_schema_retains_s3_bounds_and_environment_precedence() -> Result {
        let settings = Settings::for_test(
            "schema_version: 1\nstorage:\n  type: s3\n  s3_endpoint: https://example.invalid\n  s3_cache_files: 8\n  s3_allow_loopback_http: 'false'\n",
            &[("SIGNAL_S3_CACHE_FILES", "4")],
        )?;
        assert_eq!(
            settings.optional("SIGNAL_STORAGE_TYPE")?.as_deref(),
            Some("s3")
        );
        assert_eq!(settings.number("SIGNAL_S3_CACHE_FILES", 16)?, 4);
        for yaml in [
            "schema_version: 1\nstorage:\n  s3_secret_key: secret\n",
            "schema_version: 1\nstorage:\n  s3_cache_files: 0\n",
            "schema_version: 1\nstorage:\n  s3_allow_loopback_http: true\n",
        ] {
            assert!(Settings::for_test(yaml, &[]).is_err());
        }
        Ok(())
    }
}
