//! Explicit existing Standard deployment; no owner credentials or installation.
use crate::config::{self, ConfigError, Settings};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use signal_control::{
    ConnectionSettings, ControlClient, ControlError, Scope, ScopedFindingsBinding,
};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Document {
    #[serde(skip)]
    pub revision: [u8; 32],
    pub schema_version: u32,
    pub scope: Scope,
    pub scope_generation: Uuid,
    pub schema_owner: String,
    pub backend_id: Uuid,
    pub catalog_profile: Profile,
    pub lease_ms: u32,
    pub database: Database,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Profile {
    Catalog4,
    RestoredCatalog5,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Database {
    pub host: String,
    pub address: Option<IpAddr>,
    pub port: u16,
    pub database: String,
    pub producer_user: String,
    pub producer_password_env: String,
    pub reader_user: String,
    pub reader_password_env: String,
    pub roots_der_base64: Vec<String>,
}
impl Document {
    pub async fn load(settings: &Settings) -> Result<Self, ConfigError> {
        let path = settings
            .optional("SIGNAL_SHARED_CONFIG")?
            .ok_or(ConfigError::Invalid("Standard configuration required"))?;
        if path.is_empty() || path.len() > 4096 {
            return Err(ConfigError::Invalid("Standard configuration path"));
        }
        config::read_document(
            path.into(),
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
            Self::parse,
        )
        .await
    }
    fn parse(text: &str) -> Result<Self, ConfigError> {
        let invalid = || ConfigError::Invalid("Standard configuration schema or bounds");
        let mut doc: Self = serde_json::from_str(text).map_err(|_| invalid())?;
        if doc.schema_version != 1
            || doc.scope.validate().is_err()
            || doc.scope_generation.is_nil()
            || doc.backend_id.is_nil()
            || !(15000..=60000).contains(&doc.lease_ms)
            || doc.schema_owner.is_empty()
            || doc.schema_owner.len() > 63
            || !doc
                .schema_owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || doc.database.producer_user == doc.database.reader_user
            || doc.database.producer_password_env == doc.database.reader_password_env
            || doc.database.roots_der_base64.is_empty()
            || doc.database.roots_der_base64.len() > 8
            || doc
                .database
                .roots_der_base64
                .iter()
                .any(|s| s.len() > 21848)
            || doc
                .database
                .roots_der_base64
                .iter()
                .map(String::len)
                .sum::<usize>()
                > 87392
        {
            return Err(invalid());
        }
        use sha2::Digest;
        doc.revision = sha2::Sha256::digest(text.as_bytes()).into();
        Ok(doc)
    }
    pub fn binding(&self) -> ScopedFindingsBinding {
        ScopedFindingsBinding {
            store: self.scope.store_id,
            generation: self.scope.generation,
            scope_generation: self.scope_generation,
            schema_owner: self.schema_owner.clone(),
        }
    }
    pub fn clients(
        &self,
        settings: &Settings,
    ) -> Result<(Arc<ControlClient>, Arc<ControlClient>), crate::AppError> {
        let mut roots = rustls::RootCertStore::empty();
        let mut bytes = 0usize;
        for encoded in &self.database.roots_der_base64 {
            let der = STANDARD
                .decode(encoded)
                .map_err(|_| ControlError::Invalid)?;
            bytes = bytes.checked_add(der.len()).ok_or(ControlError::Invalid)?;
            if der.is_empty() || der.len() > 16384 || bytes > 65536 {
                return Err(ControlError::Invalid.into());
            }
            roots
                .add(rustls::pki_types::CertificateDer::from(der))
                .map_err(|_| ControlError::Invalid)?;
        }
        let connect =
            |user: &str, password_env: &str| -> Result<ConnectionSettings, crate::AppError> {
                Ok(ConnectionSettings::tls(
                    self.database.host.clone(),
                    self.database.address,
                    self.database.port,
                    self.database.database.clone(),
                    user.to_owned(),
                    settings.secret_environment(password_env)?.into_bytes(),
                    roots.clone(),
                )?)
            };
        let client = |connection| match self.catalog_profile {
            Profile::Catalog4 => ControlClient::catalog(connection),
            Profile::RestoredCatalog5 => ControlClient::restored_catalog(connection),
        };
        // Resolve and validate both credentials before spawning either pool.
        // A missing/invalid reader secret must not strand producer workers.
        let producer = connect(
            &self.database.producer_user,
            &self.database.producer_password_env,
        )?;
        let reader = connect(
            &self.database.reader_user,
            &self.database.reader_password_env,
        )?;
        Ok((Arc::new(client(producer)?), Arc::new(client(reader)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wire() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"scope":{"schema_version":1,"store_id":Uuid::new_v4(),"generation":Uuid::new_v4(),"tenant":"fixture","stream":Uuid::new_v4(),"partition_id":Uuid::new_v4()},"scope_generation":Uuid::new_v4(),"schema_owner":"signal_owner","backend_id":Uuid::new_v4(),"catalog_profile":"catalog4","lease_ms":15000,"database":{"host":"localhost","address":"127.0.0.1","port":5432,"database":"signal","producer_user":"producer","producer_password_env":"PRODUCER_PASSWORD","reader_user":"reader","reader_password_env":"READER_PASSWORD","roots_der_base64":["synthetic-not-a-certificate"]}})
    }
    #[test]
    fn standard_configuration_rejects_implicit_authority_and_unbounded_controls()
    -> Result<(), Box<dyn std::error::Error>> {
        let valid = wire();
        assert!(Document::parse(&serde_json::to_string(&valid)?).is_ok());
        for (name, value) in [
            ("schema_version", serde_json::json!(2)),
            ("lease_ms", serde_json::json!(14999)),
            ("catalog_profile", serde_json::json!("discover")),
            ("backend_id", serde_json::json!(Uuid::nil())),
            ("scope_generation", serde_json::json!(Uuid::nil())),
            ("schema_owner", serde_json::json!("unsafe\nowner")),
            ("install", serde_json::json!(true)),
        ] {
            let mut bad = valid.clone();
            bad[name] = value;
            assert!(Document::parse(&serde_json::to_string(&bad)?).is_err());
        }
        for name in ["producer_user", "producer_password_env"] {
            let mut bad = valid.clone();
            let reader = if name == "producer_user" {
                "reader_user"
            } else {
                "reader_password_env"
            };
            bad["database"][name] = bad["database"][reader].clone();
            assert!(Document::parse(&serde_json::to_string(&bad)?).is_err());
        }
        let mut bad = valid;
        bad["database"]["roots_der_base64"] = serde_json::json!([]);
        assert!(Document::parse(&serde_json::to_string(&bad)?).is_err());
        Ok(())
    }
}
