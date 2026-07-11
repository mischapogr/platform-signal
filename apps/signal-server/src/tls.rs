//! Optional native mTLS loaded through the existing bounded physical config owner.
use crate::config::{self, ConfigError, Settings};
use signal_ingest::tls::ServerTls;
use signal_protocol::transport::TLS_DOCUMENT_BYTES;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub async fn load(settings: &Settings) -> Result<Option<ServerTls>, ConfigError> {
    let Some(path) = settings.optional("SIGNAL_TLS_CONFIG")? else {
        return Ok(None);
    };
    if path.is_empty() || path.len() > 4096 {
        return Err(ConfigError::Invalid("TLS configuration path"));
    }
    config::read_limited_document(
        path.into(),
        TLS_DOCUMENT_BYTES,
        Instant::now() + Duration::from_secs(5),
        CancellationToken::new(),
        |text| {
            ServerTls::from_private_json(text.as_bytes())
                .map_err(|_| ConfigError::Invalid("private server TLS configuration"))
        },
    )
    .await
    .map(Some)
}
