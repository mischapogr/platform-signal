//! Explicit private mTLS material and one physically owned startup file worker.
pub use super::worker::WorkerError as TlsError;
use signal_protocol::transport::{TLS_DOCUMENT_BYTES, TlsMaterial};
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::PathBuf, sync::Arc};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
static WORKER: super::worker::Worker = super::worker::Worker::new();

/// Strict explicit trust; no system roots, skipped signatures or TLS resumption.
pub fn from_private_json(bytes: &[u8]) -> Result<rustls::ClientConfig, TlsError> {
    let material = TlsMaterial::from_private_json(bytes).map_err(|_| TlsError::Configuration)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for root in material.peer_roots_der {
        roots
            .add(root.into())
            .map_err(|_| TlsError::Configuration)?;
    }
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .with_crls(material.peer_crls_der.into_iter().map(Into::into))
    .enforce_revocation_expiration()
    .build()
    .map_err(|_| TlsError::Configuration)?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsError::Configuration)?
        .with_webpki_verifier(verifier)
        .with_client_auth_cert(
            material
                .certificate_chain_der
                .into_iter()
                .map(Into::into)
                .collect(),
            rustls::pki_types::PrivateKeyDer::try_from(material.private_key_der)
                .map_err(|_| TlsError::Configuration)?,
        )
        .map_err(|_| TlsError::Configuration)?;
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

/// Timeout/cancellation cannot release a physical kernel read still in progress.
/// The single retained handle/lease prevents a replacement worker until retirement.
pub async fn load(
    path: PathBuf,
    deadline: Instant,
    cancellation: CancellationToken,
) -> Result<rustls::ClientConfig, TlsError> {
    let worker_cancel = cancellation.clone();
    WORKER
        .run(
            "signal-transport-tls-config",
            deadline,
            cancellation,
            move || {
                super::worker::check(deadline, &worker_cancel)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(path)
                    .map_err(|_| TlsError::Io)?;
                let metadata = file.metadata().map_err(|_| TlsError::Io)?;
                if !metadata.is_file() || metadata.len() > TLS_DOCUMENT_BYTES as u64 {
                    return Err(TlsError::Configuration);
                }
                let mut bytes = Vec::new();
                let mut block = [0u8; 8192];
                loop {
                    super::worker::check(deadline, &worker_cancel)?;
                    let size = file.read(&mut block).map_err(|_| TlsError::Io)?;
                    if size == 0 {
                        break;
                    }
                    if size > TLS_DOCUMENT_BYTES - bytes.len() {
                        return Err(TlsError::Configuration);
                    }
                    bytes.extend_from_slice(&block[..size]);
                }
                let config = from_private_json(&bytes)?;
                super::worker::check(deadline, &worker_cancel)?;
                Ok(config)
            },
        )
        .await
}
