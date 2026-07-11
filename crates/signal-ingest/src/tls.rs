//! Mandatory peer authentication with explicit private roots and bounded material.
use signal_protocol::transport::TlsMaterial;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
pub struct ServerTls {
    pub(crate) acceptor: TlsAcceptor,
}
impl ServerTls {
    /// Network peer identity never becomes an API capability or source proof.
    /// TLS resumption is disabled so restarted trust/CRL changes cannot be bypassed.
    pub fn from_private_json(bytes: &[u8]) -> Result<Self, crate::ConfigError> {
        let invalid = || crate::ConfigError::Invalid("private server TLS configuration");
        let material = TlsMaterial::from_private_json(bytes).map_err(|_| invalid())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        for root in material.peer_roots_der {
            roots.add(root.into()).map_err(|_| invalid())?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .with_crls(material.peer_crls_der.into_iter().map(Into::into))
        .enforce_revocation_expiration()
        .build()
        .map_err(|_| invalid())?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid())?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                material
                    .certificate_chain_der
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                rustls::pki_types::PrivateKeyDer::try_from(material.private_key_der)
                    .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }
}
