//! Explicit captured credentials and TLS. There is no ambient provider fallback.
use crate::{ControlContext, ControlError};
use std::{fmt, net::IpAddr, time::Duration};
use tokio_postgres::{Client, NoTls, config::SslMode};

#[derive(Clone)]
enum Transport {
    Tls {
        host: String,
        address: Option<IpAddr>,
        roots: rustls::RootCertStore,
    },
    /// Explicitly selected local laboratory transport, never a TLS fallback.
    FixtureLoopback(IpAddr),
}

#[derive(Clone)]
pub struct ConnectionSettings {
    transport: Transport,
    port: u16,
    database: String,
    user: String,
    password: Vec<u8>,
}
impl fmt::Debug for ConnectionSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSettings")
            .field("details", &"redacted")
            .field("tls", &matches!(self.transport, Transport::Tls { .. }))
            .finish()
    }
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
impl ConnectionSettings {
    pub fn tls(
        host: String,
        address: Option<IpAddr>,
        port: u16,
        database: String,
        user: String,
        password: Vec<u8>,
        roots: rustls::RootCertStore,
    ) -> Result<Self, ControlError> {
        if host.is_empty()
            || host.len() > 253
            || host.capacity() > 253
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
            || roots.is_empty()
            || roots.len() > 64
            || roots.roots.capacity() > 64
            || roots
                .roots
                .iter()
                .try_fold(0usize, |total, root| {
                    total
                        .checked_add(root.subject.as_ref().len())?
                        .checked_add(root.subject_public_key_info.as_ref().len())?
                        .checked_add(
                            root.name_constraints
                                .as_ref()
                                .map_or(0, |value| value.as_ref().len()),
                        )
                })
                .is_none_or(|total| total > 65536)
        {
            return Err(ControlError::Invalid);
        }
        let settings = Self {
            transport: Transport::Tls {
                host,
                address,
                roots,
            },
            port,
            database,
            user,
            password,
        };
        settings.validate()?;
        Ok(settings)
    }
    /// The caller must explicitly choose a numeric loopback laboratory endpoint.
    pub fn fixture_loopback(
        address: IpAddr,
        port: u16,
        database: String,
        user: String,
        password: Vec<u8>,
    ) -> Result<Self, ControlError> {
        if !address.is_loopback() {
            return Err(ControlError::Invalid);
        }
        let settings = Self {
            transport: Transport::FixtureLoopback(address),
            port,
            database,
            user,
            password,
        };
        settings.validate()?;
        Ok(settings)
    }
    fn validate(&self) -> Result<(), ControlError> {
        if self.port == 0
            || !name(&self.database)
            || self.database.capacity() > 64
            || !name(&self.user)
            || self.user.capacity() > 64
            || self.password.is_empty()
            || self.password.len() > 4096
            || self.password.capacity() > 4096
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
    pub(crate) async fn connect(
        &self,
        context: &ControlContext,
    ) -> Result<Connection, ControlError> {
        context.check()?;
        let mut config = tokio_postgres::Config::new();
        config.port(self.port).dbname(&self.database).user(&self.user).password(&self.password)
            .application_name("signal-control").connect_timeout(Duration::from_secs(2))
            .tcp_user_timeout(Duration::from_secs(2))
            .options("-c statement_timeout=2000 -c lock_timeout=500 -c idle_in_transaction_session_timeout=2000");
        let connect = async {
            match &self.transport {
                Transport::FixtureLoopback(address) => {
                    config.host(address.to_string()).ssl_mode(SslMode::Disable);
                    let (client, driver) = config
                        .connect(NoTls)
                        .await
                        .map_err(|_| ControlError::Unavailable)?;
                    Ok(Connection {
                        client,
                        driver: tokio::spawn(async move {
                            let _ = driver.await;
                        }),
                    })
                }
                Transport::Tls {
                    host,
                    address,
                    roots,
                } => {
                    config.host(host).ssl_mode(SslMode::Require);
                    if let Some(address) = address {
                        config.hostaddr(*address);
                    }
                    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
                        rustls::crypto::ring::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .map_err(|_| ControlError::Invalid)?
                    .with_root_certificates(roots.clone())
                    .with_no_client_auth();
                    let (client, driver) = config
                        .connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
                        .await
                        .map_err(|_| ControlError::Unavailable)?;
                    Ok(Connection {
                        client,
                        driver: tokio::spawn(async move {
                            let _ = driver.await;
                        }),
                    })
                }
            }
        };
        tokio::select! { biased;
            () = context.cancellation.cancelled() => Err(ControlError::Cancelled),
            result = tokio::time::timeout_at(context.deadline, connect) => result.map_err(|_|ControlError::Timeout)?,
        }
    }
}

pub(crate) struct Connection {
    pub client: Client,
    driver: tokio::task::JoinHandle<()>,
}
impl Connection {
    /// Retire this owned socket/driver before releasing physical worker capacity.
    pub async fn retire(&mut self) {
        self.driver.abort();
        // Joining an aborted Tokio socket future performs no further network I/O.
        // Capacity remains with its worker until this driver has actually stopped.
        let _ = (&mut self.driver).await;
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plaintext_requires_explicit_numeric_loopback_and_secret_debug_is_redacted()
    -> Result<(), ControlError> {
        let settings = ConnectionSettings::fixture_loopback(
            IpAddr::from([127, 0, 0, 1]),
            5432,
            "database".into(),
            "operator".into(),
            b"synthetic-secret".to_vec(),
        )?;
        let debug = format!("{settings:?}");
        for value in ["database", "operator", "synthetic-secret", "127.0.0.1"] {
            assert!(!debug.contains(value));
        }
        assert!(
            ConnectionSettings::fixture_loopback(
                IpAddr::from([203, 0, 113, 1]),
                5432,
                "database".into(),
                "operator".into(),
                vec![1]
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn tls_never_accepts_empty_trust_or_injected_connection_options() {
        assert!(
            ConnectionSettings::tls(
                "localhost".into(),
                None,
                5432,
                "db".into(),
                "user".into(),
                vec![1],
                rustls::RootCertStore::empty()
            )
            .is_err()
        );
        assert!(
            ConnectionSettings::fixture_loopback(
                IpAddr::from([127, 0, 0, 1]),
                5432,
                "db options=bad".into(),
                "user".into(),
                vec![1]
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn precancelled_connection_has_no_network_authority() -> Result<(), ControlError> {
        let settings = ConnectionSettings::fixture_loopback(
            IpAddr::from([127, 0, 0, 1]),
            1,
            "db".into(),
            "user".into(),
            vec![1],
        )?;
        let ctx = ControlContext::new(Duration::from_secs(1))?;
        ctx.cancellation.cancel();
        assert!(matches!(
            settings.connect(&ctx).await,
            Err(ControlError::Cancelled)
        ));
        Ok(())
    }
}
