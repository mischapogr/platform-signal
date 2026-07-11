use super::{IdentityConfig, IdentityContext, IdentityError};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use signal_protocol::access::introspection::RESPONSE_BYTES;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use url::Url;

const HEADER_BYTES: usize = 16 * 1024;
const HEADER_COUNT: usize = 32;
pub(super) struct Transport {
    endpoint: Url,
    host: header::HeaderValue,
    authorization: header::HeaderValue,
    tls: Arc<rustls::ClientConfig>,
    #[cfg(test)]
    pub(super) before_lookup: std::sync::Mutex<Option<Arc<super::tests::LookupPause>>>,
}
impl Transport {
    pub(super) fn new(config: IdentityConfig) -> Result<Self, IdentityError> {
        let bounded = |value: &str, cap| {
            !value.is_empty()
                && value.len() <= cap
                && value.trim() == value
                && !value.chars().any(char::is_control)
        };
        if !bounded(&config.endpoint, 2048)
            || !bounded(&config.client_id, 1024)
            || !bounded(&config.client_secret, 1024)
            || config.extra_roots.len() > 8
        {
            return Err(IdentityError::Configuration);
        }
        let total = config
            .extra_roots
            .iter()
            .try_fold(0usize, |sum, root| {
                if root.is_empty() || root.len() > 16 * 1024 {
                    return None;
                }
                sum.checked_add(root.len()).filter(|sum| *sum <= 64 * 1024)
            })
            .ok_or(IdentityError::Configuration)?;
        let _ = total;
        let endpoint = Url::parse(&config.endpoint).map_err(|_| IdentityError::Configuration)?;
        if endpoint.scheme() != "https"
            || endpoint.host().is_none()
            || endpoint
                .port_or_known_default()
                .is_none_or(|port| port == 0)
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(IdentityError::Configuration);
        }
        let host = header::HeaderValue::from_str(
            &endpoint[url::Position::BeforeHost..url::Position::AfterPort],
        )
        .map_err(|_| IdentityError::Configuration)?;
        // RFC6749 client_secret_basic percent-encodes each credential before
        // joining with ':', then applies standard Base64. No credential logging.
        let encode = |value: &str| -> Result<String, IdentityError> {
            let encoded = serde_urlencoded::to_string([("v", value)])
                .map_err(|_| IdentityError::Configuration)?;
            encoded
                .strip_prefix("v=")
                .map(str::to_owned)
                .ok_or(IdentityError::Configuration)
        };
        let secret = format!(
            "{}:{}",
            encode(&config.client_id)?,
            encode(&config.client_secret)?
        );
        let mut authorization = header::HeaderValue::from_str(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(secret)
        ))
        .map_err(|_| IdentityError::Configuration)?;
        if authorization.as_bytes().len() > HEADER_BYTES / 2 {
            return Err(IdentityError::Configuration);
        }
        authorization.set_sensitive(true);
        let mut roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        for root in config.extra_roots {
            roots
                .add(root.into())
                .map_err(|_| IdentityError::Configuration)?;
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| IdentityError::Configuration)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            endpoint,
            host,
            authorization,
            tls: Arc::new(tls),
            #[cfg(test)]
            before_lookup: std::sync::Mutex::new(None),
        })
    }
    pub(super) async fn fetch(
        &self,
        body: Vec<u8>,
        context: &IdentityContext,
        stopping: &tokio_util::sync::CancellationToken,
    ) -> Result<Vec<u8>, IdentityError> {
        check(context, stopping)?;
        #[cfg(test)]
        if let Some(pause) = self
            .before_lookup
            .lock()
            .map_err(|_| IdentityError::Unavailable)?
            .clone()
        {
            pause.wait()?;
        }
        check(context, stopping)?;
        let port = self
            .endpoint
            .port_or_known_default()
            .ok_or(IdentityError::Configuration)?;
        // Only this retained physical worker calls native DNS. Its lease cannot
        // be freed by an abandoned frontend while the OS lookup still runs.
        let (address, name) = match self.endpoint.host().ok_or(IdentityError::Configuration)? {
            url::Host::Ipv4(ip) => (
                SocketAddr::from((ip, port)),
                rustls::pki_types::ServerName::IpAddress(ip.into()),
            ),
            url::Host::Ipv6(ip) => (
                SocketAddr::from((ip, port)),
                rustls::pki_types::ServerName::IpAddress(ip.into()),
            ),
            url::Host::Domain(domain) => (
                (domain, port)
                    .to_socket_addrs()
                    .map_err(|_| IdentityError::Unavailable)?
                    .next()
                    .ok_or(IdentityError::Unavailable)?,
                rustls::pki_types::ServerName::try_from(domain.to_owned())
                    .map_err(|_| IdentityError::Configuration)?,
            ),
        };
        check(context, stopping)?;
        let socket = TcpStream::connect(address)
            .await
            .map_err(|_| IdentityError::Unavailable)?;
        check(context, stopping)?;
        let stream = TlsConnector::from(self.tls.clone())
            .connect(name, socket)
            .await
            .map_err(|_| IdentityError::Unavailable)?;
        check(context, stopping)?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(self.endpoint.path())
            .header(header::HOST, self.host.clone())
            .header(header::AUTHORIZATION, self.authorization.clone())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ACCEPT, "application/json")
            .header(header::CONNECTION, "close")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| IdentityError::Configuration)?;
        self.exchange(stream, request, context, stopping).await
    }
    async fn exchange<T>(
        &self,
        stream: T,
        request: Request<Full<Bytes>>,
        context: &IdentityContext,
        stopping: &tokio_util::sync::CancellationToken,
    ) -> Result<Vec<u8>, IdentityError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) = http1::Builder::new()
            .max_headers(HEADER_COUNT)
            .max_buf_size(HEADER_BYTES)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| IdentityError::Unavailable)?;
        let operation = async move {
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| IdentityError::Unavailable)?;
            check(context, stopping)?;
            if response.status() != hyper::StatusCode::OK {
                return Err(IdentityError::Unavailable);
            }
            let (parts, mut body) = response.into_parts();
            for name in [
                header::CONTENT_TYPE,
                header::CONTENT_ENCODING,
                header::CONTENT_LENGTH,
                header::TRANSFER_ENCODING,
            ] {
                if parts.headers.get_all(name).iter().count() > 1 {
                    return Err(IdentityError::InvalidResponse);
                }
            }
            let content = parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .ok_or(IdentityError::InvalidResponse)?;
            if !content
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/json")
                || parts
                    .headers
                    .get(header::CONTENT_ENCODING)
                    .is_some_and(|value| value != "identity")
            {
                return Err(IdentityError::InvalidResponse);
            }
            let length = parts
                .headers
                .get(header::CONTENT_LENGTH)
                .map(|value| {
                    value
                        .to_str()
                        .ok()
                        .and_then(|value| value.parse::<usize>().ok())
                        .ok_or(IdentityError::InvalidResponse)
                })
                .transpose()?;
            if length.is_some_and(|value| value > RESPONSE_BYTES) {
                return Err(IdentityError::InvalidResponse);
            }
            let mut bytes = Vec::with_capacity(length.unwrap_or(0));
            while let Some(frame) = body.frame().await {
                check(context, stopping)?;
                let chunk = frame
                    .map_err(|_| IdentityError::InvalidResponse)?
                    .into_data()
                    .map_err(|_| IdentityError::InvalidResponse)?;
                if chunk.len() > RESPONSE_BYTES.saturating_sub(bytes.len()) {
                    return Err(IdentityError::InvalidResponse);
                }
                if bytes.capacity().saturating_sub(bytes.len()) < chunk.len() {
                    let target = (bytes.len() + chunk.len())
                        .max(bytes.capacity().saturating_mul(2))
                        .min(RESPONSE_BYTES);
                    bytes
                        .try_reserve_exact(target - bytes.len())
                        .map_err(|_| IdentityError::Unavailable)?;
                }
                if bytes.capacity() > RESPONSE_BYTES {
                    return Err(IdentityError::InvalidResponse);
                }
                bytes.extend_from_slice(&chunk);
            }
            check(context, stopping)?;
            Ok(bytes)
        };
        tokio::pin!(operation, connection);
        // No spawned driver, connection pool, redirect, proxy or retry. Drop
        // closes the exact owned socket/TLS state before physical lease release.
        tokio::select! {biased;
            result=&mut operation=>result,
            ended=&mut connection=>{ended.map_err(|_|IdentityError::Unavailable)?;operation.await}
        }
    }
}
fn check(
    context: &IdentityContext,
    stopping: &tokio_util::sync::CancellationToken,
) -> Result<(), IdentityError> {
    if stopping.is_cancelled() {
        return Err(IdentityError::Stopped);
    }
    context.check()
}
