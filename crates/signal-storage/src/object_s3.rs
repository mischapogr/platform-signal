//! Selected S3 adapter with a bounded, unspawned HTTP/1 connection driver.
//! Run only through ObjectIo's physical worker and original request scope.
//! Native AWS/IAM/KMS/Object Lock, credential refresh and process durability
//! require their separate qualification; static credentials are host-supplied.
use crate::{OperationContext, check_context};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use object_store::{
    ClientOptions, RetryConfig,
    aws::{AmazonS3, AmazonS3Builder, AwsCredential},
    client::{
        CredentialProvider, HttpClient, HttpConnector, HttpError, HttpErrorKind, HttpRequest,
        HttpResponse, HttpResponseBody, HttpService,
    },
};
use std::{
    cell::RefCell,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use url::Url;

const HEADER_BYTES: usize = 32 * 1024;
const HEADER_COUNT: usize = 64;
const CONTROL_BYTES: usize = 256 * 1024;
#[derive(Clone, Debug)]
pub struct S3Config {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub max_object_bytes: usize,
    /// Only explicit literal loopback addresses may use HTTP for local fixtures.
    pub allow_loopback_http: bool,
}
/// Never serialize or debug-print secret values, including the access key ID.
pub struct S3Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}
impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S3Credentials([redacted])")
    }
}
struct HostCredentials(Arc<AwsCredential>);
impl std::fmt::Debug for HostCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostS3Credentials([redacted])")
    }
}
#[async_trait::async_trait]
impl CredentialProvider for HostCredentials {
    type Credential = AwsCredential;
    async fn get_credential(&self) -> object_store::Result<Arc<AwsCredential>> {
        Ok(self.0.clone())
    }
}
#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum S3Error {
    #[error("invalid bounded S3 adapter configuration")]
    Config,
    #[error("S3 adapter could not be initialized")]
    Initialize,
}
#[derive(Clone, Copy, Debug)]
pub struct S3HttpMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub requests: u64,
    pub rejected: u64,
}
#[derive(Debug, Default)]
struct State {
    active: AtomicUsize,
    requests: AtomicU64,
    rejected: AtomicU64,
}
#[derive(Clone, Debug)]
pub struct S3HttpObserver(Arc<State>);
impl S3HttpObserver {
    pub fn metrics(&self) -> S3HttpMetrics {
        S3HttpMetrics {
            depth: self.0.active.load(Ordering::Acquire),
            capacity: 1,
            requests: self.0.requests.load(Ordering::Relaxed),
            rejected: self.0.rejected.load(Ordering::Relaxed),
        }
    }
}
thread_local! { static REQUEST_CONTEXT: RefCell<Option<OperationContext>> = const { RefCell::new(None) }; }
pub(crate) struct RequestScope(Option<OperationContext>);
impl RequestScope {
    pub(crate) fn enter(
        context: &OperationContext,
    ) -> Result<Self, crate::object_io::ObjectIoError> {
        REQUEST_CONTEXT.with(|slot| {
            slot.try_borrow_mut()
                .map(|mut slot| Self(slot.replace(context.clone())))
                .map_err(|_| crate::object_io::ObjectIoError::Config)
        })
    }
}
impl Drop for RequestScope {
    fn drop(&mut self) {
        REQUEST_CONTEXT.with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                *slot = self.0.take();
            }
        });
    }
}
fn context() -> Result<OperationContext, HttpError> {
    REQUEST_CONTEXT
        .with(|slot| slot.try_borrow().ok().and_then(|slot| slot.clone()))
        .ok_or_else(|| error(HttpErrorKind::Unknown))
}
fn error(kind: HttpErrorKind) -> HttpError {
    HttpError::new(
        kind,
        std::io::Error::other("bounded S3 transport refused or failed request"),
    )
}
fn check(context: &OperationContext) -> Result<(), HttpError> {
    check_context(Some(context)).map_err(|_| error(HttpErrorKind::Interrupted))
}

/// Explicit credentials prevent ambient metadata/STS/container credential probes.
/// The connector creates no tasks, proxy connections, pool or redirects.
pub fn build(
    config: &S3Config,
    credentials: &S3Credentials,
) -> Result<(AmazonS3, S3HttpObserver), S3Error> {
    let endpoint = validate(config, credentials)?;
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| S3Error::Initialize)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let state = Arc::new(State::default());
    let transport = Transport {
        endpoint,
        max_object_bytes: config.max_object_bytes,
        tls: Arc::new(tls),
        state: state.clone(),
    };
    let provider = HostCredentials(Arc::new(AwsCredential {
        key_id: credentials.access_key.clone(),
        secret_key: credentials.secret_key.clone(),
        token: credentials.session_token.clone(),
    }));
    let store = AmazonS3Builder::new()
        .with_endpoint(&config.endpoint)
        .with_region(&config.region)
        .with_bucket_name(&config.bucket)
        .with_virtual_hosted_style_request(false)
        .with_s3_express(false)
        .with_skip_signature(false)
        .with_allow_http(config.allow_loopback_http)
        .with_credentials(Arc::new(provider))
        .with_http_connector(transport)
        .with_retry(RetryConfig {
            max_retries: 0,
            ..Default::default()
        })
        .build()
        .map_err(|_| S3Error::Initialize)?;
    Ok((store, S3HttpObserver(state)))
}
fn validate(config: &S3Config, credentials: &S3Credentials) -> Result<Url, S3Error> {
    let text = |s: &str, cap| !s.is_empty() && s.len() <= cap && !s.chars().any(char::is_control);
    if !text(&config.endpoint, 1024)
        || !text(&config.region, 64)
        || !config
            .region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !(3..=63).contains(&config.bucket.len())
        || !config
            .bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        || !config.bucket.as_bytes()[0].is_ascii_alphanumeric()
        || !config.bucket.as_bytes()[config.bucket.len() - 1].is_ascii_alphanumeric()
        || config.bucket.contains("..")
        || config.max_object_bytes == 0
        || config.max_object_bytes > 1024 * 1024 * 1024
        || !text(&credentials.access_key, 256)
        || !text(&credentials.secret_key, 4096)
        || credentials
            .session_token
            .as_ref()
            .is_some_and(|s| !text(s, 16384))
    {
        return Err(S3Error::Config);
    }
    let endpoint = Url::parse(&config.endpoint).map_err(|_| S3Error::Config)?;
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
        || endpoint.host().is_none()
        || endpoint.port_or_known_default().is_none()
    {
        return Err(S3Error::Config);
    }
    let loopback = match endpoint.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if endpoint.scheme() != "https"
        && !(endpoint.scheme() == "http" && config.allow_loopback_http && loopback)
    {
        return Err(S3Error::Config);
    }
    Ok(endpoint)
}
#[derive(Clone)]
struct Transport {
    endpoint: Url,
    max_object_bytes: usize,
    tls: Arc<rustls::ClientConfig>,
    state: Arc<State>,
}
impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoundedS3HttpTransport")
    }
}
impl HttpConnector for Transport {
    fn connect(&self, _: &ClientOptions) -> object_store::Result<HttpClient> {
        Ok(HttpClient::new(self.clone()))
    }
}
struct Active {
    state: Arc<State>,
    failed: bool,
}
impl Drop for Active {
    fn drop(&mut self) {
        self.state.active.store(0, Ordering::Release);
        if self.failed {
            self.state.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}
#[async_trait::async_trait]
impl HttpService for Transport {
    async fn call(&self, mut request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let context = context()
            .and_then(|context| {
                check(&context)?;
                Ok(context)
            })
            .inspect_err(|_| {
                self.state.rejected.fetch_add(1, Ordering::Relaxed);
            })?;
        if self
            .state
            .active
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.state.rejected.fetch_add(1, Ordering::Relaxed);
            return Err(error(HttpErrorKind::Unknown));
        }
        let mut active = Active {
            state: self.state.clone(),
            failed: true,
        };
        self.state.requests.fetch_add(1, Ordering::Relaxed);
        let result = async {
            let uri_bytes = request
                .uri()
                .path_and_query()
                .map_or(0, |p| p.as_str().len())
                + request.uri().authority().map_or(0, |a| a.as_str().len())
                + request.uri().scheme_str().map_or(0, str::len)
                + 8;
            if uri_bytes > 4096 || request.body().content_length() > self.max_object_bytes {
                return Err(error(HttpErrorKind::Decode));
            }
            let uri =
                Url::parse(&request.uri().to_string()).map_err(|_| error(HttpErrorKind::Decode))?;
            if uri.scheme() != self.endpoint.scheme()
                || uri.host() != self.endpoint.host()
                || uri.port_or_known_default() != self.endpoint.port_or_known_default()
                || !uri.username().is_empty()
                || uri.password().is_some()
                || !matches!(*request.method(), Method::GET | Method::HEAD | Method::PUT)
            {
                return Err(error(HttpErrorKind::Decode));
            }
            let header_bytes = request.headers().iter().try_fold(0usize, |sum, (k, v)| {
                sum.checked_add(k.as_str().len() + v.as_bytes().len() + 4)
                    .ok_or_else(|| error(HttpErrorKind::Decode))
            })?;
            if request.headers().len() > HEADER_COUNT || header_bytes > HEADER_BYTES {
                return Err(error(HttpErrorKind::Decode));
            }
            // The only additional header is not a signed-header substitution.
            // Closing the one connection prevents pool/driver work surviving call.
            request.headers_mut().insert(
                header::CONNECTION,
                header::HeaderValue::from_static("close"),
            );
            let cap = if *request.method() == Method::GET
                && !uri.query_pairs().any(|(k, _)| k == "list-type")
                && uri.path().ends_with(".parquet")
            {
                self.max_object_bytes
            } else {
                CONTROL_BYTES
            };
            let host = uri.host().ok_or_else(|| error(HttpErrorKind::Decode))?;
            let port = uri
                .port_or_known_default()
                .ok_or_else(|| error(HttpErrorKind::Decode))?;
            // Native DNS may be non-cancellable. It runs on the retained physical
            // ObjectIo worker, never Tokio's blocking pool; no next admission can
            // release that lease until the OS call actually exits.
            let (address, name) = match host {
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
                        .map_err(|_| error(HttpErrorKind::Connect))?
                        .next()
                        .ok_or_else(|| error(HttpErrorKind::Connect))?,
                    rustls::pki_types::ServerName::try_from(domain.to_owned())
                        .map_err(|_| error(HttpErrorKind::Decode))?,
                ),
            };
            check(&context)?;
            let socket = TcpStream::connect(address)
                .await
                .map_err(|_| error(HttpErrorKind::Connect))?;
            check(&context)?;
            let response = if uri.scheme() == "https" {
                let stream = TlsConnector::from(self.tls.clone())
                    .connect(name, socket)
                    .await
                    .map_err(|_| error(HttpErrorKind::Connect))?;
                self.exchange(stream, request, cap, &context).await?
            } else {
                self.exchange(socket, request, cap, &context).await?
            };
            check(&context)?;
            Ok(response)
        }
        .await;
        active.failed = result.is_err();
        result
    }
}
impl Transport {
    async fn exchange<T>(
        &self,
        stream: T,
        mut request: HttpRequest,
        cap: usize,
        context: &OperationContext,
    ) -> Result<HttpResponse, HttpError>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Direct origin connections use origin-form; retain the signed path/query
        // and explicit Host header instead of sending proxy absolute-form.
        if !request.headers().contains_key(header::HOST) {
            return Err(error(HttpErrorKind::Decode));
        }
        let origin = request
            .uri()
            .path_and_query()
            .ok_or_else(|| error(HttpErrorKind::Decode))?
            .as_str()
            .parse()
            .map_err(|_| error(HttpErrorKind::Decode))?;
        *request.uri_mut() = origin;
        let head = *request.method() == Method::HEAD;
        let (mut sender, connection) = http1::Builder::new()
            .max_headers(HEADER_COUNT)
            .max_buf_size(HEADER_BYTES)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| error(HttpErrorKind::Request))?;
        let operation = async move {
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| error(HttpErrorKind::Request))?;
            check(context)?;
            let (parts, mut body) = response.into_parts();
            let allowed = if parts.status.is_success() {
                cap
            } else {
                CONTROL_BYTES
            };
            if parts
                .headers
                .get(header::CONTENT_ENCODING)
                .is_some_and(|v| v != "identity")
            {
                return Err(error(HttpErrorKind::Decode));
            }
            if !head && let Some(length) = parts.headers.get(header::CONTENT_LENGTH) {
                let length = length
                    .to_str()
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or_else(|| error(HttpErrorKind::Decode))?;
                if length > allowed as u64 {
                    return Err(error(HttpErrorKind::Decode));
                }
            }
            let mut bytes = Vec::new();
            if !head && let Some(length) = parts.headers.get(header::CONTENT_LENGTH) {
                let length = length
                    .to_str()
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
                    .ok_or_else(|| error(HttpErrorKind::Decode))?;
                bytes
                    .try_reserve_exact(length)
                    .map_err(|_| error(HttpErrorKind::Decode))?;
            }
            while let Some(frame) = body.frame().await {
                check(context)?;
                let frame = frame.map_err(|_| error(HttpErrorKind::Request))?;
                if let Ok(chunk) = frame.into_data() {
                    if chunk.len() > allowed.saturating_sub(bytes.len()) {
                        return Err(error(HttpErrorKind::Decode));
                    }
                    if bytes.capacity().saturating_sub(bytes.len()) < chunk.len() {
                        let target = (bytes.len() + chunk.len())
                            .max(bytes.capacity().saturating_mul(2))
                            .min(allowed);
                        bytes
                            .try_reserve_exact(target - bytes.len())
                            .map_err(|_| error(HttpErrorKind::Decode))?;
                    }
                    if bytes.capacity() > allowed {
                        return Err(error(HttpErrorKind::Decode));
                    }
                    bytes.extend_from_slice(&chunk);
                } else {
                    return Err(error(HttpErrorKind::Decode));
                }
            }
            check(context)?;
            let body = HttpResponseBody::new(
                Full::new(Bytes::from(bytes)).map_err(|never| match never {}),
            );
            Ok(HttpResponse::from_parts(parts, body))
        };
        tokio::pin!(operation, connection);
        // Drive the connection in this exact request future, with no spawned
        // driver. Dropping it synchronously closes the owned socket/TLS buffers.
        tokio::select! { biased;
            response = &mut operation => response,
            ended = &mut connection => {
                ended.map_err(|_| error(HttpErrorKind::Request))?;
                operation.await
            }
        }
    }
}
#[cfg(test)]
mod tests;
