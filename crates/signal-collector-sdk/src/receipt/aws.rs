//! Optional actual AWS JSON/S3 transport with application-supplied credentials.
//! Uses Amazon's signer, bounded HTTP I/O, no service SDK retry/deserialization loop.
use super::*;
use async_trait::async_trait;
use aws_sigv4::{
    http_request::{
        self, PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest,
        SigningSettings, UriPathNormalizationMode,
    },
    sign::v4,
};
use futures_util::TryStreamExt;
use reqwest::{
    Client, Method, Url,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

const QUEUE_REPLY_LIMIT: usize = 2 * 1024 * 1024;
// S3 canonical URI encoding differs from a generic URL path encoder: reserved
// bytes such as '+' must be encoded; actual key slashes remain unchanged.
pub(crate) fn uri_encode(input: &str, preserve_slashes: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~')
            || (preserve_slashes && byte == b'/')
        {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    out
}
/// Bounded application credential input; no Debug/serialization or environment,
/// IMDS, file or network discovery. The application supplies rotating credentials.
pub struct SigningCredentials(aws_credential_types::Credentials);
impl SigningCredentials {
    pub fn new(
        access: &str,
        secret: &str,
        token: Option<&str>,
        expires: Option<SystemTime>,
    ) -> Result<Self, SourceFailure> {
        if access.len() < 8
            || access.len() > 128
            || !access.bytes().all(|b| b.is_ascii_alphanumeric())
            || secret.len() < 12
            || secret.len() > 256
            || !secret.bytes().all(|b| b.is_ascii_graphic())
            || token.is_some_and(|s| {
                s.is_empty() || s.len() > 16 * 1024 || !s.bytes().all(|b| b.is_ascii_graphic())
            })
        {
            return Err(SourceFailure::Malformed);
        }
        Ok(Self(aws_credential_types::Credentials::new(
            access,
            secret,
            token.map(str::to_owned),
            expires,
            "application",
        )))
    }
}
#[async_trait]
pub trait AwsCredentialsProvider: Send + Sync {
    async fn credentials(
        &self,
        context: &ExtensionContext,
    ) -> Result<SigningCredentials, SourceFailure>;
}
/// Trusted endpoint/queue configuration. Plain HTTP requires explicit loopback
/// opt-in. This initial client supports commercial AWS queue ARNs and path-style
/// S3 endpoints; it does not infer hosts, owners or permission from notifications.
pub struct AwsSourceConfig {
    queue_arn: String,
    queue_owner: String,
    queue_region: String,
    queue_url: Url,
    sqs_endpoint: Url,
    s3_endpoint: Url,
    s3_region: String,
    visibility: i32,
}
pub(crate) fn region(s: &str) -> bool {
    s.len() >= 3
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub(crate) fn endpoint(s: &str, local: bool) -> Result<Url, SourceFailure> {
    if s.is_empty() || s.len() > 2048 {
        return Err(SourceFailure::Malformed);
    }
    let u = Url::parse(s).map_err(|_| SourceFailure::Malformed)?;
    let loopback = u.host_str().is_some_and(|h| {
        h.trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    });
    if u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || (u.scheme() != "https" && !(local && u.scheme() == "http" && loopback))
    {
        return Err(SourceFailure::Malformed);
    }
    Ok(u)
}
impl AwsSourceConfig {
    pub fn new(
        queue_arn: &str,
        queue_url: &str,
        s3_region: &str,
        s3_endpoint: &str,
        visibility_seconds: u32,
        allow_loopback_http: bool,
    ) -> Result<Self, SourceFailure> {
        if queue_arn.len() > 1024
            || !region(s3_region)
            || visibility_seconds == 0
            || visibility_seconds > 43200
        {
            return Err(SourceFailure::Malformed);
        }
        let parts: Vec<_> = queue_arn.split(':').collect();
        if parts.len() != 6
            || parts[0] != "arn"
            || parts[1] != "aws"
            || parts[2] != "sqs"
            || !region(parts[3])
            || parts[4].len() != 12
            || !parts[4].bytes().all(|b| b.is_ascii_digit())
            || parts[5].is_empty()
            || parts[5].len() > 80
            || !parts[5]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(SourceFailure::Malformed);
        }
        let queue_url = endpoint(queue_url, allow_loopback_http)?;
        if queue_url.path() != format!("/{}/{}", parts[4], parts[5]) {
            return Err(SourceFailure::Malformed);
        }
        let mut sqs_endpoint = queue_url.clone();
        sqs_endpoint.set_path("/");
        let s3_endpoint = endpoint(s3_endpoint, allow_loopback_http)?;
        if s3_endpoint.path() != "/" {
            return Err(SourceFailure::Malformed);
        }
        Ok(Self {
            queue_arn: queue_arn.into(),
            queue_owner: parts[4].into(),
            queue_region: parts[3].into(),
            queue_url,
            sqs_endpoint,
            s3_endpoint,
            s3_region: s3_region.into(),
            visibility: visibility_seconds as i32,
        })
    }
}
pub struct AwsSourceClient {
    transport: SignedAwsTransport,
    config: AwsSourceConfig,
}
pub(crate) struct SignedAwsTransport {
    client: Client,
    credentials: Arc<dyn AwsCredentialsProvider>,
}
impl SignedAwsTransport {
    pub(crate) fn new(
        credentials: Arc<dyn AwsCredentialsProvider>,
        connect_timeout: Duration,
    ) -> Result<Self, SourceFailure> {
        if connect_timeout.is_zero() || connect_timeout > Duration::from_secs(86400) {
            return Err(SourceFailure::Malformed);
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(connect_timeout)
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|_| SourceFailure::Malformed)?;
        Ok(Self {
            client,
            credentials,
        })
    }
    pub(crate) async fn signed_request(
        &self,
        method: Method,
        url: Url,
        scope: (&str, &str),
        headers: HeaderMap,
        body: Vec<u8>,
        ctx: &ExtensionContext,
    ) -> Result<reqwest::Response, SourceFailure> {
        ctx.check().map_err(|_| SourceFailure::Unavailable)?;
        let (service, region) = scope;
        let work = async {
            let credentials = self.credentials.credentials(ctx).await?;
            let now = SystemTime::now();
            let remaining = ctx
                .deadline()
                .saturating_duration_since(tokio::time::Instant::now());
            if credentials.0.expiry().is_some_and(|end| {
                now.checked_add(remaining)
                    .is_none_or(|latest| end <= latest)
            }) {
                return Err(SourceFailure::Denied);
            }
            let identity: aws_smithy_runtime_api::client::identity::Identity = credentials.0.into();
            let mut settings = SigningSettings::default();
            if service == "s3" {
                settings.percent_encoding_mode = PercentEncodingMode::Single;
                settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
                settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
            }
            let parameters = v4::SigningParams::builder()
                .identity(&identity)
                .region(region)
                .name(service)
                .time(now)
                .settings(settings)
                .build()
                .map_err(|_| SourceFailure::Malformed)?
                .into();
            // Sign the real body digest. Do not place receipt handles or payloads
            // in the signer's Debug-capable request, even with body tracing enabled.
            let hash = super::format::hex(&Sha256::digest(&body));
            let mut plain = Vec::new();
            for (name, value) in &headers {
                plain.push((
                    name.as_str(),
                    value.to_str().map_err(|_| SourceFailure::Malformed)?,
                ));
            }
            let request = SignableRequest::new(
                method.as_str(),
                url.as_str(),
                plain.into_iter(),
                SignableBody::Precomputed(hash),
            )
            .map_err(|_| SourceFailure::Malformed)?;
            // Keep signing traces out of application logs without changing the
            // process/global subscriber or settings. AWS credentials Debug exposes
            // the access-key ID; the transport never formats it or its errors.
            let output = tracing::subscriber::with_default(
                tracing::subscriber::NoSubscriber::default(),
                || http_request::sign(request, &parameters),
            )
            .map_err(|_| SourceFailure::Malformed)?;
            let (instructions, _) = output.into_parts();
            let (signed, query) = instructions.into_parts();
            if !query.is_empty() {
                return Err(SourceFailure::Malformed);
            }
            let mut headers = headers;
            for h in signed {
                let mut v =
                    HeaderValue::from_str(h.value()).map_err(|_| SourceFailure::Malformed)?;
                v.set_sensitive(
                    h.sensitive()
                        || h.name().eq_ignore_ascii_case("authorization")
                        || h.name().eq_ignore_ascii_case("x-amz-security-token"),
                );
                headers.insert(h.name(), v);
            }
            ctx.check().map_err(|_| SourceFailure::Unavailable)?;
            let response = self
                .client
                .request(method, url)
                .headers(headers)
                .body(body)
                .timeout(remaining)
                .send()
                .await
                .map_err(|_| SourceFailure::Unavailable)?;
            validate_headers(response.headers())?;
            Ok(response)
        };
        tokio::select! {
            biased;
            _=ctx.cancellation().cancelled()=>Err(SourceFailure::Unavailable),
            _=tokio::time::sleep_until(ctx.deadline())=>Err(SourceFailure::Unavailable),
            result=work=>{ctx.check().map_err(|_|SourceFailure::Unavailable)?;result}
        }
    }
}
impl AwsSourceClient {
    pub fn new(
        config: AwsSourceConfig,
        credentials: Arc<dyn AwsCredentialsProvider>,
        connect_timeout: Duration,
    ) -> Result<Self, SourceFailure> {
        Ok(Self {
            transport: SignedAwsTransport::new(credentials, connect_timeout)?,
            config,
        })
    }
    fn queue_scope(&self, b: &ReceiptBinding) -> Result<(), SourceFailure> {
        if b.0["queue_arn"] != self.config.queue_arn
            || b.0["queue_owner"] != self.config.queue_owner
        {
            return Err(SourceFailure::Denied);
        }
        Ok(())
    }
    async fn queue_request(
        &self,
        b: &ReceiptBinding,
        action: &'static str,
        body: Value,
        reply_cap: usize,
        ctx: &ExtensionContext,
    ) -> Result<(u16, Vec<u8>), SourceFailure> {
        self.queue_scope(b)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-amz-json-1.0"),
        );
        headers.insert("x-amz-target", HeaderValue::from_static(action));
        let bytes = serde_json::to_vec(&body).map_err(|_| SourceFailure::Malformed)?;
        if bytes.len() > 32 * 1024 {
            return Err(SourceFailure::Malformed);
        }
        let r = self
            .transport
            .signed_request(
                Method::POST,
                self.config.sqs_endpoint.clone(),
                ("sqs", &self.config.queue_region),
                headers,
                bytes,
                ctx,
            )
            .await?;
        let status = r.status().as_u16();
        let body = read_body(r, reply_cap, ctx).await?;
        if status != 200 {
            return Err(source_error(status, &body));
        }
        Ok((status, body))
    }
}
fn validate_headers(headers: &HeaderMap) -> Result<(), SourceFailure> {
    let mut size = 0usize;
    if headers.len() > 128 {
        return Err(SourceFailure::Malformed);
    }
    for (name, value) in headers {
        size = size
            .checked_add(name.as_str().len())
            .and_then(|n| n.checked_add(value.as_bytes().len()))
            .ok_or(SourceFailure::Malformed)?;
        if size > 64 * 1024 {
            return Err(SourceFailure::Malformed);
        }
    }
    Ok(())
}
pub(crate) fn source_error(status: u16, body: &[u8]) -> SourceFailure {
    let code = crate::cloudtrail::decode_json(body, QUEUE_REPLY_LIMIT, 16, 8192)
        .ok()
        .and_then(|v| v["__type"].as_str().map(str::to_owned));
    let code = code
        .as_deref()
        .and_then(|c| c.rsplit('#').next())
        .unwrap_or_default();
    if status == 429
        || matches!(
            code,
            "RequestThrottled" | "Throttling" | "ThrottlingException"
        )
    {
        SourceFailure::Throttled
    } else if status == 401
        || status == 403
        || matches!(
            code,
            "AccessDenied" | "AccessDeniedException" | "InvalidSecurity" | "ExpiredToken"
        )
    {
        SourceFailure::Denied
    } else {
        SourceFailure::Unavailable
    }
}
pub(crate) async fn read_body(
    mut response: reqwest::Response,
    cap: usize,
    ctx: &ExtensionContext,
) -> Result<Vec<u8>, SourceFailure> {
    if response.content_length().is_some_and(|n| n > cap as u64) {
        return Err(SourceFailure::Malformed);
    }
    let work = async {
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| SourceFailure::Unavailable)?
        {
            ctx.check().map_err(|_| SourceFailure::Unavailable)?;
            if chunk.len() > cap - body.len() {
                return Err(SourceFailure::Malformed);
            }
            body.try_reserve_exact(chunk.len())
                .map_err(|_| SourceFailure::Unavailable)?;
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    };
    tokio::select! {biased;
        _=ctx.cancellation().cancelled()=>Err(SourceFailure::Unavailable),
        _=tokio::time::sleep_until(ctx.deadline())=>Err(SourceFailure::Unavailable),
        result=work=>{ctx.check().map_err(|_|SourceFailure::Unavailable)?;result}
    }
}
#[async_trait]
impl SourceQueue for AwsSourceClient {
    async fn receive(
        &self,
        b: &ReceiptBinding,
        ctx: &ExtensionContext,
    ) -> Result<Option<QueueDelivery>, SourceFailure> {
        let (_,body)=self.queue_request(b,"AmazonSQS.ReceiveMessage",serde_json::json!({"QueueUrl":self.config.queue_url.as_str(),
            "MaxNumberOfMessages":1,"WaitTimeSeconds":0,"VisibilityTimeout":self.config.visibility}),QUEUE_REPLY_LIMIT,ctx).await?;
        let v = crate::cloudtrail::decode_json(&body, QUEUE_REPLY_LIMIT, 16, 8192)
            .map_err(|_| SourceFailure::Malformed)?;
        if !v.is_object()
            || ["__type", "Error", "Code"]
                .iter()
                .any(|key| v.get(key).is_some())
        {
            return Err(SourceFailure::Malformed);
        }
        let Some(messages) = v.get("Messages") else {
            return Ok(None);
        };
        let messages = messages.as_array().ok_or(SourceFailure::Malformed)?;
        if messages.is_empty() {
            return Ok(None);
        }
        if messages.len() != 1 {
            return Err(SourceFailure::Malformed);
        }
        let m = &messages[0];
        let text = |key: &str, cap: usize| {
            m[key]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= cap)
                .ok_or(SourceFailure::Malformed)
        };
        let body = text("Body", MAX_DISCOVERY_BYTES)?.as_bytes().to_vec();
        QueueDelivery::new(
            body,
            text("MessageId", 128)?.into(),
            text("ReceiptHandle", 16 * 1024)?.into(),
        )
        .map(Some)
        .map_err(|_| SourceFailure::Malformed)
    }
    async fn delete(
        &self,
        b: &ReceiptBinding,
        ticket: &SourceAckTicket,
        ctx: &ExtensionContext,
    ) -> Result<SourceAckOutcome, SourceFailure> {
        if ticket.binding() != b {
            return Err(SourceFailure::Denied);
        }
        let ack_context = ticket
            .current_context(ctx)
            .map_err(|_| SourceFailure::Unavailable)?;
        let response = self.queue_request(
            b,
            "AmazonSQS.DeleteMessage",
            serde_json::json!({"QueueUrl":self.config.queue_url.as_str(),
            "ReceiptHandle":ticket.handle()}),
            64 * 1024,
            &ack_context,
        );
        let (status, body) = tokio::select! {
            biased;
            _ = ticket.owner_fenced() => return Err(SourceFailure::Unavailable),
            response = response => response?,
        };
        Ok(SourceAckOutcome::from_sqs_json_response(status, &body))
    }
}
#[async_trait]
impl CaptureTransport for AwsSourceClient {
    async fn open(
        &self,
        d: &ObjectDiscovery,
        ctx: &ExtensionContext,
    ) -> Result<CaptureStream, CaptureFailure> {
        // Reject segments a generic URL parser can normalize into another key.
        // This is an explicit unsupported capture, never a rewritten source key.
        if d.key().split('/').any(|s| s == "." || s == "..")
            || d.key().bytes().any(|b| b.is_ascii_control())
            || d.bucket().len() < 3
            || !d
                .bucket()
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
            || d.bucket().starts_with(['.', '-'])
            || d.bucket().ends_with(['.', '-'])
            || d.bucket().contains("..")
        {
            return Err(CaptureFailure::Malformed);
        }
        let mut url = self.config.s3_endpoint.clone();
        url.set_path(&format!("/{}/{}", d.bucket(), uri_encode(d.key(), true)));
        url.set_query(Some(&format!(
            "versionId={}",
            uri_encode(d.version_id(), false)
        )));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-expected-bucket-owner",
            HeaderValue::from_str(d.expected_bucket_owner())
                .map_err(|_| CaptureFailure::Malformed)?,
        );
        let r = self
            .transport
            .signed_request(
                Method::GET,
                url,
                ("s3", &self.config.s3_region),
                headers,
                Vec::new(),
                ctx,
            )
            .await
            .map_err(|e| match e {
                SourceFailure::Denied => CaptureFailure::Denied,
                SourceFailure::Throttled => CaptureFailure::Throttled,
                SourceFailure::Malformed => CaptureFailure::Malformed,
                _ => CaptureFailure::Unavailable,
            })?;
        let status = r.status().as_u16();
        if status != 200 {
            let body = read_body(r, 64 * 1024, ctx)
                .await
                .map_err(|_| CaptureFailure::Unavailable)?;
            let code = std::str::from_utf8(&body)
                .ok()
                .and_then(|s| {
                    s.split_once("<Code>")
                        .and_then(|(_, tail)| tail.split_once("</Code>"))
                })
                .map(|(code, _)| code);
            return Err(match (status, code) {
                (_, Some("InvalidObjectState")) => CaptureFailure::RestorePending,
                (429, _) | (_, Some("SlowDown" | "Throttling")) => CaptureFailure::Throttled,
                (401 | 403, _) => CaptureFailure::Denied,
                (404, _) => CaptureFailure::MissingVersion,
                _ => CaptureFailure::Unavailable,
            });
        }
        if r.content_length()
            .is_some_and(|n| n > MAX_CAPTURE_BYTES as u64)
        {
            return Err(CaptureFailure::Malformed);
        }
        let text = |name: &str| {
            r.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .map(str::to_owned)
        };
        let version_id = text("x-amz-version-id").ok_or(CaptureFailure::Malformed)?;
        let etag = if r.headers().contains_key("etag") {
            Some(text("etag").ok_or(CaptureFailure::Malformed)?)
        } else {
            None
        };
        let stream = r
            .bytes_stream()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        Ok(CaptureStream {
            version_id,
            etag,
            body: Box::new(tokio_util::io::StreamReader::new(Box::pin(stream))),
        })
    }
}
