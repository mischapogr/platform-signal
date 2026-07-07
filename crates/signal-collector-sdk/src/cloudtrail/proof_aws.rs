//! Optional actual regional ListPublicKeys adapter. The application supplies a
//! trusted endpoint and rotating credentials; there is no discovery or retry loop.
use super::*;
use crate::receipt::{AwsCredentialsProvider, SourceFailure, aws};
use reqwest::{
    Method, Url,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Debug, Error)]
pub enum KeySourceError {
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error(transparent)]
    Source(#[from] SourceFailure),
    #[error("regional key source has an active operation")]
    Busy,
}
#[derive(Clone, Copy, Debug)]
pub struct KeySourceMetrics {
    pub active: usize,
    pub capacity: usize,
    pub rejected: u64,
}
/// One physical HTTP operation at a time, no waiting queue. This is a read-only
/// provider; caller cancellation drops owned request/body work before releasing
/// its active lease. Returned key sets require bounded retention by the caller.
pub struct RegionalKeySource {
    region: String,
    endpoint: Url,
    transport: aws::SignedAwsTransport,
    active: Semaphore,
    rejected: AtomicU64,
}
impl RegionalKeySource {
    pub fn new(
        region: &str,
        endpoint: &str,
        allow_loopback_http: bool,
        credentials: Arc<dyn AwsCredentialsProvider>,
        connect_timeout: Duration,
    ) -> Result<Self, KeySourceError> {
        if !aws::region(region) {
            return Err(ProofError::Configuration.into());
        }
        let endpoint = aws::endpoint(endpoint, allow_loopback_http)?;
        if endpoint.path() != "/" {
            return Err(ProofError::Configuration.into());
        }
        Ok(Self {
            region: region.into(),
            endpoint,
            transport: aws::SignedAwsTransport::new(credentials, connect_timeout)?,
            active: Semaphore::new(1),
            rejected: AtomicU64::new(0),
        })
    }
    pub fn metrics(&self) -> KeySourceMetrics {
        KeySourceMetrics {
            active: 1 - self.active.available_permits(),
            capacity: 1,
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    /// UTC start/end are transmitted as exact decimal epoch seconds. The finite
    /// interval is at most 90 days; no NextToken is silently discarded. Key
    /// responses are authenticated by the configured TLS/credential authority,
    /// never by keys or endpoints in a native digest.
    pub async fn fetch(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        ctx: &ExtensionContext,
    ) -> Result<Vec<TrustedRegionalKey>, KeySourceError> {
        check(ctx)?;
        if !valid_time(start)
            || !valid_time(end)
            || start.timestamp() < 0
            || start >= end
            || end - start > chrono::Duration::days(90)
        {
            return Err(ProofError::Configuration.into());
        }
        let _lease = match self.active.try_acquire() {
            Ok(lease) => lease,
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                return Err(KeySourceError::Busy);
            }
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-amz-json-1.1"),
        );
        headers.insert(
            "x-amz-target",
            HeaderValue::from_static(
                "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.ListPublicKeys",
            ),
        );
        let body = format!(
            "{{\"StartTime\":{},\"EndTime\":{}}}",
            epoch_text(start),
            epoch_text(end)
        )
        .into_bytes();
        let response = self
            .transport
            .signed_request(
                Method::POST,
                self.endpoint.clone(),
                ("cloudtrail", &self.region),
                headers,
                body,
                ctx,
            )
            .await?;
        let status = response.status().as_u16();
        let bytes = aws::read_body(response, MAX_KEY_RESPONSE_BYTES, ctx).await?;
        check(ctx)?;
        if status != 200 {
            return Err(aws::source_error(status, &bytes).into());
        }
        let keys = trusted_keys_from_response(&self.region, &bytes, ctx)?;
        check(ctx)?;
        Ok(keys)
    }
}
fn epoch_text(time: DateTime<Utc>) -> String {
    format!("{}.{:09}", time.timestamp(), time.timestamp_subsec_nanos())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeObjectKind {
    Digest,
    Log,
}
#[derive(Debug, Error)]
pub enum ObjectSourceError {
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error(transparent)]
    Source(#[from] SourceFailure),
    #[error("native source version is missing")]
    MissingVersion,
    #[error("native source requires restoration")]
    RestorePending,
    #[error("native object source has an active operation")]
    Busy,
}
struct OwnedDigestMetadata {
    signature: String,
    algorithm: String,
    generated: Option<DateTime<Utc>>,
}
/// A complete bounded response from the configured authenticated source, not an
/// RSA proof. No body/metadata are exposed before exact version and EOF checks.
pub struct NativeCapture {
    object: CapturedObject,
    bytes: Vec<u8>,
    metadata: Option<OwnedDigestMetadata>,
}
impl NativeCapture {
    pub fn object(&self) -> &CapturedObject {
        &self.object
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn digest_metadata(&self) -> Option<DigestMetadata<'_>> {
        self.metadata.as_ref().map(|m| DigestMetadata {
            signature_hex: &m.signature,
            signature_algorithm: &m.algorithm,
            backfill_generated_at: m.generated,
        })
    }
}
/// One bounded exact-version S3 read. Host configuration fixes the source scope,
/// bucket region and endpoint; URLs/keys/owners cannot come from digest claims.
/// No LIST/latest fallback, retries, original deletion or archive write authority.
pub struct NativeObjectSource {
    scope: ProofScope,
    region: String,
    endpoint: Url,
    transport: aws::SignedAwsTransport,
    active: Semaphore,
    rejected: AtomicU64,
}
impl NativeObjectSource {
    pub fn new(
        scope: ProofScope,
        bucket_region: &str,
        endpoint: &str,
        allow_loopback_http: bool,
        credentials: Arc<dyn AwsCredentialsProvider>,
        connect_timeout: Duration,
    ) -> Result<Self, ObjectSourceError> {
        scope.validate()?;
        if !aws::region(bucket_region) {
            return Err(ProofError::Configuration.into());
        }
        let endpoint = aws::endpoint(endpoint, allow_loopback_http)?;
        if endpoint.path() != "/" {
            return Err(ProofError::Configuration.into());
        }
        Ok(Self {
            scope,
            region: bucket_region.into(),
            endpoint,
            transport: aws::SignedAwsTransport::new(credentials, connect_timeout)?,
            active: Semaphore::new(1),
            rejected: AtomicU64::new(0),
        })
    }
    pub fn metrics(&self) -> KeySourceMetrics {
        KeySourceMetrics {
            active: 1 - self.active.available_permits(),
            capacity: 1,
            rejected: self.rejected.load(Ordering::Relaxed),
        }
    }
    pub async fn fetch(
        &self,
        object: &CapturedObject,
        kind: NativeObjectKind,
        ctx: &ExtensionContext,
    ) -> Result<NativeCapture, ObjectSourceError> {
        check(ctx)?;
        object.validate()?;
        let allowed = match kind {
            NativeObjectKind::Digest => {
                object.key.starts_with(&format!(
                    "{}/CloudTrail-Digest/{}/",
                    self.scope.root, self.scope.region
                )) && object.key.ends_with(".json.gz")
            }
            NativeObjectKind::Log => self.scope.log_key(&object.key),
        };
        if object.bucket != self.scope.bucket || object.owner != self.scope.owner || !allowed {
            return Err(ProofError::Scope.into());
        }
        let _lease = match self.active.try_acquire() {
            Ok(lease) => lease,
            Err(_) => {
                self.rejected.fetch_add(1, Ordering::Relaxed);
                return Err(ObjectSourceError::Busy);
            }
        };
        let mut url = self.endpoint.clone();
        url.set_path(&format!(
            "/{}/{}",
            object.bucket,
            aws::uri_encode(&object.key, true)
        ));
        url.set_query(Some(&format!(
            "versionId={}",
            aws::uri_encode(&object.version, false)
        )));
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-expected-bucket-owner",
            HeaderValue::from_str(&object.owner).map_err(|_| ProofError::Configuration)?,
        );
        let response = self
            .transport
            .signed_request(
                Method::GET,
                url,
                ("s3", &self.region),
                headers,
                Vec::new(),
                ctx,
            )
            .await?;
        let status = response.status().as_u16();
        if status != 200 {
            let body = aws::read_body(response, 64 * 1024, ctx).await?;
            let code = std::str::from_utf8(&body).ok().and_then(|s| {
                s.split_once("<Code>")
                    .and_then(|(_, tail)| tail.split_once("</Code>"))
                    .map(|(code, _)| code)
            });
            return Err(match (status, code) {
                (_, Some("InvalidObjectState")) => ObjectSourceError::RestorePending,
                (404, _) => ObjectSourceError::MissingVersion,
                (429, _) | (_, Some("SlowDown" | "Throttling")) => SourceFailure::Throttled.into(),
                (401 | 403, _) => SourceFailure::Denied.into(),
                _ => SourceFailure::Unavailable.into(),
            });
        }
        let version = one_header(response.headers(), "x-amz-version-id", 1024)?
            .ok_or(ProofError::Malformed)?;
        if version != object.version {
            return Err(ProofError::Scope.into());
        }
        let metadata = if kind == NativeObjectKind::Digest {
            let signature = one_header(response.headers(), "x-amz-meta-signature", 2048)?
                .ok_or(ProofError::Malformed)?;
            decode_hex(&signature, 256, 1024)?;
            let algorithm = one_header(response.headers(), "x-amz-meta-signature-algorithm", 32)?
                .ok_or(ProofError::Malformed)?;
            if algorithm != "SHA256withRSA" {
                return Err(ProofError::Unsupported.into());
            }
            let generated = one_header(
                response.headers(),
                "x-amz-meta-backfill-generation-timestamp",
                40,
            )?
            .map(|s| native_time(&s))
            .transpose()?;
            if object.key.ends_with("_backfill.json.gz") != generated.is_some() {
                return Err(ProofError::Scope.into());
            }
            Some(OwnedDigestMetadata {
                signature,
                algorithm,
                generated,
            })
        } else {
            None
        };
        let cap = match kind {
            NativeObjectKind::Digest => MAX_DIGEST_BYTES,
            NativeObjectKind::Log => MAX_LOG_COMPRESSED_BYTES,
        };
        let bytes = aws::read_body(response, cap, ctx).await?;
        if bytes.is_empty() {
            return Err(ProofError::Malformed.into());
        }
        check(ctx)?;
        Ok(NativeCapture {
            object: object.clone(),
            bytes,
            metadata,
        })
    }
}
fn one_header(headers: &HeaderMap, name: &str, max: usize) -> Result<Option<String>, ProofError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ProofError::Malformed);
    }
    let value = value.to_str().map_err(|_| ProofError::Malformed)?;
    if !text(value, max) {
        return Err(ProofError::Malformed);
    }
    Ok(Some(value.into()))
}
