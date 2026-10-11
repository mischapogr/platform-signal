//! Signed exact-version GET with non-bypassable Object Lock readback.
use super::*;
use crate::{
    object_custody::RetainedVersionRead, object_io::ObjectIoError, object_manifest::QueryObjectRef,
};
use chrono::{DateTime, Utc};

/// Trusted deployment chooses endpoint, bucket, credentials and expected owner.
/// Use only through ObjectIo::remote_retained. No retention mutation or DELETE.
pub fn build_custody_reader(
    config: &S3Config,
    credentials: &S3Credentials,
    expected_bucket_owner: &str,
) -> Result<(Arc<dyn RetainedVersionRead>, S3HttpObserver), S3Error> {
    let endpoint = validate(config, credentials)?;
    if expected_bucket_owner.len() != 12
        || !expected_bucket_owner.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(S3Error::Config);
    }
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
    let reader = Reader {
        transport: Transport {
            endpoint,
            max_object_bytes: config.max_object_bytes,
            tls: Arc::new(tls),
            state: state.clone(),
            delete_scope: None,
            retained_reads: true,
        },
        credential: Arc::new(AwsCredential {
            key_id: credentials.access_key.clone(),
            secret_key: credentials.secret_key.clone(),
            token: credentials.session_token.clone(),
        }),
        bucket: config.bucket.clone(),
        region: config.region.clone(),
        owner: expected_bucket_owner.into(),
    };
    Ok((Arc::new(reader), S3HttpObserver(state)))
}
struct Reader {
    transport: Transport,
    credential: Arc<AwsCredential>,
    bucket: String,
    region: String,
    owner: String,
}

fn singleton<'a>(headers: &'a header::HeaderMap, name: &str) -> Result<&'a str, ObjectIoError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(ObjectIoError::Condition)?;
    if values.next().is_some() {
        return Err(ObjectIoError::Corrupt);
    }
    value.to_str().map_err(|_| ObjectIoError::Corrupt)
}
#[async_trait::async_trait]
impl RetainedVersionRead for Reader {
    async fn verify_retained(
        &self,
        reference: &QueryObjectRef,
        retain_until: DateTime<Utc>,
        ctx: &OperationContext,
    ) -> Result<DateTime<Utc>, ObjectIoError> {
        crate::object_custody::validate(
            reference,
            retain_until,
            self.transport.max_object_bytes as u64,
        )?;
        context().map_err(|_| ObjectIoError::Config)?;
        check(ctx).map_err(|_| ObjectIoError::Cancelled)?;
        let version = reference
            .version
            .as_deref()
            .ok_or(ObjectIoError::Condition)?;
        let mut url = self.transport.endpoint.clone();
        url.path_segments_mut()
            .map_err(|_| ObjectIoError::Config)?
            .pop_if_empty()
            .push(&self.bucket)
            .extend(reference.key.split('/'));
        url.query_pairs_mut().append_pair("versionId", version);
        let mut builder = hyper::Request::builder()
            .method(Method::GET)
            .uri(url.as_str())
            .header("x-amz-expected-bucket-owner", &self.owner);
        if let Some(etag) = &reference.etag {
            builder = builder.header(header::IF_MATCH, crate::object_reclamation::etag(etag)?);
        }
        let mut request = builder
            .body(object_store::client::HttpRequestBody::empty())
            .map_err(|_| ObjectIoError::Config)?;
        object_store::aws::AwsAuthorizer::new(&self.credential, "s3", &self.region)
            .try_authorize(&mut request, None)
            .map_err(|_| ObjectIoError::Backend)?;
        // Bound transport buffering to this immutable description's length,
        // before trusting or parsing any response retention metadata.
        let transport = Transport {
            endpoint: self.transport.endpoint.clone(),
            max_object_bytes: reference.bytes as usize,
            tls: self.transport.tls.clone(),
            state: self.transport.state.clone(),
            delete_scope: None,
            retained_reads: true,
        };
        let response = transport
            .call(request)
            .await
            .map_err(|_| ObjectIoError::Backend)?;
        if response.status() != hyper::StatusCode::OK {
            return Err(ObjectIoError::Backend);
        }
        let h = response.headers();
        if singleton(h, "x-amz-version-id")? != version
            || singleton(h, "x-amz-object-lock-mode")? != "COMPLIANCE"
            || singleton(h, "content-length")?
                .parse::<u64>()
                .map_err(|_| ObjectIoError::Corrupt)?
                != reference.bytes
            || h.contains_key(header::CONTENT_RANGE)
            || h.get_all("x-amz-delete-marker").iter().count() > 1
            || h.get("x-amz-delete-marker").is_some_and(|v| v != "false")
        {
            return Err(ObjectIoError::Condition);
        }
        if let Some(expected) = &reference.etag
            && crate::object_reclamation::etag(singleton(h, "etag")?)?
                != crate::object_reclamation::etag(expected)?
        {
            return Err(ObjectIoError::Condition);
        }
        let horizon =
            DateTime::parse_from_rfc3339(singleton(h, "x-amz-object-lock-retain-until-date")?)
                .map_err(|_| ObjectIoError::Corrupt)?
                .with_timezone(&Utc);
        if horizon < retain_until || horizon <= Utc::now() {
            return Err(ObjectIoError::Condition);
        }
        crate::object_custody::validate(
            reference,
            horizon,
            self.transport.max_object_bytes as u64,
        )?;
        let body = response
            .into_body()
            .bytes()
            .await
            .map_err(|_| ObjectIoError::Backend)?;
        if body.len() as u64 != reference.bytes
            || crate::object_manifest::sha256(&body) != reference.sha256
        {
            return Err(ObjectIoError::Corrupt);
        }
        check(ctx).map_err(|_| ObjectIoError::Cancelled)?;
        Ok(horizon)
    }
}
