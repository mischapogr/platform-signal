use super::*;
use async_trait::async_trait;
use reqwest::{Client, Url, header};
use std::time::Duration;

/// One configured authenticated ingest client. Endpoint and token remain private;
/// no Debug. Caller owns active-request count, trust roots and deployment policy.
pub struct HttpReceiptPublisher {
    client: Client,
    endpoint: Url,
    token: Option<header::HeaderValue>,
}
impl HttpReceiptPublisher {
    pub fn new(
        endpoint: &str,
        token: Option<&str>,
        connect_timeout: Duration,
    ) -> Result<Self, ReceiptError> {
        Self::with_tls(endpoint, token, connect_timeout, None)
    }

    /// Select an explicit private client identity/trust configuration from the
    /// shared native builder. TLS requires HTTPS and never falls back to HTTP.
    pub fn with_tls(
        endpoint: &str,
        token: Option<&str>,
        connect_timeout: Duration,
        tls: Option<rustls::ClientConfig>,
    ) -> Result<Self, ReceiptError> {
        if endpoint.is_empty()
            || endpoint.len() > 2048
            || connect_timeout.is_zero()
            || connect_timeout > Duration::from_secs(86400)
            || token.is_some_and(|t| t.is_empty() || t.len() > 4096)
        {
            return Err(ReceiptError::Configuration);
        }
        let mut endpoint = Url::parse(endpoint).map_err(|_| ReceiptError::Configuration)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || (tls.is_some() && endpoint.scheme() != "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ReceiptError::Configuration);
        }
        match endpoint.path() {
            "" | "/" | "/v1/events/batch" => endpoint.set_path("/v1/events/batch"),
            _ => return Err(ReceiptError::Configuration),
        }
        let token = token
            .map(|token| {
                let mut value = header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| ReceiptError::Configuration)?;
                value.set_sensitive(true);
                Ok(value)
            })
            .transpose()?;
        let client = crate::transport::client(connect_timeout, None, tls)
            .map_err(|_| ReceiptError::Configuration)?;
        Ok(Self {
            client,
            endpoint,
            token,
        })
    }
}
#[async_trait]
impl ReceiptPublisher for HttpReceiptPublisher {
    async fn publish(
        &self,
        batch: &PreparedBatch,
        ctx: &ExtensionContext,
    ) -> Result<AdmissionReply, PublishFailure> {
        ctx.check().map_err(|_| PublishFailure::Uncertain)?;
        let work = async {
            let remaining = ctx
                .deadline()
                .saturating_duration_since(tokio::time::Instant::now());
            let mut request = self
                .client
                .post(self.endpoint.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json")
                .body(batch.body().to_vec())
                .timeout(remaining);
            if let Some(token) = &self.token {
                request = request.header(header::AUTHORIZATION, token.clone());
            }
            let mut response = request
                .send()
                .await
                .map_err(|_| PublishFailure::Uncertain)?;
            let status = response.status().as_u16();
            if response
                .content_length()
                .is_some_and(|n| n > progress::RESPONSE_LIMIT as u64)
            {
                return Err(PublishFailure::Uncertain);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| PublishFailure::Uncertain)?
            {
                ctx.check().map_err(|_| PublishFailure::Uncertain)?;
                if chunk.len() > progress::RESPONSE_LIMIT - body.len() {
                    return Err(PublishFailure::Uncertain);
                }
                let needed = body.len() + chunk.len();
                if needed > body.capacity() {
                    let capacity = (body.capacity().max(4096) * 2)
                        .min(progress::RESPONSE_LIMIT)
                        .max(needed);
                    body.try_reserve_exact(capacity - body.len())
                        .map_err(|_| PublishFailure::Uncertain)?;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(AdmissionReply { status, body })
        };
        reply_before_deadline(ctx, work).await
    }
}

pub(super) async fn reply_before_deadline(
    ctx: &ExtensionContext,
    work: impl std::future::Future<Output = Result<AdmissionReply, PublishFailure>>,
) -> Result<AdmissionReply, PublishFailure> {
    tokio::pin!(work);
    let guarded = std::future::poll_fn(|cx| {
        if ctx.check().is_err() {
            std::task::Poll::Ready(Err(PublishFailure::Uncertain))
        } else {
            work.as_mut().poll(cx).map(|result| {
                ctx.check().map_err(|_| PublishFailure::Uncertain)?;
                result
            })
        }
    });
    tokio::select! {
            biased;
            _=ctx.cancellation().cancelled()=>Err(PublishFailure::Uncertain),
            _=tokio::time::sleep_until(ctx.deadline())=>Err(PublishFailure::Uncertain),
            result=guarded=>result,
    }
}
