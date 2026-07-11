//! Shared outbound client mechanisms; private trust/policy remain caller owned.
mod dns;
pub mod tls;
mod worker;
pub use dns::Resolver as BoundedDnsResolver;
use std::{sync::Arc, time::Duration};
pub use worker::WorkerError as TransportError;

/// Fixed HTTP/1 policy: no ambient proxy, redirect, decompression or detached DNS.
/// An optional explicit client identity/trust configuration is built by [`tls`].
/// The caller applies its own exact operation deadline when no total is supplied.
pub fn client(
    connect_timeout: Duration,
    request_timeout: Option<Duration>,
    tls: Option<rustls::ClientConfig>,
) -> Result<reqwest::Client, TransportError> {
    if request_timeout
        .is_some_and(|t| t.is_zero() || t < connect_timeout || t > Duration::from_secs(86400))
    {
        return Err(TransportError::Configuration);
    }
    let resolver = BoundedDnsResolver::new(connect_timeout)?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .dns_resolver(Arc::new(resolver))
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .connect_timeout(connect_timeout)
        .pool_max_idle_per_host(1);
    if let Some(timeout) = request_timeout {
        builder = builder.timeout(timeout);
    }
    if let Some(tls) = tls {
        builder = builder.use_preconfigured_tls(tls);
    }
    builder.build().map_err(|_| TransportError::Configuration)
}

/// One physically retained DNS slot shared by outbound clients in this process.
pub fn dns_depth() -> usize {
    dns::depth()
}
pub fn dns_rejections() -> u64 {
    dns::rejections()
}
