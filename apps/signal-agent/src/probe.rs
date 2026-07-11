//! Quiet local health/readiness checks using the shared authenticated client.
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, thiserror::Error, Eq, PartialEq)]
pub enum ProbeError {
    #[error("invalid probe configuration")]
    Configuration,
    #[error("probe operation failed")]
    Failed,
    #[error("probe deadline expired")]
    Deadline,
}
struct Config {
    address: SocketAddr,
    tls: Option<PathBuf>,
}
fn configuration(
    address: Option<&str>,
    tls: Option<&str>,
    server_tls: bool,
) -> Result<Config, ProbeError> {
    let address = address.unwrap_or("127.0.0.1:8080");
    if address.len() > 128 {
        return Err(ProbeError::Configuration);
    }
    let address: SocketAddr = address.parse().map_err(|_| ProbeError::Configuration)?;
    if !address.ip().is_loopback()
        || address.port() == 0
        || tls.is_some_and(|p| p.is_empty() || p.len() > 4096)
        || (server_tls && tls.is_none())
    {
        return Err(ProbeError::Configuration);
    }
    Ok(Config {
        address,
        tls: tls.map(PathBuf::from),
    })
}
fn check(deadline: Instant, cancellation: &CancellationToken) -> Result<(), ProbeError> {
    if cancellation.is_cancelled() {
        Err(ProbeError::Failed)
    } else if Instant::now() >= deadline {
        Err(ProbeError::Deadline)
    } else {
        Ok(())
    }
}
async fn within_deadline<T>(
    deadline: Instant,
    cancellation: &CancellationToken,
    work: impl std::future::Future<Output = Result<T, ProbeError>>,
) -> Result<T, ProbeError> {
    tokio::pin!(work);
    let guarded = std::future::poll_fn(|cx| {
        if let Err(error) = check(deadline, cancellation) {
            std::task::Poll::Ready(Err(error))
        } else {
            work.as_mut().poll(cx).map(|result| {
                check(deadline, cancellation)?;
                result
            })
        }
    });
    tokio::select! { biased;
        _=cancellation.cancelled()=>Err(ProbeError::Failed),
        result=tokio::time::timeout_at(deadline, guarded)=>result.map_err(|_|ProbeError::Deadline)?,
    }
}
async fn run(
    config: Config,
    ready: bool,
    deadline: Instant,
    cancellation: CancellationToken,
) -> Result<(), ProbeError> {
    check(deadline, &cancellation)?;
    let selected_tls = config.tls.is_some();
    let tls = match config.tls {
        Some(path) => Some(
            signal_collector_sdk::transport::tls::load(path, deadline, cancellation.clone())
                .await
                .map_err(|_| ProbeError::Failed)?,
        ),
        None => None,
    };
    check(deadline, &cancellation)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let client = signal_collector_sdk::transport::client(remaining, Some(remaining), tls)
        .map_err(|_| ProbeError::Configuration)?;
    let endpoint = format!(
        "{}://{}{}",
        if selected_tls { "https" } else { "http" },
        config.address,
        if ready { "/readyz" } else { "/healthz" }
    );
    within_deadline(deadline, &cancellation, async {
        let mut response = client
            .get(endpoint)
            .send()
            .await
            .map_err(|_| ProbeError::Failed)?;
        if response.status() != reqwest::StatusCode::OK
            || response.content_length().is_some_and(|n| n > 1024)
        {
            return Err(ProbeError::Failed);
        }
        let mut bytes = 0usize;
        while let Some(chunk) = response.chunk().await.map_err(|_| ProbeError::Failed)? {
            check(deadline, &cancellation)?;
            if chunk.len() > 1024 - bytes {
                return Err(ProbeError::Failed);
            }
            bytes += chunk.len();
        }
        Ok(())
    })
    .await
}

/// No token, source, spool or response/configuration diagnostics. Exactly one
/// original two-second operation budget; container/kubelet supervision is three seconds.
pub fn from_env(ready: bool) -> Result<(), ProbeError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    fn optional(name: &str) -> Result<Option<String>, ProbeError> {
        match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(ProbeError::Configuration),
        }
    }
    let address = optional("SIGNAL_HEALTHCHECK_ADDR")?;
    let tls = optional("SIGNAL_PROBE_TLS_CONFIG")?;
    let server_tls = std::env::var_os("SIGNAL_TLS_CONFIG").is_some();
    let config = configuration(address.as_deref(), tls.as_deref(), server_tls)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ProbeError::Failed)?;
    runtime.block_on(run(config, ready, deadline, CancellationToken::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_wildcard_zero_port_and_missing_private_probe_identity_deny() {
        for address in [
            "0.0.0.0:8080",
            "192.0.2.1:8080",
            "[::]:8080",
            "localhost:8080",
            "127.0.0.1:0",
        ] {
            assert!(configuration(Some(address), None, false).is_err());
        }
        assert!(configuration(None, None, true).is_err());
        assert!(configuration(None, Some(""), true).is_err());
        assert!(configuration(Some("[::1]:8080"), Some("private-probe.json"), true).is_ok());
    }
    #[tokio::test]
    async fn ready_probe_handoff_cannot_succeed_after_deadline() {
        let cancellation = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_millis(10);
        let result = within_deadline(deadline, &cancellation, async {
            std::thread::sleep(Duration::from_millis(25));
            Ok(())
        })
        .await;
        assert_eq!(result, Err(ProbeError::Deadline));
    }
    #[tokio::test]
    async fn actual_http_probe_requires_complete_bounded_success_with_original_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (reply, stall, expected) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".as_slice(),
                false,
                Ok(()),
            ),
            (
                b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".as_slice(),
                false,
                Err(ProbeError::Failed),
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1025\r\n\r\n".as_slice(),
                false,
                Err(ProbeError::Failed),
            ),
            (b"not-http\r\n".as_slice(), false, Err(ProbeError::Failed)),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nO".as_slice(),
                true,
                Err(ProbeError::Deadline),
            ),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let mut request = [0u8; 1024];
                let n = stream.read(&mut request).await?;
                assert!(request[..n].starts_with(b"GET /readyz "));
                stream.write_all(reply).await?;
                if stall {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Ok::<(), std::io::Error>(())
            });
            let began = Instant::now();
            let result = run(
                Config { address, tls: None },
                true,
                began + Duration::from_millis(100),
                CancellationToken::new(),
            )
            .await;
            assert_eq!(result, expected);
            assert!(began.elapsed() < Duration::from_millis(500));
            if stall {
                server.abort();
                let _ = server.await;
            } else {
                tokio::time::timeout(Duration::from_secs(1), server).await???;
            }
        }
        Ok(())
    }
}
