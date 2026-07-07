//! Bounded batch transport. Only verified WAL admission prefixes may leave the spool.
use std::{io, time::Duration};

use reqwest::{Client, StatusCode, header};
use serde::Serialize;
use signal_event::SignalEvent;
use signal_protocol::{API_SCHEMA_VERSION, IngestResponse};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

const RESPONSE_LIMIT: usize = 64 * 1024;

pub use signal_protocol::{AdmissionDisposition as Disposition, AdmissionOutcome as BatchOutcome};

/// All errors imply zero local acknowledgement. Diagnostics contain no caller data.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SendError {
    #[error("invalid HTTP sender configuration")]
    Configuration,
    #[error("batch exceeds local count or byte limit")]
    BatchLimit,
    #[error("batch serialization failed")]
    Serialization,
    #[error("HTTP transport failed; admission is uncertain")]
    Transport,
    #[error("HTTP deadline exceeded; admission is uncertain")]
    Deadline,
    #[error("HTTP send cancelled; admission is uncertain")]
    Cancelled,
    #[error("HTTP response exceeds byte limit; admission is uncertain")]
    ResponseLimit,
    #[error("HTTP acknowledgement is invalid; admission is uncertain")]
    InvalidResponse,
}

/// One reusable client. The runtime owns a single sender loop and its bounded spool.
/// Deliberately does not implement Debug: both endpoint and header can hold secrets.
pub struct BatchSender {
    client: Client,
    endpoint: url::Url,
    token: Option<header::HeaderValue>,
    max_events: usize,
    max_request_bytes: usize,
    request_timeout: Duration,
}

impl BatchSender {
    pub fn new(
        endpoint: &str,
        token: Option<&str>,
        max_events: usize,
        max_request_bytes: usize,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, SendError> {
        let mut endpoint = url::Url::parse(endpoint).map_err(|_| SendError::Configuration)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || max_events == 0
            || max_request_bytes == 0
            || connect_timeout.is_zero()
            || request_timeout.is_zero()
            || connect_timeout > request_timeout
            || tokio::time::Instant::now()
                .checked_add(request_timeout)
                .is_none()
        {
            return Err(SendError::Configuration);
        }
        match endpoint.path() {
            "" | "/" | "/v1/events/batch" => endpoint.set_path("/v1/events/batch"),
            _ => return Err(SendError::Configuration),
        }
        let token = token
            .map(|token| {
                if token.is_empty() {
                    return Err(SendError::Configuration);
                }
                let mut value = header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| SendError::Configuration)?;
                value.set_sensitive(true);
                Ok(value)
            })
            .transpose()?;
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(connect_timeout)
            .timeout(request_timeout)
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|_| SendError::Configuration)?;
        Ok(Self {
            client,
            endpoint,
            token,
            max_events,
            max_request_bytes,
            request_timeout,
        })
    }

    pub async fn send(
        &self,
        events: &[SignalEvent],
        cancel: &CancellationToken,
    ) -> Result<BatchOutcome, SendError> {
        if cancel.is_cancelled() {
            return Err(SendError::Cancelled);
        }
        if events.is_empty() || events.len() > self.max_events {
            return Err(SendError::BatchLimit);
        }
        #[derive(Serialize)]
        struct Batch<'a> {
            schema_version: u16,
            events: &'a [SignalEvent],
        }
        let batch = Batch {
            schema_version: API_SCHEMA_VERSION,
            events,
        };
        // Count without allocating the JSON body, then allocate exactly its bounded size.
        let mut count = BoundedCount {
            count: 0,
            limit: self.max_request_bytes,
        };
        if serde_json::to_writer(&mut count, &batch).is_err() {
            return Err(if count.count > count.limit {
                SendError::BatchLimit
            } else {
                SendError::Serialization
            });
        }
        let mut body = Vec::with_capacity(count.count);
        serde_json::to_writer(&mut body, &batch).map_err(|_| SendError::Serialization)?;
        let work = async {
            let mut request = self
                .client
                .post(self.endpoint.clone())
                .header(header::CONTENT_TYPE, "application/json")
                .body(body);
            if let Some(token) = &self.token {
                request = request.header(header::AUTHORIZATION, token.clone());
            }
            let mut response = request.send().await.map_err(transport_error)?;
            let status = response.status();
            if response
                .content_length()
                .is_some_and(|length| length > RESPONSE_LIMIT as u64)
            {
                return Err(SendError::ResponseLimit);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
                if chunk.len() > RESPONSE_LIMIT - bytes.len() {
                    return Err(SendError::ResponseLimit);
                }
                bytes.extend_from_slice(&chunk);
            }
            let response: IngestResponse =
                serde_json::from_slice(&bytes).map_err(|_| SendError::InvalidResponse)?;
            verify(status, response, events)
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(SendError::Cancelled),
            result = tokio::time::timeout(self.request_timeout, work) =>
                result.map_err(|_| SendError::Deadline)?,
        }
    }
}

fn transport_error(error: reqwest::Error) -> SendError {
    if error.is_timeout() {
        SendError::Deadline
    } else {
        SendError::Transport
    }
}

struct BoundedCount {
    count: usize,
    limit: usize,
}
impl io::Write for BoundedCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self.count.saturating_add(bytes.len());
        if self.count > self.limit {
            return Err(io::Error::other("batch limit"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn verify(
    status: StatusCode,
    response: IngestResponse,
    events: &[SignalEvent],
) -> Result<BatchOutcome, SendError> {
    let ids: Vec<_> = events.iter().map(|e| e.id).collect();
    signal_protocol::verify_admission_response(status.as_u16(), response, &ids)
        .map_err(|_| SendError::InvalidResponse)
}

/// Capped exponential delay with deterministic jitter supplied by the runtime.
/// The caller can seed jitter from an event ID; no random dependency is needed.
pub fn retry_delay(attempt: u32, base: Duration, cap: Duration, jitter: u64) -> Duration {
    let ceiling = base
        .saturating_mul(1_u32.checked_shl(attempt).unwrap_or(u32::MAX))
        .min(cap);
    let half = ceiling / 2;
    let window = ceiling.saturating_sub(half).as_nanos();
    let nanos = u128::from(jitter) % window.saturating_add(1);
    half.saturating_add(Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64))
        .min(cap)
}

pub async fn wait_retry(delay: Duration, cancel: &CancellationToken) -> Result<(), SendError> {
    let deadline = tokio::time::Instant::now()
        .checked_add(delay)
        .ok_or(SendError::Configuration)?;
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(SendError::Cancelled),
        _ = tokio::time::sleep_until(deadline) => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    fn event(id: &str) -> SignalEvent {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "id": id,
            "timestamp": "2026-10-06T12:00:00Z",
            "observed_at": "2026-10-06T12:00:00Z",
            "source": {"type": "stdin"},
            "severity": "info", "message": "hello", "attributes": {}, "tags": []
        }))
        .unwrap()
    }

    fn events() -> Vec<SignalEvent> {
        vec![
            event("00000000-0000-4000-8000-000000000001"),
            event("00000000-0000-4000-8000-000000000002"),
        ]
    }

    fn sender(endpoint: &str, token: Option<&str>, deadline: Duration) -> BatchSender {
        BatchSender::new(endpoint, token, 10, 16 * 1024, deadline, deadline).unwrap()
    }

    async fn request(stream: &mut TcpStream) -> (String, serde_json::Value) {
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                break bytes.len();
            }
            assert!(bytes.len() < 16 * 1024);
        };
        let headers = String::from_utf8(bytes).unwrap();
        let length: usize = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        assert!(length < 16 * 1024);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        assert!(header_end > 0);
        (headers, serde_json::from_slice(&body).unwrap())
    }

    async fn respond(stream: &mut TcpStream, status: u16, body: &str) {
        let headers = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(body.as_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn partial_retry_preserves_suffix_ids_and_order() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let batch = events();
        let first_id = batch[0].id;
        let second_id = batch[1].id;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (headers, body) = request(&mut stream).await;
            assert!(headers.starts_with("POST /v1/events/batch HTTP/1.1"));
            assert_eq!(body["events"][0]["id"], first_id.to_string());
            assert_eq!(body["events"][1]["id"], second_id.to_string());
            respond(&mut stream, 429, &serde_json::json!({"schema_version":1,"accepted":1,"rejected":1,"event_ids":[first_id],"error":{"code":"full","message":"full","index":1}}).to_string()).await;
            let (mut stream, _) = listener.accept().await.unwrap();
            let (_, body) = request(&mut stream).await;
            assert_eq!(body["events"].as_array().unwrap().len(), 1);
            assert_eq!(body["events"][0]["id"], second_id.to_string());
            respond(&mut stream, 202, &serde_json::json!({"schema_version":1,"accepted":1,"rejected":0,"event_ids":[second_id]}).to_string()).await;
        });
        let sender = sender(&endpoint, None, Duration::from_secs(2));
        let cancel = CancellationToken::new();
        let outcome = sender.send(&batch, &cancel).await.unwrap();
        assert_eq!(
            outcome,
            BatchOutcome {
                accepted: 1,
                disposition: Disposition::Retry
            }
        );
        assert_eq!(
            sender
                .send(&batch[outcome.accepted..], &cancel)
                .await
                .unwrap(),
            BatchOutcome {
                accepted: 1,
                disposition: Disposition::Complete
            }
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_success_has_no_acknowledgement() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            respond(
                &mut stream,
                202,
                r#"{"schema_version":1,"accepted":2,"rejected":0,"event_ids":[]}"#,
            )
            .await;
        });
        assert_eq!(
            sender(&endpoint, None, Duration::from_secs(2))
                .send(&events(), &CancellationToken::new())
                .await,
            Err(SendError::InvalidResponse)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unauthorized_retains_every_event_without_echoing_secret() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (headers, _) = request(&mut stream).await;
            assert!(
                headers
                    .to_lowercase()
                    .contains("authorization: bearer test-secret")
            );
            respond(&mut stream, 401, r#"{"schema_version":1,"accepted":0,"rejected":0,"event_ids":[],"error":{"code":"unauthorized","message":"test-secret"}}"#).await;
        });
        let outcome = sender(&endpoint, Some("test-secret"), Duration::from_secs(2))
            .send(&events(), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            outcome,
            BatchOutcome {
                accepted: 0,
                disposition: Disposition::Permanent
            }
        );
        assert!(!format!("{outcome:?}").contains("test-secret"));
        assert!(!SendError::Transport.to_string().contains("test-secret"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn body_limit_and_total_deadline_bound_response_reads() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            // No content length: exercise actual streamed byte accounting.
            stream
                .write_all(b"HTTP/1.1 202 Test\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let _ = stream.write_all(&vec![b'x'; RESPONSE_LIMIT + 1]).await;
        });
        assert_eq!(
            sender(&endpoint, None, Duration::from_secs(2))
                .send(&events(), &CancellationToken::new())
                .await,
            Err(SendError::ResponseLimit)
        );
        server.await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 202 Test\r\nContent-Length: 100\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        assert_eq!(
            sender(&endpoint, None, Duration::from_millis(100))
                .send(&events(), &CancellationToken::new())
                .await,
            Err(SendError::Deadline)
        );
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn redirect_never_receives_token_and_cancel_interrupts_request() {
        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let location = format!("http://{}", destination.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            stream.write_all(format!("HTTP/1.1 307 Test\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        });
        assert_eq!(
            sender(&endpoint, Some("test-secret"), Duration::from_secs(2))
                .send(&events(), &CancellationToken::new())
                .await,
            Err(SendError::InvalidResponse)
        );
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), destination.accept())
                .await
                .is_err()
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            trigger.cancel();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        assert_eq!(
            sender(&endpoint, None, Duration::from_secs(2))
                .send(&events(), &cancel)
                .await,
            Err(SendError::Cancelled)
        );
        server.abort();
        let _ = server.await;
    }

    #[test]
    fn acknowledgement_rejects_wrong_prefix_status_counts_and_index() {
        let batch = events();
        for value in [
            serde_json::json!({"schema_version":1,"accepted":1,"rejected":1,"event_ids":[batch[1].id],"error":{"code":"full","message":"full","index":1}}),
            serde_json::json!({"schema_version":1,"accepted":1,"rejected":0,"event_ids":[batch[0].id],"error":{"code":"full","message":"full","index":1}}),
            serde_json::json!({"schema_version":1,"accepted":1,"rejected":1,"event_ids":[batch[0].id],"error":{"code":"full","message":"full","index":0}}),
            serde_json::json!({"schema_version":1,"accepted":1,"rejected":1,"event_ids":[batch[0].id],"error":{"code":"unauthorized","message":"full","index":1}}),
        ] {
            assert_eq!(
                verify(
                    StatusCode::TOO_MANY_REQUESTS,
                    serde_json::from_value(value).unwrap(),
                    &batch
                ),
                Err(SendError::InvalidResponse)
            );
        }
        // Validation happens before any event is admitted, so an arbitrary failing
        // validation index is valid with a zero accepted prefix.
        let response = serde_json::from_value(serde_json::json!({"schema_version":1,"accepted":0,"rejected":2,"event_ids":[],"error":{"code":"invalid_event","message":"invalid","index":1}})).unwrap();
        assert_eq!(
            verify(StatusCode::BAD_REQUEST, response, &batch)
                .unwrap()
                .disposition,
            Disposition::Permanent
        );
    }

    #[test]
    fn admission_deadline_and_unavailability_ack_only_verified_prefix() {
        let batch = events();
        for (status, code) in [
            (408, "request_timeout"),
            (503, "unavailable"),
            (503, "stopping"),
        ] {
            let response = serde_json::from_value(serde_json::json!({
                "schema_version":1,"accepted":1,"rejected":1,"event_ids":[batch[0].id],
                "error":{"code":code,"message":"retry","index":1}
            }))
            .unwrap();
            assert_eq!(
                verify(StatusCode::from_u16(status).unwrap(), response, &batch).unwrap(),
                BatchOutcome {
                    accepted: 1,
                    disposition: Disposition::Retry
                }
            );
        }
        let response = serde_json::from_value(serde_json::json!({
            "schema_version":1,"accepted":0,"rejected":0,"event_ids":[],
            "error":{"code":"payload_too_large","message":"too large"}
        }))
        .unwrap();
        assert_eq!(
            verify(StatusCode::PAYLOAD_TOO_LARGE, response, &batch).unwrap(),
            BatchOutcome {
                accepted: 0,
                disposition: Disposition::ReduceBatch
            }
        );
    }

    #[tokio::test]
    async fn local_limits_and_backoff_are_bounded_and_cancellable() {
        let tiny = BatchSender::new(
            "http://127.0.0.1:1",
            None,
            1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            tiny.send(&events()[..1], &CancellationToken::new()).await,
            Err(SendError::BatchLimit)
        );
        for attempt in [0, 1, 10, 32, u32::MAX] {
            let delay = retry_delay(
                attempt,
                Duration::from_millis(100),
                Duration::from_secs(5),
                u64::MAX,
            );
            assert!(delay <= Duration::from_secs(5));
            assert!(!delay.is_zero());
        }
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            wait_retry(Duration::from_secs(20), &cancel).await,
            Err(SendError::Cancelled)
        );
    }
}
