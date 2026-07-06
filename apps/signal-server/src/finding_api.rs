//! Authenticated, bounded URL queries over the durable finding journal.
use axum::{
    Json, Router,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use signal_findings::{
    DetectionSeverity, Finding, FindingContext, FindingError, FindingQuery, FindingStore,
};
use signal_ingest::{IngestConfig, authorized};
use std::{collections::HashSet, io::Write, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct FindingState {
    store: Arc<FindingStore>,
    auth: IngestConfig,
    limit: usize,
    response_bytes: usize,
    timeout: Duration,
    stopping: CancellationToken,
}

pub fn router(
    store: Arc<FindingStore>,
    auth: IngestConfig,
    limit: usize,
    response_bytes: usize,
    timeout: Duration,
    stopping: CancellationToken,
) -> Router {
    Router::new()
        .route("/v1/findings", get(findings))
        .with_state(FindingState {
            store,
            auth,
            limit,
            response_bytes,
            timeout,
            stopping,
        })
}

struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Serialize)]
struct FindingResponse {
    schema_version: u16,
    findings: Vec<Finding>,
}

async fn findings(
    State(state): State<FindingState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    if !authorized(&state.auth, &headers) {
        return error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "valid bearer token required",
        );
    }
    let query = match parse(raw.as_deref().unwrap_or(""), state.limit) {
        Ok(query) => query,
        Err(()) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "invalid URL query parameters",
            );
        }
    };
    let cancellation = state.stopping.child_token();
    let _guard = CancelOnDrop(cancellation.clone());
    let result = state
        .store
        .query(
            query,
            FindingContext {
                deadline: tokio::time::Instant::now() + state.timeout,
                cancellation,
            },
        )
        .await;
    match result {
        Ok(findings) => {
            let response = FindingResponse {
                schema_version: 1,
                findings,
            };
            let mut bytes = LimitedBytes {
                bytes: Vec::new(),
                limit: state.response_bytes,
            };
            if serde_json::to_writer(&mut bytes, &response).is_err() {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "resource_limit",
                    "finding response limit exceeded",
                );
            }
            ([("content-type", "application/json")], bytes.bytes).into_response()
        }
        Err(FindingError::Invalid(_)) => error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "invalid finding query",
        ),
        Err(FindingError::Full) => error(
            StatusCode::TOO_MANY_REQUESTS,
            "full",
            "finding store capacity is full",
        ),
        Err(FindingError::Quota) => error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "resource_limit",
            "finding response limit exceeded",
        ),
        Err(FindingError::Timeout) => error(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "finding query deadline exceeded",
        ),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "finding store unavailable",
        ),
    }
}

struct LimitedBytes {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for LimitedBytes {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("response limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({"schema_version":1,"error":{"code":code,"message":message}})),
    )
        .into_response()
}

fn parse(raw: &str, max_limit: usize) -> Result<FindingQuery, ()> {
    if raw.len() > 16_384 || max_limit == 0 {
        return Err(());
    }
    let bytes = raw.as_bytes();
    let mut offset = 0;
    let mut decoded = Vec::with_capacity(bytes.len());
    while offset < bytes.len() {
        if bytes[offset] == b'%' {
            if offset + 2 >= bytes.len()
                || !bytes[offset + 1].is_ascii_hexdigit()
                || !bytes[offset + 2].is_ascii_hexdigit()
            {
                return Err(());
            }
            let byte = u8::from_str_radix(&raw[offset + 1..offset + 3], 16).map_err(|_| ())?;
            decoded.push(byte);
            offset += 3;
        } else {
            decoded.push(bytes[offset]);
            offset += 1;
        }
    }
    std::str::from_utf8(&decoded).map_err(|_| ())?;
    let pairs: Vec<(String, String)> = serde_urlencoded::from_str(raw).map_err(|_| ())?;
    let mut query = FindingQuery {
        limit: 100.min(max_limit),
        ..Default::default()
    };
    let mut seen = HashSet::new();
    for (key, value) in pairs {
        if !seen.insert(key.clone()) {
            return Err(());
        }
        match key.as_str() {
            "from" => {
                query.from =
                    Some(signal_protocol::query::parse_query_timestamp(&value).map_err(|_| ())?)
            }
            "to" => {
                query.to =
                    Some(signal_protocol::query::parse_query_timestamp(&value).map_err(|_| ())?)
            }
            "severity" => {
                query.severity = Some(match value.as_str() {
                    "low" => DetectionSeverity::Low,
                    "medium" => DetectionSeverity::Medium,
                    "high" => DetectionSeverity::High,
                    "critical" => DetectionSeverity::Critical,
                    _ => return Err(()),
                })
            }
            "rule_id" if !value.trim().is_empty() && value.len() <= 256 => {
                query.rule_id = Some(value)
            }
            "limit" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                query.limit = value.parse().map_err(|_| ())?
            }
            _ => return Err(()),
        }
    }
    if query.limit == 0
        || query.limit > max_limit
        || matches!((query.from,query.to), (Some(from),Some(to)) if from >= to)
    {
        return Err(());
    }
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finding_url_contract_is_strict_and_bounded() {
        assert_eq!(parse("", 10).map(|q| q.limit), Ok(10));
        assert_eq!(
            parse("rule_id=%EF%BF%BD", 10).ok().and_then(|q| q.rule_id),
            Some("\u{fffd}".into())
        );
        let query = parse(
            "severity=high&rule_id=auth.example&limit=3&from=2026-10-06T00%3A00%3A00Z",
            100,
        );
        assert!(query.is_ok());
        for raw in [
            "sql=SELECT",
            "severity=error",
            "limit=0",
            "limit=101",
            "limit=%2B1",
            "rule_id=",
            "rule_id=%FF",
            "rule_id=%",
            "limit=1&%6cimit=2",
            "from=2026-10-06",
            "from=2026-10-07T00:00:00Z&to=2026-10-06T00:00:00Z",
        ] {
            assert!(parse(raw, 100).is_err(), "{raw}");
        }
    }
}
