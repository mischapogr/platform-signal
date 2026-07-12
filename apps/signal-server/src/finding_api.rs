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
use signal_ingest::{IngestConfig, identity::IdentityBackend};
use signal_protocol::access::{Operation, RequestGrant};
use signal_protocol::findings_feed::{FeedQueryError, parse_findings_feed_query};
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
    security: Security,
}

#[cfg(test)]
pub fn router(
    store: Arc<FindingStore>,
    auth: IngestConfig,
    limit: usize,
    response_bytes: usize,
    timeout: Duration,
    stopping: CancellationToken,
) -> Router {
    router_with_security(
        store,
        auth,
        limit,
        response_bytes,
        timeout,
        stopping,
        Security::default(),
    )
}

#[derive(Clone, Default)]
pub struct Security {
    pub identity: Option<IdentityBackend>,
    pub audit: Option<Arc<crate::audit::Control>>,
}

pub fn router_with_security(
    store: Arc<FindingStore>,
    auth: IngestConfig,
    limit: usize,
    response_bytes: usize,
    timeout: Duration,
    stopping: CancellationToken,
    security: Security,
) -> Router {
    Router::new()
        .route("/v1/findings", get(findings))
        .route("/v1/findings/feed", get(feed))
        .with_state(FindingState {
            store,
            auth,
            limit,
            response_bytes,
            timeout,
            stopping,
            security,
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

async fn feed(
    State(state): State<FindingState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let mut response = read(state, raw, headers, Operation::ReadFindingsFeed).await;
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
async fn feed_inner(
    state: &FindingState,
    raw: Option<String>,
    context: &FindingContext,
    grant: Option<&RequestGrant>,
) -> Response {
    let query = match parse_findings_feed_query(raw.as_deref().unwrap_or(""), state.limit) {
        Ok(query) => query,
        Err(FeedQueryError::InvalidQuery) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "invalid feed query",
            );
        }
        Err(FeedQueryError::InvalidCursor) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "invalid findings cursor",
            );
        }
        Err(FeedQueryError::UnsupportedCursorVersion) => {
            return error(
                StatusCode::BAD_REQUEST,
                "unsupported_cursor_version",
                "unsupported findings cursor version",
            );
        }
    };
    match state
        .store
        .feed(query, state.response_bytes, context.clone())
        .await
    {
        Ok(bytes) => match finish(context, grant, Operation::ReadFindingsFeed) {
            None => ([("content-type", "application/json")], bytes).into_response(),
            Some(response) => response,
        },
        Err(FindingError::CursorStreamMismatch) => error(
            StatusCode::CONFLICT,
            "cursor_stream_mismatch",
            "findings cursor stream mismatch",
        ),
        Err(FindingError::CursorPositionUnavailable) => error(
            StatusCode::CONFLICT,
            "cursor_position_unavailable",
            "findings cursor position unavailable",
        ),
        Err(FindingError::CursorHistoryMismatch) => error(
            StatusCode::CONFLICT,
            "cursor_history_mismatch",
            "findings cursor history mismatch",
        ),
        Err(FindingError::PageBudgetExceeded) => error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "page_budget_exceeded",
            "findings feed page budget exceeded",
        ),
        Err(FindingError::Denied) => {
            error(StatusCode::FORBIDDEN, "forbidden", "finding access denied")
        }
        Err(FindingError::Invalid(_)) => error(
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "invalid feed query",
        ),
        Err(FindingError::Full) => error(
            StatusCode::TOO_MANY_REQUESTS,
            "full",
            "finding store capacity is full",
        ),
        Err(FindingError::Timeout) => error(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "findings feed deadline exceeded",
        ),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "finding store unavailable",
        ),
    }
}

async fn findings(
    State(state): State<FindingState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let mut response = read(state, raw, headers, Operation::ReadFindings).await;
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
async fn findings_inner(
    state: &FindingState,
    raw: Option<String>,
    context: &FindingContext,
    grant: Option<&Arc<RequestGrant>>,
) -> Response {
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
    let result = match grant {
        Some(grant) => {
            state
                .store
                .query_authorized(query, context.clone(), grant.clone())
                .await
        }
        None => state.store.query(query, context.clone()).await,
    };
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
            match finish(context, grant.map(AsRef::as_ref), Operation::ReadFindings) {
                None => ([("content-type", "application/json")], bytes.bytes).into_response(),
                Some(response) => response,
            }
        }
        Err(FindingError::Denied) => {
            error(StatusCode::FORBIDDEN, "forbidden", "finding access denied")
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

fn request_context(state: &FindingState) -> FindingContext {
    FindingContext {
        deadline: tokio::time::Instant::now() + state.timeout,
        cancellation: state.stopping.child_token(),
    }
}
fn allowed(grant: &RequestGrant, operation: Operation) -> bool {
    if operation == Operation::ReadFindingsFeed {
        crate::access::now()
            .is_some_and(|at| grant.scopes(operation, at).any(|scope| scope.is_all()))
    } else {
        crate::access::capable(grant, operation)
    }
}
async fn read(
    state: FindingState,
    raw: Option<String>,
    headers: HeaderMap,
    operation: Operation,
) -> Response {
    use signal_protocol::audit::{Actor, Decision};
    let context = request_context(&state);
    let _guard = CancelOnDrop(context.cancellation.clone());
    let authentication = crate::access::authenticate(
        &state.auth,
        state.security.identity.as_ref(),
        &headers,
        context.deadline,
        context.cancellation.clone(),
    )
    .await;
    let (grant, early, actor, decision) = match authentication {
        Ok(grant) => {
            let actor = crate::audit::actor(grant.as_ref(), state.auth.api_token.is_some());
            let early = finish(&context, grant.as_ref(), operation);
            let decision = match early.as_ref().map(Response::status) {
                None => Decision::Granted,
                Some(StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED) => Decision::Denied,
                Some(_) => Decision::Unavailable,
            };
            (grant.map(Arc::new), early, actor, decision)
        }
        Err(response) => {
            let decision = if matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ) {
                Decision::Denied
            } else {
                Decision::Unavailable
            };
            (None, Some(response), Actor::Unattributed {}, decision)
        }
    };
    let session = if let Some(audit) = state
        .security
        .audit
        .as_ref()
        .filter(|audit| audit.selected(operation))
    {
        match audit
            .begin(
                actor,
                decision,
                operation,
                context.deadline,
                context.cancellation.clone(),
            )
            .await
        {
            Ok(session) => Some(session),
            Err(_) => return audit_unavailable(),
        }
    } else {
        None
    };
    let response = match early {
        Some(response) => response,
        None => {
            // Recording the decision cannot renew the grant or request deadline.
            if let Some(response) = finish(&context, grant.as_deref(), operation) {
                response
            } else if operation == Operation::ReadFindingsFeed {
                feed_inner(&state, raw, &context, grant.as_deref()).await
            } else {
                findings_inner(&state, raw, &context, grant.as_ref()).await
            }
        }
    };
    if let Some(session) = session {
        if session
            .finish(crate::audit::completion(response.status(), decision))
            .await
            .is_err()
        {
            return audit_unavailable();
        }
        if response.status().is_success() {
            if let Some(response) = finish(&context, grant.as_deref(), operation) {
                return response;
            }
        } else if let Some(response) = finish(&context, None, operation) {
            return response;
        }
    }
    response
}
fn audit_unavailable() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
        "restricted audit unavailable",
    )
}
fn finish(
    context: &FindingContext,
    grant: Option<&RequestGrant>,
    operation: Operation,
) -> Option<Response> {
    if context.cancellation.is_cancelled() {
        return Some(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "server stopping",
        ));
    }
    if tokio::time::Instant::now() >= context.deadline {
        return Some(error(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "finding request deadline exceeded",
        ));
    }
    if grant.is_some_and(|grant| !allowed(grant, operation)) {
        return Some(error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "finding access denied",
        ));
    }
    None
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
    #[test]
    fn audited_read_guards_preserve_feed_authority_and_expiry()
    -> Result<(), Box<dyn std::error::Error>> {
        use signal_protocol::access::{
            AccessPolicy, AuthenticatedIdentity, Permission, ResourceScope, Role, Selection,
            SubjectBinding,
        };
        let now = crate::access::now().ok_or("clock unavailable")?;
        let make = |permissions: Vec<Permission>,
                    issued: u64,
                    expires: u64|
         -> Result<RequestGrant, Box<dyn std::error::Error>> {
            let policy = AccessPolicy {
                schema_version: 1,
                roles: vec![Role {
                    id: "fixture-role".into(),
                    permissions,
                }],
                bindings: vec![SubjectBinding {
                    issuer: "fixture-issuer".into(),
                    subject: "fixture-subject".into(),
                    roles: vec!["fixture-role".into()],
                }],
            }
            .compile()?;
            // Explicit host-verified fixture. Never derived from network headers.
            Ok(policy.grant(
                AuthenticatedIdentity::from_verified_backend(
                    "fixture-issuer".into(),
                    "fixture-subject".into(),
                    issued,
                    expires,
                )?,
                issued,
            )?)
        };
        let restricted = make(
            vec![Permission {
                operation: Operation::ReadFindings,
                scope: ResourceScope {
                    sources: Selection::Only(vec!["fixture-source".into()]),
                    accounts: Selection::All,
                    resources: Selection::All,
                },
            }],
            now,
            now + 60,
        )?;
        let context = FindingContext::new(Duration::from_secs(10));
        assert!(finish(&context, Some(&restricted), Operation::ReadFindings).is_none());
        assert_eq!(
            finish(&context, Some(&restricted), Operation::ReadFindingsFeed).map(|r| r.status()),
            Some(StatusCode::FORBIDDEN)
        );
        let global = make(
            vec![Permission {
                operation: Operation::ReadFindingsFeed,
                scope: ResourceScope::all(),
            }],
            now,
            now + 60,
        )?;
        assert!(finish(&context, Some(&global), Operation::ReadFindingsFeed).is_none());
        let expired = make(
            vec![Permission {
                operation: Operation::ReadFindingsFeed,
                scope: ResourceScope::all(),
            }],
            now - 3,
            now - 1,
        )?;
        assert_eq!(
            finish(&context, Some(&expired), Operation::ReadFindingsFeed).map(|r| r.status()),
            Some(StatusCode::FORBIDDEN)
        );
        assert!(matches!(
            crate::audit::actor(Some(&expired), true),
            signal_protocol::audit::Actor::Unattributed {}
        ));
        let cancelled = FindingContext::new(Duration::from_secs(10));
        cancelled.cancellation.cancel();
        assert_eq!(
            finish(&cancelled, Some(&global), Operation::ReadFindingsFeed).map(|r| r.status()),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        let expired_context = FindingContext {
            deadline: tokio::time::Instant::now() - Duration::from_secs(1),
            cancellation: CancellationToken::new(),
        };
        assert_eq!(
            finish(&expired_context, Some(&global), Operation::ReadFindingsFeed)
                .map(|r| r.status()),
            Some(StatusCode::REQUEST_TIMEOUT)
        );
        Ok(())
    }
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    async fn http_fixture(
        bytes: usize,
    ) -> Result<(tempfile::TempDir, Arc<FindingStore>, Router), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = Arc::new(
            FindingStore::open(
                signal_findings::FindingConfig {
                    directory: temp.path().into(),
                    ..Default::default()
                },
                uuid::Uuid::new_v4(),
            )
            .await?,
        );
        let app = router(
            store.clone(),
            IngestConfig {
                api_token: Some("synthetic-feed-token".into()),
                ..Default::default()
            },
            3,
            bytes,
            Duration::from_secs(2),
            CancellationToken::new(),
        );
        Ok((temp, store, app))
    }
    async fn request(
        app: &Router,
        path: &str,
        token: Option<&str>,
    ) -> Result<(StatusCode, serde_json::Value), Box<dyn std::error::Error>> {
        use tower::ServiceExt;
        let mut request = axum::http::Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(axum::body::Body::empty())?)
            .await?;
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|h| h.to_str().ok()),
            Some("no-store")
        );
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 65536).await?;
        Ok((status, serde_json::from_slice(&bytes)?))
    }
    #[tokio::test]
    async fn feed_http_authorizes_before_strict_query_and_never_echoes_input() -> TestResult {
        let (_temp, store, app) = http_fixture(65536).await?;
        assert_eq!(
            request(
                &app,
                "/v1/findings/feed?after=private-secret-sentinel",
                None
            )
            .await?
            .0,
            StatusCode::UNAUTHORIZED
        );
        for (query, code) in [
            ("", "invalid_query"),
            ("after=private-secret-sentinel", "invalid_cursor"),
            ("after=begin&after=begin", "invalid_query"),
            ("after=begin&limit=4", "invalid_query"),
            ("after=%FF", "invalid_query"),
            ("after=begin&severity=high", "invalid_query"),
        ] {
            let (status, body) = request(
                &app,
                &format!("/v1/findings/feed?{query}"),
                Some("synthetic-feed-token"),
            )
            .await?;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["error"]["code"], code);
            assert!(body.get("next_cursor").is_none());
            assert!(!body.to_string().contains("private-secret-sentinel"));
        }
        let (status, empty) = request(
            &app,
            "/v1/findings/feed?after=begin",
            Some("synthetic-feed-token"),
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(empty["schema_version"], 1);
        assert_eq!(empty["findings"], serde_json::json!([]));
        assert_eq!(empty["has_more"], false);
        store
            .shutdown(FindingContext::new(Duration::from_secs(2)))
            .await?;
        Ok(())
    }
    #[tokio::test]
    async fn feed_http_restore_errors_do_not_return_replacement_progress() -> TestResult {
        use signal_protocol::findings_feed::FindingsCursor;
        let (_temp, store, app) = http_fixture(65536).await?;
        let (_, empty) = request(
            &app,
            "/v1/findings/feed?after=begin",
            Some("synthetic-feed-token"),
        )
        .await?;
        let zero = FindingsCursor::decode(empty["next_cursor"].as_str().ok_or("cursor")?)?;
        for (cursor, code) in [
            (
                FindingsCursor::initial(uuid::Uuid::new_v4())?,
                "cursor_stream_mismatch",
            ),
            (
                zero.advance(b"not a retained finding")?,
                "cursor_position_unavailable",
            ),
        ] {
            let (status, body) = request(
                &app,
                &format!("/v1/findings/feed?after={}", cursor.encode()),
                Some("synthetic-feed-token"),
            )
            .await?;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(body["error"]["code"], code);
            assert!(body.get("next_cursor").is_none());
        }
        store
            .shutdown(FindingContext::new(Duration::from_secs(2)))
            .await?;
        Ok(())
    }
    #[tokio::test]
    async fn feed_http_budget_and_shutdown_are_static_without_progress() -> TestResult {
        let (_temp, store, app) = http_fixture(100).await?;
        let (status, body) = request(
            &app,
            "/v1/findings/feed?after=begin",
            Some("synthetic-feed-token"),
        )
        .await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"]["code"], "page_budget_exceeded");
        assert!(body.get("next_cursor").is_none());
        store
            .shutdown(FindingContext::new(Duration::from_secs(2)))
            .await?;
        let (status, body) = request(
            &app,
            "/v1/findings/feed?after=begin",
            Some("synthetic-feed-token"),
        )
        .await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "unavailable");
        Ok(())
    }
}
