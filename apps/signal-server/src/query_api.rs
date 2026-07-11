//! Authenticated URL queries with the same shutdown and request deadline as ingest.
use axum::{
    Json, Router,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use signal_ingest::{IngestConfig, identity::IdentityBackend};
use signal_protocol::{API_SCHEMA_VERSION, parse_event_query};
use signal_query::{QueryEngine, QueryError};
use signal_storage::OperationContext;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct QueryState {
    engine: Arc<QueryEngine>,
    auth: IngestConfig,
    max_limit: usize,
    timeout: Duration,
    stopping: CancellationToken,
    identity: Option<IdentityBackend>,
}

pub fn router_with_identity(
    engine: Arc<QueryEngine>,
    auth: IngestConfig,
    max_limit: usize,
    timeout: Duration,
    stopping: CancellationToken,
    identity: Option<IdentityBackend>,
) -> Router {
    Router::new()
        .route("/v1/events", get(events))
        .with_state(QueryState {
            engine,
            auth,
            max_limit,
            timeout,
            stopping,
            identity,
        })
}

// Cancelling on drop covers aborted sockets and deadline expiry without detached work.
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn events(
    State(state): State<QueryState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let deadline = tokio::time::Instant::now() + state.timeout;
    let cancellation = state.stopping.child_token();
    let _guard = CancelOnDrop(cancellation.clone());
    let grant = match crate::access::authenticate(
        &state.auth,
        state.identity.as_ref(),
        &headers,
        deadline,
        cancellation.clone(),
    )
    .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    if grant.as_ref().is_some_and(|g| {
        !crate::access::capable(g, signal_protocol::access::Operation::QueryEvents)
    }) {
        return error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "event query access denied",
        );
    }
    let query = match parse_event_query(raw.as_deref().unwrap_or(""), state.max_limit) {
        Ok(query) => query,
        Err(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_query",
                "invalid URL query parameters",
            );
        }
    };
    let context = OperationContext {
        deadline,
        cancellation,
    };
    let result = match &grant {
        Some(grant) => state.engine.execute_authorized(query, context, grant).await,
        None => state.engine.execute(query, context).await,
    };
    let response = match result {
        Ok(result) => {
            let response = Json(result).into_response();
            // Serialization and a late resumed caller cannot extend a grant.
            if tokio::time::Instant::now() >= deadline {
                error(
                    StatusCode::REQUEST_TIMEOUT,
                    "request_timeout",
                    "query deadline exceeded",
                )
            } else if grant.as_ref().is_some_and(|g| {
                !crate::access::capable(g, signal_protocol::access::Operation::QueryEvents)
            }) {
                error(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "event query access denied",
                )
            } else {
                response
            }
        }
        Err(QueryError::Denied) => error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "event query access denied",
        ),
        Err(QueryError::Invalid) => {
            error(StatusCode::BAD_REQUEST, "invalid_query", "invalid query")
        }
        Err(QueryError::Busy) => error(
            StatusCode::TOO_MANY_REQUESTS,
            "full",
            "query capacity is full",
        ),
        Err(QueryError::Timeout) => error(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "query deadline exceeded",
        ),
        Err(QueryError::Resource) => error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "resource_limit",
            "query resource limit exceeded",
        ),
        Err(QueryError::Cancelled | QueryError::Unavailable | QueryError::Config(_)) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "query unavailable",
        ),
    };
    let mut response = response;
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

fn error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "schema_version": API_SCHEMA_VERSION,
            "error": { "code": code, "message": message }
        })),
    )
        .into_response()
}
