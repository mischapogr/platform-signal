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
    audit: Option<Arc<crate::audit::Control>>,
}

pub fn router_with_identity(
    engine: Arc<QueryEngine>,
    auth: IngestConfig,
    max_limit: usize,
    timeout: Duration,
    stopping: CancellationToken,
    identity: Option<IdentityBackend>,
    audit: Option<Arc<crate::audit::Control>>,
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
            audit,
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
    let authentication = crate::access::authenticate(
        &state.auth,
        state.identity.as_ref(),
        &headers,
        deadline,
        cancellation.clone(),
    )
    .await;
    use signal_protocol::audit::{Actor, Completion, Decision};
    let (grant, early_response, actor, decision) = match authentication {
        Ok(grant) => {
            let denied = grant.as_ref().is_some_and(|g| {
                !crate::access::capable(g, signal_protocol::access::Operation::QueryEvents)
            });
            let actor = match &grant {
                Some(grant) => crate::access::now()
                    .and_then(|now| grant.audit_subject_key(now))
                    .map_or(Actor::Unattributed {}, |key| Actor::VerifiedSubject { key }),
                None if state.auth.api_token.is_some() => Actor::Bootstrap {},
                None => Actor::Anonymous {},
            };
            let response = denied.then(|| {
                error(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    "event query access denied",
                )
            });
            (
                grant,
                response,
                actor,
                if denied {
                    Decision::Denied
                } else {
                    Decision::Granted
                },
            )
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
    let session = if let Some(audit) = &state.audit {
        match audit
            .begin(actor, decision, deadline, cancellation.clone())
            .await
        {
            Ok(session) => Some(session),
            Err(_) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "audit_unavailable",
                    "restricted audit unavailable",
                );
            }
        }
    } else {
        None
    };
    let response = match early_response {
        Some(response) => response,
        None => execute(&state, raw, grant.as_ref(), deadline, cancellation.clone()).await,
    };
    if let Some(session) = session {
        let completion = if response.status().is_success() {
            Completion::Success
        } else if decision == Decision::Denied || response.status() == StatusCode::FORBIDDEN {
            Completion::Denied
        } else if matches!(
            response.status(),
            StatusCode::REQUEST_TIMEOUT | StatusCode::SERVICE_UNAVAILABLE
        ) {
            Completion::Uncertain
        } else {
            Completion::Failed
        };
        if session.finish(completion).await.is_err() {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                "restricted audit unavailable",
            );
        }
        // Audit I/O cannot extend the original request or verified grant lease.
        if cancellation.is_cancelled() || tokio::time::Instant::now() >= deadline {
            return error(
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "query deadline exceeded",
            );
        }
        if response.status().is_success()
            && grant.as_ref().is_some_and(|g| {
                !crate::access::capable(g, signal_protocol::access::Operation::QueryEvents)
            })
        {
            return error(
                StatusCode::FORBIDDEN,
                "forbidden",
                "event query access denied",
            );
        }
    }
    response
}

async fn execute(
    state: &QueryState,
    raw: Option<String>,
    grant: Option<&signal_protocol::access::RequestGrant>,
    deadline: tokio::time::Instant,
    cancellation: CancellationToken,
) -> Response {
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
    let result = match grant {
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
    let mut response = (
        status,
        Json(serde_json::json!({
            "schema_version": API_SCHEMA_VERSION,
            "error": { "code": code, "message": message }
        })),
    )
        .into_response();
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
