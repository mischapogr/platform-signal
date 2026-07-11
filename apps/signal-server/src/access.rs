//! Private, bounded identity configuration and fail-closed monolith route seams.
use crate::config::{self, ConfigError, Settings};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use signal_ingest::{
    IngestConfig, authorized,
    identity::{IdentityBackend, IdentityConfig, IdentityContext, IdentityError},
};
use signal_protocol::{
    API_SCHEMA_VERSION,
    access::{AccessPolicy, Operation, RequestGrant, introspection::IntrospectionProfile},
};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const CONFIG_BYTES: usize = 512 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: u16,
    endpoint: String,
    client_id: String,
    issuer: String,
    audience: String,
    lease_seconds: u64,
    workers: usize,
    request_timeout_ms: u64,
    #[serde(default)]
    roots_der_base64: Vec<String>,
    // Parsing Value would erase duplicate fields in the nested policy.
    policy: Box<serde_json::value::RawValue>,
}
pub struct Configuration {
    config: IdentityConfig,
    profile: IntrospectionProfile,
    policy: Arc<signal_protocol::access::CompiledPolicy>,
}
impl Configuration {
    pub async fn load(settings: &Settings) -> Result<Option<Self>, ConfigError> {
        let Some(path) = settings.optional("SIGNAL_ACCESS_CONFIG")? else {
            return Ok(None);
        };
        if path.is_empty() || settings.optional("SIGNAL_API_TOKEN")?.is_some() {
            return Err(ConfigError::Invalid(
                "identity configuration conflicts with bootstrap token",
            ));
        }
        let secret = settings.secret_environment("SIGNAL_IDENTITY_CLIENT_SECRET")?;
        config::read_limited_document(
            path.into(),
            CONFIG_BYTES,
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
            move |text| Self::parse(text, secret),
        )
        .await
        .map(Some)
    }
    fn parse(text: &str, secret: String) -> Result<Self, ConfigError> {
        let invalid = || ConfigError::Invalid("identity configuration schema or bounds");
        if text.is_empty()
            || text.len() > CONFIG_BYTES
            || text.bytes().find(|b| !b.is_ascii_whitespace()) != Some(b'{')
        {
            return Err(invalid());
        }
        let wire: Wire = serde_json::from_str(text).map_err(|_| invalid())?;
        if wire.schema_version != 1
            || !(1..=16).contains(&wire.workers)
            || !(1..=30_000).contains(&wire.request_timeout_ms)
            || wire.roots_der_base64.len() > 8
            || wire.roots_der_base64.iter().any(|s| s.len() > 21_848)
            || wire.roots_der_base64.iter().map(String::len).sum::<usize>() > 87_392
        {
            return Err(invalid());
        }
        let mut roots = Vec::with_capacity(wire.roots_der_base64.len());
        let mut root_bytes = 0usize;
        for root in wire.roots_der_base64 {
            let root = STANDARD.decode(root).map_err(|_| invalid())?;
            root_bytes += root.len();
            if root.is_empty() || root.len() > 16_384 || root_bytes > 65_536 {
                return Err(invalid());
            }
            roots.push(root);
        }
        let profile = IntrospectionProfile::new(wire.issuer, wire.audience, wire.lease_seconds)
            .map_err(|_| invalid())?;
        let policy = AccessPolicy::from_json(wire.policy.get().as_bytes())
            .and_then(AccessPolicy::compile)
            .map_err(|_| invalid())?;
        Ok(Self {
            config: IdentityConfig {
                endpoint: wire.endpoint,
                client_id: wire.client_id,
                client_secret: secret,
                extra_roots: roots,
                workers: wire.workers,
                max_request_duration: Duration::from_millis(wire.request_timeout_ms),
            },
            profile,
            policy,
        })
    }
    pub fn open(self) -> Result<IdentityBackend, IdentityError> {
        IdentityBackend::new(
            self.config,
            self.profile,
            self.policy,
            tokio::runtime::Handle::current(),
        )
    }
}

pub fn now() -> Option<u64> {
    u64::try_from(chrono::Utc::now().timestamp()).ok()
}
pub fn capable(grant: &RequestGrant, operation: Operation) -> bool {
    now().is_some_and(|at| grant.scopes(operation, at).next().is_some())
}
pub async fn authenticate(
    bootstrap: &IngestConfig,
    identity: Option<&IdentityBackend>,
    headers: &HeaderMap,
    deadline: Instant,
    cancellation: CancellationToken,
) -> Result<Option<RequestGrant>, Response> {
    if let Some(identity) = identity {
        return identity
            .authenticate_headers(
                headers,
                IdentityContext {
                    deadline,
                    cancellation,
                },
            )
            .await
            .map(Some)
            .map_err(identity_error);
    }
    if authorized(bootstrap, headers) {
        Ok(None)
    } else {
        Err(error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "valid bearer token required",
        ))
    }
}
fn identity_error(error_value: IdentityError) -> Response {
    match error_value {
        IdentityError::InvalidCredential => error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "valid bearer token required",
        ),
        IdentityError::Denied => {
            error(StatusCode::FORBIDDEN, "forbidden", "identity access denied")
        }
        IdentityError::Busy => error(
            StatusCode::TOO_MANY_REQUESTS,
            "full",
            "identity capacity is full",
        ),
        IdentityError::Timeout => error(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "identity deadline exceeded",
        ),
        _ => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "identity backend unavailable",
        ),
    }
}
pub fn error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({"schema_version": API_SCHEMA_VERSION,
        "error": {"code": code, "message": message}})),
    )
        .into_response()
}
pub struct CancelOnDrop(pub CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[derive(Clone)]
struct Protected {
    identity: IdentityBackend,
    timeout: Duration,
    stopping: CancellationToken,
}
/// Coverage identity binding is not qualified yet. Authenticate freshly, then
/// deny forwarding into the legacy route rather than inferring another capability.
pub fn protect_unbound_routes(
    router: Router,
    identity: IdentityBackend,
    timeout: Duration,
    stopping: CancellationToken,
) -> Router {
    router.route_layer(middleware::from_fn_with_state(
        Protected {
            identity,
            timeout,
            stopping,
        },
        unbound,
    ))
}
async fn unbound(State(state): State<Protected>, request: Request, _next: Next) -> Response {
    let deadline = Instant::now() + state.timeout;
    let cancellation = state.stopping.child_token();
    let _guard = CancelOnDrop(cancellation.clone());
    let result = state
        .identity
        .authenticate_headers(
            request.headers(),
            IdentityContext {
                deadline,
                cancellation,
            },
        )
        .await;
    let mut response = match result {
        Ok(_) => error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "scoped route contract unavailable",
        ),
        Err(error) => identity_error(error),
    };
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"endpoint":"https://identity.example.test/token",
            "client_id":"synthetic-client","issuer":"https://identity.example.test",
            "audience":"signal","lease_seconds":30,"workers":2,"request_timeout_ms":1000,
            "policy":{"schema_version":1,"roles":[],"bindings":[]}})
    }
    #[test]
    fn bounded_private_configuration_preserves_strict_nested_policy_and_redaction() {
        let valid = document().to_string();
        assert!(Configuration::parse(&valid, "synthetic-secret".into()).is_ok());
        let mut bad = vec![
            String::new(),
            "[]".into(),
            "null".into(),
            format!("[{valid}]"),
            " ".repeat(CONFIG_BYTES + 1),
            valid.replacen(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
                1,
            ),
            valid.replace("\"bindings\":[]", "\"bindings\":[],\"bindings\":[]"),
        ];
        for (field, value) in [
            ("schema_version", serde_json::json!(2)),
            ("workers", serde_json::json!(0)),
            ("workers", serde_json::json!(17)),
            ("request_timeout_ms", serde_json::json!(30001)),
            ("lease_seconds", serde_json::json!(301)),
            ("roots_der_base64", serde_json::json!(["invalid!"])),
            ("roots_der_base64", serde_json::json!(vec!["AA=="; 9])),
            (
                "roots_der_base64",
                serde_json::json!([STANDARD.encode(vec![0; 16385])]),
            ),
            ("policy", serde_json::json!([])),
            ("unexpected", serde_json::json!("private-value")),
        ] {
            let mut wire = document();
            wire[field] = value;
            bad.push(wire.to_string());
        }
        for text in bad {
            let Err(e) = Configuration::parse(&text, "synthetic-secret".into()) else {
                panic!("accepted invalid private configuration");
            };
            assert!(!format!("{e:?} {e}").contains("synthetic-secret"));
            assert!(!format!("{e:?} {e}").contains("private-value"));
        }
    }
}
