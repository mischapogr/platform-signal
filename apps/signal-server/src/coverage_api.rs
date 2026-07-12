//! Scoped durable coverage intake/history. API admission is no source-health proof.
use crate::config::{self, ConfigError, Settings};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use signal_coverage::{
    AuthorizedBinding, CoverageConfig, CoverageError, CoverageStore, CoverageSubmission,
    IntakeContext, IntakeOutcome, IntakePolicy, OperationContext, Receipt, ScanBudget, ScanCursor,
    format::{HistoryBinding, MAX_RAW_BYTES, ProfileDefinition, Timestamp},
};
use signal_ingest::{IngestConfig, authorized, identity::IdentityBackend};
use signal_protocol::access::{Operation as AccessOperation, RequestGrant, ScopeFacts};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Semaphore, time::Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_SCOPES: usize = 32;
const RESPONSE_BYTES: usize = 524_288;
const QUERY_BYTES: usize = 16_384;
const REQUEST_CAPACITY: usize = 4;

// Configuration names/policies remain deployment-owned. Tokens resolve only from
// explicitly named environment variables and have no Debug/serialization path.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: u16,
    directory: String,
    limits: Limits,
    scopes: Vec<ScopeWire>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_payloads: u64,
    max_identities: u64,
    max_bindings: u64,
    max_ledger_bytes: u64,
    max_database_pages: u32,
    max_journal_bytes: u64,
    operation_capacity: usize,
    transient_memory_bytes: u64,
    worker_memory_bytes: u64,
    max_vm_steps: u64,
    operation_timeout_ms: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeWire {
    binding_json: String,
    // Explicit null retires new admissions; exact retained replay remains possible.
    #[serde(deserialize_with = "required_profile")]
    profile_json: Option<String>,
    authority_revision: String,
    #[serde(default)]
    token_env: Option<String>,
    #[serde(default)]
    identity: Option<IdentityScopeWire>,
    max_report_age_seconds: u32,
    max_clock_skew_seconds: u32,
    payload_retention_seconds: u32,
    identity_retention_seconds: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityScopeWire {
    scope_id: String,
    #[serde(deserialize_with = "required_account")]
    account_id: Option<String>,
    writer_issuer: String,
    writer_subject: String,
}
fn required_account<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}
enum ScopeAuth {
    Legacy(IngestConfig),
    Native(IdentityScopeWire),
}
impl ScopeAuth {
    fn legacy_token(&self) -> Option<&str> {
        match self {
            Self::Legacy(config) => config.api_token.as_deref(),
            Self::Native(_) => None,
        }
    }
}
fn private_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn required_profile<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}
struct Scope {
    binding: HistoryBinding,
    profile: Option<ProfileDefinition>,
    revision: String,
    policy: IntakePolicy,
    auth: ScopeAuth,
}
pub struct Configuration {
    store: CoverageConfig,
    scopes: Vec<Scope>,
}
impl Configuration {
    pub async fn load(settings: &Settings) -> Result<Option<Self>, ConfigError> {
        let Some(path) = settings.optional("SIGNAL_COVERAGE_CONFIG")? else {
            return Ok(None);
        };
        let wire: Wire = config::read_document(
            path.into(),
            Instant::now() + Duration::from_secs(5),
            CancellationToken::new(),
            |text| {
                if text.is_empty() || text.len() > 65_536 {
                    return Err(ConfigError::Invalid("coverage configuration byte bound"));
                }
                serde_json::from_str(text)
                    .map_err(|_| ConfigError::Invalid("coverage configuration schema"))
            },
        )
        .await?;
        let configuration = Self::validate_mode(
            wire,
            |name| settings.secret_environment(name),
            settings.optional("SIGNAL_ACCESS_CONFIG")?.is_some(),
        )?;
        if let Some(token) = settings.optional("SIGNAL_API_TOKEN")?
            && configuration
                .scopes
                .iter()
                .any(|scope| scope.auth.legacy_token() == Some(token.as_str()))
        {
            return Err(ConfigError::Invalid(
                "coverage credential must differ from API token",
            ));
        }
        Ok(Some(configuration))
    }
    #[cfg(test)]
    fn validate(
        wire: Wire,
        secret: impl Fn(&str) -> Result<String, ConfigError>,
    ) -> Result<Self, ConfigError> {
        Self::validate_mode(wire, secret, false)
    }
    fn validate_mode(
        wire: Wire,
        secret: impl Fn(&str) -> Result<String, ConfigError>,
        native: bool,
    ) -> Result<Self, ConfigError> {
        if wire.schema_version != 1 || wire.scopes.is_empty() || wire.scopes.len() > MAX_SCOPES {
            return Err(ConfigError::Invalid(
                "coverage configuration version/scopes",
            ));
        }
        let limits = wire.limits;
        let store = CoverageConfig {
            directory: wire.directory.into(),
            max_payloads: limits.max_payloads,
            max_identities: limits.max_identities,
            max_bindings: limits.max_bindings,
            max_ledger_bytes: limits.max_ledger_bytes,
            max_database_pages: limits.max_database_pages,
            max_journal_bytes: limits.max_journal_bytes,
            operation_capacity: limits.operation_capacity,
            transient_memory_bytes: limits.transient_memory_bytes,
            worker_memory_bytes: limits.worker_memory_bytes,
            max_vm_steps: limits.max_vm_steps,
            operation_timeout: Duration::from_millis(limits.operation_timeout_ms),
        };
        store
            .validate()
            .map_err(|_| ConfigError::Invalid("coverage store limits"))?;
        if wire.scopes.len() as u64 > store.max_bindings {
            return Err(ConfigError::Invalid("coverage scope capacity"));
        }
        let mut scopes: Vec<Scope> = Vec::new();
        for wire in wire.scopes {
            let binding = HistoryBinding::parse(wire.binding_json.as_bytes())
                .map_err(|_| ConfigError::Invalid("coverage binding"))?;
            if binding.encoded().len() > 6144 {
                return Err(ConfigError::Invalid("coverage HTTP binding/cursor budget"));
            }
            let profile = wire
                .profile_json
                .as_ref()
                .map(|text| ProfileDefinition::parse(text.as_bytes()))
                .transpose()
                .map_err(|_| ConfigError::Invalid("coverage profile"))?;
            if profile
                .as_ref()
                .is_some_and(|p| !binding.profile_matches(p))
            {
                return Err(ConfigError::Invalid("coverage binding/profile identity"));
            }
            let revision = wire.authority_revision;
            AuthorizedBinding::new(binding.observer_id(), binding.clone(), revision.clone())
                .map_err(|_| ConfigError::Invalid("coverage authority"))?;
            let policy = IntakePolicy::new(
                wire.max_report_age_seconds,
                wire.max_clock_skew_seconds,
                wire.payload_retention_seconds,
                wire.identity_retention_seconds,
            )
            .map_err(|_| ConfigError::Invalid("coverage intake policy"))?;
            let auth = match (native, wire.token_env, wire.identity) {
                (false, Some(name), None) => {
                    let token = secret(&name)?;
                    if token.len() < 16
                        || token.len() > 4096
                        || !token.bytes().all(|b| b.is_ascii_graphic())
                        || scopes
                            .iter()
                            .any(|scope| scope.auth.legacy_token() == Some(token.as_str()))
                    {
                        return Err(ConfigError::Invalid("coverage unique credential/binding"));
                    }
                    ScopeAuth::Legacy(IngestConfig {
                        api_token: Some(token),
                        ..Default::default()
                    })
                }
                (true, None, Some(mut identity)) => {
                    if identity.scope_id.is_empty() || identity.scope_id.len()>128
                        || !identity.scope_id.bytes().all(|b|b.is_ascii_alphanumeric() || b"._:-".contains(&b))
                        || !private_identifier(&identity.writer_issuer,2048)
                        || !private_identifier(&identity.writer_subject,256)
                        || identity.account_id.as_ref().is_some_and(|account| !private_identifier(account,256))
                        || !private_identifier(binding.source_id(),256)
                        || !private_identifier(binding.resource_id(),256)
                        || scopes.iter().any(|scope|matches!(&scope.auth,ScopeAuth::Native(other) if other.scope_id==identity.scope_id)) {
                        return Err(ConfigError::Invalid("coverage native identity/binding bounds"));
                    }
                    identity.scope_id = identity.scope_id.into_boxed_str().into_string();
                    identity.writer_issuer = identity.writer_issuer.into_boxed_str().into_string();
                    identity.writer_subject =
                        identity.writer_subject.into_boxed_str().into_string();
                    identity.account_id = identity
                        .account_id
                        .map(|value| value.into_boxed_str().into_string());
                    ScopeAuth::Native(identity)
                }
                _ => {
                    return Err(ConfigError::Invalid(
                        "coverage authentication mode conflict",
                    ));
                }
            };
            if scopes
                .iter()
                .any(|scope| scope.binding.encoded() == binding.encoded())
            {
                return Err(ConfigError::Invalid("coverage unique credential/binding"));
            }
            scopes.push(Scope {
                binding,
                profile,
                revision,
                policy,
                auth,
            });
        }
        // Fingerprint conflicts under one profile ID/revision fail before store opening.
        for a in &scopes {
            for b in &scopes {
                if let (Some(a), Some(b)) = (&a.profile, &b.profile)
                    && a.id() == b.id()
                    && a.revision() == b.revision()
                    && a.fingerprint() != b.fingerprint()
                {
                    return Err(ConfigError::Invalid("coverage profile revision conflict"));
                }
            }
        }
        Ok(Self { store, scopes })
    }
    pub async fn initialize(self) -> Result<(), CoverageError> {
        let store = CoverageStore::initialize(self.store, Uuid::new_v4(), now()?).await?;
        store
            .shutdown(OperationContext::new(Duration::from_secs(5)))
            .await
    }
    #[cfg(test)]
    pub async fn open(
        self,
        timeout: Duration,
        stopping: CancellationToken,
    ) -> Result<Arc<CoverageState>, CoverageError> {
        self.open_with_identity(timeout, stopping, None, None).await
    }
    pub async fn open_with_identity(
        self,
        timeout: Duration,
        stopping: CancellationToken,
        identity: Option<IdentityBackend>,
        audit: Option<Arc<crate::audit::Control>>,
    ) -> Result<Arc<CoverageState>, CoverageError> {
        if self
            .scopes
            .iter()
            .any(|scope| matches!(scope.auth, ScopeAuth::Native(_)))
            != identity.is_some()
        {
            return Err(CoverageError::Config(
                "coverage authentication mode conflict",
            ));
        }
        let store = Arc::new(CoverageStore::open(self.store).await?);
        Ok(Arc::new(CoverageState {
            store,
            scopes: self.scopes,
            timeout: timeout.min(Duration::from_secs(10)),
            stopping,
            requests: Semaphore::new(REQUEST_CAPACITY),
            rejected: AtomicU64::new(0),
            identity,
            audit,
        }))
    }
}
pub struct CoverageState {
    pub store: Arc<CoverageStore>,
    scopes: Vec<Scope>,
    timeout: Duration,
    stopping: CancellationToken,
    requests: Semaphore,
    rejected: AtomicU64,
    identity: Option<IdentityBackend>,
    audit: Option<Arc<crate::audit::Control>>,
}
impl CoverageState {
    fn scope(&self, headers: &HeaderMap) -> Option<&Scope> {
        // Ambiguous duplicate credentials are never accepted by this boundary.
        if headers.get_all("authorization").iter().count() != 1 {
            return None;
        }
        self.scopes.iter().find(
            |scope| matches!(&scope.auth,ScopeAuth::Legacy(config) if authorized(config,headers)),
        )
    }
    async fn authorize<'a>(
        &'a self,
        headers: &HeaderMap,
        operation: AccessOperation,
        aggregate: bool,
        context: &OperationContext,
        actor: &mut signal_protocol::audit::Actor,
    ) -> Result<ScopeAccess<'a>, Response> {
        if let Some(identity) = &self.identity {
            let grant = crate::access::authenticate(
                &IngestConfig::default(),
                Some(identity),
                headers,
                context.deadline,
                context.cancellation.clone(),
            )
            .await?
            .ok_or_else(|| error(StatusCode::FORBIDDEN, "forbidden"))?;
            *actor = crate::audit::actor(Some(&grant), false);
            if !crate::access::capable(&grant, operation) {
                return Err(error(StatusCode::FORBIDDEN, "forbidden"));
            }
            let mut values = headers.get_all("x-signal-coverage-scope").iter();
            let selector = values.next().and_then(|value| value.to_str().ok());
            if values.next().is_some() || selector.is_none_or(|id| id.is_empty() || id.len() > 128)
            {
                return Err(error(StatusCode::FORBIDDEN, "forbidden"));
            }
            let scope=self.scopes.iter().find(|scope|matches!(&scope.auth,ScopeAuth::Native(identity) if Some(identity.scope_id.as_str())==selector))
                .ok_or_else(||error(StatusCode::FORBIDDEN,"forbidden"))?;
            if !native_allowed(scope, &grant, operation, aggregate) {
                return Err(error(StatusCode::FORBIDDEN, "forbidden"));
            }
            let (start, end) = grant.lease_bounds();
            let authority = grant_binding(scope)
                .and_then(|binding| binding.with_lease(start, end))
                .map_err(failure)?;
            Ok(ScopeAccess {
                scope,
                request_grant: Some(grant),
                authority,
                operation,
                aggregate,
            })
        } else {
            let scope = self
                .scope(headers)
                .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "unauthorized"))?;
            *actor = signal_protocol::audit::Actor::Bootstrap {};
            let authority = grant_binding(scope).map_err(failure)?;
            Ok(ScopeAccess {
                scope,
                request_grant: None,
                authority,
                operation,
                aggregate,
            })
        }
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/v1/coverage/records/{record_id}", get(record).post(record))
            .route("/v1/coverage/history", get(history))
            .route("/v1/coverage/metrics", get(metrics))
            .with_state(self.clone())
    }
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
fn now() -> Result<Timestamp, CoverageError> {
    Timestamp::parse(&chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
}
fn grant_binding(scope: &Scope) -> Result<AuthorizedBinding, CoverageError> {
    AuthorizedBinding::new(
        scope.binding.observer_id(),
        scope.binding.clone(),
        scope.revision.clone(),
    )
}
struct ScopeAccess<'a> {
    scope: &'a Scope,
    request_grant: Option<RequestGrant>,
    authority: AuthorizedBinding,
    operation: AccessOperation,
    aggregate: bool,
}
fn native_allowed(
    scope: &Scope,
    grant: &RequestGrant,
    operation: AccessOperation,
    aggregate: bool,
) -> bool {
    let ScopeAuth::Native(identity) = &scope.auth else {
        return false;
    };
    let Some(at) = crate::access::now() else {
        return false;
    };
    if !grant.allows(
        operation,
        ScopeFacts {
            source: Some(scope.binding.source_id()),
            account: identity.account_id.as_deref(),
            resource: Some(scope.binding.resource_id()),
        },
        at,
    ) {
        return false;
    }
    if operation == AccessOperation::WriteCoverage
        && !grant.subject_matches(&identity.writer_issuer, &identity.writer_subject, at)
    {
        return false;
    }
    !aggregate || grant.scopes(operation, at).any(|scope| scope.is_all())
}
impl ScopeAccess<'_> {
    fn deadline(&self, original: Instant) -> Instant {
        self.authority
            .lease_deadline()
            .map_or(original, |lease| original.min(lease))
    }
    fn finish(&self, context: &OperationContext) -> Option<Response> {
        if context.cancellation.is_cancelled() {
            return Some(error(StatusCode::SERVICE_UNAVAILABLE, "stopping"));
        }
        if Instant::now() >= context.deadline {
            return Some(error(StatusCode::REQUEST_TIMEOUT, "timeout"));
        }
        if self
            .request_grant
            .as_ref()
            .is_some_and(|grant| !native_allowed(self.scope, grant, self.operation, self.aggregate))
            || self
                .authority
                .lease_deadline()
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Some(error(StatusCode::FORBIDDEN, "forbidden"));
        }
        None
    }
}
fn request_context(state: &CoverageState) -> OperationContext {
    OperationContext {
        deadline: Instant::now() + state.timeout,
        cancellation: state.stopping.child_token(),
    }
}
fn completed_response(
    access: &ScopeAccess<'_>,
    context: &OperationContext,
    result: Result<Response, CoverageError>,
    state: &CoverageState,
) -> Response {
    match result {
        Ok(response) => match access.finish(context) {
            None => response,
            Some(denial) => {
                state.rejected.fetch_add(1, Ordering::Relaxed);
                // A late denied POST response must not imply a definitely absent
                // write. Exact retry under fresh authority is the recovery path.
                if access.operation == AccessOperation::WriteCoverage
                    && response.status().is_success()
                {
                    failure(CoverageError::OutcomeUnknown)
                } else {
                    denial
                }
            }
        },
        Err(error) => {
            state.rejected.fetch_add(1, Ordering::Relaxed);
            failure(error)
        }
    }
}
fn response(status: StatusCode, value: impl Serialize) -> Response {
    let mut output = LimitedBytes {
        bytes: Vec::new(),
        limit: RESPONSE_BYTES,
    };
    if serde_json::to_writer(&mut output, &value).is_err() {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "response_limit");
    }
    (
        status,
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ],
        output.bytes,
    )
        .into_response()
}
fn error(status: StatusCode, code: &'static str) -> Response {
    (
        status,
        [("cache-control", "no-store")],
        Json(serde_json::json!({"schema_version":1,"error":{"code":code}})),
    )
        .into_response()
}
fn failure(error_value: CoverageError) -> Response {
    use CoverageError::*;
    let (status, code) = match error_value {
        NotAuthorized => (StatusCode::FORBIDDEN, "scope_denied"),
        Capacity | Quota => (StatusCode::TOO_MANY_REQUESTS, "capacity"),
        Timeout => (StatusCode::REQUEST_TIMEOUT, "deadline"),
        HistoryUnavailable | IdentityPruned => (StatusCode::GONE, "record_unavailable"),
        HistoryPruned(_) => (StatusCode::GONE, "history_pruned"),
        IdContentConflict | ProfileRevisionConflict | ReceiptMismatch | ClockRegression => {
            (StatusCode::CONFLICT, "conflict")
        }
        ReplayWindowExpired => (StatusCode::GONE, "replay_expired"),
        OutcomeUnknown => (StatusCode::SERVICE_UNAVAILABLE, "outcome_unknown"),
        Invalid(_)
        | Coverage(_)
        | InvalidCursor
        | InvalidCorrection(_)
        | CorrectionBindingMismatch
        | CorrectionTargetUnavailable
        | ReportTooOld => (StatusCode::BAD_REQUEST, "invalid_request"),
        ResponseLimit | ScanWorkLimit => (StatusCode::PAYLOAD_TOO_LARGE, "resource_limit"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    error(status, code)
}
fn query(raw: Option<&str>, allowed: &str) -> Result<Option<String>, CoverageError> {
    let raw = raw.unwrap_or("");
    if raw.len() > QUERY_BYTES {
        return Err(CoverageError::Invalid("URL bound"));
    }
    if raw.is_empty() {
        return Ok(None);
    }
    let bytes = raw.as_bytes();
    let mut i = 0;
    let mut decoded = Vec::new();
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(CoverageError::Invalid("URL encoding"));
            }
            decoded.push(
                u8::from_str_radix(&raw[i + 1..i + 3], 16)
                    .map_err(|_| CoverageError::Invalid("URL encoding"))?,
            );
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    std::str::from_utf8(&decoded).map_err(|_| CoverageError::Invalid("URL encoding"))?;
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(raw).map_err(|_| CoverageError::Invalid("URL schema"))?;
    if pairs.len() != 1 || pairs[0].0 != allowed || pairs[0].1.is_empty() {
        return Err(CoverageError::Invalid("URL schema"));
    }
    Ok(Some(
        pairs
            .into_iter()
            .next()
            .ok_or(CoverageError::Invalid("URL schema"))?
            .1,
    ))
}
fn uuid(value: &str) -> Result<Uuid, CoverageError> {
    let id = Uuid::parse_str(value).map_err(|_| CoverageError::Invalid("record ID"))?;
    if id.is_nil() || id.to_string() != value {
        return Err(CoverageError::Invalid("canonical record ID"));
    }
    Ok(id)
}
#[derive(Serialize)]
struct IntakeResponse {
    schema_version: u16,
    disposition: &'static str,
    receipt: Receipt,
    current_health: &'static str,
}
#[derive(Serialize)]
struct RecordResponse<'a> {
    schema_version: u16,
    receipt: &'a Receipt,
    raw: Option<&'a str>,
    profile_json: &'a str,
    current_health: &'static str,
}
#[derive(Clone, Copy)]
enum Route {
    Record,
    History,
    Metrics,
}
async fn record(State(state): State<Arc<CoverageState>>, request: Request) -> Response {
    access(state, request, Route::Record).await
}
async fn access(state: Arc<CoverageState>, request: Request, route: Route) -> Response {
    use signal_protocol::audit::{Actor, Decision};
    let context = request_context(&state);
    let _guard = CancelOnDrop(context.cancellation.clone());
    if state.stopping.is_cancelled() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "stopping");
    }
    let operation = if matches!(route, Route::Record) && request.method() == Method::POST {
        AccessOperation::WriteCoverage
    } else {
        AccessOperation::ReadCoverage
    };
    let mut actor = Actor::Unattributed {};
    let authorization = state
        .authorize(
            request.headers(),
            operation,
            matches!(route, Route::Metrics),
            &context,
            &mut actor,
        )
        .await;
    let decision = match &authorization {
        Ok(_) => Decision::Granted,
        Err(response)
            if matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ) =>
        {
            Decision::Denied
        }
        Err(_) => Decision::Unavailable,
    };
    if authorization.is_err() {
        state.rejected.fetch_add(1, Ordering::Relaxed);
    }
    let session = if let Some(audit) = state
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
            Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable"),
        }
    } else {
        None
    };
    let (response, access) = match authorization {
        Err(response) => (response, None),
        Ok(access) => {
            let response = execute(&state, &access, request, &context, route).await;
            (response, Some(access))
        }
    };
    if let Some(session) = session {
        if session
            .finish(crate::audit::completion(response.status(), decision))
            .await
            .is_err()
        {
            // A POST may already have a committed immutable receipt. Never roll
            // it back or claim audit uncertainty proves the write did not occur.
            return error(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable");
        }
        if let Some(access) = access.as_ref() {
            return post_audit_response(access, &context, response, &state);
        }
        if context.cancellation.is_cancelled() {
            return error(StatusCode::SERVICE_UNAVAILABLE, "stopping");
        }
        if Instant::now() >= context.deadline {
            return error(StatusCode::REQUEST_TIMEOUT, "timeout");
        }
    }
    response
}
fn post_audit_response(
    access: &ScopeAccess<'_>,
    context: &OperationContext,
    response: Response,
    state: &CoverageState,
) -> Response {
    if response.status().is_success() {
        completed_response(access, context, Ok(response), state)
    } else {
        // These static errors disclose no evidence. A prior uncertain write
        // must remain uncertain even if its authority expires during auditing.
        response
    }
}
async fn execute(
    state: &CoverageState,
    access: &ScopeAccess<'_>,
    request: Request,
    context: &OperationContext,
    route: Route,
) -> Response {
    let Ok(_permit) = state.requests.try_acquire() else {
        state.rejected.fetch_add(1, Ordering::Relaxed);
        return error(StatusCode::TOO_MANY_REQUESTS, "capacity");
    };
    if let Some(response) = access.finish(context) {
        state.rejected.fetch_add(1, Ordering::Relaxed);
        return response;
    }
    let result = match route {
        Route::Record => handle_record(state, access, request, context.clone()).await,
        Route::History => handle_history(state, access, request, context.clone()).await,
        Route::Metrics => handle_metrics(state, request),
    };
    completed_response(access, context, result, state)
}
async fn handle_record(
    state: &CoverageState,
    access: &ScopeAccess<'_>,
    request: Request,
    context: OperationContext,
) -> Result<Response, CoverageError> {
    let scope = access.scope;
    let id = uuid(
        request
            .uri()
            .path()
            .rsplit('/')
            .next()
            .ok_or(CoverageError::Invalid("record ID"))?,
    )?;
    let authority = access.authority.clone();
    if request.method() == Method::POST {
        let correction = query(request.uri().query(), "correction_of")?
            .map(|v| uuid(&v))
            .transpose()?;
        if request.headers().get_all("content-type").iter().count() != 1
            || request
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                != Some("application/json")
            || request.headers().contains_key("content-encoding")
        {
            return Err(CoverageError::Invalid("original JSON content type"));
        }
        let raw = tokio::select! {
            biased;
            _ = context.cancellation.cancelled() => return Err(CoverageError::Cancelled),
            _ = tokio::time::sleep_until(access.deadline(context.deadline)) => return Err(if Instant::now()>=context.deadline {CoverageError::Timeout} else {CoverageError::NotAuthorized}),
            raw = to_bytes(request.into_body(), MAX_RAW_BYTES) => raw.map_err(|_| CoverageError::Invalid("original body bound"))?,
        };
        let submission = CoverageSubmission::new(id, &raw, correction)?;
        let intake = IntakeContext::new(authority, now()?, scope.profile.clone(), scope.policy);
        let outcome = state.store.submit(submission, intake, context).await?;
        let (status, disposition, receipt) = match outcome {
            IntakeOutcome::Accepted(r) => (StatusCode::CREATED, "accepted", r),
            IntakeOutcome::Replayed(r) => (StatusCode::OK, "replayed", r),
        };
        return Ok(response(
            status,
            IntakeResponse {
                schema_version: 1,
                disposition,
                receipt,
                current_health: "unknown",
            },
        ));
    }
    if request.uri().query().is_some() {
        return Err(CoverageError::Invalid("record query"));
    }
    let record = state
        .store
        .get_authorized(id, authority, context)
        .await?
        .ok_or(CoverageError::HistoryUnavailable)?;
    let profile = record.profile.definition_bytes()?;
    let profile_json = std::str::from_utf8(&profile).map_err(|_| CoverageError::Unavailable)?;
    let raw = record
        .raw
        .as_deref()
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|_| CoverageError::Unavailable)?;
    Ok(response(
        StatusCode::OK,
        RecordResponse {
            schema_version: 1,
            receipt: &record.receipt,
            raw,
            profile_json,
            current_health: "unknown",
        },
    ))
}
#[derive(Serialize)]
struct ScanRow<'a> {
    receipt: &'a Receipt,
    raw: Option<&'a str>,
}
#[derive(Serialize)]
struct HistoryResponse<'a> {
    schema_version: u16,
    records: Vec<ScanRow<'a>>,
    continuation: Option<&'a str>,
    frontier: String,
    payload_pruned_through: String,
    identity_pruned_through: String,
    scanned_records: u64,
    scanned_bytes: u64,
    current_health: &'static str,
}
async fn history(State(state): State<Arc<CoverageState>>, request: Request) -> Response {
    access(state, request, Route::History).await
}
async fn handle_history(
    state: &CoverageState,
    access: &ScopeAccess<'_>,
    request: Request,
    context: OperationContext,
) -> Result<Response, CoverageError> {
    let cursor = query(request.uri().query(), "cursor")?
        .map(|v| ScanCursor::parse(&v))
        .transpose()?;
    let m = state.store.metrics();
    let page = state
        .store
        .scan(
            access.authority.clone(),
            cursor,
            ScanBudget {
                max_records: 1,
                max_response_bytes: signal_coverage::MAX_SCAN_RESPONSE_BYTES,
                max_scanned_records: m.identity_capacity.min(64),
                max_scanned_bytes: m.ledger_capacity.min(4_194_304),
            },
            context,
        )
        .await?;
    let mut records = Vec::new();
    for row in page.records() {
        records.push(ScanRow {
            receipt: &row.receipt,
            raw: row
                .raw
                .as_deref()
                .map(std::str::from_utf8)
                .transpose()
                .map_err(|_| CoverageError::Unavailable)?,
        });
    }
    let availability = page.availability();
    Ok(response(
        StatusCode::OK,
        HistoryResponse {
            schema_version: 1,
            records,
            continuation: page.continuation().map(ScanCursor::as_str),
            frontier: page.frontier().to_string(),
            payload_pruned_through: availability.payload_pruned_through.to_string(),
            identity_pruned_through: availability.identity_pruned_through.to_string(),
            scanned_records: page.scanned_records(),
            scanned_bytes: page.scanned_bytes(),
            current_health: "unknown",
        },
    ))
}
async fn metrics(State(state): State<Arc<CoverageState>>, request: Request) -> Response {
    access(state, request, Route::Metrics).await
}
fn handle_metrics(state: &CoverageState, request: Request) -> Result<Response, CoverageError> {
    if request.uri().query().is_some() {
        return Ok(error(StatusCode::BAD_REQUEST, "invalid_query"));
    }
    let m = state.store.metrics();
    // Aggregate bounds only, no record identity, binding, profile, token or source payload.
    let response = response(
        StatusCode::OK,
        serde_json::json!({"schema_version":1,"current_health":"unknown",
        "available":m.available,"http_in_flight":REQUEST_CAPACITY-state.requests.available_permits(),"http_capacity":REQUEST_CAPACITY,"operations_in_flight":m.operations_in_flight,"operation_capacity":m.operation_capacity,
        "command_depth":m.command_depth,"command_capacity":m.command_capacity,"payloads":m.payloads,"payload_capacity":m.payload_capacity,
        "identities":m.identities,"identity_capacity":m.identity_capacity,"ledger_bytes":m.ledger_bytes,"ledger_capacity":m.ledger_capacity,
        "accepted":m.accepted,"replayed":m.replayed,"store_rejected":m.rejected,"http_rejected":state.rejected.load(Ordering::Relaxed),"timeouts":m.timeouts,"failures":m.failures}),
    );
    Ok(response)
}
struct LimitedBytes {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for LimitedBytes {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("coverage response limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
mod tests;
