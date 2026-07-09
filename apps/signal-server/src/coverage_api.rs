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
use signal_ingest::{IngestConfig, authorized};
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
    token_env: String,
    max_report_age_seconds: u32,
    max_clock_skew_seconds: u32,
    payload_retention_seconds: u32,
    identity_retention_seconds: u32,
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
    auth: IngestConfig,
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
        let configuration = Self::validate(wire, |name| settings.secret_environment(name))?;
        if let Some(token) = settings.optional("SIGNAL_API_TOKEN")?
            && configuration
                .scopes
                .iter()
                .any(|scope| scope.auth.api_token.as_deref() == Some(&token))
        {
            return Err(ConfigError::Invalid(
                "coverage credential must differ from API token",
            ));
        }
        Ok(Some(configuration))
    }
    fn validate(
        wire: Wire,
        secret: impl Fn(&str) -> Result<String, ConfigError>,
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
            let token = secret(&wire.token_env)?;
            // A bounded, unique token authenticates precisely one whole binding.
            if token.len() < 16
                || token.len() > 4096
                || !token.bytes().all(|b| b.is_ascii_graphic())
                || scopes.iter().any(|s| {
                    s.auth.api_token.as_deref() == Some(&token)
                        || s.binding.encoded() == binding.encoded()
                })
            {
                return Err(ConfigError::Invalid("coverage unique credential/binding"));
            }
            scopes.push(Scope {
                binding,
                profile,
                revision,
                policy,
                auth: IngestConfig {
                    api_token: Some(token),
                    ..Default::default()
                },
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
    pub async fn open(
        self,
        timeout: Duration,
        stopping: CancellationToken,
    ) -> Result<Arc<CoverageState>, CoverageError> {
        let store = Arc::new(CoverageStore::open(self.store).await?);
        Ok(Arc::new(CoverageState {
            store,
            scopes: self.scopes,
            timeout: timeout.min(Duration::from_secs(10)),
            stopping,
            requests: Semaphore::new(REQUEST_CAPACITY),
            rejected: AtomicU64::new(0),
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
}
impl CoverageState {
    fn scope(&self, headers: &HeaderMap) -> Option<&Scope> {
        // Ambiguous duplicate credentials are never accepted by this boundary.
        if headers.get_all("authorization").iter().count() != 1 {
            return None;
        }
        self.scopes
            .iter()
            .find(|scope| authorized(&scope.auth, headers))
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
fn grant(scope: &Scope) -> Result<AuthorizedBinding, CoverageError> {
    AuthorizedBinding::new(
        scope.binding.observer_id(),
        scope.binding.clone(),
        scope.revision.clone(),
    )
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
async fn record(State(state): State<Arc<CoverageState>>, request: Request) -> Response {
    if state.stopping.is_cancelled() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "stopping");
    }
    let Some(scope) = state.scope(request.headers()) else {
        state.rejected.fetch_add(1, Ordering::Relaxed);
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let Ok(_permit) = state.requests.try_acquire() else {
        state.rejected.fetch_add(1, Ordering::Relaxed);
        return error(StatusCode::TOO_MANY_REQUESTS, "capacity");
    };
    let cancellation = state.stopping.child_token();
    let _guard = CancelOnDrop(cancellation.clone());
    let context = OperationContext {
        deadline: Instant::now() + state.timeout,
        cancellation,
    };
    let result = handle_record(&state, scope, request, context).await;
    match result {
        Ok(response) => response,
        Err(e) => {
            state.rejected.fetch_add(1, Ordering::Relaxed);
            failure(e)
        }
    }
}
async fn handle_record(
    state: &CoverageState,
    scope: &Scope,
    request: Request,
    context: OperationContext,
) -> Result<Response, CoverageError> {
    let id = uuid(
        request
            .uri()
            .path()
            .rsplit('/')
            .next()
            .ok_or(CoverageError::Invalid("record ID"))?,
    )?;
    let authority = grant(scope)?;
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
            _ = tokio::time::sleep_until(context.deadline) => return Err(CoverageError::Timeout),
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
    if state.stopping.is_cancelled() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "stopping");
    }
    let Some(scope) = state.scope(request.headers()) else {
        state.rejected.fetch_add(1, Ordering::Relaxed);
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    let Ok(_permit) = state.requests.try_acquire() else {
        state.rejected.fetch_add(1, Ordering::Relaxed);
        return error(StatusCode::TOO_MANY_REQUESTS, "capacity");
    };
    let cancellation = state.stopping.child_token();
    let _guard = CancelOnDrop(cancellation.clone());
    let context = OperationContext {
        deadline: Instant::now() + state.timeout,
        cancellation,
    };
    let result = handle_history(&state, scope, request, context).await;
    match result {
        Ok(response) => response,
        Err(e) => {
            state.rejected.fetch_add(1, Ordering::Relaxed);
            failure(e)
        }
    }
}
async fn handle_history(
    state: &CoverageState,
    scope: &Scope,
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
            grant(scope)?,
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
    if state.stopping.is_cancelled() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "stopping");
    }
    if state.scope(request.headers()).is_none() {
        state.rejected.fetch_add(1, Ordering::Relaxed);
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if request.uri().query().is_some() {
        return error(StatusCode::BAD_REQUEST, "invalid_query");
    }
    let m = state.store.metrics();
    // Aggregate bounds only, no record identity, binding, profile, token or source payload.
    response(
        StatusCode::OK,
        serde_json::json!({"schema_version":1,"current_health":"unknown",
        "available":m.available,"http_in_flight":REQUEST_CAPACITY-state.requests.available_permits(),"http_capacity":REQUEST_CAPACITY,"operations_in_flight":m.operations_in_flight,"operation_capacity":m.operation_capacity,
        "command_depth":m.command_depth,"command_capacity":m.command_capacity,"payloads":m.payloads,"payload_capacity":m.payload_capacity,
        "identities":m.identities,"identity_capacity":m.identity_capacity,"ledger_bytes":m.ledger_bytes,"ledger_capacity":m.ledger_capacity,
        "accepted":m.accepted,"replayed":m.replayed,"store_rejected":m.rejected,"http_rejected":state.rejected.load(Ordering::Relaxed),"timeouts":m.timeouts,"failures":m.failures}),
    )
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
