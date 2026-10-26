//! Opt-in Small SOC transport. Actor identity, exact originals and target
//! eligibility are independent; a durable backend receipt is never a write DTO.
mod config;
mod eligibility;
mod episode;
mod reference;
#[cfg(test)]
mod tests;
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
pub use config::Configuration;
use signal_findings::{
    FindingContext,
    cases::{
        CaseAuthority, CaseChange, CaseError, CaseInventoryAuthority, CaseRequest, CaseStore,
        CaseUtcWindow,
    },
};
use signal_ingest::{IngestConfig, identity::IdentityBackend};
use signal_protocol::{
    access::{Operation, RequestGrant},
    audit::{Decision, WorkflowTarget},
};
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

pub struct Host {
    namespace: Uuid,
    store: Arc<CaseStore>,
    registry: reference::Registry,
    directory: Option<Arc<eligibility::Directory>>,
    identity: IdentityBackend,
    audit: Arc<crate::audit::Control>,
    slots: Semaphore,
    capacity: usize,
    rejected: AtomicU64,
    timeout: Duration,
    response_bytes: usize,
    stopping: CancellationToken,
}
#[derive(Clone, Copy)]
enum Route {
    Create,
    Assign,
    Detail,
    History,
    List,
    Evidence,
}
impl Route {
    fn operation(self) -> Operation {
        match self {
            Self::Create => Operation::CreateCases,
            Self::Assign => Operation::AssignCases,
            Self::Detail | Self::History | Self::List => Operation::ReadCases,
            Self::Evidence => Operation::ReadEvidence,
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum Failure {
    Invalid,
    Denied,
    Unavailable,
    Capacity,
    Conflict,
    Timeout,
}
impl From<CaseError> for Failure {
    fn from(e: CaseError) -> Self {
        match e {
            CaseError::Invalid => Self::Invalid,
            CaseError::Forbidden | CaseError::NotFound => Self::Denied,
            CaseError::Capacity => Self::Capacity,
            CaseError::Conflict => Self::Conflict,
            CaseError::Timeout => Self::Timeout,
            _ => Self::Unavailable,
        }
    }
}
impl Failure {
    fn response(self) -> Response {
        let (status, code) = match self {
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_case_request"),
            Self::Denied => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "reconciliation_required"),
            Self::Capacity => (StatusCode::TOO_MANY_REQUESTS, "capacity_exhausted"),
            Self::Conflict => (StatusCode::CONFLICT, "case_conflict"),
            Self::Timeout => (StatusCode::REQUEST_TIMEOUT, "request_timeout"),
        };
        crate::access::error(
            status,
            code,
            "case response unavailable; reconcile writes with the same intent when applicable",
        )
    }
}
fn check(context: &FindingContext) -> Result<(), Failure> {
    if context.cancellation.is_cancelled() {
        Err(Failure::Unavailable)
    } else if Instant::now() >= context.deadline {
        Err(Failure::Timeout)
    } else {
        Ok(())
    }
}
impl Host {
    pub fn metrics(&self) -> signal_protocol::CaseSinkMetrics {
        let physical = self.store.metrics();
        let (shared_file_depth, shared_file_capacity, shared_file_rejected) =
            crate::config::file_worker_metrics();
        signal_protocol::CaseSinkMetrics {
            request_depth: self.capacity - self.slots.available_permits(),
            request_capacity: self.capacity,
            request_rejected: self.rejected.load(Ordering::Relaxed),
            physical_depth: physical.depth,
            physical_capacity: physical.capacity,
            physical_rejected: physical.rejections,
            shared_file_depth,
            shared_file_capacity,
            shared_file_rejected,
            closed: physical.closed || self.stopping.is_cancelled(),
        }
    }
    pub fn stop_admission(&self) {
        self.stopping.cancel();
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/v1/cases", get(list).post(create))
            .route("/v1/cases/{case_id}", get(detail))
            .route("/v1/cases/{case_id}/history", get(history))
            .route("/v1/cases/{case_id}/assignment", post(assign))
            .route(
                "/v1/cases/{case_id}/evidence/{stream_id}/{finding_id}",
                get(evidence),
            )
            .with_state(self.clone())
    }
    pub async fn stop(&self, context: FindingContext) -> Result<(), CaseError> {
        self.stopping.cancel();
        self.store.stop(context).await
    }
    fn inventory_authority(
        &self,
        actor: &str,
        grant: &RequestGrant,
        context: &FindingContext,
    ) -> Result<CaseInventoryAuthority, Failure> {
        let (from, until) = grant.lease_bounds();
        Ok(CaseInventoryAuthority::new_bounded(
            self.namespace,
            actor.into(),
            context.clone(),
            CaseUtcWindow::new(from, until)?,
        )?)
    }
    async fn authenticate(
        &self,
        headers: &axum::http::HeaderMap,
        context: &FindingContext,
    ) -> Result<RequestGrant, Response> {
        crate::access::authenticate(
            &IngestConfig::default(),
            Some(&self.identity),
            headers,
            context.deadline,
            context.cancellation.clone(),
        )
        .await?
        .ok_or_else(|| Failure::Denied.response())
    }
}
async fn create(State(host): State<Arc<Host>>, request: Request) -> Response {
    run(host, request, Route::Create).await
}
async fn assign(State(host): State<Arc<Host>>, request: Request) -> Response {
    run(host, request, Route::Assign).await
}
async fn detail(State(host): State<Arc<Host>>, request: Request) -> Response {
    run(host, request, Route::Detail).await
}
async fn history(State(host): State<Arc<Host>>, request: Request) -> Response {
    run(host, request, Route::History).await
}
async fn list(State(host): State<Arc<Host>>, request: Request) -> Response {
    run(host, request, Route::List).await
}
async fn evidence(State(host): State<Arc<Host>>, request: Request) -> Response {
    run(host, request, Route::Evidence).await
}

enum Action {
    Write(CaseRequest),
    Read {
        case_id: Uuid,
        after: Option<u64>,
        limit: usize,
    },
    List,
    Evidence {
        case_id: Uuid,
        reference: signal_findings::disposition::FindingReference,
    },
}
struct Plan {
    action: Action,
    inventories: Vec<(Uuid, reference::Inventory)>,
    eligibility: Option<eligibility::TargetLease>,
    target: WorkflowTarget,
}
impl Plan {
    fn authorize(&self, grant: &RequestGrant, operation: Operation) -> Result<(), Failure> {
        if let Action::Evidence { reference, .. } = self.action {
            let (_, inventory) = self.inventories.first().ok_or(Failure::Unavailable)?;
            inventory.authorize(grant, Operation::ReadCases)?;
            return inventory.authorize_reference(grant, Operation::ReadEvidence, reference);
        }
        for (_, inventory) in &self.inventories {
            inventory.authorize(grant, operation)?;
        }
        if let (Action::Write(request), Some(lease)) = (&self.action, &self.eligibility) {
            let (_, inventory) = self.inventories.first().ok_or(Failure::Unavailable)?;
            lease.check(request, inventory)?;
        }
        Ok(())
    }
}
async fn decode(
    request: Request,
    route: Route,
    context: &FindingContext,
) -> Result<Action, Failure> {
    let raw_query = request.uri().query().unwrap_or("");
    if raw_query.len() > 128 {
        return Err(Failure::Invalid);
    }
    match route {
        Route::Evidence => {
            if !raw_query.is_empty() {
                return Err(Failure::Invalid);
            }
            let parse = |position| {
                request
                    .uri()
                    .path()
                    .split('/')
                    .nth(position)
                    .filter(|s| s.len() == 36)
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .filter(|id| !id.is_nil())
                    .ok_or(Failure::Invalid)
            };
            Ok(Action::Evidence {
                case_id: path_id(&request)?,
                reference: signal_findings::disposition::FindingReference {
                    stream_id: parse(5)?,
                    finding_id: parse(6)?,
                },
            })
        }
        Route::Create | Route::Assign => {
            if !raw_query.is_empty() {
                return Err(Failure::Invalid);
            }
            let path_id = if matches!(route, Route::Assign) {
                Some(path_id(&request)?)
            } else {
                None
            };
            let body = tokio::select! { biased;
                () = context.cancellation.cancelled() => return Err(Failure::Unavailable),
                body = tokio::time::timeout_at(context.deadline, to_bytes(request.into_body(), 32 * 1024)) =>
                    body.map_err(|_| Failure::Timeout)?.map_err(|_| Failure::Invalid)?,
            };
            let request: CaseRequest =
                serde_json::from_slice(&body).map_err(|_| Failure::Invalid)?;
            request.validate()?;
            if !matches!(
                (&request.change, route),
                (CaseChange::Create { .. }, Route::Create)
                    | (CaseChange::Assign { .. }, Route::Assign)
            ) || path_id.is_some_and(|id| id != request.case_id)
            {
                return Err(Failure::Invalid);
            }
            Ok(Action::Write(request))
        }
        Route::List => {
            if raw_query.is_empty() {
                Ok(Action::List)
            } else {
                Err(Failure::Invalid)
            }
        }
        Route::Detail | Route::History => {
            let mut after = None;
            let mut limit = 50;
            if matches!(route, Route::History) {
                after = Some(0);
                let values: Vec<(String, String)> =
                    serde_urlencoded::from_str(raw_query).map_err(|_| Failure::Invalid)?;
                let mut seen = std::collections::BTreeSet::new();
                for (key, value) in values {
                    if !seen.insert(key.clone())
                        || value.is_empty()
                        || !value.bytes().all(|b| b.is_ascii_digit())
                    {
                        return Err(Failure::Invalid);
                    }
                    match key.as_str() {
                        "after_revision" => {
                            after = Some(value.parse().map_err(|_| Failure::Invalid)?)
                        }
                        "limit" => limit = value.parse().map_err(|_| Failure::Invalid)?,
                        _ => return Err(Failure::Invalid),
                    }
                }
            } else if !raw_query.is_empty() {
                return Err(Failure::Invalid);
            }
            if !(1..=100).contains(&limit) || after.is_some_and(|a| a >= 1_000_000) {
                return Err(Failure::Invalid);
            }
            Ok(Action::Read {
                case_id: path_id(&request)?,
                after,
                limit,
            })
        }
    }
}
fn path_id(request: &Request) -> Result<Uuid, Failure> {
    let text = request
        .uri()
        .path()
        .split('/')
        .nth(3)
        .ok_or(Failure::Invalid)?;
    if text.len() != 36 {
        return Err(Failure::Invalid);
    }
    Uuid::parse_str(text)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or(Failure::Invalid)
}
async fn prepare(
    host: &Host,
    action: Action,
    grant: &RequestGrant,
    actor: &str,
    operation: Operation,
    context: &FindingContext,
) -> Result<Plan, Failure> {
    check(context)?;
    let mut inventories = Vec::new();
    let target = match &action {
        Action::Evidence { case_id, reference } => {
            let entry = host
                .store
                .reference_inventory(
                    host.inventory_authority(actor, grant, context)?,
                    *case_id,
                    context.clone(),
                )
                .await?;
            let inventory = host.registry.resolve(entry.references(), context).await?;
            inventory.authorize(grant, Operation::ReadCases)?;
            inventory.authorize_reference(grant, Operation::ReadEvidence, *reference)?;
            inventories.push((*case_id, inventory));
            WorkflowTarget::CaseEvidence {
                namespace: host.namespace,
                case_id: *case_id,
                stream_id: reference.stream_id,
                finding_id: reference.finding_id,
            }
        }
        Action::Write(request) => {
            let references = match &request.change {
                CaseChange::Create { references, .. } => references.clone(),
                CaseChange::Assign { .. } => host
                    .store
                    .reference_inventory(
                        host.inventory_authority(actor, grant, context)?,
                        request.case_id,
                        context.clone(),
                    )
                    .await?
                    .references()
                    .to_vec(),
            };
            let inventory = host.registry.resolve(&references, context).await?;
            inventory.authorize(grant, operation)?;
            inventories.push((request.case_id, inventory));
            WorkflowTarget::CaseMutation {
                namespace: host.namespace,
                case_id: request.case_id,
                intent_id: request.operation_id,
                expected_revision: request.expected_revision,
            }
        }
        Action::Read { case_id, .. } => {
            let entry = host
                .store
                .reference_inventory(
                    host.inventory_authority(actor, grant, context)?,
                    *case_id,
                    context.clone(),
                )
                .await?;
            let inventory = host.registry.resolve(entry.references(), context).await?;
            inventory.authorize(grant, operation)?;
            inventories.push((*case_id, inventory));
            WorkflowTarget::Case {
                namespace: host.namespace,
                case_id: *case_id,
            }
        }
        Action::List => {
            // First-version full bounded scan: no raw snapshot cursor or denied
            // count escapes. Refuse a larger inventory, never return false-empty.
            let page = host
                .store
                .inventory_page(
                    host.inventory_authority(actor, grant, context)?,
                    None,
                    None,
                    100,
                    context.clone(),
                )
                .await?;
            if page.has_more() {
                return Err(Failure::Capacity);
            }
            for entry in page.entries() {
                let inventory = host.registry.resolve(entry.references(), context).await?;
                match inventory.authorize(grant, operation) {
                    Ok(()) => inventories.push((entry.case_id(), inventory)),
                    Err(Failure::Denied) => (),
                    Err(e) => return Err(e),
                }
            }
            WorkflowTarget::Namespace {
                namespace: host.namespace,
            }
        }
    };
    let eligibility = if let Action::Write(request) = &action {
        if let CaseChange::Assign {
            assignee: Some(target),
        } = &request.change
        {
            let directory = host.directory.as_ref().ok_or(Failure::Denied)?;
            let (_, inventory) = inventories.first().ok_or(Failure::Unavailable)?;
            Some(
                directory
                    .verify_target(target, request, inventory, context)
                    .await?,
            )
        } else {
            None
        }
    } else {
        None
    };
    Ok(Plan {
        action,
        inventories,
        eligibility,
        target,
    })
}

async fn run(host: Arc<Host>, request: Request, route: Route) -> Response {
    let mut context = FindingContext {
        deadline: Instant::now() + host.timeout,
        cancellation: host.stopping.child_token(),
    };
    let _guard = context.cancellation.clone().drop_guard();
    let Ok(_permit) = host.slots.try_acquire() else {
        host.rejected.fetch_add(1, Ordering::Relaxed);
        return Failure::Capacity.response();
    };
    let headers = request.headers().clone();
    let operation = route.operation();
    let grant = match host.authenticate(&headers, &context).await {
        Ok(grant) => grant,
        Err(response) => {
            return denied_audit(&host, None, operation, response, &context).await;
        }
    };
    let Some(now) = crate::access::now() else {
        return Failure::Unavailable.response();
    };
    let (from, until) = grant.lease_bounds();
    if now < from || now >= until {
        return Failure::Denied.response();
    }
    context.deadline = context
        .deadline
        .min(Instant::now() + Duration::from_secs(until - now));
    if !crate::access::capable(&grant, operation)
        || !crate::access::capable(&grant, Operation::ReadFindings)
    {
        return denied_audit(
            &host,
            Some(&grant),
            operation,
            Failure::Denied.response(),
            &context,
        )
        .await;
    }
    let Some(actor) = crate::access::now().and_then(|at| grant.audit_subject_key(at)) else {
        return Failure::Denied.response();
    };
    let plan = match decode(request, route, &context).await {
        Ok(action) => prepare(&host, action, &grant, &actor, operation, &context).await,
        Err(e) => Err(e),
    };
    let plan = match plan {
        Ok(plan) => plan,
        Err(e) => {
            return denied_audit(&host, Some(&grant), operation, e.response(), &context).await;
        }
    };
    let session = match host
        .audit
        .begin_workflow(
            crate::audit::actor(Some(&grant), false),
            Decision::Granted,
            operation,
            plan.target.clone(),
            context.deadline,
            context.cancellation.clone(),
        )
        .await
    {
        Ok(session) => session,
        Err(_) => return Failure::Unavailable.response(),
    };
    // Decision auditing is physical I/O too. A current refusal discovered after
    // it must precede mutation; the original grant/eligibility lease still caps
    // the backend proof and is never renewed by this refresh.
    let result = match refresh(&host, &plan, &headers, &actor, operation, &context).await {
        Ok(()) => execute(&host, &plan, &grant, &actor, &context).await,
        Err(e) => Err(e),
    };
    let result = match result {
        Ok(response) => match refresh(&host, &plan, &headers, &actor, operation, &context).await {
            Ok(()) => Ok(response),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    let response = result.unwrap_or_else(Failure::response);
    if session
        .finish(crate::audit::completion(
            response.status(),
            Decision::Granted,
        ))
        .await
        .is_err()
    {
        return Failure::Unavailable.response();
    }
    // Completing a durable audit can itself block. Its success cannot renew
    // identity, target status or provider availability for response delivery.
    if response.status().is_success()
        && refresh(&host, &plan, &headers, &actor, operation, &context)
            .await
            .is_err()
    {
        return Failure::Unavailable.response();
    }
    if check(&context).is_err() || plan.authorize(&grant, operation).is_err() {
        return Failure::Unavailable.response();
    }
    response
}
async fn denied_audit(
    host: &Host,
    grant: Option<&RequestGrant>,
    operation: Operation,
    response: Response,
    context: &FindingContext,
) -> Response {
    let decision = if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        Decision::Denied
    } else {
        Decision::Unavailable
    };
    let session = host
        .audit
        .begin_workflow(
            crate::audit::actor(grant, false),
            decision,
            operation,
            WorkflowTarget::Namespace {
                namespace: host.namespace,
            },
            context.deadline,
            context.cancellation.clone(),
        )
        .await;
    if let Ok(session) = session
        && session
            .finish(crate::audit::completion(response.status(), decision))
            .await
            .is_ok()
    {
        return response;
    }
    Failure::Unavailable.response()
}
async fn refresh(
    host: &Host,
    plan: &Plan,
    headers: &axum::http::HeaderMap,
    actor: &str,
    operation: Operation,
    context: &FindingContext,
) -> Result<(), Failure> {
    check(context)?;
    let current = host
        .authenticate(headers, context)
        .await
        .map_err(|_| Failure::Unavailable)?;
    if crate::access::now()
        .and_then(|at| current.audit_subject_key(at))
        .as_deref()
        != Some(actor)
    {
        return Err(Failure::Denied);
    }
    plan.authorize(&current, operation)?;
    for (_, old) in &plan.inventories {
        let fresh = host.registry.resolve(&old.references, context).await?;
        if fresh.digest != old.digest {
            return Err(Failure::Unavailable);
        }
        if let Action::Evidence { reference, .. } = plan.action {
            fresh.authorize(&current, Operation::ReadCases)?;
            fresh.authorize_reference(&current, Operation::ReadEvidence, reference)?;
        } else {
            fresh.authorize(&current, operation)?;
        }
    }
    if let Action::Write(request) = &plan.action
        && let CaseChange::Assign {
            assignee: Some(target),
        } = &request.change
    {
        let directory = host.directory.as_ref().ok_or(Failure::Denied)?;
        let (_, inventory) = plan.inventories.first().ok_or(Failure::Unavailable)?;
        directory
            .verify_target(target, request, inventory, context)
            .await?
            .check(request, inventory)?;
    }
    check(context)
}
fn authority(
    host: &Host,
    plan: &Plan,
    grant: &RequestGrant,
    actor: &str,
    case_id: Uuid,
    inventory: &reference::Inventory,
    context: &FindingContext,
) -> Result<CaseAuthority, Failure> {
    let (mut from, mut until) = grant.lease_bounds();
    if let Some((provider_from, provider_until)) = inventory.bounds()? {
        from = from.max(provider_from);
        until = until.min(provider_until);
    }
    if let Some(target) = &plan.eligibility {
        from = from.max(target.not_before);
        until = until.min(target.expires_at);
    }
    let window = CaseUtcWindow::new(from, until)?;
    match &plan.action {
        Action::Write(request) => Ok(CaseAuthority::for_write_bounded(
            host.namespace,
            actor.into(),
            inventory.references.clone(),
            request,
            context.clone(),
            window,
        )?),
        _ => Ok(CaseAuthority::for_read_bounded(
            host.namespace,
            case_id,
            actor.into(),
            inventory.references.clone(),
            context.clone(),
            window,
        )?),
    }
}
async fn execute(
    host: &Host,
    plan: &Plan,
    grant: &RequestGrant,
    actor: &str,
    context: &FindingContext,
) -> Result<Response, Failure> {
    plan.authorize(
        grant,
        match plan.action {
            Action::Write(ref r) => match r.change {
                CaseChange::Create { .. } => Operation::CreateCases,
                _ => Operation::AssignCases,
            },
            Action::Evidence { .. } => Operation::ReadEvidence,
            _ => Operation::ReadCases,
        },
    )?;
    check(context)?;
    match &plan.action {
        Action::Evidence { case_id, reference } => {
            let (_, inventory) = plan.inventories.first().ok_or(Failure::Unavailable)?;
            host.store
                .head(
                    authority(host, plan, grant, actor, *case_id, inventory, context)?,
                    context.clone(),
                )
                .await?;
            let evidence = host.registry.evidence(*reference, context).await?;
            wire(
                &serde_json::json!({"schema_version":1,"reference":reference,"finding":evidence.finding,"episode":evidence.episode}),
                host.response_bytes,
            )
        }
        Action::Write(request) => {
            let (_, inventory) = plan.inventories.first().ok_or(Failure::Unavailable)?;
            let receipt = host
                .store
                .record(
                    authority(
                        host,
                        plan,
                        grant,
                        actor,
                        request.case_id,
                        inventory,
                        context,
                    )?,
                    request.clone(),
                    context.clone(),
                )
                .await?;
            wire(
                &serde_json::json!({"schema_version":1,"case_id":request.case_id,
                "operation_id":request.operation_id,"result_revision":receipt.record.head.revision,"replayed":receipt.replayed}),
                host.response_bytes,
            )
        }
        Action::Read {
            case_id,
            after,
            limit,
        } => {
            let (_, inventory) = plan.inventories.first().ok_or(Failure::Unavailable)?;
            let proof = authority(host, plan, grant, actor, *case_id, inventory, context)?;
            if let Some(after) = after {
                wire(
                    &host
                        .store
                        .history(proof, *after, *limit, context.clone())
                        .await?,
                    host.response_bytes,
                )
            } else {
                wire(
                    &host.store.head(proof, context.clone()).await?,
                    host.response_bytes,
                )
            }
        }
        Action::List => {
            let mut heads = Vec::with_capacity(plan.inventories.len());
            for (id, inventory) in &plan.inventories {
                heads.push(
                    host.store
                        .head(
                            authority(host, plan, grant, actor, *id, inventory, context)?,
                            context.clone(),
                        )
                        .await?,
                );
            }
            wire(
                &serde_json::json!({"schema_version":1,"cases":heads}),
                host.response_bytes,
            )
        }
    }
}
struct LimitedBytes {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for LimitedBytes {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("case response limit"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn wire(value: &impl serde::Serialize, limit: usize) -> Result<Response, Failure> {
    let mut writer = LimitedBytes {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| Failure::Capacity)?;
    Ok((
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
        ],
        writer.bytes,
    )
        .into_response())
}
