//! Explicit authenticated custody confirmation; HTTP202 keeps its WAL meaning.
use crate::shared_custody::ConfiguredCustodyVerifier;
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::Utc;
use signal_control::{
    ControlClient, ControlContext, ControlError, LeaseToken, ObjectCustodyDescription,
    coordinate_object_custody,
};
use signal_ingest::identity::{IdentityBackend, IdentityContext, IdentityError};
use signal_protocol::{
    access::{Operation, RequestGrant},
    object_custody::{CONFIRM_PATH, ConfirmRequest, Confirmation, WIRE_BYTES},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

pub struct CustodyApi {
    control: Arc<ControlClient>,
    token: LeaseToken,
    verifier: Arc<ConfiguredCustodyVerifier>,
    identity: IdentityBackend,
    stopping: CancellationToken,
    slots: Arc<Semaphore>,
    confirmed: AtomicU64,
    rejected: AtomicU64,
}
#[derive(Clone, Copy)]
pub struct CustodyApiMetrics {
    pub depth: usize,
    pub capacity: usize,
    pub confirmed: u64,
    pub rejected: u64,
    pub closed: bool,
}
impl CustodyApi {
    /// Mount only behind the selected native TLS server. No bootstrap token or
    /// producer-supplied identity/roles can authorize this route.
    pub fn new(
        control: Arc<ControlClient>,
        token: LeaseToken,
        verifier: Arc<ConfiguredCustodyVerifier>,
        identity: IdentityBackend,
        stopping: CancellationToken,
    ) -> Result<Arc<Self>, ControlError> {
        token.validate()?;
        if &token.scope != verifier.configured_scope() {
            return Err(ControlError::Fenced);
        }
        Ok(Arc::new(Self {
            control,
            token,
            verifier,
            identity,
            stopping,
            slots: Arc::new(Semaphore::new(4)),
            confirmed: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }))
    }
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(CONFIRM_PATH, post(confirm))
            .with_state(self.clone())
    }
    pub fn metrics(&self) -> CustodyApiMetrics {
        CustodyApiMetrics {
            depth: 4 - self.slots.available_permits(),
            capacity: 4,
            confirmed: self.confirmed.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            closed: self.stopping.is_cancelled(),
        }
    }
    async fn request(
        &self,
        request: Request,
        context: &ControlContext,
    ) -> Result<Vec<u8>, StatusCode> {
        let grant = self
            .identity
            .authenticate_headers(
                request.headers(),
                IdentityContext {
                    deadline: context.deadline(),
                    cancellation: context.cancellation_token(),
                },
            )
            .await
            .map_err(identity_error)?;
        if !authorized(&grant) {
            return Err(StatusCode::FORBIDDEN);
        }
        if request.uri().query().is_some()
            || request
                .headers()
                .get_all(header::CONTENT_TYPE)
                .iter()
                .count()
                != 1
            || request
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|s| s.to_str().ok())
                .is_none_or(|s| {
                    s.split(';')
                        .next()
                        .is_none_or(|s| s.trim() != "application/json")
                })
        {
            return Err(StatusCode::BAD_REQUEST);
        }
        let bytes = to_bytes(request.into_body(), WIRE_BYTES)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        let wire: ConfirmRequest =
            serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
        wire.validate().map_err(|_| StatusCode::BAD_REQUEST)?;
        let description =
            ObjectCustodyDescription::try_from(wire.description.clone()).map_err(control_error)?;
        let permit = coordinate_object_custody(
            self.control.as_ref(),
            self.verifier.as_ref(),
            self.token.clone(),
            description,
            self.verifier.authority_revision(),
            context.clone(),
        )
        .await
        .map_err(control_error)?;
        context.check().map_err(control_error)?;
        if !authorized(&grant) {
            return Err(StatusCode::FORBIDDEN);
        }
        let receipt = permit.checked_receipt().map_err(control_error)?;
        let confirmed_at = Utc::now();
        let remaining = context
            .deadline()
            .saturating_duration_since(tokio::time::Instant::now());
        let lease_until = chrono::DateTime::from_timestamp(
            i64::try_from(grant.lease_bounds().1).map_err(|_| StatusCode::FORBIDDEN)?,
            0,
        )
        .ok_or(StatusCode::FORBIDDEN)?;
        let valid_until = (confirmed_at
            + chrono::Duration::from_std(remaining)
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?)
        .min(lease_until)
        .min(receipt.description.retain_until);
        let result = Confirmation {
            schema_version: 1,
            request_nonce: wire.request_nonce,
            description: (&receipt.description).into(),
            description_sha256: receipt.description_sha256,
            confirmed_at,
            valid_until,
            valid_for_ms: u32::try_from((valid_until - confirmed_at).num_milliseconds())
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
            server_elapsed_ms: u32::try_from(
                Duration::from_secs(5).saturating_sub(remaining).as_millis(),
            )
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        };
        result
            .validate_for(&wire)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let response = serde_json::to_vec(&result).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if response.len() > WIRE_BYTES {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        permit.checked_receipt().map_err(control_error)?;
        if !authorized(&grant) {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(response)
    }
}
struct CancelOnDrop(ControlContext);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct Outcome(Arc<CustodyApi>, bool);
impl Drop for Outcome {
    fn drop(&mut self) {
        if !self.1 {
            self.0.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}
async fn confirm(State(api): State<Arc<CustodyApi>>, request: Request) -> Response {
    let _slot = match api.slots.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            api.rejected.fetch_add(1, Ordering::Relaxed);
            return failure(StatusCode::TOO_MANY_REQUESTS);
        }
    };
    let mut outcome = Outcome(api.clone(), false);
    let context = match ControlContext::new_cancellable(Duration::from_secs(5), &api.stopping) {
        Ok(c) => c,
        Err(e) => return failure(control_error(e)),
    };
    let _cancel = CancelOnDrop(context.clone());
    let cancellation = context.cancellation_token();
    let result = tokio::select! {biased; _=cancellation.cancelled()=>Err(StatusCode::SERVICE_UNAVAILABLE),result=tokio::time::timeout_at(context.deadline(),api.request(request,&context))=>result.unwrap_or(Err(StatusCode::REQUEST_TIMEOUT))};
    match result {
        Ok(bytes) => {
            api.confirmed.fetch_add(1, Ordering::Relaxed);
            outcome.1 = true;
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                bytes,
            )
                .into_response()
        }
        Err(status) => failure(status),
    }
}
fn authorized(grant: &RequestGrant) -> bool {
    u64::try_from(Utc::now().timestamp())
        .ok()
        .is_some_and(|now| {
            grant
                .scopes(Operation::ConfirmObjectCustody, now)
                .any(|scope| scope.is_all())
        })
}
fn identity_error(e: IdentityError) -> StatusCode {
    match e {
        IdentityError::InvalidCredential => StatusCode::UNAUTHORIZED,
        IdentityError::Denied => StatusCode::FORBIDDEN,
        IdentityError::Busy => StatusCode::TOO_MANY_REQUESTS,
        IdentityError::Timeout => StatusCode::REQUEST_TIMEOUT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
fn control_error(e: ControlError) -> StatusCode {
    match e {
        ControlError::Invalid => StatusCode::BAD_REQUEST,
        ControlError::Fenced | ControlError::Conflict => StatusCode::CONFLICT,
        ControlError::Full => StatusCode::TOO_MANY_REQUESTS,
        ControlError::Timeout => StatusCode::REQUEST_TIMEOUT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
fn failure(status: StatusCode) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        "{\"schema_version\":1,\"error\":\"custody_confirmation_refused\"}",
    )
        .into_response()
}
