//! Host-granted mandatory predicates over canonical stored identity only.
use crate::QueryError;
use datafusion::{
    logical_expr::Expr,
    prelude::{col, lit},
};
use signal_event::SignalEvent;
use signal_protocol::access::{Operation, RequestGrant, ResourceScope, ScopeFacts, Selection};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> Result<u64, QueryError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| QueryError::Denied)
}
pub(super) fn check(grant: Option<&RequestGrant>) -> Result<(), QueryError> {
    if let Some(grant) = grant
        && grant
            .scopes(Operation::QueryEvents, now()?)
            .next()
            .is_none()
    {
        return Err(QueryError::Denied);
    }
    Ok(())
}
pub(super) fn check_event(
    grant: Option<&RequestGrant>,
    event: &SignalEvent,
) -> Result<(), QueryError> {
    if let Some(grant) = grant
        && !grant.allows(Operation::QueryEvents, ScopeFacts::event(event), now()?)
    {
        return Err(QueryError::Denied);
    }
    Ok(())
}
fn selector(column: &str, selection: &Selection) -> Expr {
    match selection {
        Selection::All => lit(true),
        // SQL NULL does not satisfy IN. No attribute fallback for missing facts.
        Selection::Only(values) => col(column).in_list(
            values.iter().map(|value| lit(value.as_str())).collect(),
            false,
        ),
    }
}
fn scope(scope: &ResourceScope) -> Expr {
    selector("source_type", &scope.sources)
        .and(selector("resource_account_id", &scope.accounts))
        .and(selector("resource_id", &scope.resources))
}
pub(super) fn predicate(grant: &RequestGrant) -> Result<Expr, QueryError> {
    // Immutable policy bounds this to at most eight scopes for one operation.
    // Keep each complete permission conjoined; OR only complete paired scopes.
    grant
        .scopes(Operation::QueryEvents, now()?)
        .map(scope)
        .reduce(Expr::or)
        .ok_or(QueryError::Denied)
}
