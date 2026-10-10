//! Explicit database SELECT authority plus a current authenticated all-scope
//! host grant. Producer function EXECUTE privileges are never sufficient.
use crate::{
    ControlContext, ControlError, ITEM_BYTES, ITEMS, REPLY_BYTES, RetainedFinding,
    RetainedFindingsPage,
};
use signal_protocol::{
    access::{Operation, RequestGrant},
    findings_feed::{FindingsAfter, FindingsCursor, FindingsFeedQuery},
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_postgres::Client;
use uuid::Uuid;

pub(crate) struct FeedRead {
    pub store: Uuid,
    pub generation: Uuid,
    pub query: FindingsFeedQuery,
    pub grant: Arc<RequestGrant>,
    pub output_context: ControlContext,
    pub stopping: tokio_util::sync::CancellationToken,
}
fn now() -> Result<Duration, ControlError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ControlError::Fenced)
}
fn allowed(grant: &RequestGrant) -> Result<(), ControlError> {
    if grant
        .scopes(Operation::ReadFindingsFeed, now()?.as_secs())
        .any(|scope| scope.is_all())
    {
        Ok(())
    } else {
        Err(ControlError::Fenced)
    }
}
impl FeedRead {
    pub(crate) fn budget(&self, context: ControlContext) -> Result<ControlContext, ControlError> {
        context.check()?;
        if self.stopping.is_cancelled() {
            return Err(ControlError::Cancelled);
        }
        if self.store.is_nil()
            || self.generation.is_nil()
            || !(1..=ITEMS).contains(&self.query.limit)
        {
            return Err(ControlError::Invalid);
        }
        allowed(&self.grant)?;
        let remaining = Duration::from_secs(self.grant.lease_bounds().1)
            .checked_sub(now()?)
            .ok_or(ControlError::Fenced)?;
        let context =
            context.limited_to(tokio::time::Instant::now() + remaining.min(Duration::from_secs(5)));
        context.check()?;
        Ok(context)
    }
}
/// Original operation and request grant remain attached through response use.
/// Database credentials must be independently enrolled for global table reads.
pub struct AuthorizedFindingsPage {
    page: RetainedFindingsPage,
    grant: Arc<RequestGrant>,
    stopping: tokio_util::sync::CancellationToken,
}
impl AuthorizedFindingsPage {
    fn check(&self) -> Result<(), ControlError> {
        if self.stopping.is_cancelled() {
            return Err(ControlError::Cancelled);
        }
        allowed(&self.grant)
    }
    pub fn records(&self) -> Result<&[RetainedFinding], ControlError> {
        self.check()?;
        self.page.records()
    }
    pub fn next_cursor(&self) -> Result<FindingsCursor, ControlError> {
        self.check()?;
        self.page.next_cursor()
    }
    pub fn has_more(&self) -> Result<bool, ControlError> {
        self.check()?;
        self.page.has_more()
    }
}
async fn privileges(db: &Client) -> Result<(), ControlError> {
    let row=db.query_one("SELECT has_schema_privilege(session_user,'signal_control','USAGE') AND has_table_privilege(session_user,'signal_control.store','SELECT') AND has_table_privilege(session_user,'signal_control.migrations','SELECT') AND has_table_privilege(session_user,'signal_control.findings','SELECT')", &[]).await.map_err(crate::client::database_error)?;
    if row
        .try_get::<_, bool>(0)
        .map_err(|_| ControlError::Corrupt)?
    {
        Ok(())
    } else {
        Err(ControlError::Fenced)
    }
}
fn cursor(store: Uuid, position: i64, digest: Vec<u8>) -> Result<FindingsCursor, ControlError> {
    FindingsCursor::from_retained_parts(
        store,
        u64::try_from(position).map_err(|_| ControlError::Corrupt)?,
        digest.try_into().map_err(|_| ControlError::Corrupt)?,
    )
    .map_err(|_| ControlError::Corrupt)
}
pub(crate) async fn run(
    db: &Client,
    read: &FeedRead,
    context: &ControlContext,
    routines: [u8; 32],
) -> Result<AuthorizedFindingsPage, ControlError> {
    read.budget(context.clone())?;
    db.batch_execute("SET LOCAL search_path=pg_catalog,signal_control,pg_temp")
        .await
        .map_err(crate::client::database_error)?;
    privileges(db).await?;
    let revision = if routines == crate::catalog_schema_identity().1 {
        4_i32
    } else if routines == crate::restored_catalog_schema_identity().1 {
        5_i32
    } else {
        return Err(ControlError::Invalid);
    };
    // Bound schema discovery before materializing the existing canonical catalog.
    let tables=db.query("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_control' AND c.relkind IN ('r','v','m','f','p') LIMIT 22",&[]).await.map_err(crate::client::database_error)?;
    if tables.len() != crate::administration::TABLES.len() + if revision == 4 { 2 } else { 3 } {
        return Err(ControlError::Corrupt);
    }
    let logical: String = db
        .query_one(
            include_str!("../../../schemas/shared-control/catalog-query.sql"),
            &[],
        )
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    let expected = if revision == 4 {
        include_str!("../../../schemas/shared-control/005-catalog.sha256")
    } else {
        include_str!("../../../schemas/shared-control/006-catalog.sha256")
    };
    if logical != expected.trim() {
        return Err(ControlError::Corrupt);
    }
    let head=db.query_one("SELECT store_id,generation,revision,ready,schema_sha256,routines_sha256,feed_position,feed_digest FROM signal_control.store WHERE singleton",&[]).await.map_err(crate::client::database_error)?;
    let get_uuid = |i| {
        head.try_get::<_, Uuid>(i)
            .map_err(|_| ControlError::Corrupt)
    };
    if get_uuid(0)? != read.store
        || get_uuid(1)? != read.generation
        || !head
            .try_get::<_, bool>(3)
            .map_err(|_| ControlError::Corrupt)?
    {
        return Err(ControlError::Fenced);
    }
    if head
        .try_get::<_, i32>(2)
        .map_err(|_| ControlError::Corrupt)?
        != revision
        || head
            .try_get::<_, Vec<u8>>(4)
            .map_err(|_| ControlError::Corrupt)?
            != crate::schema_identity().0
        || head
            .try_get::<_, Vec<u8>>(5)
            .map_err(|_| ControlError::Corrupt)?
            != routines
    {
        return Err(ControlError::Corrupt);
    }
    let history=db.query("SELECT ordinal,artifact,sha256 FROM signal_control.migrations ORDER BY ordinal LIMIT 6",&[]).await.map_err(crate::client::database_error)?;
    let mut expected_history = vec![
        ("001.sql", crate::schema_identity().0),
        ("002-functions.sql", crate::legacy_identity()),
        ("003-administration.sql", crate::schema_identity().1),
        ("005-catalog.sql", crate::catalog_schema_identity().1),
    ];
    if revision == 5 {
        expected_history.push((
            "006-catalog-restore.sql",
            crate::restored_catalog_schema_identity().1,
        ));
    }
    if history.len() != expected_history.len() {
        return Err(ControlError::Corrupt);
    }
    for (i, (row, (artifact, hash))) in history.iter().zip(expected_history).enumerate() {
        if row
            .try_get::<_, i32>(0)
            .map_err(|_| ControlError::Corrupt)?
            != i as i32 + 1
            || row
                .try_get::<_, String>(1)
                .map_err(|_| ControlError::Corrupt)?
                != artifact
            || row
                .try_get::<_, Vec<u8>>(2)
                .map_err(|_| ControlError::Corrupt)?
                != hash
        {
            return Err(ControlError::Corrupt);
        }
    }
    let head = cursor(
        read.store,
        head.try_get(6).map_err(|_| ControlError::Corrupt)?,
        head.try_get(7).map_err(|_| ControlError::Corrupt)?,
    )?;
    let initial = FindingsCursor::initial(read.store).map_err(|_| ControlError::Invalid)?;
    if head.position() == 0 {
        if head != initial {
            return Err(ControlError::Corrupt);
        }
    } else {
        let row = db
            .query_opt(
                "SELECT cursor_digest FROM signal_control.findings WHERE position=$1",
                &[&(head.position() as i64)],
            )
            .await
            .map_err(crate::client::database_error)?
            .ok_or(ControlError::Corrupt)?;
        if cursor(
            read.store,
            head.position() as i64,
            row.try_get(0).map_err(|_| ControlError::Corrupt)?,
        )? != head
        {
            return Err(ControlError::Corrupt);
        }
    }
    let requested = match read.query.after {
        FindingsAfter::Begin => initial,
        FindingsAfter::Cursor(c) => c,
    };
    if requested.stream() != read.store {
        return Err(ControlError::Conflict);
    }
    if requested.position() > head.position() {
        return Err(ControlError::CursorPositionUnavailable);
    }
    let anchor = if requested.position() == 0 {
        initial
    } else {
        let row = db
            .query_opt(
                "SELECT cursor_digest FROM signal_control.findings WHERE position=$1",
                &[&(requested.position() as i64)],
            )
            .await
            .map_err(crate::client::database_error)?
            .ok_or(ControlError::Conflict)?;
        cursor(
            read.store,
            requested.position() as i64,
            row.try_get(0).map_err(|_| ControlError::Corrupt)?,
        )?
    };
    if anchor != requested {
        return Err(ControlError::Conflict);
    }
    let mut records = Vec::with_capacity(read.query.limit);
    let mut charge = records.capacity() * std::mem::size_of::<RetainedFinding>() + 256;
    let mut position = anchor.position();
    while position < head.position() && records.len() < read.query.limit {
        context.check()?;
        allowed(&read.grant)?;
        // One <=64KiB row in flight; no materialized unbounded SQL result.
        let row=db.query_opt("SELECT id,position,cursor_digest,content_sha256,octet_length(content),CASE WHEN octet_length(content)<=65536 THEN content ELSE NULL END FROM signal_control.findings WHERE position>$1 AND position<=$2 ORDER BY position LIMIT 1",&[&(position as i64),&(head.position() as i64)]).await.map_err(crate::client::database_error)?.ok_or(ControlError::Corrupt)?;
        let length: i32 = row.try_get(4).map_err(|_| ControlError::Corrupt)?;
        if !(1..=ITEM_BYTES as i32).contains(&length) {
            return Err(ControlError::Full);
        }
        let bytes: Vec<u8> = row.try_get(5).map_err(|_| ControlError::Corrupt)?;
        let next_charge = charge
            .checked_add(bytes.capacity())
            .and_then(|n| n.checked_add(128))
            .ok_or(ControlError::Full)?;
        if bytes.capacity() > ITEM_BYTES || next_charge > REPLY_BYTES {
            if records.is_empty() {
                return Err(ControlError::Full);
            } else {
                break;
            }
        }
        let next = cursor(
            read.store,
            row.try_get(1).map_err(|_| ControlError::Corrupt)?,
            row.try_get(2).map_err(|_| ControlError::Corrupt)?,
        )?;
        records.push(RetainedFinding {
            id: row.try_get(0).map_err(|_| ControlError::Corrupt)?,
            cursor: next,
            sha256: row
                .try_get::<_, Vec<u8>>(3)
                .map_err(|_| ControlError::Corrupt)?
                .try_into()
                .map_err(|_| ControlError::Corrupt)?,
            bytes,
        });
        position = next.position();
        charge = next_charge;
    }
    let page = RetainedFindingsPage::verify(
        read.store,
        read.generation,
        read.query,
        anchor,
        head,
        records,
        read.output_context.clone(),
    )?;
    allowed(&read.grant)?;
    privileges(db).await?;
    Ok(AuthorizedFindingsPage {
        page,
        grant: read.grant.clone(),
        stopping: read.stopping.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_protocol::access::{
        AccessPolicy, AuthenticatedIdentity, Permission, ResourceScope, Role, SubjectBinding,
    };
    fn grant(
        operation: Operation,
        issued: u64,
        expires: u64,
    ) -> Result<Arc<RequestGrant>, Box<dyn std::error::Error>> {
        let policy = AccessPolicy {
            schema_version: 1,
            roles: vec![Role {
                id: "synthetic".into(),
                permissions: vec![Permission {
                    operation,
                    scope: ResourceScope::all(),
                }],
            }],
            bindings: vec![SubjectBinding {
                issuer: "synthetic".into(),
                subject: "reader".into(),
                roles: vec!["synthetic".into()],
            }],
        }
        .compile()?;
        Ok(Arc::new(policy.grant(
            AuthenticatedIdentity::from_verified_backend(
                "synthetic".into(),
                "reader".into(),
                issued,
                expires,
            )?,
            issued,
        )?))
    }
    #[tokio::test]
    async fn wrong_operation_or_expired_grant_denied_before_network()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = crate::ControlClient::catalog(crate::ConnectionSettings::fixture_loopback(
            std::net::IpAddr::from([127, 0, 0, 1]),
            1,
            "unused".into(),
            "unused".into(),
            b"synthetic".to_vec(),
        )?)?;
        let at = now()?.as_secs();
        for grant in [
            grant(Operation::ReadFindings, at, at + 60)?,
            grant(Operation::ReadFindingsFeed, 1, 2)?,
        ] {
            assert!(matches!(
                client
                    .read_findings_feed(
                        Uuid::new_v4(),
                        Uuid::new_v4(),
                        FindingsFeedQuery {
                            after: FindingsAfter::Begin,
                            limit: 1
                        },
                        grant,
                        ControlContext::new(Duration::from_secs(1))?
                    )
                    .await,
                Err(ControlError::Fenced)
            ));
        }
        client
            .shutdown(ControlContext::new(Duration::from_secs(1))?)
            .await?;
        Ok(())
    }
    #[test]
    fn grant_budget_never_extends_original_operation() -> Result<(), Box<dyn std::error::Error>> {
        let at = now()?.as_secs();
        let context = ControlContext::new(Duration::from_secs(1))?;
        let deadline = context.deadline();
        let read = FeedRead {
            store: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            query: FindingsFeedQuery {
                after: FindingsAfter::Begin,
                limit: 1,
            },
            grant: grant(Operation::ReadFindingsFeed, at, at + 60)?,
            output_context: context.clone(),
            stopping: tokio_util::sync::CancellationToken::new(),
        };
        assert!(read.budget(context.clone())?.deadline() <= deadline);
        context.cancel();
        assert!(matches!(read.budget(context), Err(ControlError::Cancelled)));
        Ok(())
    }
}
