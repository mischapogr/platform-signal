//! Host-owned read credentials and live paired scopes over immutable shared history.
//! This list has no feed cursor and never filters a global feed page.
use crate::{ControlContext, ControlError, ITEMS, REPLY_BYTES};
use signal_findings::{Finding, FindingQuery};
use signal_protocol::access::{Operation, RequestGrant, ScopeFacts};
use std::{
    io::Write,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_postgres::Client;
use uuid::Uuid;

/// Explicit configured store/scope catalog and schema owner, never request claims.
#[derive(Clone)]
pub struct ScopedFindingsBinding {
    pub store: Uuid,
    pub generation: Uuid,
    pub scope_generation: Uuid,
    pub schema_owner: String,
}
pub(crate) struct ScopedRead {
    pub binding: ScopedFindingsBinding,
    pub query: FindingQuery,
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
    grant
        .scopes(Operation::ReadFindings, now()?.as_secs())
        .next()
        .map(|_| ())
        .ok_or(ControlError::Fenced)
}
impl ScopedRead {
    pub(crate) fn budget(&self, context: ControlContext) -> Result<ControlContext, ControlError> {
        context.check()?;
        if self.stopping.is_cancelled() {
            return Err(ControlError::Cancelled);
        }
        let b = &self.binding;
        if b.store.is_nil()
            || b.generation.is_nil()
            || b.scope_generation.is_nil()
            || b.schema_owner.is_empty()
            || b.schema_owner.len() > 63
            || b.schema_owner.capacity() > 63
            || !b
                .schema_owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !(1..=ITEMS).contains(&self.query.limit)
            || self
                .query
                .from
                .zip(self.query.to)
                .is_some_and(|(from, to)| from >= to)
            || self
                .query
                .rule_id
                .as_ref()
                .is_some_and(|id| id.trim().is_empty() || id.len() > 256 || id.capacity() > 256)
        {
            return Err(ControlError::Invalid);
        }
        allowed(&self.grant)?;
        // Capture the monotonic anchor first: descheduling cannot extend expiry.
        let anchor = tokio::time::Instant::now();
        let remaining = Duration::from_secs(self.grant.lease_bounds().1)
            .checked_sub(now()?)
            .ok_or(ControlError::Fenced)?;
        let context = context.limited_to(anchor + remaining.min(Duration::from_secs(5)));
        context.check()?;
        Ok(context)
    }
}
/// Original live grant/deadline remains attached through serialization and use.
/// Taking a list never renews its operation or creates durable read authority.
pub struct AuthorizedFindingsList {
    findings: Vec<Finding>,
    grant: Arc<RequestGrant>,
    context: ControlContext,
    stopping: tokio_util::sync::CancellationToken,
}
impl AuthorizedFindingsList {
    pub fn findings(&self) -> Result<&[Finding], ControlError> {
        self.context.check()?;
        if self.stopping.is_cancelled() {
            return Err(ControlError::Cancelled);
        }
        allowed(&self.grant)?;
        Ok(&self.findings)
    }
}
struct Selectors(Vec<u8>);
impl Write for Selectors {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > 131072usize.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("selector capacity"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn selectors(grant: &RequestGrant) -> Result<String, ControlError> {
    allowed(grant)?;
    let scopes: Vec<_> = grant
        .scopes(Operation::ReadFindings, now()?.as_secs())
        .take(129)
        .collect();
    if scopes.is_empty() || scopes.len() > 128 {
        return Err(ControlError::Full);
    }
    let mut writer = Selectors(Vec::new());
    // Serialize only borrowed bounded selector descriptions, never identity,
    // credentials, operations or the RequestGrant itself.
    serde_json::to_writer(&mut writer, &scopes).map_err(|_| ControlError::Full)?;
    String::from_utf8(writer.0.into_boxed_slice().into_vec()).map_err(|_| ControlError::Invalid)
}
async fn privileges(db: &Client) -> Result<(), ControlError> {
    let row = db.query_one("SELECT has_schema_privilege(session_user,'signal_control','USAGE') AND has_schema_privilege(session_user,'signal_finding_scope','USAGE') AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['signal_control.store','signal_control.migrations','signal_control.findings','signal_control.partitions','signal_finding_scope.activation','signal_finding_scope.profile','signal_finding_scope.producers','signal_finding_scope.facts','signal_finding_scope.requests']) name WHERE NOT has_table_privilege(session_user,name,'SELECT'))",&[]).await.map_err(crate::client::database_error)?;
    if row
        .try_get::<_, bool>(0)
        .map_err(|_| ControlError::Corrupt)?
    {
        Ok(())
    } else {
        Err(ControlError::Fenced)
    }
}
const LIST: &str = r#"
WITH permitted AS (
 SELECT f.id,f.content,f.content_sha256,s.source,s.account,s.resource,
        convert_from(f.content,'UTF8')::jsonb payload
 FROM signal_control.findings f
 LEFT JOIN signal_finding_scope.facts s ON s.finding_id=f.id AND s.partition_id=f.partition_id AND s.scope_generation=$2
 WHERE EXISTS (SELECT 1 FROM jsonb_array_elements($1::text::jsonb) g WHERE
   ((g->'sources'->>'mode')='all' OR s.source IN (SELECT jsonb_array_elements_text(g->'sources'->'values')))
   AND ((g->'accounts'->>'mode')='all' OR s.account IN (SELECT jsonb_array_elements_text(g->'accounts'->'values')))
   AND ((g->'resources'->>'mode')='all' OR s.resource IN (SELECT jsonb_array_elements_text(g->'resources'->'values'))))
), seconds AS (
 SELECT *,regexp_replace(regexp_replace(payload->>'created_at','[.][0-9]+',''),':60',':59') clock
 FROM permitted
), timed AS (
 SELECT *, EXTRACT(EPOCH FROM (
   CASE WHEN left(clock,4)='0000'
     THEN '0001'||substr(clock,5)||' BC'
     ELSE clock END
   )::timestamptz)*2000000000
   + COALESCE(rpad(substring(payload->>'created_at' FROM '[.]([0-9]+)'),9,'0')::numeric,0)
   + CASE WHEN position(':60' IN payload->>'created_at')>0 THEN 1000000000 ELSE 0 END stamp
 FROM seconds
)
SELECT id,content_sha256,source,account,resource,octet_length(content) FROM timed
WHERE ($3::text IS NULL OR stamp >= $3::text::numeric)
 AND ($4::text IS NULL OR stamp < $4::text::numeric)
 AND ($5::text IS NULL OR payload->>'severity'=$5)
 AND ($6::text IS NULL OR payload->>'rule_id'=$6)
ORDER BY stamp,id LIMIT $7
"#;
pub(crate) async fn run(
    db: &Client,
    read: &ScopedRead,
    context: &ControlContext,
    routines: [u8; 32],
) -> Result<AuthorizedFindingsList, ControlError> {
    read.budget(context.clone())?;
    db.batch_execute("SET LOCAL search_path=pg_catalog,signal_control,pg_temp")
        .await
        .map_err(crate::client::database_error)?;
    privileges(db).await?;
    let profile = if routines == crate::catalog_schema_identity().1 {
        crate::FindingScopeProfile::Catalog4Scoped
    } else if routines == crate::restored_catalog_schema_identity().1 {
        crate::FindingScopeProfile::RestoredCatalog5Scoped
    } else {
        return Err(ControlError::Invalid);
    };
    crate::finding_scope::read_binding(db, &read.binding, profile, context).await?;
    let scopes = selectors(&read.grant)?;
    // Preserve Chrono's (whole seconds, fractional nanos) ordering. Leap
    // seconds use fractional nanos >=1e9; a two-billion radix keeps them
    // distinct from the following ordinary second instead of folding time.
    let order_key = |t: chrono::DateTime<chrono::Utc>| {
        (i128::from(t.timestamp()) * 2000000000 + i128::from(t.timestamp_subsec_nanos()))
            .to_string()
    };
    let from = read.query.from.map(order_key);
    let to = read.query.to.map(order_key);
    let severity = read.query.severity.map(|s| match s {
        signal_findings::DetectionSeverity::Low => "low",
        signal_findings::DetectionSeverity::Medium => "medium",
        signal_findings::DetectionSeverity::High => "high",
        signal_findings::DetectionSeverity::Critical => "critical",
    });
    // SQL chooses at most128 small metadata records. Fetch one <=64KiB body
    // at a time only after charging its conservative decoded allocation.
    let limit = read.query.limit as i64;
    let metadata = db
        .query(
            LIST,
            &[
                &scopes,
                &read.binding.scope_generation,
                &from,
                &to,
                &severity,
                &read.query.rule_id,
                &limit,
            ],
        )
        .await
        .map_err(crate::client::database_error)?;
    let mut findings = Vec::with_capacity(read.query.limit);
    let mut charge = findings.capacity() * std::mem::size_of::<Finding>() + 256;
    for row in metadata {
        context.check()?;
        allowed(&read.grant)?;
        let length: i32 = row.try_get(5).map_err(|_| ControlError::Corrupt)?;
        if !(1..=crate::ITEM_BYTES as i32).contains(&length) {
            return Err(ControlError::Full);
        }
        charge = (length as usize)
            .checked_mul(64)
            .and_then(|n| n.checked_add(charge))
            .filter(|n| *n <= REPLY_BYTES)
            .ok_or(ControlError::Full)?;
        let id: Uuid = row.try_get(0).map_err(|_| ControlError::Corrupt)?;
        let body = db.query_one("SELECT CASE WHEN octet_length(content) BETWEEN 1 AND 65536 THEN content ELSE NULL END FROM signal_control.findings WHERE id=$1", &[&id]).await.map_err(crate::client::database_error)?;
        let bytes: Vec<u8> = body.try_get(0).map_err(|_| ControlError::Corrupt)?;
        if bytes.len() != length as usize || bytes.capacity() > crate::ITEM_BYTES {
            return Err(ControlError::Full);
        }
        let finding: Finding = serde_json::from_slice(&bytes).map_err(|_| ControlError::Corrupt)?;
        finding.validate().map_err(|_| ControlError::Corrupt)?;
        use sha2::{Digest, Sha256};
        if finding.id != id
            || Sha256::digest(&bytes).as_slice()
                != row
                    .try_get::<_, Vec<u8>>(1)
                    .map_err(|_| ControlError::Corrupt)?
        {
            return Err(ControlError::Corrupt);
        }
        let source: Option<String> = row.try_get(2).map_err(|_| ControlError::Corrupt)?;
        let account: Option<String> = row.try_get(3).map_err(|_| ControlError::Corrupt)?;
        let resource: Option<String> = row.try_get(4).map_err(|_| ControlError::Corrupt)?;
        if !read.grant.allows(
            Operation::ReadFindings,
            ScopeFacts {
                source: source.as_deref(),
                account: account.as_deref(),
                resource: resource.as_deref(),
            },
            now()?.as_secs(),
        ) {
            return Err(ControlError::Corrupt);
        }
        findings.push(finding);
    }
    context.check()?;
    allowed(&read.grant)?;
    privileges(db).await?;
    Ok(AuthorizedFindingsList {
        findings,
        grant: read.grant.clone(),
        context: read.output_context.clone(),
        stopping: read.stopping.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_protocol::access::{AccessPolicy, AuthenticatedIdentity};
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    fn grant(
        operation: &str,
    ) -> std::result::Result<Arc<RequestGrant>, Box<dyn std::error::Error>> {
        let bytes = serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"roles":[{"id":"r","permissions":[{"operation":operation,"scope":{"sources":{"mode":"all"},"accounts":{"mode":"all"},"resources":{"mode":"all"}}}]}],"bindings":[{"issuer":"issuer","subject":"subject","roles":["r"]}]}),
        )?;
        let current = now()?.as_secs();
        Ok(Arc::new(
            AccessPolicy::from_json(&bytes)?.compile()?.grant(
                AuthenticatedIdentity::from_verified_backend(
                    "issuer".into(),
                    "subject".into(),
                    current,
                    current + 60,
                )?,
                current,
            )?,
        ))
    }
    fn read(grant: Arc<RequestGrant>) -> std::result::Result<ScopedRead, ControlError> {
        Ok(ScopedRead {
            binding: ScopedFindingsBinding {
                store: Uuid::new_v4(),
                generation: Uuid::new_v4(),
                scope_generation: Uuid::new_v4(),
                schema_owner: "owner".into(),
            },
            query: FindingQuery {
                limit: 1,
                ..Default::default()
            },
            grant,
            output_context: ControlContext::new(Duration::from_secs(1))?,
            stopping: tokio_util::sync::CancellationToken::new(),
        })
    }
    #[tokio::test]
    async fn scoped_read_keeps_deadline_and_rejects_wrong_operation_and_cancellation() -> Result {
        let context = ControlContext::new(Duration::from_millis(100))?;
        let r = read(grant("read_findings")?)?;
        assert_eq!(r.budget(context.clone())?.deadline(), context.deadline());
        assert!(matches!(
            read(grant("ingest_events")?)?.budget(context.clone()),
            Err(ControlError::Fenced)
        ));
        context.cancel();
        assert!(matches!(r.budget(context), Err(ControlError::Cancelled)));
        Ok(())
    }
    #[tokio::test]
    async fn scoped_read_retained_response_honors_original_cancellation_and_shutdown() -> Result {
        let context = ControlContext::new(Duration::from_secs(1))?;
        let stopping = tokio_util::sync::CancellationToken::new();
        let list = AuthorizedFindingsList {
            findings: Vec::new(),
            grant: grant("read_findings")?,
            context: context.clone(),
            stopping: stopping.clone(),
        };
        assert!(list.findings()?.is_empty());
        stopping.cancel();
        assert!(matches!(list.findings(), Err(ControlError::Cancelled)));
        let list = AuthorizedFindingsList {
            findings: Vec::new(),
            grant: grant("read_findings")?,
            context: context.clone(),
            stopping: tokio_util::sync::CancellationToken::new(),
        };
        context.cancel();
        assert!(matches!(list.findings(), Err(ControlError::Cancelled)));
        Ok(())
    }
    #[test]
    fn scoped_read_selector_capacity_is_enforced_before_allocation() -> Result {
        let mut writer = Selectors(Vec::new());
        writer.write_all(&vec![1; 131072])?;
        assert!(writer.write_all(&[1]).is_err());
        assert_eq!(writer.0.len(), 131072);
        Ok(())
    }
}
