//! Verify the additive module inside the existing bounded publication worker.
use crate::{ControlContext, ControlError};
use sha2::{Digest, Sha256};
use tokio_postgres::Client;

pub(crate) async fn verify(db: &Client, context: &ControlContext) -> Result<(), ControlError> {
    context.check()?;
    crate::window_history::verify(db, context).await?;
    db.batch_execute("SET LOCAL search_path=pg_catalog,signal_control,pg_temp")
        .await
        .map_err(crate::client::database_error)?;
    let valid:bool=db.query_one("SELECT (SELECT count(*) FROM (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_multi_event' AND c.relkind IN ('r','v','m','f','p') LIMIT 4) x)=3 AND (SELECT count(*) FROM (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='signal_multi_event' LIMIT 2) x)=1 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_multi_event' AND (c.relowner<>n.nspowner OR n.nspowner<>(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') OR c.relrowsecurity OR c.relforcerowsecurity OR EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal AND NOT coalesce((t.tgname='archive_window_publication' AND c.relname='requests' AND t.tgfoid=(SELECT hp.oid FROM pg_proc hp JOIN pg_namespace hn ON hn.oid=hp.pronamespace WHERE hn.nspname='signal_window_history' AND hp.proname='archive_publication' AND hp.pronargs=0)),false))))",&[]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Corrupt);
    }
    let query = include_str!("../../../schemas/shared-control/catalog-query.sql").replace(
        "n.nspname='signal_control'",
        "n.nspname='signal_multi_event'",
    );
    let catalog: String = db
        .query_one(&query, &[])
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    if catalog
        != include_str!("../../../schemas/shared-control/010-multi-event-catalog.sha256").trim()
    {
        return Err(ControlError::Corrupt);
    }
    let source = include_str!("../../../schemas/shared-control/010-multi-event-publication.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_multi_event' AND p.proname='publish' AND p.pronargs=6 AND p.pronargdefaults=0 AND p.provariadic=0 AND p.prokind='f' AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='bytea'::regtype AND p.proargtypes[2]='bytea'::regtype AND p.proargtypes[3]='boolean'::regtype AND p.proargtypes[4]='bytea'::regtype AND p.proargtypes[5]='bytea'::regtype AND p.prorettype='jsonb'::regtype AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}

/// Optional read-only validation of the complete bounded companion inventory.
/// Missing SELECT authority refuses; mere module presence grants no read scope.
pub(crate) async fn inspect_read(
    db: &Client,
    binding: &crate::ScopedFindingsBinding,
    context: &ControlContext,
) -> Result<bool, ControlError> {
    let present: bool = db
        .query_one(
            "SELECT to_regnamespace('signal_multi_event') IS NOT NULL",
            &[],
        )
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    if !present {
        return Ok(false);
    }
    verify(db, context).await?;
    let allowed:bool=db.query_one("SELECT current_user=$1::name OR (has_schema_privilege(session_user,'signal_multi_event','USAGE') AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['signal_multi_event.profile','signal_multi_event.facts','signal_multi_event.requests','signal_control.commits']) name WHERE NOT has_table_privilege(session_user,name,'SELECT')))",&[&binding.schema_owner]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !allowed {
        return Err(ControlError::Fenced);
    }
    let row=db.query_one("SELECT scope_generation,max_rows,max_bytes,used_rows,used_bytes FROM signal_multi_event.profile WHERE singleton",&[]).await.map_err(crate::client::database_error)?;
    let generation: uuid::Uuid = row.try_get(0).map_err(|_| ControlError::Corrupt)?;
    let max_rows: i64 = row.try_get(1).map_err(|_| ControlError::Corrupt)?;
    let max_bytes: i64 = row.try_get(2).map_err(|_| ControlError::Corrupt)?;
    let used_rows: i64 = row.try_get(3).map_err(|_| ControlError::Corrupt)?;
    let used_bytes: i64 = row.try_get(4).map_err(|_| ControlError::Corrupt)?;
    if generation != binding.scope_generation
        || !(1..=65536).contains(&max_rows)
        || !(4096..=67108864).contains(&max_bytes)
    {
        return Err(ControlError::Corrupt);
    }
    let row=db.query_one("SELECT (SELECT count(*) FROM (SELECT 1 FROM signal_multi_event.facts LIMIT 65537) x)+(SELECT count(*) FROM (SELECT 1 FROM signal_multi_event.requests LIMIT 65537) x),(SELECT coalesce(sum(512+octet_length(fact)),0) FROM signal_multi_event.facts)+(SELECT coalesce(sum(256+octet_length(claims)),0) FROM signal_multi_event.requests),EXISTS(SELECT 1 FROM signal_multi_event.requests m JOIN signal_control.commits c ON c.partition_id=m.partition_id AND c.id=m.commit_id WHERE m.claims_sha256<>sha256(m.claims) OR c.request_sha256<>sha256(c.request))",&[]).await.map_err(crate::client::database_error)?;
    let rows: i64 = row.try_get(0).map_err(|_| ControlError::Corrupt)?;
    let bytes: i64 = row.try_get(1).map_err(|_| ControlError::Corrupt)?;
    if rows != used_rows
        || bytes != used_bytes
        || rows > max_rows
        || bytes > max_bytes
        || row
            .try_get::<_, bool>(2)
            .map_err(|_| ControlError::Corrupt)?
    {
        return Err(ControlError::Corrupt);
    }
    // Fetch at most8 original bodies at once, under the64MiB stored budget.
    let mut after = uuid::Uuid::nil();
    let mut seen = 0usize;
    loop {
        context.check()?;
        let batch=db.query("SELECT m.finding_id,m.scope_generation,m.fact,m.fact_sha256,m.finding_sha256,f.content,f.content_sha256,f.position,a.prefix_position,EXISTS(SELECT 1 FROM signal_finding_scope.facts s WHERE s.finding_id=m.finding_id) FROM signal_multi_event.facts m JOIN signal_control.findings f ON f.id=m.finding_id AND f.partition_id=m.partition_id JOIN signal_finding_scope.activation a ON a.singleton WHERE m.finding_id>$1 AND octet_length(m.fact) BETWEEN 1 AND 131072 AND octet_length(f.content) BETWEEN 1 AND 65536 ORDER BY m.finding_id LIMIT 8",&[&after]).await.map_err(crate::client::database_error)?;
        if batch.is_empty() {
            break;
        }
        for row in batch {
            context.check()?;
            seen += 1;
            if seen > 65536 {
                return Err(ControlError::Full);
            }
            after = row.try_get(0).map_err(|_| ControlError::Corrupt)?;
            let fact: Vec<u8> = row.try_get(2).map_err(|_| ControlError::Corrupt)?;
            let finding: Vec<u8> = row.try_get(5).map_err(|_| ControlError::Corrupt)?;
            if row
                .try_get::<_, uuid::Uuid>(1)
                .map_err(|_| ControlError::Corrupt)?
                != generation
                || row
                    .try_get::<_, Vec<u8>>(3)
                    .map_err(|_| ControlError::Corrupt)?
                    != Sha256::digest(&fact).to_vec()
                || row
                    .try_get::<_, Vec<u8>>(4)
                    .map_err(|_| ControlError::Corrupt)?
                    != Sha256::digest(&finding).to_vec()
                || row
                    .try_get::<_, Vec<u8>>(6)
                    .map_err(|_| ControlError::Corrupt)?
                    != Sha256::digest(&finding).to_vec()
                || row
                    .try_get::<_, i64>(7)
                    .map_err(|_| ControlError::Corrupt)?
                    <= row
                        .try_get::<_, i64>(8)
                        .map_err(|_| ControlError::Corrupt)?
                || row
                    .try_get::<_, bool>(9)
                    .map_err(|_| ControlError::Corrupt)?
            {
                return Err(ControlError::Corrupt);
            }
            crate::multi_event_claims::validate_stored_fact(&fact, &finding, generation)?;
        }
    }
    let facts: i64 = db
        .query_one("SELECT count(*) FROM signal_multi_event.facts", &[])
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    if facts != seen as i64 {
        return Err(ControlError::Corrupt);
    }
    context.check()?;
    Ok(true)
}
