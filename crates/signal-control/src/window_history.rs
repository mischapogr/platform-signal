//! Optional owner-installed history trigger identity, never automatic enrollment.
use crate::{ControlContext, ControlError};
use sha2::{Digest, Sha256};
pub(crate) async fn verify(
    db: &tokio_postgres::Client,
    context: &ControlContext,
) -> Result<bool, ControlError> {
    context.check()?;
    db.batch_execute("SET LOCAL search_path=pg_catalog,signal_control,pg_temp")
        .await
        .map_err(crate::client::database_error)?;
    let present: bool = db
        .query_one(
            "SELECT to_regnamespace('signal_window_history') IS NOT NULL",
            &[],
        )
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    if !present {
        return Ok(false);
    }
    let structural:bool=db.query_one("SELECT (SELECT count(*) FROM (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_window_history' AND c.relkind IN ('r','v','m','f','p') LIMIT 3) x)=2 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_window_history' AND (c.relowner<>n.nspowner OR n.nspowner<>(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') OR c.relrowsecurity OR c.relforcerowsecurity OR EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)))",&[]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !structural {
        return Err(ControlError::Corrupt);
    }
    let query = include_str!("../../../schemas/shared-control/catalog-query.sql").replace(
        "n.nspname='signal_control'",
        "n.nspname='signal_window_history'",
    );
    let catalog: String = db
        .query_one(&query, &[])
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    if catalog
        != include_str!("../../../schemas/shared-control/012-window-history-catalog.sha256").trim()
    {
        return Err(ControlError::Corrupt);
    }
    let source = include_str!("../../../schemas/shared-control/012-window-history.sql");
    let clock_body = source
        .split_once(" AS $time$")
        .and_then(|(_, tail)| tail.split_once("\nEND $time$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let clock_hash: Vec<u8> = Sha256::digest(clock_body.as_bytes()).to_vec();
    let clock_valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_window_history' AND p.proname='timestamp_pair' AND p.pronargs=1 AND p.pronargdefaults=0 AND p.proargtypes[0]='text'::regtype AND p.prorettype='bigint[]'::regtype AND p.prokind='f' AND NOT p.prosecdef AND NOT p.proretset AND p.proisstrict AND NOT p.proleakproof AND p.provolatile='i' AND p.proparallel='s' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1)",&[&clock_hash]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !clock_valid {
        return Err(ControlError::Fenced);
    }
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang JOIN pg_trigger t ON t.tgfoid=p.oid WHERE n.nspname='signal_window_history' AND p.proname='archive_publication' AND p.pronargs=0 AND p.prorettype='trigger'::regtype AND p.prokind='f' AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1 AND (SELECT count(*) FROM pg_proc x WHERE x.pronamespace=n.oid)=2 AND t.tgrelid='signal_multi_event.requests'::regclass AND t.tgname='archive_window_publication' AND t.tgtype=5 AND t.tgenabled='O' AND NOT t.tgisinternal AND NOT t.tgdeferrable AND t.tgqual IS NULL AND t.tgnargs=0)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()?;
    Ok(true)
}
