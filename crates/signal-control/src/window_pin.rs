//! Narrow replay pin grant for an exact committed Window state.
use crate::{ControlContext, ControlError};
use sha2::{Digest, Sha256};
pub(crate) async fn verify(
    db: &tokio_postgres::Client,
    context: &ControlContext,
) -> Result<(), ControlError> {
    context.check()?;
    let source = include_str!("../../../schemas/shared-control/017-window-replay-pin.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_window_pin' AND p.proname='retain' AND p.pronargs=4 AND p.pronargdefaults=0 AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='bytea'::regtype AND p.proargtypes[2]='bytea'::regtype AND p.proargtypes[3]='bytea'::regtype AND p.prorettype='jsonb'::regtype AND p.prokind='f' AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1 AND (SELECT count(*) FROM pg_proc x WHERE x.pronamespace=n.oid)=1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}
