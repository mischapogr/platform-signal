//! Explicit enrolled Window profile/readiness check; never automatic enrollment.
use crate::{ControlContext, ControlError, LeaseToken, StateReadInput};
use sha2::{Digest, Sha256};
use uuid::Uuid;
#[derive(Clone)]
pub struct WindowProfile {
    pub schema_version: u16,
    pub scope_generation: Uuid,
    pub history_rows: usize,
    pub history_bytes: usize,
    pub retention_ms: i64,
    pub bootstrap_checkpoint: Option<u64>,
}
impl WindowProfile {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 1
            || self.scope_generation.is_nil()
            || !(1..=16384).contains(&self.history_rows)
            || !(4096..=33554432).contains(&self.history_bytes)
            || !(1..=31536000000).contains(&self.retention_ms)
            || self
                .bootstrap_checkpoint
                .is_some_and(|c| c > i64::MAX as u64)
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}
pub(crate) async fn verify(
    db: &tokio_postgres::Client,
    context: &ControlContext,
) -> Result<(), ControlError> {
    crate::window_pin::verify(db, context).await?;
    crate::finding_lookup::verify(db, context).await?;
    crate::multi_event_module::verify(db, context).await?;
    crate::replay_transfer::verify(db, context).await?;
    crate::replay_release::verify(db, context).await?;
    let source = include_str!("../../../schemas/shared-control/015-window-profile.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_window_profile' AND p.proname='inspect' AND p.pronargs=4 AND p.pronargdefaults=0 AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='jsonb'::regtype AND p.proargtypes[2]='bytea'::regtype AND p.proargtypes[3]='bytea'::regtype AND p.prorettype='boolean'::regtype AND p.prokind='f' AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1 AND (SELECT count(*) FROM pg_proc x WHERE x.pronamespace=n.oid)=1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}

pub(crate) async fn run(
    db: &tokio_postgres::Client,
    token: &LeaseToken,
    input: &StateReadInput,
    profile: &WindowProfile,
    context: &ControlContext,
    routines: [u8; 32],
) -> Result<(), ControlError> {
    verify(db, context).await?;
    let request = serde_json::json!({"schema_version":profile.schema_version,"key":input.key,"head":input.expected_head,
        "scope_generation":profile.scope_generation,"history_rows":profile.history_rows,"history_bytes":profile.history_bytes,
        "retention_ms":profile.retention_ms,"bootstrap_checkpoint":profile.bootstrap_checkpoint});
    let token = serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
    let schema = crate::schema_identity().0;
    let valid: bool = db
        .query_one(
            "SELECT signal_window_profile.inspect($1,$2,$3,$4)",
            &[&token, &request, &&schema[..], &&routines[..]],
        )
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}
