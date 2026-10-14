//! Conservative replay protection transfer under current fenced state.
use crate::{ControlContext, ControlError};
use sha2::{Digest, Sha256};
use uuid::Uuid;
#[derive(Clone)]
pub struct ReplayPinReplacement {
    pub id: Uuid,
    pub replacement: Uuid,
    pub state_key: String,
    pub expected_head: Uuid,
    pub revision: [u8; 32],
    pub value_sha256: [u8; 32],
}
impl ReplayPinReplacement {
    pub(crate) fn wire(&self) -> Result<Vec<u8>, ControlError> {
        if self.id.is_nil()
            || self.replacement.is_nil()
            || self.id == self.replacement
            || self.expected_head.is_nil()
            || self.state_key.is_empty()
            || self.state_key.len() > 256
            || self.state_key.capacity() > 256
            || self.state_key.chars().any(char::is_control)
        {
            return Err(ControlError::Invalid);
        }
        crate::publication::encode(
            &serde_json::json!({"schema_version":1,"id":self.id,"replacement":self.replacement,"state_key":self.state_key,"expected_head":self.expected_head,"revision":crate::publication::hex(&self.revision),"value_sha256":crate::publication::hex(&self.value_sha256)}),
        )
    }
}
pub(crate) async fn verify(
    db: &tokio_postgres::Client,
    context: &ControlContext,
) -> Result<(), ControlError> {
    context.check()?;
    let source = include_str!("../../../schemas/shared-control/011-replay-pin-transfer.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_replay_transfer' AND p.proname='release_replaced' AND p.pronargs=4 AND p.pronargdefaults=0 AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='bytea'::regtype AND p.proargtypes[2]='bytea'::regtype AND p.proargtypes[3]='bytea'::regtype AND p.prorettype='jsonb'::regtype AND p.prokind='f' AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1 AND (SELECT count(*) FROM pg_proc x WHERE x.pronamespace=n.oid)=1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}
