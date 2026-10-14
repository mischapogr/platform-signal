//! Obsolete replay-pin release under complete bounded source accounting.
use crate::{ControlContext, ControlError};
use sha2::{Digest, Sha256};
use uuid::Uuid;
#[derive(Clone)]
pub struct ObsoleteReplayPin {
    pub id: Uuid,
    pub state_key: String,
    pub expected_head: Uuid,
    pub revision: [u8; 32],
    pub value_sha256: [u8; 32],
}
impl ObsoleteReplayPin {
    pub(crate) fn wire(&self) -> Result<Vec<u8>, ControlError> {
        if self.id.is_nil()
            || self.expected_head.is_nil()
            || self.state_key.is_empty()
            || self.state_key.len() > 256
            || self.state_key.capacity() > 256
            || self.state_key.chars().any(char::is_control)
        {
            return Err(ControlError::Invalid);
        }
        let mut identity = Vec::with_capacity(96 + self.state_key.len());
        identity.extend_from_slice(self.id.as_bytes());
        identity.extend_from_slice(self.expected_head.as_bytes());
        identity.extend_from_slice(&self.revision);
        identity.extend_from_slice(&self.value_sha256);
        identity.extend_from_slice(self.state_key.as_bytes());
        let catalog = Uuid::new_v5(&Uuid::from_bytes(*b"SIGNAL-UNPIN-001"), &identity);
        crate::publication::encode(
            &serde_json::json!({"schema_version":1,"id":self.id,"catalog_id":catalog,"state_key":self.state_key,"expected_head":self.expected_head,"revision":crate::publication::hex(&self.revision),"value_sha256":crate::publication::hex(&self.value_sha256)}),
        )
    }
}
pub(crate) async fn verify(
    db: &tokio_postgres::Client,
    context: &ControlContext,
) -> Result<(), ControlError> {
    crate::window_history_read::verify(db, context).await?;
    let source = include_str!("../../../schemas/shared-control/014-obsolete-replay-pin.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_replay_release' AND p.proname='release_obsolete' AND p.pronargs=4 AND p.pronargdefaults=0 AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='bytea'::regtype AND p.proargtypes[2]='bytea'::regtype AND p.proargtypes[3]='bytea'::regtype AND p.prorettype='jsonb'::regtype AND p.prokind='f' AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1 AND (SELECT count(*) FROM pg_proc x WHERE x.pronamespace=n.oid)=1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_identity_is_replay_stable_and_binds_the_confirmed_transition()
    -> Result<(), ControlError> {
        let input = ObsoleteReplayPin {
            id: Uuid::from_u128(1),
            state_key: "fixture".into(),
            expected_head: Uuid::from_u128(2),
            revision: [1; 32],
            value_sha256: [2; 32],
        };
        assert_eq!(input.wire()?, input.clone().wire()?);
        let original: serde_json::Value =
            serde_json::from_slice(&input.wire()?).map_err(|_| ControlError::Corrupt)?;
        let mut advanced = input.clone();
        advanced.expected_head = Uuid::from_u128(3);
        let advanced: serde_json::Value =
            serde_json::from_slice(&advanced.wire()?).map_err(|_| ControlError::Corrupt)?;
        assert_ne!(original["catalog_id"], advanced["catalog_id"]);
        let mut changed = input.clone();
        changed.value_sha256 = [3; 32];
        let changed: serde_json::Value =
            serde_json::from_slice(&changed.wire()?).map_err(|_| ControlError::Corrupt)?;
        assert_ne!(original["catalog_id"], changed["catalog_id"]);
        let mut oversized = input.clone();
        oversized.state_key = String::with_capacity(4096);
        oversized.state_key.push_str(&input.state_key);
        assert!(matches!(oversized.wire(), Err(ControlError::Invalid)));
        Ok(())
    }
}
