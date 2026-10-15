//! Explicit initial unknown sensor state; never event publication.
use crate::{
    LeaseToken, MultiEventStateEnvelope, RevisionedState, StateReadInput, StateReadResult,
};
use uuid::Uuid;
#[derive(Clone)]
pub struct SensorBootstrap {
    pub head: Option<Uuid>,
    pub checkpoint: u64,
    pub state: RevisionedState,
}
impl SensorBootstrap {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.state.validate()?;
        if self.head.is_some_and(|head| head.is_nil())
            || (self.head.is_none() != (self.checkpoint == 0))
        {
            return Err(ControlError::Invalid);
        }
        let envelope: MultiEventStateEnvelope =
            serde_json::from_slice(&self.state.bytes).map_err(|_| ControlError::Invalid)?;
        envelope.encode()?;
        if envelope.checkpoint != self.checkpoint || !envelope.canonical_sequences.is_empty() {
            return Err(ControlError::Fenced);
        }
        Ok(())
    }
}
pub(crate) async fn run(
    db: &tokio_postgres::Client,
    token: &LeaseToken,
    input: &SensorBootstrap,
    context: &ControlContext,
    routines: [u8; 32],
) -> Result<StateReadResult, ControlError> {
    input.validate()?;
    verify(db, context).await?;
    let raw = crate::publication::encode(
        &serde_json::json!({"schema_version":1,"head":input.head,"checkpoint":input.checkpoint,
        "state":{"key":input.state.key,"revision":crate::publication::hex(&input.state.revision),"bytes":crate::publication::hex(&input.state.bytes)}}),
    )?;
    let t = serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
    let schema = crate::schema_identity().0;
    let value: serde_json::Value = db
        .query_one(
            "SELECT signal_sensor_bootstrap.initialize($1,$2,$3,$4)",
            &[&t, &raw, &&schema[..], &&routines[..]],
        )
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    let result = crate::state_read::decode(
        value,
        token,
        &StateReadInput {
            key: input.state.key.clone(),
            expected_head: input.head,
        },
    )?;
    if result.checkpoint != input.checkpoint
        || result
            .state
            .as_ref()
            .is_none_or(|s| s.bytes != input.state.bytes || s.revision != input.state.revision)
    {
        return Err(ControlError::Corrupt);
    }
    context.check()?;
    Ok(result)
}
use crate::{ControlContext, ControlError};
use sha2::{Digest, Sha256};
pub(crate) async fn verify(
    db: &tokio_postgres::Client,
    context: &ControlContext,
) -> Result<(), ControlError> {
    context.check()?;
    let source = include_str!("../../../schemas/shared-control/021-sensor-bootstrap.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_sensor_bootstrap' AND p.proname='initialize' AND p.pronargs=4 AND p.pronargdefaults=0 AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='bytea'::regtype AND p.proargtypes[2]='bytea'::regtype AND p.proargtypes[3]='bytea'::regtype AND p.prorettype='jsonb'::regtype AND p.prokind='f' AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1 AND (SELECT count(*) FROM pg_proc x WHERE x.pronamespace=n.oid)=1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zero_checkpoint_requires_empty_references_and_no_head() -> Result<(), ControlError> {
        let value = MultiEventStateEnvelope {
            schema_version: 1,
            scope_generation: Uuid::from_u128(1),
            checkpoint: 0,
            metadata: serde_json::json!({"canonical_sha256":{}}),
            canonical_sequences: Default::default(),
        };
        let mut input = SensorBootstrap {
            head: None,
            checkpoint: 0,
            state: RevisionedState {
                key: "sensor".into(),
                revision: [1; 32],
                bytes: value.encode()?,
            },
        };
        input.validate()?;
        input.head = Some(Uuid::from_u128(2));
        assert!(matches!(input.validate(), Err(ControlError::Invalid)));
        let mut invalid = value;
        invalid.canonical_sequences.insert(Uuid::from_u128(3), 1);
        assert!(invalid.encode().is_err());
        Ok(())
    }
}
