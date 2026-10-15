//! Fenced metadata recovery, never an independent publication or tenant grant.
use crate::{ControlContext, ControlError, ITEM_BYTES, LeaseToken, RevisionedState};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio_postgres::Client;
use uuid::Uuid;
#[derive(Clone)]
pub struct StateReadInput {
    pub key: String,
    pub expected_head: Option<Uuid>,
}
impl StateReadInput {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.key.is_empty()
            || self.key.len() > 256
            || self.key.capacity() > 256
            || self.key.chars().any(char::is_control)
            || self.expected_head.is_some_and(|id| id.is_nil())
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct StateReadResult {
    pub schema_version: u32,
    pub partition_id: Uuid,
    pub head: Option<Uuid>,
    pub checkpoint: u64,
    /// Absence is unavailable recovery evidence, not an empty detector state.
    pub state: Option<RevisionedState>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireState {
    key: String,
    revision: String,
    bytes: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: u32,
    partition_id: Uuid,
    head: Option<Uuid>,
    checkpoint: u64,
    state: Option<WireState>,
}
fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ControlError> {
    if text.len() > maximum * 2 || !text.len().is_multiple_of(2) {
        return Err(ControlError::Corrupt);
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(ControlError::Corrupt),
    };
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(digit(pair[0])? * 16 + digit(pair[1])?))
        .collect()
}
pub(crate) fn decode(
    value: serde_json::Value,
    token: &LeaseToken,
    input: &StateReadInput,
) -> Result<StateReadResult, ControlError> {
    let wire: Wire = serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
    if wire.schema_version != 1
        || wire.partition_id != token.scope.partition_id
        || wire.head != input.expected_head
        || wire.checkpoint > i64::MAX as u64
        || (wire.checkpoint == 0) != wire.head.is_none()
    {
        return Err(ControlError::Corrupt);
    }
    let state = wire
        .state
        .map(|state| {
            if state.key != input.key {
                return Err(ControlError::Corrupt);
            }
            let state = RevisionedState {
                key: state.key,
                revision: unhex(&state.revision, 32)?
                    .try_into()
                    .map_err(|_| ControlError::Corrupt)?,
                bytes: unhex(&state.bytes, ITEM_BYTES)?,
            };
            state.validate().map_err(|_| ControlError::Corrupt)?;
            Ok(state)
        })
        .transpose()?;
    Ok(StateReadResult {
        schema_version: 1,
        partition_id: wire.partition_id,
        head: wire.head,
        checkpoint: wire.checkpoint,
        state,
    })
}
pub(crate) async fn run(
    db: &Client,
    token: &LeaseToken,
    input: &StateReadInput,
    context: &ControlContext,
    routines: [u8; 32],
) -> Result<StateReadResult, ControlError> {
    context.check()?;
    let source = include_str!("../../../schemas/shared-control/009-state-read.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let verified:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_state_read' AND p.proname='read_state' AND p.pronargs=5 AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='text'::regtype AND p.proargtypes[2]='uuid'::regtype AND p.proargtypes[3]='bytea'::regtype AND p.proargtypes[4]='bytea'::regtype AND p.prorettype='jsonb'::regtype AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !verified {
        return Err(ControlError::Fenced);
    }
    context.check()?;
    let scope = serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
    let schema = crate::schema_identity().0;
    let value: serde_json::Value = db
        .query_one(
            "SELECT signal_state_read.read_state($1,$2,$3,$4,$5)",
            &[
                &scope,
                &input.key,
                &input.expected_head,
                &&schema[..],
                &&routines[..],
            ],
        )
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    context.check()?;
    decode(value, token, input)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn token() -> LeaseToken {
        LeaseToken {
            scope: crate::Scope {
                schema_version: 1,
                store_id: Uuid::from_u128(1),
                generation: Uuid::from_u128(2),
                tenant: "fixture".into(),
                stream: Uuid::from_u128(3),
                partition_id: Uuid::from_u128(4),
            },
            owner: Uuid::from_u128(5),
            epoch: 1,
        }
    }
    #[test]
    fn absent_state_is_explicit_and_reply_identity_bounds_are_checked() -> Result<(), ControlError>
    {
        let token = token();
        let input = StateReadInput {
            key: "counter".into(),
            expected_head: None,
        };
        let empty = serde_json::json!({"schema_version":1,"partition_id":token.scope.partition_id,"head":null,"checkpoint":0,"state":null});
        assert!(decode(empty.clone(), &token, &input)?.state.is_none());
        for (field, replacement) in [
            ("partition_id", serde_json::json!(Uuid::from_u128(99))),
            ("checkpoint", serde_json::json!(1)),
            ("schema_version", serde_json::json!(2)),
        ] {
            let mut changed = empty.clone();
            changed[field] = replacement;
            assert!(decode(changed, &token, &input).is_err());
        }
        let value = serde_json::json!({"schema_version":1,"partition_id":token.scope.partition_id,"head":null,"checkpoint":0,
            "state":{"key":"counter","revision":"01".repeat(32),"bytes":"0102"}});
        assert_eq!(
            decode(value.clone(), &token, &input)?
                .state
                .ok_or(ControlError::Corrupt)?
                .bytes,
            vec![1, 2]
        );
        for (field, replacement) in [
            ("key", serde_json::json!("foreign")),
            ("revision", serde_json::json!("01")),
            ("bytes", serde_json::json!("gg")),
            ("bytes", serde_json::json!("")),
        ] {
            let mut changed = value.clone();
            changed["state"][field] = replacement;
            assert!(decode(changed, &token, &input).is_err());
        }
        assert!(unhex(&"00".repeat(ITEM_BYTES + 1), ITEM_BYTES).is_err());
        assert!(
            StateReadInput {
                key: "\n".into(),
                expected_head: None
            }
            .validate()
            .is_err()
        );
        Ok(())
    }
}
