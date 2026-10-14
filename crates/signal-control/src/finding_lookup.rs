//! Lease-bound immutable finding comparison; never changes or grants scope.
use crate::{ControlContext, ControlError, FindingInput, LeaseToken};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
#[derive(Clone)]
pub(crate) struct Input {
    pub head: Option<Uuid>,
    pub items: Vec<FindingInput>,
}
impl Input {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.head.is_some_and(|id| id.is_nil())
            || self.items.len() > 128
            || self.items.capacity() > 128
        {
            return Err(ControlError::Invalid);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut bytes = 0usize;
        for item in &self.items {
            item.validate()?;
            if !ids.insert(item.id) {
                return Err(ControlError::Conflict);
            }
            bytes = bytes
                .checked_add(item.bytes.len())
                .ok_or(ControlError::Full)?;
            if bytes > 1048576 || item.bytes.capacity() > 65536 {
                return Err(ControlError::Full);
            }
        }
        Ok(())
    }
}
pub(crate) async fn verify(
    db: &tokio_postgres::Client,
    context: &ControlContext,
) -> Result<(), ControlError> {
    let source = include_str!("../../../schemas/shared-control/016-known-findings.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_finding_lookup' AND p.proname='known' AND p.pronargs=4 AND p.pronargdefaults=0 AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='jsonb'::regtype AND p.proargtypes[2]='bytea'::regtype AND p.proargtypes[3]='bytea'::regtype AND p.prorettype='jsonb'::regtype AND p.prokind='f' AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1 AND (SELECT count(*) FROM pg_proc x WHERE x.pronamespace=n.oid)=1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    schema_version: u16,
    partition_id: Uuid,
    head: Option<Uuid>,
    ids: Vec<Uuid>,
}
pub(crate) async fn run(
    db: &tokio_postgres::Client,
    token: &LeaseToken,
    input: &Input,
    context: &ControlContext,
    routines: [u8; 32],
) -> Result<Vec<Uuid>, ControlError> {
    verify(db, context).await?;
    let mut items = Vec::with_capacity(input.items.len());
    for item in &input.items {
        let finding: signal_findings::Finding =
            serde_json::from_slice(&item.bytes).map_err(|_| ControlError::Invalid)?;
        finding.validate().map_err(|_| ControlError::Invalid)?;
        if finding.id != item.id {
            return Err(ControlError::Invalid);
        }
        items.push(serde_json::json!({"id":item.id,"payload":finding}));
    }
    let request = serde_json::json!({"schema_version":1,"head":input.head,"items":items});
    if serde_json::to_vec(&request)
        .map_err(|_| ControlError::Invalid)?
        .len()
        > 2097152
    {
        return Err(ControlError::Full);
    }
    let token_value = serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
    let schema = crate::schema_identity().0;
    let value: serde_json::Value = db
        .query_one(
            "SELECT signal_finding_lookup.known($1,$2,$3,$4)",
            &[&token_value, &request, &&schema[..], &&routines[..]],
        )
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    let reply: Reply = serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
    if reply.schema_version != 1
        || reply.partition_id != token.scope.partition_id
        || reply.head != input.head
        || reply.ids.len() > input.items.len()
        || reply
            .ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != reply.ids.len()
        || reply
            .ids
            .iter()
            .any(|id| !input.items.iter().any(|item| item.id == *id))
    {
        return Err(ControlError::Corrupt);
    }
    context.check()?;
    Ok(reply.ids)
}
