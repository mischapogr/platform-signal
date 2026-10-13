//! Explicit additive historical-receipt resolution. Metadata grants no custody.
use crate::{ControlContext, ControlError, LeaseToken, ObjectCustodyDescription, ReceiptResult};
use sha2::{Digest, Sha256};
use tokio_postgres::Client;

const SQL: &str = include_str!("../../../schemas/shared-control/009-restored-custody.sql");
pub(crate) enum Action {
    Install {
        owner: String,
    },
    Resolve {
        token: LeaseToken,
        description: Box<ObjectCustodyDescription>,
    },
}
fn owner_valid(owner: &str) -> bool {
    !owner.is_empty()
        && owner.len() <= 63
        && owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
pub(crate) fn validate(action: &Action) -> Result<(), ControlError> {
    match action {
        Action::Install { owner } if owner_valid(owner) && owner.capacity() <= 63 => Ok(()),
        Action::Install { .. } => Err(ControlError::Invalid),
        Action::Resolve { token, description } => {
            token.validate()?;
            description.validate()?;
            let mut origin = token.scope.clone();
            origin.generation = description.scope.generation;
            if origin != description.scope || token.scope.generation == origin.generation {
                return Err(ControlError::Fenced);
            }
            Ok(())
        }
    }
}
pub(crate) async fn install(
    db: &Client,
    owner: &str,
    routines: &[u8],
    context: &ControlContext,
) -> Result<(), ControlError> {
    context.check()?;
    if !owner_valid(owner) {
        return Err(ControlError::Invalid);
    }
    let allowed: bool = db.query_one(
        "SELECT pg_has_role(session_user,$1::name,'MEMBER') AND EXISTS(SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='signal_control' AND r.rolname=$1::text) AND EXISTS(SELECT 1 FROM signal_control.store WHERE singleton AND ready AND revision IN (3,5) AND routines_sha256=$2) AND EXISTS(SELECT 1 FROM signal_control.restore_record r WHERE singleton AND complete AND generation=(SELECT generation FROM signal_control.store WHERE singleton) AND seal=signal_control.restore_record_seal(r))",
        &[&owner,&routines],
    ).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !allowed {
        return Err(ControlError::Fenced);
    }
    db.batch_execute(&format!("SET LOCAL ROLE \"{owner}\""))
        .await
        .map_err(crate::client::database_error)?;
    db.batch_execute(SQL)
        .await
        .map_err(crate::client::database_error)?;
    let artifact: Vec<u8> = Sha256::digest(SQL).to_vec();
    db.execute("INSERT INTO signal_custody_restore.contract SELECT true,1,current_user::name,$1,sha256(convert_to(pg_get_functiondef('signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea)'::regprocedure),'UTF8'))",&[&artifact])
        .await.map_err(crate::client::database_error)?;
    context.check()
}
pub(crate) async fn resolve(
    db: &Client,
    token: &LeaseToken,
    description: &ObjectCustodyDescription,
    schema: &[u8],
    routines: &[u8],
    context: &ControlContext,
) -> Result<ReceiptResult, ControlError> {
    context.check()?;
    let raw = description.input()?.wire()?;
    let token = serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
    let artifact: Vec<u8> = Sha256::digest(SQL).to_vec();
    let value: serde_json::Value = db
        .query_one(
            "SELECT signal_custody_restore.resolve($1,$2,$3,$4,$5)",
            &[&token, &raw, &schema, &routines, &artifact],
        )
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    let result: ReceiptResult = serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
    if result.schema_version != 1
        || result.id != description.id
        || result.prepared_count != 0
        || result.source_record_count != 0
        || result.verified_prefix != 0
    {
        return Err(ControlError::Corrupt);
    }
    context.check()?;
    Ok(result)
}
