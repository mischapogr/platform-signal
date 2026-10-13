//! Explicit additive historical-receipt resolution. Metadata grants no custody.
use crate::{ControlContext, ControlError, LeaseToken, ObjectCustodyDescription, ReceiptResult};
use sha2::{Digest, Sha256};
use tokio_postgres::Client;

const SQL: &str = include_str!("../../../schemas/shared-control/009-restored-custody.sql");
pub(crate) enum Action {
    Inspect {
        owner: String,
    },
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
        Action::Install { owner } | Action::Inspect { owner }
            if owner_valid(owner) && owner.capacity() <= 63 =>
        {
            Ok(())
        }
        Action::Install { .. } | Action::Inspect { .. } => Err(ControlError::Invalid),
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

/// One singleton contract is public mechanism metadata, never a workflow row.
pub(crate) async fn inspect(
    db: &Client,
    owner: &str,
    context: &ControlContext,
) -> Result<(), ControlError> {
    context.check()?;
    let allowed:bool=db.query_one("SELECT NOT pg_has_role(session_user,$1::name,'MEMBER') AND coalesce(has_schema_privilege(session_user,to_regnamespace('signal_custody_restore'),'USAGE'),false) AND coalesce(has_table_privilege(session_user,to_regclass('signal_custody_restore.contract'),'SELECT'),false) AND coalesce(has_function_privilege(session_user,to_regprocedure('signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea)'),'EXECUTE'),false) AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE pg_has_role(session_user,r.oid,'MEMBER') AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname='signal_custody_restore' AND (pg_has_role(r.oid,n.nspowner,'MEMBER') OR has_schema_privilege(r.oid,n.oid,'CREATE'))) OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='signal_custody_restore' AND (has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION') OR (has_function_privilege(r.oid,p.oid,'EXECUTE') AND p.oid<>to_regprocedure('signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea)')))) OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_custody_restore' AND (pg_has_role(r.oid,c.relowner,'MEMBER') OR (c.relkind IN ('r','p','v','m','f') AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES') OR (c.relname<>'contract' AND (has_table_privilege(r.oid,c.oid,'SELECT') OR has_any_column_privilege(r.oid,c.oid,'SELECT'))))) OR (c.relkind='S' AND has_sequence_privilege(r.oid,c.oid,'USAGE,SELECT,UPDATE'))))))",&[&owner]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !allowed {
        return Err(ControlError::Fenced);
    }
    let artifact: Vec<u8> = Sha256::digest(SQL).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM signal_custody_restore.contract cfg JOIN pg_namespace n ON n.nspname='signal_custody_restore' JOIN pg_roles role ON role.oid=n.nspowner JOIN pg_class c ON c.relnamespace=n.oid AND c.relname='contract' JOIN pg_proc p ON p.pronamespace=n.oid AND p.oid='signal_custody_restore.resolve(jsonb,bytea,bytea,bytea,bytea)'::regprocedure WHERE cfg.singleton AND cfg.schema_version=1 AND cfg.owner=$1::name AND role.rolname=$1::name AND c.relowner=n.nspowner AND p.proowner=n.nspowner AND p.prosecdef AND cfg.artifact_sha256=$2 AND cfg.routine_sha256=sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')))",&[&owner,&artifact]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}
