//! Explicit stopped physical-generation migration; logical output identity stays fixed.
use crate::{AdministrativeScope, ControlError, MultiEventStateEnvelope, RevisionedState, Scope};
use serde::{Deserialize, Serialize};
use tokio_postgres::{Client, Row};
use uuid::Uuid;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateScopeRebindInput {
    pub schema_version: u16,
    pub scope: AdministrativeScope,
    pub current: Scope,
    pub old_generation: Uuid,
    pub source: RevisionedState,
    pub target: RevisionedState,
}
impl StateScopeRebindInput {
    pub fn new(
        current: Scope,
        old_generation: Uuid,
        source: RevisionedState,
    ) -> Result<Self, ControlError> {
        let target = target(&current, old_generation, &source)?;
        Ok(Self {
            schema_version: 1,
            scope: AdministrativeScope {
                schema_version: 1,
                store_id: current.store_id,
                generation: current.generation,
            },
            current,
            old_generation,
            source,
            target,
        })
    }
    pub fn validate(&self) -> Result<(), ControlError> {
        self.scope.validate()?;
        self.target.validate()?;
        if self.schema_version != 1
            || self.scope.store_id != self.current.store_id
            || self.scope.generation != self.current.generation
        {
            return Err(ControlError::Invalid);
        }
        if self.target != target(&self.current, self.old_generation, &self.source)? {
            return Err(ControlError::Conflict);
        }
        Ok(())
    }
}
fn target(
    current: &Scope,
    old_generation: Uuid,
    source: &RevisionedState,
) -> Result<RevisionedState, ControlError> {
    current.validate()?;
    source.validate()?;
    if old_generation.is_nil() || old_generation == current.generation || source.revision == [0; 32]
    {
        return Err(ControlError::Invalid);
    }
    let mut frame: MultiEventStateEnvelope =
        serde_json::from_slice(&source.bytes).map_err(|_| ControlError::Corrupt)?;
    frame.encode()?;
    let old: Scope = serde_json::from_value(
        frame
            .metadata
            .get("scope")
            .cloned()
            .ok_or(ControlError::Corrupt)?,
    )
    .map_err(|_| ControlError::Corrupt)?;
    let mut expected = current.clone();
    expected.generation = old_generation;
    if old != expected {
        return Err(ControlError::Fenced);
    }
    frame.metadata["scope"]["generation"] =
        serde_json::to_value(current.generation).map_err(|_| ControlError::Invalid)?;
    Ok(RevisionedState {
        key: source.key.clone(),
        revision: source.revision,
        bytes: frame.encode()?,
    })
}
pub(crate) async fn run(
    db: &Client,
    owner: &str,
    input: &StateScopeRebindInput,
) -> Result<Row, ControlError> {
    input.validate()?;
    db.batch_execute("LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT")
        .await
        .map_err(crate::client::database_error)?;
    crate::administration::inspect_profile(db, owner, 5).await?;
    let (schema, routines) = crate::restored_catalog_schema_identity();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM signal_control.store s JOIN signal_control.restore_record r ON r.singleton WHERE s.singleton AND NOT s.ready AND s.revision=5 AND s.store_id=$1 AND s.generation=$2 AND s.schema_sha256=$3 AND s.routines_sha256=$4 AND r.complete AND r.generation=s.generation AND r.old_generation=$5 AND r.seal=signal_control.restore_record_seal(r)) AND NOT EXISTS(SELECT 1 FROM signal_control.partitions WHERE owner IS NOT NULL OR lease_until IS NOT NULL)",&[&input.current.store_id,&input.current.generation,&&schema[..],&&routines[..],&input.old_generation]).await.map_err(crate::client::database_error)?.get(0);
    if !valid {
        return Err(ControlError::Fenced);
    }
    crate::administration::validate_restored_catalog_state(db).await?;
    let part=db.query_opt("SELECT checkpoint FROM signal_control.partitions WHERE id=$1 AND tenant=$2 AND stream=$3 AND kind='pipeline' FOR UPDATE",&[&input.current.partition_id,&input.current.tenant,&input.current.stream]).await.map_err(crate::client::database_error)?.ok_or(ControlError::Fenced)?;
    let frame: MultiEventStateEnvelope =
        serde_json::from_slice(&input.source.bytes).map_err(|_| ControlError::Corrupt)?;
    if u64::try_from(part.get::<_, i64>(0)).map_err(|_| ControlError::Corrupt)? != frame.checkpoint
    {
        return Err(ControlError::Conflict);
    }
    let row=db.query_opt("SELECT revision,value FROM signal_control.state WHERE partition_id=$1 AND key=$2 FOR UPDATE",&[&input.current.partition_id,&input.source.key]).await.map_err(crate::client::database_error)?.ok_or(ControlError::Conflict)?;
    let revision: Vec<u8> = row.get(0);
    let value: Vec<u8> = row.get(1);
    if revision != input.source.revision {
        return Err(ControlError::Conflict);
    }
    if value != input.target.bytes {
        if value != input.source.bytes {
            return Err(ControlError::Conflict);
        }
        let delta = input.target.bytes.len() as i64 - input.source.bytes.len() as i64;
        let charged=db.execute("UPDATE signal_control.store SET used_bytes=used_bytes+$1::bigint WHERE singleton AND ($1::bigint<=0 OR $1::bigint<=max_bytes-used_bytes)",&[&delta]).await.map_err(crate::client::database_error)?;
        if charged != 1 {
            return Err(ControlError::Full);
        }
        db.execute(
            "UPDATE signal_control.state SET value=$1 WHERE partition_id=$2 AND key=$3",
            &[
                &input.target.bytes,
                &input.current.partition_id,
                &input.source.key,
            ],
        )
        .await
        .map_err(crate::client::database_error)?;
    }
    crate::administration::validate_restored_catalog_state(db).await?;
    db.query_one("SELECT jsonb_build_object('schema_version',1,'store_id',store_id,'generation',generation,'revision',revision,'ready',ready,'routines_sha256',encode(routines_sha256,'hex')) FROM signal_control.store WHERE singleton",&[]).await.map_err(crate::client::database_error)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Result<StateScopeRebindInput, ControlError> {
        let old = Scope {
            schema_version: 1,
            store_id: Uuid::from_u128(0xabcd),
            generation: Uuid::from_u128(2),
            tenant: "fixture".into(),
            stream: Uuid::from_u128(3),
            partition_id: Uuid::from_u128(4),
        };
        let mut source=RevisionedState{key:"fixture".into(),revision:[1;32],bytes:MultiEventStateEnvelope{schema_version:1,scope_generation:Uuid::from_u128(9),checkpoint:2,metadata:serde_json::json!({"scope":old,"canonical_sha256":{},"pending":{"original_id":"fixture-original","original_body":[1,2,3]},"private":{"nested":true}}),canonical_sequences:Default::default()}.encode()?};
        let mut value: serde_json::Value =
            serde_json::from_slice(&source.bytes).map_err(|_| ControlError::Invalid)?;
        value["metadata"]["scope"]["store_id"] =
            serde_json::json!(old.store_id.to_string().to_uppercase());
        source.bytes = serde_json::to_vec(&value).map_err(|_| ControlError::Invalid)?;
        let mut current = old;
        current.generation = Uuid::from_u128(5);
        StateScopeRebindInput::new(current, Uuid::from_u128(2), source)
    }
    #[test]
    fn only_physical_generation_changes_and_request_round_trips()
    -> Result<(), Box<dyn std::error::Error>> {
        let input = request()?;
        input.validate()?;
        let original: MultiEventStateEnvelope = serde_json::from_slice(&input.source.bytes)?;
        let rebound: MultiEventStateEnvelope = serde_json::from_slice(&input.target.bytes)?;
        assert_eq!(original.scope_generation, rebound.scope_generation);
        let mut expected = serde_json::to_value(&original)?;
        expected["metadata"]["scope"]["generation"] = serde_json::json!(input.current.generation);
        assert_eq!(serde_json::to_value(&rebound)?, expected);
        assert_eq!(original.metadata["pending"], rebound.metadata["pending"]);
        let restored: StateScopeRebindInput = serde_json::from_slice(&serde_json::to_vec(&input)?)?;
        assert_eq!(restored, input);
        restored.validate()?;
        Ok(())
    }
    #[test]
    fn changed_output_logical_generation_and_wrong_source_scope_are_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        for pointer in [
            "/scope_generation",
            "/metadata/pending/original_id",
            "/metadata/private/nested",
        ] {
            let mut input = request()?;
            let mut value: serde_json::Value = serde_json::from_slice(&input.target.bytes)?;
            *value.pointer_mut(pointer).ok_or("pointer")? = serde_json::json!(Uuid::from_u128(77));
            input.target.bytes = serde_json::to_vec(&value)?;
            assert!(matches!(input.validate(), Err(ControlError::Conflict)));
        }
        let mut input = request()?;
        input.current.stream = Uuid::from_u128(55);
        assert!(matches!(input.validate(), Err(ControlError::Fenced)));
        let mut input = request()?;
        input.old_generation = input.current.generation;
        assert!(matches!(input.validate(), Err(ControlError::Invalid)));
        Ok(())
    }
}
