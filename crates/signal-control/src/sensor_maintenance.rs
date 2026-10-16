use crate::{
    FindingInput, LeaseToken, MultiEventStateEnvelope, PriorStateProvenance, RevisionedState,
    StateReadInput, StateReadResult,
};
use uuid::Uuid;
#[derive(Clone)]
pub struct SensorMaintenance {
    pub head: Option<Uuid>,
    pub prior: PriorStateProvenance,
    pub state: RevisionedState,
    pub retired: Vec<FindingInput>,
}
impl SensorMaintenance {
    pub fn validate(&self) -> Result<(), ControlError> {
        self.state.validate()?;
        if self.head.is_some_and(|head| head.is_nil())
            || self.prior.schema_version != 1
            || self.prior.key != self.state.key
            || self.prior.key.capacity() > 256
            || self.prior.revision != self.state.revision
            || self.prior.scope_generation.is_nil()
            || self.retired.len() > 128
            || self.retired.capacity() > 128
        {
            return Err(ControlError::Invalid);
        }
        let envelope: MultiEventStateEnvelope =
            serde_json::from_slice(&self.state.bytes).map_err(|_| ControlError::Invalid)?;
        envelope.encode()?;
        if (self.head.is_none() != (envelope.checkpoint == 0))
            || envelope.checkpoint != self.prior.checkpoint
            || envelope.scope_generation != self.prior.scope_generation
        {
            return Err(ControlError::Fenced);
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut bytes = self
            .state
            .bytes
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(4096))
            .ok_or(ControlError::Full)?;
        for finding in &self.retired {
            bytes = bytes
                .checked_add(finding.bytes.len())
                .ok_or(ControlError::Full)?;
            if bytes > crate::REQUEST_BYTES {
                return Err(ControlError::Full);
            }
            finding.validate()?;
            if !ids.insert(finding.id) {
                return Err(ControlError::Conflict);
            }
        }
        Ok(())
    }
    fn wire(&self) -> Result<Vec<u8>, ControlError> {
        self.validate()?;
        let mut retired = Vec::with_capacity(self.retired.len());
        for input in &self.retired {
            let finding: signal_findings::Finding =
                serde_json::from_slice(&input.bytes).map_err(|_| ControlError::Invalid)?;
            finding.validate().map_err(|_| ControlError::Invalid)?;
            if finding.id != input.id {
                return Err(ControlError::Invalid);
            }
            retired.push(serde_json::json!({"id":input.id,"payload":finding}));
        }
        crate::publication::encode(&serde_json::json!({"schema_version":1,"head":self.head,
            "prior":{"schema_version":1,"key":self.prior.key,"checkpoint":self.prior.checkpoint,
            "revision":crate::publication::hex(&self.prior.revision),"value_sha256":crate::publication::hex(&self.prior.value_sha256),"scope_generation":self.prior.scope_generation},
            "state":{"key":self.state.key,"revision":crate::publication::hex(&self.state.revision),"bytes":crate::publication::hex(&self.state.bytes)},"retired":retired}))
    }
}
pub(crate) async fn run(
    db: &tokio_postgres::Client,
    token: &LeaseToken,
    input: &SensorMaintenance,
    context: &ControlContext,
    routines: [u8; 32],
) -> Result<StateReadResult, ControlError> {
    verify(db, context).await?;
    let raw = input.wire()?;
    let token_value = serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
    let schema = crate::schema_identity().0;
    let value: serde_json::Value = db
        .query_one(
            "SELECT signal_sensor_maintenance.apply($1,$2,$3,$4)",
            &[&token_value, &raw, &&schema[..], &&routines[..]],
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
    if result.checkpoint != input.prior.checkpoint
        || result
            .state
            .as_ref()
            .is_none_or(|s| s.revision != input.state.revision || s.bytes != input.state.bytes)
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
    let source = include_str!("../../../schemas/shared-control/020-sensor-maintenance.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let valid:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_sensor_maintenance' AND p.proname='apply' AND p.pronargs=4 AND p.pronargdefaults=0 AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='bytea'::regtype AND p.proargtypes[2]='bytea'::regtype AND p.proargtypes[3]='bytea'::regtype AND p.prorettype='jsonb'::regtype AND p.prokind='f' AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND sha256(convert_to(p.prosrc,'UTF8'))=$1 AND (SELECT count(*) FROM pg_proc x WHERE x.pronamespace=n.oid)=1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !valid {
        return Err(ControlError::Fenced);
    }
    context.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Result<SensorMaintenance, ControlError> {
        let generation = Uuid::from_u128(3);
        Ok(SensorMaintenance {
            head: Some(Uuid::from_u128(1)),
            prior: PriorStateProvenance {
                schema_version: 1,
                key: "sensor".into(),
                checkpoint: 1,
                revision: [1; 32],
                value_sha256: [2; 32],
                scope_generation: generation,
            },
            state: RevisionedState {
                key: "sensor".into(),
                revision: [1; 32],
                bytes: MultiEventStateEnvelope {
                    schema_version: 1,
                    scope_generation: generation,
                    checkpoint: 1,
                    metadata: serde_json::json!({"canonical_sha256":{}}),
                    canonical_sequences: Default::default(),
                }
                .encode()?,
            },
            retired: Vec::new(),
        })
    }
    fn finding(id: u128, padding: usize) -> Result<FindingInput, ControlError> {
        let id = Uuid::from_u128(id);
        let bytes=serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":id,"rule_id":"fixture","created_at":"2026-10-15T00:00:00Z","severity":"high","title":"fixture","event_ids":[Uuid::from_u128(10)],"attributes":{"fixture":"x".repeat(padding)}})).map_err(|_|ControlError::Invalid)?.into_boxed_slice().into_vec();
        Ok(FindingInput { id, bytes })
    }
    #[test]
    fn bounded_admission_refuses_spare_capacity_duplicate_ids_and_total_bytes()
    -> Result<(), ControlError> {
        input()?.validate()?;
        let mut oversized = input()?;
        let mut key = String::with_capacity(512);
        key.push_str("sensor");
        oversized.prior.key = key;
        assert!(matches!(oversized.validate(), Err(ControlError::Invalid)));
        let mut oversized = input()?;
        oversized.retired = Vec::with_capacity(129);
        assert!(matches!(oversized.validate(), Err(ControlError::Invalid)));
        let mut duplicate = input()?;
        duplicate.retired = vec![finding(4, 0)?; 2];
        assert!(matches!(duplicate.validate(), Err(ControlError::Conflict)));
        let mut oversized = input()?;
        oversized.retired = (1..=18)
            .map(|id| finding(id, 60000))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(matches!(oversized.validate(), Err(ControlError::Full)));
        let mut foreign = input()?;
        foreign.prior.scope_generation = Uuid::from_u128(4);
        assert!(matches!(foreign.validate(), Err(ControlError::Fenced)));
        Ok(())
    }
}
