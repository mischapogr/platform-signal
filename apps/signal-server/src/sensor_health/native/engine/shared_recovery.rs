//! Bounded protected catalog recovery under one original host budget.
use super::*;
use signal_control::{
    CanonicalRecoveryLimits, CatalogInput, ControlClient, ControlContext, ControlError, LeaseToken,
    PriorStateProvenance, RecoveredCanonicalInputs, StateReadInput,
};
use signal_storage::{object_codec::ObjectCodec, object_io::ObjectIo};

/// Borrows existing physical workers; no journal, lease or worker is created.
pub struct SharedRecovery<'a> {
    pub binding: &'a SharedBinding,
    pub engine: &'a Engine,
    pub control: &'a ControlClient,
    pub objects: &'a ObjectIo,
    pub codec: &'a ObjectCodec,
    pub limits: CanonicalRecoveryLimits,
}
/// Protected original bytes and pin identities, never new observer authority.
pub struct RecoveredSensor {
    pub snapshot: Snapshot,
    pub prior: PriorStateProvenance,
    pub canonical: RecoveredCanonicalInputs,
    pub replay_pins: Vec<Uuid>,
}
impl SharedRecovery<'_> {
    /// Partial or uncertain pin work remains retained. The caller may not mark
    /// ready or release pins after an error merely because this future ended.
    pub async fn recover(
        &self,
        token: LeaseToken,
        context: ControlContext,
    ) -> Result<RecoveredSensor, SharedError> {
        context.check()?;
        self.limits.validate()?;
        token.validate()?;
        if token.scope != self.binding.producer.scope {
            return Err(ControlError::Fenced.into());
        }
        let catalog = self
            .control
            .read_catalog_snapshot(
                token.scope.clone(),
                CatalogInput {
                    schema_version: 1,
                    id: Uuid::new_v4(),
                    pin_ms: 5000,
                },
                context.clone(),
            )
            .await?;
        let context = context.limited_to(catalog.snapshot()?.deadline());
        let rules = RuleContext {
            deadline: context.deadline(),
            cancellation: context.cancellation_token(),
        };
        let read = self
            .control
            .read_state(
                token.clone(),
                StateReadInput {
                    key: self.binding.key.clone(),
                    expected_head: catalog.head()?,
                },
                context.clone(),
            )
            .await?;
        if read.checkpoint != catalog.checkpoint()? {
            return Err(ControlError::Conflict.into());
        }
        let references = self.binding.references(self.engine, &read, &rules)?;
        let canonical = signal_control::recover_canonical_inputs_at(
            &catalog,
            self.objects,
            self.codec,
            &references,
            self.limits,
            context.clone(),
        )
        .await?;
        let (snapshot, prior) =
            self.binding
                .restore(self.engine, &read, canonical.rows()?, &rules)?;
        self.engine.validate_recovery(&snapshot, &rules)?;
        let replay_pins = signal_control::retain_sensor_canonical_inputs(
            self.control,
            token,
            &canonical,
            &self.binding.key,
            self.binding.rule_revision,
            prior.value_sha256,
            context.clone(),
        )
        .await?;
        context.check()?;
        catalog.snapshot()?.check()?;
        Ok(RecoveredSensor {
            snapshot,
            prior,
            canonical,
            replay_pins,
        })
    }
}
