//! Trusted Standard embedding of retained-object observations into control custody.
use chrono::{DateTime, Datelike, Utc};
use signal_control::{
    ControlContext, ControlError, CustodyFuture, ObjectCustodyDescription, ObjectCustodyVerifier,
    RetainedObjectObservation, Scope,
};
use signal_storage::{
    OperationContext,
    object_io::{ObjectIo, ObjectIoError},
    object_manifest::QueryObjectRef,
};
use std::sync::Arc;
use uuid::Uuid;

/// Deployment/application-owned binding. Never deserialize producer policy.
pub struct CustodyBinding {
    pub scope: Scope,
    pub backend: Uuid,
    pub key_prefix: String,
    pub authority_revision: [u8; 32],
    pub required_until: DateTime<Utc>,
}
pub struct ConfiguredCustodyVerifier {
    binding: CustodyBinding,
    objects: Arc<ObjectIo>,
    restored: bool,
}
impl ConfiguredCustodyVerifier {
    pub fn new(binding: CustodyBinding, objects: Arc<ObjectIo>) -> Result<Self, ControlError> {
        Self::configured(binding, objects, false)
    }
    /// Trusted host opt-in. Observations grant no release authority; historical
    /// calls must use the existing-only restored coordinator before object I/O.
    pub fn new_restored(
        binding: CustodyBinding,
        objects: Arc<ObjectIo>,
    ) -> Result<Self, ControlError> {
        Self::configured(binding, objects, true)
    }
    pub fn restored_enabled(&self) -> bool {
        self.restored
    }
    fn configured(
        binding: CustodyBinding,
        objects: Arc<ObjectIo>,
        restored: bool,
    ) -> Result<Self, ControlError> {
        binding.scope.validate()?;
        if binding.backend.is_nil()
            || binding.authority_revision == [0; 32]
            || binding.key_prefix.is_empty()
            || binding.key_prefix.len() >= 512
            || binding.key_prefix.capacity() > 512
            || !binding.key_prefix.ends_with('/')
            || binding.key_prefix.starts_with('/')
            || binding.key_prefix.chars().any(char::is_control)
            || binding.key_prefix.contains(['\\', '%', '?', '#'])
            || binding
                .key_prefix
                .strip_suffix('/')
                .is_none_or(|p| p.split('/').any(|s| s.is_empty() || s == "." || s == ".."))
            || binding.required_until <= Utc::now()
            || !(1..=9999).contains(&binding.required_until.year())
            || binding.required_until.timestamp_subsec_nanos() >= 1_000_000_000
        {
            return Err(ControlError::Invalid);
        }
        Ok(Self {
            binding,
            objects,
            restored,
        })
    }
    pub fn authority_revision(&self) -> [u8; 32] {
        self.binding.authority_revision
    }
    pub fn configured_scope(&self) -> &Scope {
        &self.binding.scope
    }
    fn bound(&self, description: &ObjectCustodyDescription) -> Result<(), ControlError> {
        description.validate()?;
        let mut expected = self.binding.scope.clone();
        if self.restored {
            expected.generation = description.scope.generation;
        }
        if description.scope != expected
            || description.object.backend_id != self.binding.backend
            || !description.object.key.starts_with(&self.binding.key_prefix)
            || description.object.key.len() <= self.binding.key_prefix.len()
            || description
                .object
                .key
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
            || description.retain_until < self.binding.required_until
        {
            return Err(ControlError::Fenced);
        }
        Ok(())
    }
}
impl ObjectCustodyVerifier for ConfiguredCustodyVerifier {
    fn verify<'a>(
        &'a self,
        description: &'a ObjectCustodyDescription,
        context: ControlContext,
    ) -> CustodyFuture<'a, RetainedObjectObservation> {
        Box::pin(async move {
            context.check()?;
            self.bound(description)?;
            let reference = QueryObjectRef {
                key: description.object.key.clone(),
                version: Some(description.object.version.clone()),
                etag: None,
                bytes: description.bytes,
                sha256: description.sha256,
            };
            let retained_until = self
                .objects
                .verify_retained(
                    &reference,
                    description.retain_until,
                    OperationContext {
                        deadline: context.deadline(),
                        cancellation: context.cancellation_token(),
                    },
                )
                .await
                .map_err(object_error)?;
            context.check()?;
            Ok(RetainedObjectObservation {
                description_sha256: description.digest()?,
                authority_revision: self.binding.authority_revision,
                observed_at: Utc::now(),
                retained_until,
            })
        })
    }
}
fn object_error(error: ObjectIoError) -> ControlError {
    match error {
        ObjectIoError::Full => ControlError::Full,
        ObjectIoError::Timeout => ControlError::Timeout,
        ObjectIoError::Cancelled => ControlError::Cancelled,
        ObjectIoError::Corrupt => ControlError::Corrupt,
        ObjectIoError::Condition | ObjectIoError::OwnerBinding => ControlError::Fenced,
        ObjectIoError::Config => ControlError::Invalid,
        _ => ControlError::Unavailable,
    }
}
