//! Explicit host-owned Standard bootstrap. This does not enable shared readiness.
use signal_buffer::{BufferMetrics, DurableBuffer, Policy};
use signal_control::{
    CatalogInput, CatalogPin, ConnectionSettings, ControlClient, ControlContext, ControlError,
    ControlMetrics, Scope,
};
use std::sync::Arc;
use uuid::Uuid;

/// Select an exact supported schema; never discover, install, migrate or fall back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogProfile {
    Catalog4,
    RestoredCatalog5,
}

/// Retains the client even after failed verification, for bounded physical drain.
/// ConnectionSettings captures credentials and verified TLS explicitly. Its
/// numeric-loopback fixture constructor is laboratory-only, not a TLS fallback.
pub struct SharedStartup {
    control: Arc<ControlClient>,
    scope: Scope,
    backend: Uuid,
    wal: Arc<DurableBuffer>,
}

/// Original finite catalog capability, not a persisted startup/READY certificate.
/// A caller must recheck it at each transition; reads do not renew its lifetime.
pub struct VerifiedStartup {
    catalog: CatalogPin,
    context: ControlContext,
    wal: Arc<DurableBuffer>,
    scope: Scope,
    backend: Uuid,
}

fn validate_wal(scope: &Scope, wal: BufferMetrics) -> Result<(), ControlError> {
    if wal.stream_id != scope.stream {
        return Err(ControlError::Fenced);
    }
    if wal.closed {
        return Err(ControlError::Unavailable);
    }
    if wal.dropped != 0
        || wal.corruptions != 0
        || wal.checkpoint > wal.last_sequence
        || wal.last_sequence > i64::MAX as u64
    {
        return Err(ControlError::Corrupt);
    }
    Ok(())
}

impl SharedStartup {
    pub fn new(
        connection: ConnectionSettings,
        profile: CatalogProfile,
        scope: Scope,
        backend: Uuid,
        wal: Arc<DurableBuffer>,
    ) -> Result<Self, ControlError> {
        scope.validate()?;
        if backend.is_nil() || wal.policy() == Policy::DropOldest {
            return Err(ControlError::Invalid);
        }
        validate_wal(&scope, wal.snapshot())?;
        let client = match profile {
            CatalogProfile::Catalog4 => ControlClient::catalog(connection)?,
            CatalogProfile::RestoredCatalog5 => ControlClient::restored_catalog(connection)?,
        };
        Ok(Self {
            control: Arc::new(client),
            scope,
            backend,
            wal,
        })
    }

    /// Check one complete database-owned catalog against the existing local WAL.
    /// No lease is acquired, no local prefix is checkpointed and no source ACK is
    /// granted. Committed-but-unacknowledged records require exact replay later.
    pub async fn verify(&self, context: ControlContext) -> Result<VerifiedStartup, ControlError> {
        context.check()?;
        validate_wal(&self.scope, self.wal.snapshot())?;
        let catalog = self
            .control
            .read_catalog_snapshot(
                self.scope.clone(),
                CatalogInput {
                    schema_version: 1,
                    id: Uuid::new_v4(),
                    pin_ms: 5000,
                },
                context.clone(),
            )
            .await?;
        let verified = VerifiedStartup {
            catalog,
            context,
            wal: self.wal.clone(),
            scope: self.scope.clone(),
            backend: self.backend,
        };
        verified.catalog()?;
        Ok(verified)
    }

    /// Host-owned shared dependency; every later operation still checks authority.
    pub fn control(&self) -> Arc<ControlClient> {
        self.control.clone()
    }
    /// Configured native identity mode is a host boundary, not event credentials.
    /// Capture the existing WAL floor before any future Standard HTTP admission.
    /// A changing/closed WAL withholds the capability even after uncertain effects.
    pub async fn enroll_finding_scope(
        &self,
        administrator: &signal_control::FindingScopeAdministrator,
        scope_generation: Uuid,
        startup: Uuid,
        _native_identity: &signal_ingest::identity::IdentityBackend,
        context: ControlContext,
    ) -> Result<signal_control::FindingScopePin, ControlError> {
        context.check()?;
        let before = self.wal.snapshot();
        validate_wal(&self.scope, before)?;
        let pin = administrator
            .enroll(
                signal_control::ProducerEnrollment {
                    scope: self.scope.clone(),
                    scope_generation,
                    startup,
                    wal_floor: before.last_sequence,
                },
                context.clone(),
            )
            .await?;
        let after = self.wal.snapshot();
        validate_wal(&self.scope, after)?;
        let checkpoint = pin.binding()?.checkpoint.ok_or(ControlError::Corrupt)?;
        if before.checkpoint > checkpoint || checkpoint > before.last_sequence {
            return Err(ControlError::Fenced);
        }
        if before.last_sequence != after.last_sequence || before.checkpoint != after.checkpoint {
            return Err(ControlError::Fenced);
        }
        context.check()?;
        pin.binding()?;
        Ok(pin)
    }
    pub fn metrics(&self) -> ControlMetrics {
        self.control.metrics()
    }
    /// Stop dependent query/publication users before closing the control client.
    /// This does not own or checkpoint the WAL; the host drains it separately.
    pub async fn shutdown(&self, context: ControlContext) -> Result<(), ControlError> {
        self.control.shutdown(context).await
    }
}

impl VerifiedStartup {
    pub fn catalog(&self) -> Result<&CatalogPin, ControlError> {
        self.context.check()?;
        let wal = self.wal.snapshot();
        validate_wal(&self.scope, wal)?;
        if self.catalog.backend()? != self.backend {
            return Err(ControlError::Fenced);
        }
        let checkpoint = self.catalog.checkpoint()?;
        if checkpoint < wal.checkpoint || checkpoint > wal.last_sequence {
            return Err(ControlError::Corrupt);
        }
        self.catalog.snapshot()?;
        self.context.check()?;
        Ok(&self.catalog)
    }
}
