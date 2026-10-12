use super::*;
use chrono::{Duration as ChronoDuration, Utc};
use signal_control::{CanonicalObjectRef, ObjectCustodyDescription, ObjectCustodyVerifier};
use signal_server::shared_custody::{ConfiguredCustodyVerifier, CustodyBinding};
fn scope() -> Scope {
    Scope {
        schema_version: 1,
        store_id: Uuid::from_u128(0xc100),
        generation: Uuid::from_u128(0xc101),
        tenant: "synthetic-custody".into(),
        stream: Uuid::from_u128(0xc102),
        partition_id: Uuid::from_u128(0xc103),
    }
}
fn binding() -> CustodyBinding {
    CustodyBinding {
        scope: scope(),
        backend: Uuid::from_u128(0xc104),
        key_prefix: "custody/original/".into(),
        authority_revision: [7; 32],
        required_until: Utc::now() + ChronoDuration::hours(1),
    }
}
fn description(required_until: chrono::DateTime<Utc>) -> ObjectCustodyDescription {
    ObjectCustodyDescription {
        schema_version: 1,
        id: Uuid::from_u128(0xc105),
        scope: scope(),
        object: CanonicalObjectRef {
            schema_version: 1,
            backend_id: Uuid::from_u128(0xc104),
            key: "custody/original/source".into(),
            version: "v1".into(),
        },
        bytes: 4,
        sha256: signal_storage::object_manifest::sha256(b"body"),
        retain_until: required_until,
    }
}
fn objects() -> Result<Arc<ObjectIo>> {
    Ok(Arc::new(ObjectIo::remote(
        Arc::new(object_store::memory::InMemory::new()),
        tokio::runtime::Handle::current(),
        ObjectIoLimits::default(),
    )?))
}
#[tokio::test]
async fn configured_scope_backend_prefix_and_retention_fail_before_object_io() -> Result {
    let b = binding();
    let original = description(b.required_until);
    let io = objects()?;
    let verifier = ConfiguredCustodyVerifier::new(b, io.clone())?;
    let mut candidates = Vec::new();
    let mut d = original.clone();
    d.scope.generation = Uuid::from_u128(99);
    candidates.push(d);
    let mut d = original.clone();
    d.scope.tenant = "foreign".into();
    candidates.push(d);
    let mut d = original.clone();
    d.object.backend_id = Uuid::from_u128(99);
    candidates.push(d);
    for key in [
        "custody/originals/source",
        "custody/original/",
        "custody/original/../source",
        "custody/original//source",
    ] {
        let mut d = original.clone();
        d.object.key = key.into();
        candidates.push(d);
    }
    let mut d = original.clone();
    d.retain_until -= ChronoDuration::seconds(1);
    candidates.push(d);
    for d in candidates {
        assert!(matches!(
            verifier.verify(&d, context()?).await,
            Err(ControlError::Fenced | ControlError::Invalid)
        ));
    }
    let cancelled = context()?;
    cancelled.cancel();
    assert!(matches!(
        verifier.verify(&original, cancelled).await,
        Err(ControlError::Cancelled)
    ));
    assert_eq!(io.metrics().processed, 0);
    io.shutdown(signal_storage::OperationContext::new(Duration::from_secs(
        2,
    )))
    .await?;
    Ok(())
}
#[tokio::test]
async fn configured_binding_and_missing_retention_capability_fail_closed() -> Result {
    let io = objects()?;
    for prefix in [
        "",
        "/custody/",
        "custody",
        "custody//",
        "custody/../",
        "custody/./",
    ] {
        let mut b = binding();
        b.key_prefix = prefix.into();
        assert!(ConfiguredCustodyVerifier::new(b, io.clone()).is_err());
    }
    let mut b = binding();
    b.backend = Uuid::nil();
    assert!(ConfiguredCustodyVerifier::new(b, io.clone()).is_err());
    let mut b = binding();
    b.authority_revision = [0; 32];
    assert!(ConfiguredCustodyVerifier::new(b, io.clone()).is_err());
    let mut b = binding();
    b.required_until = Utc::now() - ChronoDuration::seconds(1);
    assert!(ConfiguredCustodyVerifier::new(b, io.clone()).is_err());
    let b = binding();
    let d = description(b.required_until);
    let verifier = ConfiguredCustodyVerifier::new(b, io.clone())?;
    assert_eq!(verifier.authority_revision(), [7; 32]);
    assert!(matches!(
        verifier.verify(&d, context()?).await,
        Err(ControlError::Invalid)
    ));
    io.shutdown(signal_storage::OperationContext::new(Duration::from_secs(
        2,
    )))
    .await?;
    Ok(())
}
#[cfg(feature = "s3-query")]
#[path = "shared_custody_runtime.rs"]
mod runtime;
