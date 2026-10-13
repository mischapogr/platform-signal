use super::*;
#[test]
fn wire_description_preserves_existing_control_bytes_and_digest() -> Result<(), ControlError> {
    let original = description();
    let wire = signal_protocol::object_custody::Description::from(&original);
    assert_eq!(
        serde_json::to_vec(&original).map_err(|_| ControlError::Invalid)?,
        serde_json::to_vec(&wire).map_err(|_| ControlError::Invalid)?
    );
    assert_eq!(
        original.digest()?,
        wire.digest().map_err(|_| ControlError::Invalid)?
    );
    let decoded = ObjectCustodyDescription::try_from(wire)?;
    assert_eq!(decoded, original);
    assert_eq!(decoded.input()?.reference, original.input()?.reference);
    Ok(())
}
use std::sync::{
    Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

struct Backend {
    epoch: AtomicU64,
    records: Mutex<Vec<ReceiptInput>>,
    calls: AtomicUsize,
    uncertain_first: bool,
    stall: bool,
}
impl ObjectCustodyRecorder for Backend {
    fn record<'a>(
        &'a self,
        token: LeaseToken,
        input: ReceiptInput,
        _context: ControlContext,
    ) -> CustodyFuture<'a, ReceiptResult> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if token.epoch != self.epoch.load(Ordering::SeqCst) {
                return Err(ControlError::Fenced);
            }
            {
                let mut records = self.records.lock().map_err(|_| ControlError::Corrupt)?;
                if let Some(old) = records.iter().find(|old| old.id == input.id) {
                    if old.reference != input.reference {
                        return Err(ControlError::Conflict);
                    }
                } else {
                    records.push(input.clone());
                }
            }
            if self.stall {
                std::future::pending::<()>().await;
            }
            if self.uncertain_first && call == 0 {
                return Err(ControlError::Uncertain);
            }
            Ok(ReceiptResult {
                schema_version: 1,
                id: input.id,
                prepared_count: 0,
                source_record_count: 0,
                verified_prefix: 0,
            })
        })
    }
}
struct Verifier<'a> {
    backend: &'a Backend,
    calls: AtomicUsize,
    fail_after_commit: bool,
    takeover: bool,
    substitute_authority: bool,
    invalid_observation: u8,
}
impl ObjectCustodyVerifier for Verifier<'_> {
    fn verify<'a>(
        &'a self,
        description: &'a ObjectCustodyDescription,
        _context: ControlContext,
    ) -> CustodyFuture<'a, RetainedObjectObservation> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_after_commit && call > 0 {
                return Err(ControlError::Unavailable);
            }
            if self.takeover && call == 1 {
                self.backend.epoch.store(2, Ordering::SeqCst);
            }
            Ok(RetainedObjectObservation {
                description_sha256: if self.invalid_observation == 1 {
                    [9; 32]
                } else {
                    description.digest()?
                },
                authority_revision: if self.substitute_authority {
                    [2; 32]
                } else {
                    [1; 32]
                },
                observed_at: Utc::now()
                    - if self.invalid_observation == 2 {
                        chrono::Duration::seconds(1)
                    } else {
                        chrono::Duration::zero()
                    },
                retained_until: description.retain_until
                    - if self.invalid_observation == 3 {
                        chrono::Duration::seconds(1)
                    } else {
                        chrono::Duration::zero()
                    },
            })
        })
    }
}
fn backend(uncertain_first: bool, stall: bool) -> Backend {
    Backend {
        epoch: AtomicU64::new(1),
        records: Mutex::new(Vec::new()),
        calls: AtomicUsize::new(0),
        uncertain_first,
        stall,
    }
}
fn verifier(backend: &Backend) -> Verifier<'_> {
    Verifier {
        backend,
        calls: AtomicUsize::new(0),
        fail_after_commit: false,
        takeover: false,
        substitute_authority: false,
        invalid_observation: 0,
    }
}
fn description() -> ObjectCustodyDescription {
    ObjectCustodyDescription {
        schema_version: 1,
        id: Uuid::from_u128(9),
        scope: Scope {
            schema_version: 1,
            store_id: Uuid::from_u128(1),
            generation: Uuid::from_u128(2),
            tenant: "synthetic-custody".into(),
            stream: Uuid::from_u128(3),
            partition_id: Uuid::from_u128(4),
        },
        object: CanonicalObjectRef {
            schema_version: 1,
            backend_id: Uuid::from_u128(5),
            key: "custody/immutable/original".into(),
            version: "pinned-version".into(),
        },
        bytes: 128,
        sha256: [3; 32],
        retain_until: Utc::now() + chrono::Duration::days(1),
    }
}
fn token(description: &ObjectCustodyDescription) -> LeaseToken {
    LeaseToken {
        scope: description.scope.clone(),
        owner: Uuid::from_u128(6),
        epoch: 1,
    }
}
fn context() -> Result<ControlContext, ControlError> {
    ControlContext::new(std::time::Duration::from_secs(1))
}

#[tokio::test]
async fn lost_commit_reply_reconciles_same_description_and_conflicts_do_not_replace()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = backend(true, false);
    let verifier = verifier(&backend);
    let description = description();
    assert!(matches!(
        coordinate_object_custody(
            &backend,
            &verifier,
            token(&description),
            description.clone(),
            [1; 32],
            context()?
        )
        .await,
        Err(ControlError::Uncertain)
    ));
    let permit = coordinate_object_custody(
        &backend,
        &verifier,
        token(&description),
        description.clone(),
        [1; 32],
        context()?,
    )
    .await?;
    assert_eq!(permit.checked_receipt()?.description, description);
    permit.checked_receipt()?.validate()?;
    let original = backend.records.lock().map_err(|_| "lock")?[0]
        .reference
        .clone();
    let mut conflict = description.clone();
    conflict.sha256 = [4; 32];
    assert!(matches!(
        coordinate_object_custody(
            &backend,
            &verifier,
            token(&conflict),
            conflict,
            [1; 32],
            context()?
        )
        .await,
        Err(ControlError::Conflict)
    ));
    let records = backend.records.lock().map_err(|_| "lock")?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].reference, original);
    Ok(())
}

#[tokio::test]
async fn unavailable_object_after_commit_and_takeover_never_grant_permit()
-> Result<(), Box<dyn std::error::Error>> {
    for takeover in [false, true] {
        let backend = backend(false, false);
        let mut verifier = verifier(&backend);
        verifier.fail_after_commit = !takeover;
        verifier.takeover = takeover;
        let description = description();
        let result = coordinate_object_custody(
            &backend,
            &verifier,
            token(&description),
            description,
            [1; 32],
            context()?,
        )
        .await;
        assert!(matches!(
            result,
            Err(ControlError::Unavailable | ControlError::Fenced)
        ));
        assert_eq!(backend.records.lock().map_err(|_| "lock")?.len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn foreign_scope_expiry_authority_and_null_version_reject_before_control()
-> Result<(), Box<dyn std::error::Error>> {
    let backend = backend(false, false);
    let mut verifier = verifier(&backend);
    let description = description();
    let mut foreign = token(&description);
    foreign.scope.tenant = "foreign".into();
    assert!(matches!(
        coordinate_object_custody(
            &backend,
            &verifier,
            foreign,
            description.clone(),
            [1; 32],
            context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    let mut expired = description.clone();
    expired.retain_until = Utc::now() - chrono::Duration::seconds(1);
    assert!(matches!(
        coordinate_object_custody(
            &backend,
            &verifier,
            token(&expired),
            expired,
            [1; 32],
            context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    let mut invalid = description.clone();
    invalid.object.version = "null".into();
    assert!(matches!(
        coordinate_object_custody(
            &backend,
            &verifier,
            token(&invalid),
            invalid,
            [1; 32],
            context()?
        )
        .await,
        Err(ControlError::Invalid)
    ));
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
    verifier.substitute_authority = true;
    assert!(matches!(
        coordinate_object_custody(
            &backend,
            &verifier,
            token(&description),
            description,
            [1; 32],
            context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn submitted_commit_timeout_is_uncertain_and_permit_cancellation_is_enforced()
-> Result<(), Box<dyn std::error::Error>> {
    let stalled = backend(false, true);
    let stalled_verifier = verifier(&stalled);
    let description = description();
    let short = ControlContext::new(std::time::Duration::from_millis(20))?;
    assert!(matches!(
        coordinate_object_custody(
            &stalled,
            &stalled_verifier,
            token(&description),
            description.clone(),
            [1; 32],
            short
        )
        .await,
        Err(ControlError::Uncertain)
    ));
    assert_eq!(stalled.records.lock().map_err(|_| "lock")?.len(), 1);
    let backend = backend(false, false);
    let verifier = verifier(&backend);
    let ctx = context()?;
    let permit = coordinate_object_custody(
        &backend,
        &verifier,
        token(&description),
        description,
        [1; 32],
        ctx.clone(),
    )
    .await?;
    ctx.cancel();
    assert!(matches!(
        permit.checked_receipt(),
        Err(ControlError::Cancelled)
    ));
    Ok(())
}

#[tokio::test]
async fn stale_substituted_or_shortened_observation_never_submits_control()
-> Result<(), Box<dyn std::error::Error>> {
    for invalid in 1..=3 {
        let backend = backend(false, false);
        let mut verifier = verifier(&backend);
        verifier.invalid_observation = invalid;
        let description = description();
        assert!(matches!(
            coordinate_object_custody(
                &backend,
                &verifier,
                token(&description),
                description,
                [1; 32],
                context()?
            )
            .await,
            Err(ControlError::Fenced)
        ));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
