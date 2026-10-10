//! Stopped restore coordination. Backup bytes are evidence, never current authority.
//!
//! Adapters must be supplied explicitly by a trusted embedding application. None
//! deserialize credentials, reconstruct policy, send notifications or delete objects.
use crate::{CanonicalObjectRef, ControlContext, ControlError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, future::Future, pin::Pin};
use uuid::Uuid;

const MEMBERS: usize = 128;
const INVENTORY_BYTES: usize = 256 * 1024;
const SOURCE_ROUTINES: &str =
    include_str!("../../../schemas/shared-control/003-administration.sql");
const SOURCE_SCHEMA: &str = include_str!("../../../schemas/shared-control/001.sql");
pub type RestoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ControlError>> + Send + 'a>>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreObject {
    pub object: CanonicalObjectRef,
    pub sha256: [u8; 32],
    pub bytes: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSourceCursor {
    pub partition_id: Uuid,
    pub epoch: u64,
    pub checkpoint: u64,
    pub feed_position: u64,
    /// Exact opaque external source-progress state; no source ACK is inferred.
    pub state_sha256: [u8; 32],
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRevision {
    pub rule_sha256: [u8; 32],
    pub normalizer: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreConsumerCursor {
    pub consumer_id: Uuid,
    pub position: u64,
    pub digest: [u8; 32],
}
/// Bounded, canonical inventory from the stopped checkpoint. The backend must
/// derive it from actual retained rows and verify the complete source catalog,
/// counters, request seals and feed chain. A dump's own ready/credentials are ignored.
/// Larger inventories require a separately qualified streaming adapter; never truncate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreInventory {
    pub schema_version: u32,
    pub store_id: Uuid,
    pub old_generation: Uuid,
    pub revision: u32,
    pub schema_sha256: [u8; 32],
    pub routines_sha256: [u8; 32],
    pub checkpoint_sha256: [u8; 32],
    pub objects: Vec<RestoreObject>,
    /// Exact object-identity digests for every active evidence/replay/restore root.
    pub protected_objects: Vec<[u8; 32]>,
    pub source_cursors: Vec<RestoreSourceCursor>,
    pub revisions: Vec<RestoreRevision>,
    /// Complete enrolled consumer set with exact restored feed anchors.
    pub consumers: Vec<RestoreConsumerCursor>,
    pub feed_position: u64,
    pub feed_digest: [u8; 32],
    /// Full sealed attempt history, including original authority and outcome bytes.
    pub notification_history_sha256: [u8; 32],
    pub attempted_work: u32,
}
fn nonzero(hash: &[u8; 32]) -> bool {
    *hash != [0; 32]
}
fn bounded_members<T>(items: &Vec<T>) -> Result<(), ControlError> {
    if items.len() > MEMBERS || items.capacity() > MEMBERS {
        return Err(ControlError::Full);
    }
    Ok(())
}
impl RestoreInventory {
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 1
            || self.store_id.is_nil()
            || self.old_generation.is_nil()
            || !matches!(self.revision, 2 | 4)
            || self.schema_sha256 != <[u8; 32]>::from(Sha256::digest(SOURCE_SCHEMA))
            || self.routines_sha256
                != if self.revision == 4 {
                    crate::catalog_schema_identity().1
                } else {
                    <[u8; 32]>::from(Sha256::digest(SOURCE_ROUTINES))
                }
            || !nonzero(&self.checkpoint_sha256)
            || !nonzero(&self.feed_digest)
            || !nonzero(&self.notification_history_sha256)
            || self.feed_position > i64::MAX as u64
            || self.attempted_work > 65536
        {
            return Err(ControlError::Corrupt);
        }
        let seed: [u8; 32] = Sha256::digest(
            [
                b"SIGNAL-FINDINGS-CURSOR-V1".as_slice(),
                self.store_id.as_bytes(),
            ]
            .concat(),
        )
        .into();
        if self.feed_position == 0 && self.feed_digest != seed {
            return Err(ControlError::Corrupt);
        }
        bounded_members(&self.objects)?;
        bounded_members(&self.protected_objects)?;
        bounded_members(&self.source_cursors)?;
        bounded_members(&self.revisions)?;
        bounded_members(&self.consumers)?;
        let mut objects = BTreeSet::new();
        for object in &self.objects {
            let digest = object.object.digest()?;
            if !nonzero(&object.sha256)
                || object.bytes == 0
                || object.bytes > i64::MAX as u64
                || !objects.insert(digest)
            {
                return Err(ControlError::Corrupt);
            }
        }
        let mut roots = BTreeSet::new();
        for root in &self.protected_objects {
            if !objects.contains(root) || !roots.insert(root) {
                return Err(ControlError::Corrupt);
            }
        }
        let mut partitions = BTreeSet::new();
        for cursor in &self.source_cursors {
            if cursor.partition_id.is_nil()
                || cursor.epoch > i64::MAX as u64
                || cursor.checkpoint > i64::MAX as u64
                || (cursor.checkpoint > 0 && cursor.epoch == 0)
                || cursor.feed_position > self.feed_position
                || !nonzero(&cursor.state_sha256)
                || !partitions.insert(cursor.partition_id)
            {
                return Err(ControlError::Corrupt);
            }
        }
        let mut revisions = BTreeSet::new();
        for revision in &self.revisions {
            if !nonzero(&revision.rule_sha256)
                || revision.normalizer.is_empty()
                || revision.normalizer.len() > 256
                || revision.normalizer.capacity() > 256
                || revision.normalizer.chars().any(char::is_control)
                || !revisions.insert((&revision.rule_sha256, &revision.normalizer))
            {
                return Err(ControlError::Corrupt);
            }
        }
        if self.source_cursors.iter().any(|c| c.checkpoint > 0) && self.revisions.is_empty() {
            return Err(ControlError::Corrupt);
        }
        let mut consumers = BTreeSet::new();
        for cursor in &self.consumers {
            if cursor.consumer_id.is_nil()
                || cursor.position > self.feed_position
                || !nonzero(&cursor.digest)
                || (cursor.position == 0 && cursor.digest != seed)
                || (cursor.position == self.feed_position && cursor.digest != self.feed_digest)
                || !consumers.insert(cursor.consumer_id)
            {
                return Err(ControlError::Corrupt);
            }
        }
        // Strict ordering gives one inventory identity; never silently reorder evidence.
        if !self
            .objects
            .windows(2)
            .all(|p| p[0].object.digest().ok() < p[1].object.digest().ok())
            || !self.protected_objects.windows(2).all(|p| p[0] < p[1])
            || !self
                .source_cursors
                .windows(2)
                .all(|p| p[0].partition_id < p[1].partition_id)
            || !self.revisions.windows(2).all(|p| {
                (&p[0].rule_sha256, &p[0].normalizer) < (&p[1].rule_sha256, &p[1].normalizer)
            })
            || !self
                .consumers
                .windows(2)
                .all(|p| p[0].consumer_id < p[1].consumer_id)
        {
            return Err(ControlError::Corrupt);
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32], ControlError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| ControlError::Invalid)?;
        if bytes.len() > INVENTORY_BYTES {
            return Err(ControlError::Full);
        }
        Ok(Sha256::digest([b"SIGNAL-STOPPED-RESTORE-V1".as_slice(), &bytes].concat()).into())
    }
    pub fn source_progress_digest(&self) -> Result<[u8; 32], ControlError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&self.source_cursors).map_err(|_| ControlError::Invalid)?;
        Ok(Sha256::digest([b"SIGNAL-RESTORE-SOURCE-V1".as_slice(), &bytes].concat()).into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreChallenge {
    pub destination_id: Uuid,
    pub new_generation: Uuid,
    pub inventory_sha256: [u8; 32],
    pub checkpoint_sha256: [u8; 32],
}
/// A current decision from a separately supplied trusted adapter. Deliberately
/// not serializable; backup metadata cannot be submitted as an approval object.
/// The adapter validates current approval, fresh destination, actual object
/// custody, credentials, exact rule/normalizer availability and complete consumers.
#[derive(Clone, Debug)]
pub struct RestoreDecision {
    pub challenge: RestoreChallenge,
    pub approval_id: Uuid,
    pub custody_sha256: [u8; 32],
    pub credential_binding_sha256: [u8; 32],
    pub expires_at: tokio::time::Instant,
}
impl RestoreDecision {
    fn check(&self, challenge: &RestoreChallenge) -> Result<(), ControlError> {
        if self.challenge != *challenge
            || self.approval_id.is_nil()
            || !nonzero(&self.custody_sha256)
            || !nonzero(&self.credential_binding_sha256)
            || self.expires_at <= tokio::time::Instant::now()
        {
            return Err(ControlError::Fenced);
        }
        Ok(())
    }
    fn same_authority(&self, other: &Self) -> bool {
        self.challenge == other.challenge
            && self.approval_id == other.approval_id
            && self.custody_sha256 == other.custody_sha256
            && self.credential_binding_sha256 == other.credential_binding_sha256
    }
}
pub trait RestoreAuthority: Send + Sync {
    fn authorize<'a>(
        &'a self,
        challenge: &'a RestoreChallenge,
        inventory: &'a RestoreInventory,
        context: ControlContext,
    ) -> RestoreFuture<'a, RestoreDecision>;
}
/// Explicit provider adapter must read/hash the exact immutable object version,
/// verify its byte count and retain all protected roots under current custody.
/// Success cannot be based only on the backup's own recorded SHA or a HEAD alias.
pub trait RestoreCustody: Send + Sync {
    fn verify<'a>(
        &'a self,
        object: &'a RestoreObject,
        protected: bool,
        decision: &'a RestoreDecision,
        context: ControlContext,
    ) -> RestoreFuture<'a, ()>;
}
/// A permit can only be constructed after current approval and object validation.
/// The database adapter must recheck its expiry under locks before committing.
pub struct RestorePermit {
    inventory: RestoreInventory,
    decision: RestoreDecision,
}
impl RestorePermit {
    pub fn inventory(&self) -> &RestoreInventory {
        &self.inventory
    }
    pub fn decision(&self) -> &RestoreDecision {
        &self.decision
    }
    pub fn check(&self) -> Result<(), ControlError> {
        self.decision.check(&self.decision.challenge)?;
        if self.inventory.digest()? != self.decision.challenge.inventory_sha256 {
            return Err(ControlError::Corrupt);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestoreReceipt {
    pub challenge: RestoreChallenge,
    pub source_progress_sha256: [u8; 32],
    pub notification_history_sha256: [u8; 32],
    pub uncertain_work: u32,
    pub ready: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciledConsumers {
    pub challenge: RestoreChallenge,
    pub consumers: Vec<RestoreConsumerCursor>,
}
/// Constructed only after exact consumer reconciliation and fresh reauthorization.
pub struct RestoreReadyPermit {
    decision: RestoreDecision,
    receipt: RestoreReceipt,
    consumers: Vec<RestoreConsumerCursor>,
}
impl RestoreReadyPermit {
    pub fn decision(&self) -> &RestoreDecision {
        &self.decision
    }
    pub fn receipt(&self) -> &RestoreReceipt {
        &self.receipt
    }
    pub fn consumers(&self) -> &[RestoreConsumerCursor] {
        &self.consumers
    }
    pub fn check(&self) -> Result<(), ControlError> {
        self.decision.check(&self.receipt.challenge)
    }
}
/// Explicitly owned fresh, isolated destination. stage must reject live writers,
/// any ready source, unverified schema/catalog, missing references, inconsistent
/// cursors and a reused destination. No restore callback is invoked at runtime open.
/// commit_generation must atomically revalidate the checkpoint under writer locks,
/// compare the permit's destination ID with its separately enrolled captured
/// destination identity (never a value imported from the backup), revoke all
/// leases, preserve epochs/history/keys/plans, set attempted obligations
/// uncertain and leave readiness false. Reconcile validates each feed anchor against
/// the actual chain. enable rechecks locks, progress, authority, generation and
/// reconciliation before setting ready. Cancellation cleanup stays owned by adapter
/// workers; a dropped mutation must never free a still-active transaction seat.
pub trait StoppedRestoreBackend: Send + Sync {
    fn stage(&self, context: ControlContext) -> RestoreFuture<'_, RestoreInventory>;
    fn commit_generation(
        &self,
        permit: RestorePermit,
        context: ControlContext,
    ) -> RestoreFuture<'_, RestoreReceipt>;
    fn reconcile<'a>(
        &'a self,
        receipt: &'a RestoreReceipt,
        consumers: &'a [RestoreConsumerCursor],
        context: ControlContext,
    ) -> RestoreFuture<'a, ReconciledConsumers>;
    fn enable(
        &self,
        permit: RestoreReadyPermit,
        context: ControlContext,
    ) -> RestoreFuture<'_, RestoreReceipt>;
}
pub(crate) async fn bounded<T>(
    context: &ControlContext,
    mutation: bool,
    future: RestoreFuture<'_, T>,
) -> Result<T, ControlError> {
    context.check()?;
    tokio::select! {
        biased;
        _ = context.cancellation.cancelled() => Err(if mutation { ControlError::Uncertain } else { ControlError::Cancelled }),
        _ = tokio::time::sleep_until(context.deadline) => Err(if mutation { ControlError::Uncertain } else { ControlError::Timeout }),
        result = future => result,
    }
}
async fn verify_objects(
    inventory: &RestoreInventory,
    custody: &dyn RestoreCustody,
    decision: &RestoreDecision,
    context: &ControlContext,
) -> Result<(), ControlError> {
    for object in &inventory.objects {
        decision.check(&decision.challenge)?;
        let protected = inventory
            .protected_objects
            .contains(&object.object.digest()?);
        bounded(
            context,
            false,
            custody.verify(object, protected, decision, context.clone()),
        )
        .await?;
    }
    decision.check(&decision.challenge)
}
/// Finite serial orchestration. Errors never cause retries, downgrade, redetection,
/// source acknowledgement, object deletion or notification effects. A mutation's
/// lost reply remains Uncertain and needs an explicit read-only resolution path.
pub async fn coordinate_stopped_restore(
    backend: &dyn StoppedRestoreBackend,
    authority: &dyn RestoreAuthority,
    custody: &dyn RestoreCustody,
    destination_id: Uuid,
    new_generation: Uuid,
    context: ControlContext,
) -> Result<RestoreReceipt, ControlError> {
    if destination_id.is_nil() || new_generation.is_nil() {
        return Err(ControlError::Invalid);
    }
    let inventory = bounded(&context, false, backend.stage(context.clone())).await?;
    let challenge = RestoreChallenge {
        destination_id,
        new_generation,
        inventory_sha256: inventory.digest()?,
        checkpoint_sha256: inventory.checkpoint_sha256,
    };
    if inventory.old_generation == new_generation {
        return Err(ControlError::Fenced);
    }
    let decision = bounded(
        &context,
        false,
        authority.authorize(&challenge, &inventory, context.clone()),
    )
    .await?;
    decision.check(&challenge)?;
    verify_objects(&inventory, custody, &decision, &context).await?;
    let permit = RestorePermit {
        inventory: inventory.clone(),
        decision: decision.clone(),
    };
    permit.check()?;
    let receipt = bounded(
        &context,
        true,
        backend.commit_generation(permit, context.clone()),
    )
    .await?;
    if receipt.challenge != challenge
        || receipt.ready
        || receipt.source_progress_sha256 != inventory.source_progress_digest()?
        || receipt.notification_history_sha256 != inventory.notification_history_sha256
        || receipt.uncertain_work != inventory.attempted_work
    {
        return Err(ControlError::Corrupt);
    }
    finish_restore(
        backend, authority, custody, inventory, receipt, decision, context,
    )
    .await
}
/// Explicit continuation after read-only resolution of an uncertain barrier or
/// a refused readiness gate. Revalidates original checkpoint evidence, current
/// authority and custody; never retries the generation mutation or resets state.
pub async fn resume_stopped_restore(
    backend: &dyn StoppedRestoreBackend,
    authority: &dyn RestoreAuthority,
    custody: &dyn RestoreCustody,
    inventory: RestoreInventory,
    receipt: RestoreReceipt,
    context: ControlContext,
) -> Result<RestoreReceipt, ControlError> {
    inventory.validate()?;
    let challenge = &receipt.challenge;
    if receipt.ready
        || challenge.destination_id.is_nil()
        || challenge.new_generation.is_nil()
        || challenge.new_generation == inventory.old_generation
        || challenge.inventory_sha256 != inventory.digest()?
        || challenge.checkpoint_sha256 != inventory.checkpoint_sha256
        || receipt.source_progress_sha256 != inventory.source_progress_digest()?
        || receipt.notification_history_sha256 != inventory.notification_history_sha256
        || receipt.uncertain_work != inventory.attempted_work
    {
        return Err(ControlError::Corrupt);
    }
    let decision = bounded(
        &context,
        false,
        authority.authorize(challenge, &inventory, context.clone()),
    )
    .await?;
    decision.check(challenge)?;
    verify_objects(&inventory, custody, &decision, &context).await?;
    finish_restore(
        backend, authority, custody, inventory, receipt, decision, context,
    )
    .await
}
async fn finish_restore(
    backend: &dyn StoppedRestoreBackend,
    authority: &dyn RestoreAuthority,
    custody: &dyn RestoreCustody,
    inventory: RestoreInventory,
    receipt: RestoreReceipt,
    decision: RestoreDecision,
    context: ControlContext,
) -> Result<RestoreReceipt, ControlError> {
    let challenge = receipt.challenge.clone();
    let reconciled = bounded(
        &context,
        false,
        backend.reconcile(&receipt, &inventory.consumers, context.clone()),
    )
    .await?;
    if reconciled.challenge != challenge || reconciled.consumers != inventory.consumers {
        return Err(ControlError::Corrupt);
    }
    let current = bounded(
        &context,
        false,
        authority.authorize(&challenge, &inventory, context.clone()),
    )
    .await?;
    current.check(&challenge)?;
    if !decision.same_authority(&current) {
        return Err(ControlError::Fenced);
    }
    // Custody is checked again at readiness; an earlier valid copy is not a current grant.
    verify_objects(&inventory, custody, &current, &context).await?;
    let ready = RestoreReadyPermit {
        decision: current,
        receipt: receipt.clone(),
        consumers: reconciled.consumers,
    };
    ready.check()?;
    let result = bounded(&context, true, backend.enable(ready, context.clone())).await?;
    let mut expected = receipt;
    expected.ready = true;
    if result != expected {
        return Err(ControlError::Uncertain);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        time::Duration,
    };

    fn inventory() -> Result<RestoreInventory, ControlError> {
        let object = RestoreObject {
            object: CanonicalObjectRef {
                schema_version: 1,
                backend_id: Uuid::from_u128(10),
                key: "query/synthetic/immutable".into(),
                version: "version-1".into(),
            },
            sha256: Sha256::digest(b"actual synthetic immutable bytes").into(),
            bytes: 32,
        };
        Ok(RestoreInventory {
            schema_version: 1,
            store_id: Uuid::from_u128(1),
            old_generation: Uuid::from_u128(2),
            revision: 2,
            schema_sha256: Sha256::digest(SOURCE_SCHEMA).into(),
            routines_sha256: Sha256::digest(SOURCE_ROUTINES).into(),
            checkpoint_sha256: Sha256::digest(b"coherent stopped database bytes").into(),
            protected_objects: vec![object.object.digest()?],
            objects: vec![object],
            source_cursors: vec![RestoreSourceCursor {
                partition_id: Uuid::from_u128(3),
                epoch: 1,
                checkpoint: 5,
                feed_position: 1,
                state_sha256: Sha256::digest(b"exact retained receipt state").into(),
            }],
            revisions: vec![RestoreRevision {
                rule_sha256: Sha256::digest(b"exact rule bytes").into(),
                normalizer: "synthetic-exact-v1".into(),
            }],
            consumers: vec![RestoreConsumerCursor {
                consumer_id: Uuid::from_u128(4),
                position: 1,
                digest: [8; 32],
            }],
            feed_position: 1,
            feed_digest: [8; 32],
            notification_history_sha256: Sha256::digest(
                b"original sealed delivered attempt evidence",
            )
            .into(),
            attempted_work: 1,
        })
    }
    struct Backend {
        inventory: RestoreInventory,
        barriers: AtomicUsize,
        enables: AtomicUsize,
        ready: AtomicBool,
        wrong_progress: bool,
        missing_consumer: bool,
        stall_commit: bool,
    }
    impl Backend {
        fn new() -> Result<Self, ControlError> {
            Ok(Self {
                inventory: inventory()?,
                barriers: AtomicUsize::new(0),
                enables: AtomicUsize::new(0),
                ready: AtomicBool::new(false),
                wrong_progress: false,
                missing_consumer: false,
                stall_commit: false,
            })
        }
        fn stopped(&self) {
            assert!(!self.ready.load(Ordering::SeqCst));
            assert_eq!(self.enables.load(Ordering::SeqCst), 0);
        }
    }
    impl StoppedRestoreBackend for Backend {
        fn stage(&self, _: ControlContext) -> RestoreFuture<'_, RestoreInventory> {
            Box::pin(async { Ok(self.inventory.clone()) })
        }
        fn commit_generation(
            &self,
            permit: RestorePermit,
            _: ControlContext,
        ) -> RestoreFuture<'_, RestoreReceipt> {
            Box::pin(async move {
                permit.check()?;
                self.barriers.fetch_add(1, Ordering::SeqCst);
                if self.stall_commit {
                    std::future::pending::<()>().await;
                }
                Ok(RestoreReceipt {
                    challenge: permit.decision().challenge.clone(),
                    source_progress_sha256: if self.wrong_progress {
                        [0; 32]
                    } else {
                        self.inventory.source_progress_digest()?
                    },
                    notification_history_sha256: self.inventory.notification_history_sha256,
                    uncertain_work: self.inventory.attempted_work,
                    ready: false,
                })
            })
        }
        fn reconcile<'a>(
            &'a self,
            receipt: &'a RestoreReceipt,
            consumers: &'a [RestoreConsumerCursor],
            _: ControlContext,
        ) -> RestoreFuture<'a, ReconciledConsumers> {
            Box::pin(async move {
                Ok(ReconciledConsumers {
                    challenge: receipt.challenge.clone(),
                    consumers: if self.missing_consumer {
                        vec![]
                    } else {
                        consumers.to_vec()
                    },
                })
            })
        }
        fn enable(
            &self,
            permit: RestoreReadyPermit,
            _: ControlContext,
        ) -> RestoreFuture<'_, RestoreReceipt> {
            Box::pin(async move {
                permit.check()?;
                self.enables.fetch_add(1, Ordering::SeqCst);
                self.ready.store(true, Ordering::SeqCst);
                let mut receipt = permit.receipt().clone();
                receipt.ready = true;
                Ok(receipt)
            })
        }
    }
    #[derive(Default)]
    struct Authority {
        calls: AtomicUsize,
        denied: bool,
        revoked: bool,
        wrong_destination: bool,
        expired: bool,
        replaced_credentials: bool,
    }
    impl RestoreAuthority for Authority {
        fn authorize<'a>(
            &'a self,
            challenge: &'a RestoreChallenge,
            _: &'a RestoreInventory,
            _: ControlContext,
        ) -> RestoreFuture<'a, RestoreDecision> {
            Box::pin(async move {
                let call = self.calls.fetch_add(1, Ordering::SeqCst);
                if self.denied || (self.revoked && call > 0) {
                    return Err(ControlError::Fenced);
                }
                let mut binding = challenge.clone();
                if self.wrong_destination {
                    binding.destination_id = Uuid::from_u128(111);
                }
                Ok(RestoreDecision {
                    challenge: binding,
                    approval_id: Uuid::from_u128(9),
                    custody_sha256: [5; 32],
                    credential_binding_sha256: if self.replaced_credentials && call > 0 {
                        [7; 32]
                    } else {
                        [6; 32]
                    },
                    expires_at: tokio::time::Instant::now()
                        + if self.expired {
                            Duration::ZERO
                        } else {
                            Duration::from_secs(5)
                        },
                })
            })
        }
    }
    #[derive(Default)]
    struct Custody {
        calls: AtomicUsize,
        corrupt: bool,
        missing: bool,
        lose_retention: bool,
        stall: bool,
    }
    impl RestoreCustody for Custody {
        fn verify<'a>(
            &'a self,
            object: &'a RestoreObject,
            protected: bool,
            _: &'a RestoreDecision,
            _: ControlContext,
        ) -> RestoreFuture<'a, ()> {
            Box::pin(async move {
                let call = self.calls.fetch_add(1, Ordering::SeqCst);
                assert!(protected);
                if self.stall {
                    std::future::pending::<()>().await;
                }
                if self.missing {
                    return Err(ControlError::Unavailable);
                }
                if self.lose_retention && call > 0 {
                    return Err(ControlError::Fenced);
                }
                let bytes = if self.corrupt {
                    b"corrupt bytes".as_slice()
                } else {
                    b"actual synthetic immutable bytes".as_slice()
                };
                if object.object.version != "version-1"
                    || object.bytes != bytes.len() as u64
                    || object.sha256 != <[u8; 32]>::from(Sha256::digest(bytes))
                {
                    return Err(ControlError::Corrupt);
                }
                Ok(())
            })
        }
    }
    async fn run(
        backend: &Backend,
        authority: &Authority,
        custody: &Custody,
    ) -> Result<RestoreReceipt, ControlError> {
        coordinate_stopped_restore(
            backend,
            authority,
            custody,
            Uuid::from_u128(20),
            Uuid::from_u128(21),
            ControlContext::new(Duration::from_secs(2))?,
        )
        .await
    }
    #[tokio::test]
    async fn current_separate_authority_exact_bytes_and_all_consumers_gate_readiness()
    -> Result<(), ControlError> {
        let backend = Backend::new()?;
        let authority = Authority::default();
        let custody = Custody::default();
        let result = run(&backend, &authority, &custody).await?;
        assert!(result.ready);
        assert_eq!(result.uncertain_work, 1);
        assert_eq!(
            result.notification_history_sha256,
            backend.inventory.notification_history_sha256
        );
        assert_eq!(
            result.source_progress_sha256,
            backend.inventory.source_progress_digest()?
        );
        assert_eq!(backend.barriers.load(Ordering::SeqCst), 1);
        assert_eq!(backend.enables.load(Ordering::SeqCst), 1);
        assert_eq!(authority.calls.load(Ordering::SeqCst), 2);
        assert_eq!(custody.calls.load(Ordering::SeqCst), 2);
        Ok(())
    }
    #[tokio::test]
    async fn backup_consistency_cannot_replace_absent_expired_or_foreign_approval()
    -> Result<(), ControlError> {
        for authority in [
            Authority {
                denied: true,
                ..Authority::default()
            },
            Authority {
                expired: true,
                ..Authority::default()
            },
            Authority {
                wrong_destination: true,
                ..Authority::default()
            },
        ] {
            let backend = Backend::new()?;
            assert!(matches!(
                run(&backend, &authority, &Custody::default()).await,
                Err(ControlError::Fenced)
            ));
            backend.stopped();
            assert_eq!(backend.barriers.load(Ordering::SeqCst), 0);
        }
        Ok(())
    }
    #[tokio::test]
    async fn missing_or_corrupt_exact_version_refuses_generation_barrier()
    -> Result<(), ControlError> {
        for custody in [
            Custody {
                corrupt: true,
                ..Custody::default()
            },
            Custody {
                missing: true,
                ..Custody::default()
            },
        ] {
            let backend = Backend::new()?;
            assert!(matches!(
                run(&backend, &Authority::default(), &custody).await,
                Err(ControlError::Corrupt | ControlError::Unavailable)
            ));
            backend.stopped();
            assert_eq!(backend.barriers.load(Ordering::SeqCst), 0);
        }
        Ok(())
    }
    #[tokio::test]
    async fn revoked_authority_replaced_credentials_or_lost_protection_keep_stopped()
    -> Result<(), ControlError> {
        for authority in [
            Authority {
                revoked: true,
                ..Authority::default()
            },
            Authority {
                replaced_credentials: true,
                ..Authority::default()
            },
        ] {
            let backend = Backend::new()?;
            assert!(matches!(
                run(&backend, &authority, &Custody::default()).await,
                Err(ControlError::Fenced)
            ));
            backend.stopped();
            assert_eq!(backend.barriers.load(Ordering::SeqCst), 1);
        }
        let backend = Backend::new()?;
        assert!(matches!(
            run(
                &backend,
                &Authority::default(),
                &Custody {
                    lose_retention: true,
                    ..Custody::default()
                }
            )
            .await,
            Err(ControlError::Fenced)
        ));
        backend.stopped();
        Ok(())
    }
    #[tokio::test]
    async fn changed_source_progress_or_incomplete_consumers_cannot_enable()
    -> Result<(), ControlError> {
        let mut backend = Backend::new()?;
        backend.wrong_progress = true;
        assert!(matches!(
            run(&backend, &Authority::default(), &Custody::default()).await,
            Err(ControlError::Corrupt)
        ));
        backend.stopped();
        let mut backend = Backend::new()?;
        backend.missing_consumer = true;
        assert!(matches!(
            run(&backend, &Authority::default(), &Custody::default()).await,
            Err(ControlError::Corrupt)
        ));
        backend.stopped();
        Ok(())
    }
    #[tokio::test]
    async fn reused_generation_fails_before_current_authorization() -> Result<(), ControlError> {
        let backend = Backend::new()?;
        let authority = Authority::default();
        assert!(matches!(
            coordinate_stopped_restore(
                &backend,
                &authority,
                &Custody::default(),
                Uuid::from_u128(20),
                backend.inventory.old_generation,
                ControlContext::new(Duration::from_secs(1))?
            )
            .await,
            Err(ControlError::Fenced)
        ));
        assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
        backend.stopped();
        Ok(())
    }
    #[tokio::test]
    async fn deadline_on_object_verification_has_no_database_mutation() -> Result<(), ControlError>
    {
        let backend = Backend::new()?;
        assert!(matches!(
            coordinate_stopped_restore(
                &backend,
                &Authority::default(),
                &Custody {
                    stall: true,
                    ..Custody::default()
                },
                Uuid::from_u128(20),
                Uuid::from_u128(21),
                ControlContext::new(Duration::from_millis(15))?
            )
            .await,
            Err(ControlError::Timeout)
        ));
        assert_eq!(backend.barriers.load(Ordering::SeqCst), 0);
        backend.stopped();
        Ok(())
    }
    #[tokio::test]
    async fn deadline_during_generation_commit_is_uncertain_without_retry_or_enable()
    -> Result<(), ControlError> {
        let mut backend = Backend::new()?;
        backend.stall_commit = true;
        assert!(matches!(
            coordinate_stopped_restore(
                &backend,
                &Authority::default(),
                &Custody::default(),
                Uuid::from_u128(20),
                Uuid::from_u128(21),
                ControlContext::new(Duration::from_millis(15))?
            )
            .await,
            Err(ControlError::Uncertain)
        ));
        assert_eq!(backend.barriers.load(Ordering::SeqCst), 1);
        backend.stopped();
        Ok(())
    }
    #[tokio::test]
    async fn precancelled_restore_never_calls_current_authority_or_mutates()
    -> Result<(), ControlError> {
        let backend = Backend::new()?;
        let authority = Authority::default();
        let context = ControlContext::new(Duration::from_secs(1))?;
        context.cancel();
        assert!(matches!(
            coordinate_stopped_restore(
                &backend,
                &authority,
                &Custody::default(),
                Uuid::from_u128(20),
                Uuid::from_u128(21),
                context,
            )
            .await,
            Err(ControlError::Cancelled)
        ));
        assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.barriers.load(Ordering::SeqCst), 0);
        backend.stopped();
        Ok(())
    }
    #[test]
    fn catalog_restore_requires_its_explicit_source_revision_and_artifact()
    -> Result<(), ControlError> {
        let mut value = inventory()?;
        value.revision = 4;
        assert!(matches!(value.validate(), Err(ControlError::Corrupt)));
        value.routines_sha256 = crate::catalog_schema_identity().1;
        value.validate()?;
        value.revision = 2;
        assert!(matches!(value.validate(), Err(ControlError::Corrupt)));
        value.revision = 5;
        assert!(matches!(value.validate(), Err(ControlError::Corrupt)));
        Ok(())
    }
    #[test]
    fn unsupported_schema_missing_roots_duplicate_or_ahead_cursors_refuse_inventory()
    -> Result<(), ControlError> {
        let original = inventory()?;
        original.validate()?;
        let mut bad = original.clone();
        bad.revision = 3;
        assert!(matches!(bad.validate(), Err(ControlError::Corrupt)));
        let mut bad = original.clone();
        bad.protected_objects[0] = [3; 32];
        assert!(matches!(bad.validate(), Err(ControlError::Corrupt)));
        let mut bad = original.clone();
        bad.consumers[0].position = 2;
        assert!(matches!(bad.validate(), Err(ControlError::Corrupt)));
        let mut bad = original.clone();
        bad.consumers.push(bad.consumers[0].clone());
        assert!(matches!(bad.validate(), Err(ControlError::Corrupt)));
        let mut bad = original.clone();
        bad.revisions.clear();
        assert!(matches!(bad.validate(), Err(ControlError::Corrupt)));
        let mut bad = original.clone();
        bad.objects = Vec::with_capacity(MEMBERS + 1);
        assert!(matches!(bad.validate(), Err(ControlError::Full)));
        let mut bad = original;
        bad.objects[0].object.version = "version-2".into();
        assert!(matches!(bad.validate(), Err(ControlError::Corrupt)));
        Ok(())
    }
}
