//! Explicit restore of separately copied, stopped revision2 or revision4 checkpoints.
//! All transactions use the existing bounded worker/rollback/quarantine lifecycle.
use crate::{
    AdministrativeScope, CanonicalObjectRef, ConnectionSettings, ControlClient, ControlContext,
    ControlError, ControlMetrics, ReconciledConsumers, RestoreChallenge, RestoreConsumerCursor,
    RestoreFuture, RestoreInventory, RestoreObject, RestorePermit, RestoreReadyPermit,
    RestoreReceipt, RestoreRevision, RestoreSourceCursor, StoppedRestoreBackend,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tokio_postgres::{Client, Row};
use uuid::Uuid;

const SQL: &str = include_str!("../../../schemas/shared-control/004-restore.sql");
const CATALOG_SQL: &str = include_str!("../../../schemas/shared-control/006-catalog-restore.sql");
/// Explicit restored-profile identity; selecting this never installs or upgrades.
pub fn restored_schema_identity() -> ([u8; 32], [u8; 32]) {
    (crate::schema_identity().0, Sha256::digest(SQL).into())
}
pub fn restored_catalog_schema_identity() -> ([u8; 32], [u8; 32]) {
    (
        crate::schema_identity().0,
        Sha256::digest(CATALOG_SQL).into(),
    )
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RestoreProfile {
    Legacy,
    Catalog,
    CatalogScoped,
}
impl RestoreProfile {
    fn source_revision(self) -> u32 {
        if self == Self::Legacy { 2 } else { 4 }
    }
    fn destination_revision(self) -> u32 {
        if self == Self::Legacy { 3 } else { 5 }
    }
    fn source_identity(self) -> ([u8; 32], [u8; 32]) {
        if self == Self::Legacy {
            crate::schema_identity()
        } else {
            crate::catalog_schema_identity()
        }
    }
    fn restored_identity(self) -> ([u8; 32], [u8; 32]) {
        if self == Self::Legacy {
            restored_schema_identity()
        } else {
            restored_catalog_schema_identity()
        }
    }
    fn sql(self) -> &'static str {
        if self == Self::Legacy {
            SQL
        } else {
            CATALOG_SQL
        }
    }
    fn artifact(self) -> &'static str {
        if self == Self::Legacy {
            "004-restore.sql"
        } else {
            "006-catalog-restore.sql"
        }
    }
    fn tables(self) -> impl Iterator<Item = &'static str> {
        crate::administration::TABLES
            .iter()
            .copied()
            .chain((self != Self::Legacy).then_some("catalog_snapshots"))
            .chain(["migrations"])
    }
}
/// Separately enrolled destination and currently captured credential binding.
/// These values must never be recovered from the backup's configuration.
#[derive(Clone)]
pub struct RestoreDestination {
    pub id: Uuid,
    pub credential_binding_sha256: [u8; 32],
}
/// Current external consumer state, not a backup's self-reported reconciliation.
/// The adapter verifies the complete supported consumer set and exact feed anchors;
/// it must not silently reset a cursor or execute notifications during validation.
pub trait RestoreConsumers: Send + Sync {
    fn reconcile<'a>(
        &'a self,
        challenge: &'a RestoreChallenge,
        expected: &'a [RestoreConsumerCursor],
        context: ControlContext,
    ) -> RestoreFuture<'a, ReconciledConsumers>;
}
#[derive(Clone)]
pub(crate) struct RestorePlan {
    pub scope: AdministrativeScope,
    pub destination: RestoreDestination,
    pub objects: Vec<RestoreObject>,
    profile: RestoreProfile,
}
pub struct PostgresStoppedRestore {
    client: ControlClient,
    owner: String,
    plan: Arc<RestorePlan>,
    consumers: Arc<dyn RestoreConsumers>,
}
impl PostgresStoppedRestore {
    /// The caller has explicitly created a fresh controlled database and installed
    /// trusted frozen001/002/003, then imported stopped data only. This constructor
    /// does not create databases, execute dump DDL or trust restored credentials.
    pub fn new(
        settings: ConnectionSettings,
        schema_owner: String,
        source_scope: AdministrativeScope,
        destination: RestoreDestination,
        objects: Vec<RestoreObject>,
        consumers: Arc<dyn RestoreConsumers>,
    ) -> Result<Self, ControlError> {
        Self::with_profile(
            settings,
            schema_owner,
            source_scope,
            destination,
            objects,
            consumers,
            RestoreProfile::Legacy,
        )
    }
    /// Explicit revision4 source copied into a fresh trusted catalog schema.
    /// No source3 migration, profile detection or backup-provided DDL is accepted.
    pub fn catalog(
        settings: ConnectionSettings,
        schema_owner: String,
        source_scope: AdministrativeScope,
        destination: RestoreDestination,
        objects: Vec<RestoreObject>,
        consumers: Arc<dyn RestoreConsumers>,
    ) -> Result<Self, ControlError> {
        Self::with_profile(
            settings,
            schema_owner,
            source_scope,
            destination,
            objects,
            consumers,
            RestoreProfile::Catalog,
        )
    }
    /// Explicit catalog4 source with fully populated frozen007/008 scope history.
    /// The independently authorized barrier rebinds only its store generation;
    /// scope generation, producer enrollment, original claims and facts survive.
    pub fn scoped_catalog(
        settings: ConnectionSettings,
        schema_owner: String,
        source_scope: AdministrativeScope,
        destination: RestoreDestination,
        objects: Vec<RestoreObject>,
        consumers: Arc<dyn RestoreConsumers>,
    ) -> Result<Self, ControlError> {
        Self::with_profile(
            settings,
            schema_owner,
            source_scope,
            destination,
            objects,
            consumers,
            RestoreProfile::CatalogScoped,
        )
    }

    fn with_profile(
        settings: ConnectionSettings,
        schema_owner: String,
        source_scope: AdministrativeScope,
        destination: RestoreDestination,
        objects: Vec<RestoreObject>,
        consumers: Arc<dyn RestoreConsumers>,
        profile: RestoreProfile,
    ) -> Result<Self, ControlError> {
        source_scope.validate()?;
        if schema_owner.is_empty()
            || schema_owner.len() > 63
            || schema_owner.capacity() > 63
            || !schema_owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || destination.id.is_nil()
            || destination.credential_binding_sha256 == [0; 32]
            || objects.len() > 128
            || objects.capacity() > 128
        {
            return Err(ControlError::Invalid);
        }
        let mut previous = None;
        for object in &objects {
            let id = object.object.digest()?;
            if previous.is_some_and(|p| p >= id)
                || object.sha256 == [0; 32]
                || object.bytes == 0
                || object.bytes > i64::MAX as u64
            {
                return Err(ControlError::Invalid);
            }
            previous = Some(id);
        }
        Ok(Self {
            client: ControlClient::new(settings)?,
            owner: schema_owner,
            plan: Arc::new(RestorePlan {
                scope: source_scope,
                destination,
                objects,
                profile,
            }),
            consumers,
        })
    }
    /// Read-only resolution before ordinary writers resume. Verifies the retained
    /// barrier, current destination and unchanged checkpoint; never grants readiness.
    pub async fn resolve(&self, context: ControlContext) -> Result<RestoreReceipt, ControlError> {
        match self.submit(RestoreAction::Resolve, context).await? {
            RestoreReply::Receipt(r) => Ok(r.into()),
            _ => Err(ControlError::Corrupt),
        }
    }
    pub fn metrics(&self) -> ControlMetrics {
        self.client.metrics()
    }
    pub async fn shutdown(&self, context: ControlContext) -> Result<(), ControlError> {
        self.client.shutdown(context).await
    }
    async fn submit(
        &self,
        action: RestoreAction,
        mut context: ControlContext,
    ) -> Result<RestoreReply, ControlError> {
        // A verified approval never extends the original operation budget. The
        // owned worker checks this tighter deadline again immediately before COMMIT.
        match &action {
            RestoreAction::Barrier(p) => {
                context.deadline = context.deadline.min(p.decision().expires_at)
            }
            RestoreAction::Enable(p) => {
                context.deadline = context.deadline.min(p.decision().expires_at)
            }
            _ => {}
        }
        context.check()?;
        self.client
            .restore(self.owner.clone(), self.plan.clone(), action, context)
            .await
    }
}
impl StoppedRestoreBackend for PostgresStoppedRestore {
    fn stage(&self, context: ControlContext) -> RestoreFuture<'_, RestoreInventory> {
        Box::pin(async move {
            match self.submit(RestoreAction::Stage, context).await? {
                RestoreReply::Inventory(i) => Ok(i),
                _ => Err(ControlError::Corrupt),
            }
        })
    }
    fn commit_generation(
        &self,
        permit: RestorePermit,
        context: ControlContext,
    ) -> RestoreFuture<'_, RestoreReceipt> {
        Box::pin(async move {
            match self.submit(RestoreAction::Barrier(permit), context).await? {
                RestoreReply::Receipt(r) => Ok(r.into()),
                _ => Err(ControlError::Corrupt),
            }
        })
    }
    fn reconcile<'a>(
        &'a self,
        receipt: &'a RestoreReceipt,
        consumers: &'a [RestoreConsumerCursor],
        context: ControlContext,
    ) -> RestoreFuture<'a, ReconciledConsumers> {
        Box::pin(async move {
            context.check()?;
            let result = crate::restore::bounded(
                &context,
                false,
                self.consumers
                    .reconcile(&receipt.challenge, consumers, context.clone()),
            )
            .await?;
            context.check()?;
            if result.challenge != receipt.challenge || result.consumers != consumers {
                return Err(ControlError::Fenced);
            }
            match self
                .submit(
                    RestoreAction::Reconcile(
                        ReceiptWire::from(receipt.clone()),
                        result.consumers.clone(),
                    ),
                    context,
                )
                .await?
            {
                RestoreReply::Consumers(c)
                    if RestoreChallenge::from(c.challenge.clone()) == receipt.challenge
                        && c.consumers == consumers =>
                {
                    Ok(c.into())
                }
                _ => Err(ControlError::Corrupt),
            }
        })
    }
    fn enable(
        &self,
        permit: RestoreReadyPermit,
        context: ControlContext,
    ) -> RestoreFuture<'_, RestoreReceipt> {
        Box::pin(async move {
            match self.submit(RestoreAction::Enable(permit), context).await? {
                RestoreReply::Receipt(r) => Ok(r.into()),
                _ => Err(ControlError::Corrupt),
            }
        })
    }
}
// Wire responses contain evidence only. No verified permit/credential is deserialized.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptWire {
    challenge: ChallengeWire,
    source_progress_sha256: [u8; 32],
    notification_history_sha256: [u8; 32],
    uncertain_work: u32,
    ready: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChallengeWire {
    destination_id: Uuid,
    new_generation: Uuid,
    inventory_sha256: [u8; 32],
    checkpoint_sha256: [u8; 32],
}
impl From<RestoreChallenge> for ChallengeWire {
    fn from(c: RestoreChallenge) -> Self {
        Self {
            destination_id: c.destination_id,
            new_generation: c.new_generation,
            inventory_sha256: c.inventory_sha256,
            checkpoint_sha256: c.checkpoint_sha256,
        }
    }
}
impl From<ChallengeWire> for RestoreChallenge {
    fn from(c: ChallengeWire) -> Self {
        Self {
            destination_id: c.destination_id,
            new_generation: c.new_generation,
            inventory_sha256: c.inventory_sha256,
            checkpoint_sha256: c.checkpoint_sha256,
        }
    }
}
impl From<RestoreReceipt> for ReceiptWire {
    fn from(r: RestoreReceipt) -> Self {
        Self {
            challenge: r.challenge.into(),
            source_progress_sha256: r.source_progress_sha256,
            notification_history_sha256: r.notification_history_sha256,
            uncertain_work: r.uncertain_work,
            ready: r.ready,
        }
    }
}
impl From<ReceiptWire> for RestoreReceipt {
    fn from(r: ReceiptWire) -> Self {
        Self {
            challenge: r.challenge.into(),
            source_progress_sha256: r.source_progress_sha256,
            notification_history_sha256: r.notification_history_sha256,
            uncertain_work: r.uncertain_work,
            ready: r.ready,
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumersWire {
    challenge: ChallengeWire,
    consumers: Vec<RestoreConsumerCursor>,
}
impl From<ReconciledConsumers> for ConsumersWire {
    fn from(c: ReconciledConsumers) -> Self {
        Self {
            challenge: c.challenge.into(),
            consumers: c.consumers,
        }
    }
}
impl From<ConsumersWire> for ReconciledConsumers {
    fn from(c: ConsumersWire) -> Self {
        Self {
            challenge: c.challenge.into(),
            consumers: c.consumers,
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum RestoreReply {
    Inventory(RestoreInventory),
    Receipt(ReceiptWire),
    Consumers(ConsumersWire),
}
pub(crate) enum RestoreAction {
    Stage,
    Resolve,
    Barrier(RestorePermit),
    Reconcile(ReceiptWire, Vec<RestoreConsumerCursor>),
    Enable(RestoreReadyPermit),
}
fn field<'a, T: tokio_postgres::types::FromSql<'a>>(
    r: &'a Row,
    n: usize,
) -> Result<T, ControlError> {
    r.try_get(n).map_err(|_| ControlError::Corrupt)
}
async fn batch(db: &Client, sql: &str) -> Result<(), ControlError> {
    db.batch_execute(sql)
        .await
        .map_err(crate::client::database_error)
}
async fn verify_history(
    db: &Client,
    profile: RestoreProfile,
    restored: bool,
) -> Result<(), ControlError> {
    let mut artifacts = vec![
        ("001.sql", crate::schema_identity().0),
        ("002-functions.sql", crate::legacy_identity()),
        ("003-administration.sql", crate::schema_identity().1),
    ];
    if profile != RestoreProfile::Legacy {
        artifacts.push(("005-catalog.sql", crate::catalog_schema_identity().1));
    }
    if restored {
        artifacts.push((profile.artifact(), profile.restored_identity().1));
    }
    let conditions = artifacts
        .iter()
        .enumerate()
        .map(|(i, (name, _))| {
            format!(
                "(ordinal={} AND artifact='{name}' AND sha256=${})",
                i + 1,
                i + 1
            )
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    let hashes = artifacts
        .iter()
        .map(|(_, hash)| hash.as_slice())
        .collect::<Vec<_>>();
    let parameters = hashes
        .iter()
        .map(|hash| hash as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect::<Vec<_>>();
    let row = db
        .query_one(
            &format!(
                "SELECT count(*)={} AND bool_and({conditions}) FROM signal_control.migrations",
                artifacts.len()
            ),
            &parameters,
        )
        .await
        .map_err(crate::client::database_error)?;
    if !field::<bool>(&row, 0)? {
        return Err(ControlError::Corrupt);
    }
    Ok(())
}
async fn lock(db: &Client, owner: &str, profile: RestoreProfile) -> Result<(), ControlError> {
    batch(db,&format!("SET LOCAL ROLE \"{owner}\"; SET LOCAL search_path=pg_catalog,signal_control,pg_temp; SET LOCAL TimeZone='UTC'; SET LOCAL bytea_output='hex'; SET LOCAL DateStyle='ISO,YMD'; LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT")).await?;
    batch(
        db,
        &format!(
            "LOCK TABLE {},signal_control.migrations IN ACCESS EXCLUSIVE MODE NOWAIT",
            profile
                .tables()
                .filter(|t| *t != "migrations")
                .map(|t| format!("signal_control.{t}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    )
    .await?;
    let exists = field::<bool>(
        &db.query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='signal_finding_scope')",
            &[],
        )
        .await
        .map_err(crate::client::database_error)?,
        0,
    )?;
    if profile == RestoreProfile::CatalogScoped {
        if !exists {
            return Err(ControlError::Corrupt);
        }
        batch(db,"LOCK TABLE signal_finding_scope.profile,signal_finding_scope.activation,signal_finding_scope.producers,signal_finding_scope.facts,signal_finding_scope.requests IN ACCESS EXCLUSIVE MODE NOWAIT").await?;
    } else if exists {
        // A core-only inventory cannot authorize unaccounted supplemental history.
        return Err(ControlError::Corrupt);
    }
    Ok(())
}
fn hash_json<T: Serialize>(value: &T) -> Result<[u8; 32], ControlError> {
    Ok(Sha256::digest(serde_json::to_vec(value).map_err(|_| ControlError::Corrupt)?).into())
}
async fn table_hash(db: &Client, table: &str) -> Result<[u8; 32], ControlError> {
    // table names are compiled constants; rows are hashed inside PostgreSQL so the
    // result size is independent of retained payload sizes. No LIMIT truncation.
    let sql = format!(
        "SELECT sha256(convert_to(coalesce(jsonb_agg(h ORDER BY h),'[]'::jsonb)::text,'UTF8')) FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS h FROM signal_control.{table} t) s"
    );
    let bytes: Vec<u8> = field(
        &db.query_one(&sql, &[])
            .await
            .map_err(crate::client::database_error)?,
        0,
    )?;
    bytes.try_into().map_err(|_| ControlError::Corrupt)
}
async fn inventory(
    db: &Client,
    owner: &str,
    plan: &RestorePlan,
    context: &ControlContext,
) -> Result<RestoreInventory, ControlError> {
    crate::administration::inspect_profile(db, owner, plan.profile.source_revision() as u8).await?;
    let head=db.query_one("SELECT store_id,generation,revision,ready,schema_sha256,routines_sha256,feed_position,feed_digest,max_rows,max_bytes FROM signal_control.store WHERE singleton LIMIT 2",&[]).await.map_err(crate::client::database_error)?;
    let (schema, routines) = plan.profile.source_identity();
    if field::<Uuid>(&head, 0)? != plan.scope.store_id
        || field::<Uuid>(&head, 1)? != plan.scope.generation
        || field::<bool>(&head, 3)?
    {
        return Err(ControlError::Fenced);
    }
    if field::<i32>(&head, 2)? != plan.profile.source_revision() as i32
        || field::<Vec<u8>>(&head, 4)? != schema
        || field::<Vec<u8>>(&head, 5)? != routines
        || field::<i64>(&head, 8)? > 65536
        || field::<i64>(&head, 9)? > 67108864
    {
        return Err(ControlError::Corrupt);
    }
    verify_history(db, plan.profile, false).await?;
    if plan.profile == RestoreProfile::CatalogScoped {
        crate::finding_scope::inspect_restore(db, owner, plan.scope.clone(), false, context)
            .await?;
    }
    let busy=db.query_one("SELECT EXISTS(SELECT 1 FROM signal_control.partitions WHERE owner IS NOT NULL OR lease_until IS NOT NULL)",&[]).await.map_err(crate::client::database_error)?;
    if field::<bool>(&busy, 0)? {
        return Err(ControlError::Fenced);
    }
    if plan.profile != RestoreProfile::Legacy {
        crate::administration::validate_catalog_state(db).await?;
    } else {
        batch(db, crate::administration::VALIDATE_SOURCE).await?;
    }
    // A coherent byte checkpoint still cannot certify contradictory progress.
    // Validate the retained publication chain and exact feed/revision anchors.
    let cursors = db.query_one(r#"SELECT
        NOT EXISTS(SELECT 1 FROM signal_control.partitions p WHERE
            p.feed_position>(SELECT feed_position FROM signal_control.store WHERE singleton)
            OR (p.kind='pipeline' AND (
                (p.checkpoint=0)<>(p.head IS NULL)
                OR p.checkpoint<>coalesce((SELECT max(c.last_sequence) FROM signal_control.commits c WHERE c.partition_id=p.id),0)
                OR (p.head IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signal_control.commits c WHERE c.partition_id=p.id AND c.id=p.head AND c.last_sequence=p.checkpoint))
                OR p.feed_position<coalesce((SELECT max(f.position) FROM signal_control.findings f WHERE f.partition_id=p.id),0))))
        AND NOT EXISTS(SELECT 1 FROM signal_control.commits c JOIN signal_control.partitions p ON p.id=c.partition_id WHERE
            p.kind<>'pipeline' OR c.epoch>p.epoch
            OR (c.previous IS NULL AND c.first_sequence<>1)
            OR (c.previous IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signal_control.commits previous WHERE previous.partition_id=c.partition_id AND previous.id=c.previous AND previous.last_sequence=c.first_sequence-1))
            OR c.feed_position>(SELECT feed_position FROM signal_control.store WHERE singleton)
            OR (c.feed_position=0 AND c.feed_digest<>sha256(convert_to('SIGNAL-FINDINGS-CURSOR-V1','UTF8')||uuid_send((SELECT store_id FROM signal_control.store WHERE singleton))))
            OR (c.feed_position>0 AND NOT EXISTS(SELECT 1 FROM signal_control.findings f WHERE f.position=c.feed_position AND f.cursor_digest=c.feed_digest)))
        AND NOT EXISTS(SELECT 1 FROM signal_control.state s WHERE NOT EXISTS(SELECT 1 FROM signal_control.commits c WHERE c.partition_id=s.partition_id AND c.rule_revision=s.revision))"#, &[]).await.map_err(crate::client::database_error)?;
    if !field::<bool>(&cursors, 0)? {
        return Err(ControlError::Corrupt);
    }

    let count=db.query_one("SELECT (SELECT count(*) FROM signal_control.partitions)<=128 AND (SELECT count(*) FROM signal_control.commits)<=128 AND (SELECT count(*) FROM signal_control.receipts)<=128 AND (SELECT coalesce(sum(octet_length(reference)),0) FROM signal_control.receipts)<=262144 AND (SELECT coalesce(sum(octet_length(manifest)),0) FROM signal_control.commits)<=262144 AND NOT EXISTS(SELECT 1 FROM signal_control.commits WHERE generation<>$1)",&[&plan.scope.generation]).await.map_err(crate::client::database_error)?;
    if !field::<bool>(&count, 0)? {
        return Err(ControlError::Full);
    }
    let mut hashes = Vec::new();
    for table in plan.profile.tables() {
        hashes.push((table, table_hash(db, table).await?));
    }
    let checkpoint_sha256 = hash_json(&hashes)?;
    let feed_position = field::<i64>(&head, 6)?
        .try_into()
        .map_err(|_| ControlError::Corrupt)?;
    let feed_digest: [u8; 32] = field::<Vec<u8>>(&head, 7)?
        .try_into()
        .map_err(|_| ControlError::Corrupt)?;
    let (sources, consumers) = source_cursors(db, plan.scope.store_id).await?;
    let mut roots = BTreeSet::new();
    let mut revisions = BTreeMap::new();
    let by_id: BTreeMap<_, _> = plan
        .objects
        .iter()
        .map(|o| Ok((o.object.digest()?, o)))
        .collect::<Result<_, ControlError>>()?;
    for row in db.query("SELECT c.backend_id,c.manifest,c.rule_revision,c.normalizer_revision,p.stream,c.first_sequence,c.last_sequence FROM signal_control.commits c JOIN signal_control.partitions p ON p.id=c.partition_id ORDER BY c.partition_id,c.id",&[]).await.map_err(crate::client::database_error)? {
        let backend_id:Uuid=field(&row,0)?;let bytes:Vec<u8>=field(&row,1)?;
        let m:signal_storage::object_manifest::QueryManifest=serde_json::from_slice(&bytes).map_err(|_|ControlError::Corrupt)?;
        if m.schema_version != 1 || m.storage_schema_version != 1
            || m.stream_id != field::<Uuid>(&row, 4)?
            || m.first_sequence != u64::try_from(field::<i64>(&row, 5)?).map_err(|_|ControlError::Corrupt)?
            || m.last_sequence != u64::try_from(field::<i64>(&row, 6)?).map_err(|_|ControlError::Corrupt)?
            || m.events != usize::try_from(m.last_sequence.checked_sub(m.first_sequence).and_then(|n| n.checked_add(1)).ok_or(ControlError::Corrupt)?).map_err(|_| ControlError::Corrupt)?
            || m.normalizer_revision != field::<String>(&row, 3)? {
            return Err(ControlError::Corrupt);
        }
        for reference in m.files.iter().map(|f|&f.object).chain(m.previous.iter().map(|p|&p.object)) {
            let object=CanonicalObjectRef{schema_version:1,backend_id,key:reference.key.clone(),version:reference.version.clone().ok_or(ControlError::Corrupt)?};
            let digest=object.digest()?;let expected=by_id.get(&digest).ok_or(ControlError::Corrupt)?;
            if expected.object!=object || expected.sha256!=reference.sha256 || expected.bytes!=reference.bytes {return Err(ControlError::Corrupt);}
            roots.insert(digest);
        }
        let rule:[u8;32]=field::<Vec<u8>>(&row,2)?.try_into().map_err(|_|ControlError::Corrupt)?;
        let normalizer:String=field(&row,3)?;revisions.insert((rule,normalizer),());
    }
    let mut protected = BTreeSet::new();
    // Custody originals may never appear in a query manifest or explicit pin.
    // Every such receipt must bind a retained exact object before restore proceeds.
    for row in db.query("SELECT r.id,r.reference,r.prepared_count,r.source_record_count,r.verified_prefix,r.state,r.commit_id,p.id,p.tenant,p.stream FROM signal_control.receipts r JOIN signal_control.partitions p ON p.id=r.partition_id ORDER BY r.partition_id,r.id", &[]).await.map_err(crate::client::database_error)? {
        context.check()?;
        let scope = crate::Scope {
            schema_version: 1, store_id: plan.scope.store_id, generation: plan.scope.generation,
            partition_id: field(&row,7)?, tenant: field(&row,8)?, stream: field(&row,9)?,
        };
        let reference: Vec<u8> = field(&row,1)?;
        if let Some(description) = restore_custody_description(&reference,field(&row,0)?,&scope)? {
            if field::<i64>(&row,2)? != 0 || field::<i64>(&row,3)? != 0
                || field::<i64>(&row,4)? != 0 || field::<String>(&row,5)? != "retained"
                || field::<Option<Uuid>>(&row,6)?.is_some() {
                return Err(ControlError::Corrupt);
            }
            let digest=description.object.digest()?;
            let expected=by_id.get(&digest).ok_or(ControlError::Corrupt)?;
            if expected.object!=description.object || expected.sha256!=description.sha256
                || expected.bytes!=description.bytes {return Err(ControlError::Corrupt);}
            roots.insert(digest);protected.insert(digest);
        }
    }

    for row in db.query("SELECT reference_sha256 FROM signal_control.object_pins WHERE state='retained' UNION SELECT unnest(object_hashes) FROM signal_control.snapshots",&[]).await.map_err(crate::client::database_error)? {
        let hash:[u8;32]=field::<Vec<u8>>(&row,0)?.try_into().map_err(|_|ControlError::Corrupt)?;
        if !by_id.contains_key(&hash) {return Err(ControlError::Corrupt);}roots.insert(hash);protected.insert(hash);
    }
    if roots.len() != by_id.len() {
        return Err(ControlError::Corrupt);
    }
    let history = table_hash(db, "notification_attempts").await?;
    let attempted: i64 = field(
        &db.query_one(
            "SELECT count(*) FROM signal_control.outbox WHERE attempts>0",
            &[],
        )
        .await
        .map_err(crate::client::database_error)?,
        0,
    )?;
    let result = RestoreInventory {
        schema_version: 1,
        store_id: plan.scope.store_id,
        old_generation: plan.scope.generation,
        revision: plan.profile.source_revision(),
        schema_sha256: schema,
        routines_sha256: routines,
        checkpoint_sha256,
        objects: plan.objects.clone(),
        protected_objects: protected.into_iter().collect(),
        source_cursors: sources,
        revisions: revisions
            .into_keys()
            .map(|(rule_sha256, normalizer)| RestoreRevision {
                rule_sha256,
                normalizer,
            })
            .collect(),
        consumers,
        feed_position,
        feed_digest,
        notification_history_sha256: history,
        attempted_work: attempted.try_into().map_err(|_| ControlError::Corrupt)?,
    };
    result.validate()?;
    Ok(result)
}
/// Decode only the reserved custody domain; unrelated opaque source references
/// remain opaque. Canonical bytes prevent silently rewriting historical identity.
fn restore_custody_description(
    bytes: &[u8],
    id: Uuid,
    scope: &crate::Scope,
) -> Result<Option<crate::ObjectCustodyDescription>, ControlError> {
    if bytes.len() > 65536 {
        return Err(ControlError::Full);
    }
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) if bytes.starts_with(b"{\"kind\":\"object_custody_v1\"") => {
            return Err(ControlError::Corrupt);
        }
        Err(_) => return Ok(None),
    };
    if value.get("kind").and_then(serde_json::Value::as_str) != Some("object_custody_v1")
        && !bytes.starts_with(b"{\"kind\":\"object_custody_v1\"")
    {
        return Ok(None);
    }
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Reference {
        kind: String,
        description: crate::ObjectCustodyDescription,
    }
    let reference: Reference = serde_json::from_slice(bytes).map_err(|_| ControlError::Corrupt)?;
    reference
        .description
        .validate()
        .map_err(|_| ControlError::Corrupt)?;
    if reference.description.id != id
        || reference.description.scope != *scope
        || serde_json::to_vec(&reference).map_err(|_| ControlError::Corrupt)? != bytes
    {
        return Err(ControlError::Corrupt);
    }
    Ok(Some(reference.description))
}

async fn cursor_digest(db: &Client, store: Uuid, position: u64) -> Result<[u8; 32], ControlError> {
    if position == 0 {
        return Ok(Sha256::digest(
            [b"SIGNAL-FINDINGS-CURSOR-V1".as_slice(), store.as_bytes()].concat(),
        )
        .into());
    }
    let position: i64 = position.try_into().map_err(|_| ControlError::Corrupt)?;
    let row = db
        .query_one(
            "SELECT cursor_digest FROM signal_control.findings WHERE position=$1",
            &[&position],
        )
        .await
        .map_err(crate::client::database_error)?;
    field::<Vec<u8>>(&row, 0)?
        .try_into()
        .map_err(|_| ControlError::Corrupt)
}

async fn source_cursors(
    db: &Client,
    store: Uuid,
) -> Result<(Vec<RestoreSourceCursor>, Vec<RestoreConsumerCursor>), ControlError> {
    let mut sources = Vec::new();
    let mut consumers = Vec::new();
    for row in db.query("SELECT p.id,p.epoch,p.checkpoint,p.feed_position,p.kind,sha256(convert_to(jsonb_build_object('partition',to_jsonb(p),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM signal_control.receipts r WHERE r.partition_id=p.id))::text,'UTF8')) FROM signal_control.partitions p ORDER BY p.id",&[]).await.map_err(crate::client::database_error)? {
        let id:Uuid=field(&row,0)?;let position:u64=field::<i64>(&row,3)?.try_into().map_err(|_|ControlError::Corrupt)?;
        sources.push(RestoreSourceCursor{partition_id:id,epoch:field::<i64>(&row,1)?.try_into().map_err(|_|ControlError::Corrupt)?,checkpoint:field::<i64>(&row,2)?.try_into().map_err(|_|ControlError::Corrupt)?,feed_position:position,state_sha256:field::<Vec<u8>>(&row,5)?.try_into().map_err(|_|ControlError::Corrupt)?});
        if field::<String>(&row,4)?=="notification" {
            let digest=cursor_digest(db,store,position).await?;
            consumers.push(RestoreConsumerCursor{consumer_id:id,position,digest});
        }
    }
    Ok((sources, consumers))
}
async fn data_hash(db: &Client, profile: RestoreProfile) -> Result<[u8; 32], ControlError> {
    let mut values = Vec::new();
    for table in profile.tables().filter(|t| *t != "store") {
        values.push((table, table_hash(db, table).await?));
    }
    if profile == RestoreProfile::CatalogScoped {
        for table in ["profile", "activation", "producers", "facts", "requests"] {
            let sql = format!(
                "SELECT sha256(convert_to(coalesce(jsonb_agg(h ORDER BY h),'[]'::jsonb)::text,'UTF8')) FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS h FROM signal_finding_scope.{table} t) s"
            );
            let digest: Vec<u8> = field(
                &db.query_one(&sql, &[])
                    .await
                    .map_err(crate::client::database_error)?,
                0,
            )?;
            values.push((table, digest.try_into().map_err(|_| ControlError::Corrupt)?));
        }
    }
    hash_json(&values)
}
fn check_destination(
    plan: &RestorePlan,
    decision: &crate::RestoreDecision,
) -> Result<(), ControlError> {
    if decision.challenge.destination_id != plan.destination.id
        || decision.credential_binding_sha256 != plan.destination.credential_binding_sha256
        || decision.expires_at <= tokio::time::Instant::now()
    {
        return Err(ControlError::Fenced);
    }
    Ok(())
}
async fn retained_receipt(
    db: &Client,
    owner: &str,
    plan: &RestorePlan,
    context: &ControlContext,
) -> Result<RestoreReceipt, ControlError> {
    if plan.profile == RestoreProfile::Legacy {
        crate::administration::inspect_restored_catalog(db, owner).await?;
    } else {
        crate::administration::inspect_profile(db, owner, 5).await?;
    }
    let row=db.query_one("SELECT r.destination_id,r.generation,r.inventory_sha256,r.checkpoint_sha256,r.source_progress_sha256,r.notification_history_sha256,r.attempted_work,h.ready,r.complete,r.seal=signal_control.restore_record_seal(r),r.post_checkpoint_sha256,r.credential_binding_sha256,h.generation,h.revision,h.routines_sha256,r.old_generation,h.store_id,h.schema_sha256 FROM signal_control.restore_record r JOIN signal_control.store h ON h.singleton WHERE r.singleton LIMIT 2",&[]).await.map_err(crate::client::database_error)?;
    let (schema, _routines) = plan.profile.restored_identity();
    verify_history(db, plan.profile, true).await?;
    if field::<Uuid>(&row, 15)? != plan.scope.generation
        || field::<Uuid>(&row, 16)? != plan.scope.store_id
        || field::<Vec<u8>>(&row, 17)? != schema
    {
        return Err(ControlError::Corrupt);
    }
    let generation: Uuid = field(&row, 1)?;
    if plan.profile == RestoreProfile::CatalogScoped {
        crate::finding_scope::inspect_restore(
            db,
            owner,
            AdministrativeScope {
                schema_version: 1,
                store_id: plan.scope.store_id,
                generation,
            },
            true,
            context,
        )
        .await?;
    }
    if field::<Uuid>(&row, 0)? != plan.destination.id
        || field::<Vec<u8>>(&row, 11)? != plan.destination.credential_binding_sha256
        || generation != field::<Uuid>(&row, 12)?
        || field::<i32>(&row, 13)? != plan.profile.destination_revision() as i32
        || field::<Vec<u8>>(&row, 14)? != plan.profile.restored_identity().1
        || !field::<bool>(&row, 9)?
        || field::<bool>(&row, 7)? != field::<bool>(&row, 8)?
    {
        return Err(ControlError::Corrupt);
    }
    let (sources, _) = source_cursors(db, plan.scope.store_id).await?;
    let bytes = serde_json::to_vec(&sources).map_err(|_| ControlError::Corrupt)?;
    let progress: [u8; 32] =
        Sha256::digest([b"SIGNAL-RESTORE-SOURCE-V1".as_slice(), &bytes].concat()).into();
    if field::<Vec<u8>>(&row, 4)? != progress
        || field::<Vec<u8>>(&row, 5)? != table_hash(db, "notification_attempts").await?
        || field::<Vec<u8>>(&row, 10)? != data_hash(db, plan.profile).await?
    {
        return Err(ControlError::Corrupt);
    }
    Ok(RestoreReceipt {
        challenge: RestoreChallenge {
            destination_id: field(&row, 0)?,
            new_generation: generation,
            inventory_sha256: field::<Vec<u8>>(&row, 2)?
                .try_into()
                .map_err(|_| ControlError::Corrupt)?,
            checkpoint_sha256: field::<Vec<u8>>(&row, 3)?
                .try_into()
                .map_err(|_| ControlError::Corrupt)?,
        },
        source_progress_sha256: progress,
        notification_history_sha256: field::<Vec<u8>>(&row, 5)?
            .try_into()
            .map_err(|_| ControlError::Corrupt)?,
        uncertain_work: field::<i32>(&row, 6)?
            .try_into()
            .map_err(|_| ControlError::Corrupt)?,
        ready: field(&row, 7)?,
    })
}
pub(crate) async fn run(
    db: &Client,
    owner: &str,
    plan: &RestorePlan,
    action: &RestoreAction,
    context: &ControlContext,
) -> Result<Row, ControlError> {
    lock(db, owner, plan.profile).await?;
    let reply = match action {
        RestoreAction::Stage => RestoreReply::Inventory(inventory(db, owner, plan, context).await?),
        RestoreAction::Resolve => {
            RestoreReply::Receipt(retained_receipt(db, owner, plan, context).await?.into())
        }
        RestoreAction::Barrier(permit) => {
            permit.check()?;
            check_destination(plan, permit.decision())?;
            let actual = inventory(db, owner, plan, context).await?;
            if actual != *permit.inventory()
                || actual.digest()? != permit.decision().challenge.inventory_sha256
                || actual.checkpoint_sha256 != permit.decision().challenge.checkpoint_sha256
            {
                return Err(ControlError::Corrupt);
            }
            context.check()?;
            batch(db, plan.profile.sql()).await?;
            let decision = permit.decision();
            let challenge = &decision.challenge;
            // Restore barriers add one finite retained record and64bytes per attempted work.
            let charge = 512i64 + 64 * i64::from(actual.attempted_work);
            let changed=db.execute("UPDATE signal_control.store SET used_rows=used_rows+1,used_bytes=used_bytes+$1 WHERE singleton AND NOT ready AND used_rows<max_rows AND $1<=max_bytes-used_bytes",&[&charge]).await.map_err(crate::client::database_error)?;
            if changed != 1 {
                return Err(ControlError::Full);
            }
            let progress = actual.source_progress_digest()?;
            let consumers = hash_json(&actual.consumers)?;
            db.execute("INSERT INTO signal_control.restore_record(singleton,destination_id,old_generation,generation,checkpoint_sha256,inventory_sha256,approval_id,custody_sha256,credential_binding_sha256,source_progress_sha256,notification_history_sha256,consumers_sha256,attempted_work,post_checkpoint_sha256,seal) VALUES(true,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)",&[&plan.destination.id,&actual.old_generation,&challenge.new_generation,&actual.checkpoint_sha256.as_slice(),&challenge.inventory_sha256.as_slice(),&decision.approval_id,&decision.custody_sha256.as_slice(),&decision.credential_binding_sha256.as_slice(),&progress.as_slice(),&actual.notification_history_sha256.as_slice(),&consumers.as_slice(),&(actual.attempted_work as i32),&[0u8;32].as_slice()]).await.map_err(crate::client::database_error)?;
            db.execute("UPDATE signal_control.outbox SET restore_generation=$1,restore_attempts=attempts,restore_sha256=$2,status=CASE WHEN attempts=10 THEN 'exhausted' ELSE 'uncertain' END WHERE attempts>0",&[&challenge.new_generation,&[0u8;32].as_slice()]).await.map_err(crate::client::database_error)?;
            batch(db,"UPDATE signal_control.outbox w SET restore_sha256=signal_control.restore_work_seal(w) WHERE restore_generation IS NOT NULL; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL").await?;
            let (base, routines) = plan.profile.restored_identity();
            db.execute(
                "INSERT INTO signal_control.migrations(ordinal,artifact,sha256) VALUES($1,$2,$3)",
                &[
                    &(if plan.profile == RestoreProfile::Legacy {
                        4_i32
                    } else {
                        5_i32
                    }),
                    &plan.profile.artifact(),
                    &routines.as_slice(),
                ],
            )
            .await
            .map_err(crate::client::database_error)?;
            db.execute("UPDATE signal_control.store SET generation=$1,revision=$4,routines_sha256=$2 WHERE singleton AND NOT ready AND schema_sha256=$3",&[&challenge.new_generation,&routines.as_slice(),&base.as_slice(),&(plan.profile.destination_revision() as i32)]).await.map_err(crate::client::database_error)?;
            if plan.profile == RestoreProfile::CatalogScoped {
                let changed=db.execute("UPDATE signal_finding_scope.activation SET store_generation=$1 WHERE singleton AND store_id=$2 AND store_generation=$3",&[&challenge.new_generation,&plan.scope.store_id,&actual.old_generation]).await.map_err(crate::client::database_error)?;
                if changed != 1 {
                    return Err(ControlError::Corrupt);
                }
            }
            let post = data_hash(db, plan.profile).await?;
            db.execute("UPDATE signal_control.restore_record SET post_checkpoint_sha256=$1 WHERE singleton",&[&post.as_slice()]).await.map_err(crate::client::database_error)?;
            batch(db,"UPDATE signal_control.restore_record r SET seal=signal_control.restore_record_seal(r)").await?;
            permit.check()?;
            check_destination(plan, decision)?;
            context.check()?;
            RestoreReply::Receipt(retained_receipt(db, owner, plan, context).await?.into())
        }
        RestoreAction::Reconcile(expected, cursors) => {
            let actual = retained_receipt(db, owner, plan, context).await?;
            if actual != expected.clone().into() || actual.ready {
                return Err(ControlError::Fenced);
            }
            let (_, actual_cursors) = source_cursors(db, plan.scope.store_id).await?;
            if *cursors != actual_cursors {
                return Err(ControlError::Corrupt);
            }
            let hash = hash_json(cursors)?;
            let row = db
                .query_one(
                    "SELECT consumers_sha256=$1 FROM signal_control.restore_record WHERE singleton",
                    &[&hash.as_slice()],
                )
                .await
                .map_err(crate::client::database_error)?;
            if !field::<bool>(&row, 0)? {
                return Err(ControlError::Corrupt);
            }
            RestoreReply::Consumers(
                ReconciledConsumers {
                    challenge: actual.challenge,
                    consumers: actual_cursors,
                }
                .into(),
            )
        }
        RestoreAction::Enable(permit) => {
            permit.check()?;
            check_destination(plan, permit.decision())?;
            let mut actual = retained_receipt(db, owner, plan, context).await?;
            if actual != *permit.receipt() || actual.ready {
                return Err(ControlError::Fenced);
            }
            let (_, actual_cursors) = source_cursors(db, plan.scope.store_id).await?;
            if permit.consumers() != actual_cursors {
                return Err(ControlError::Corrupt);
            }
            let decision = permit.decision();
            let hash = hash_json(&actual_cursors)?;
            let row=db.query_one("SELECT approval_id=$1 AND custody_sha256=$2 AND credential_binding_sha256=$3 AND consumers_sha256=$4 FROM signal_control.restore_record WHERE singleton",&[&decision.approval_id,&decision.custody_sha256.as_slice(),&decision.credential_binding_sha256.as_slice(),&hash.as_slice()]).await.map_err(crate::client::database_error)?;
            if !field::<bool>(&row, 0)? {
                return Err(ControlError::Fenced);
            }
            batch(db,"UPDATE signal_control.restore_record r SET complete=true; UPDATE signal_control.restore_record r SET seal=signal_control.restore_record_seal(r); UPDATE signal_control.store SET ready=true WHERE singleton AND NOT ready").await?;
            permit.check()?;
            context.check()?;
            actual.ready = true;
            RestoreReply::Receipt(actual.into())
        }
    };
    let value = serde_json::to_value(reply).map_err(|_| ControlError::Corrupt)?;
    if value.to_string().len() > crate::REPLY_BYTES {
        return Err(ControlError::Full);
    }
    db.query_one("SELECT $1::jsonb", &[&value])
        .await
        .map_err(crate::client::database_error)
}
pub(crate) fn validate_reply(
    action: &RestoreAction,
    reply: &RestoreReply,
    plan: &RestorePlan,
) -> Result<(), ControlError> {
    match (action, reply) {
        (RestoreAction::Stage, RestoreReply::Inventory(i)) => {
            i.validate()?;
            if i.revision != plan.profile.source_revision() {
                return Err(ControlError::Corrupt);
            }
            Ok(())
        }
        (RestoreAction::Resolve, RestoreReply::Receipt(_)) => Ok(()),
        (RestoreAction::Barrier(p), RestoreReply::Receipt(r)) => {
            let actual: RestoreReceipt = r.clone().into();
            if actual.challenge != p.decision().challenge
                || actual.ready
                || actual.source_progress_sha256 != p.inventory().source_progress_digest()?
                || actual.notification_history_sha256 != p.inventory().notification_history_sha256
                || actual.uncertain_work != p.inventory().attempted_work
            {
                return Err(ControlError::Corrupt);
            }
            Ok(())
        }
        (RestoreAction::Reconcile(r, c), RestoreReply::Consumers(result)) => {
            let expected: RestoreReceipt = r.clone().into();
            let actual: ReconciledConsumers = result.clone().into();
            if actual.challenge != expected.challenge || actual.consumers != *c {
                return Err(ControlError::Corrupt);
            }
            Ok(())
        }
        (RestoreAction::Enable(p), RestoreReply::Receipt(r)) => {
            let mut expected = p.receipt().clone();
            expected.ready = true;
            if expected != r.clone().into() {
                return Err(ControlError::Corrupt);
            }
            Ok(())
        }
        _ => Err(ControlError::Corrupt),
    }
}

#[cfg(test)]
mod restore_custody_tests {
    use super::*;
    #[test]
    fn restore_custody_description_preserves_domain_identity_and_rejects_substitution()
    -> Result<(), ControlError> {
        let scope = crate::Scope {
            schema_version: 1,
            store_id: Uuid::new_v4(),
            generation: Uuid::new_v4(),
            tenant: "synthetic".into(),
            stream: Uuid::new_v4(),
            partition_id: Uuid::new_v4(),
        };
        let description = crate::ObjectCustodyDescription {
            schema_version: 1,
            id: Uuid::new_v4(),
            scope: scope.clone(),
            object: CanonicalObjectRef {
                schema_version: 1,
                backend_id: Uuid::new_v4(),
                key: "original/body".into(),
                version: "exact-v1".into(),
            },
            bytes: 4,
            sha256: [7; 32],
            retain_until: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        #[derive(Serialize)]
        struct Reference<'a> {
            kind: &'static str,
            description: &'a crate::ObjectCustodyDescription,
        }
        let bytes = serde_json::to_vec(&Reference {
            kind: "object_custody_v1",
            description: &description,
        })
        .map_err(|_| ControlError::Corrupt)?;
        assert_eq!(
            restore_custody_description(&bytes, description.id, &scope)?,
            Some(description.clone())
        );
        assert!(matches!(
            restore_custody_description(&bytes, Uuid::new_v4(), &scope),
            Err(ControlError::Corrupt)
        ));
        let mut wrong = scope.clone();
        wrong.generation = Uuid::new_v4();
        assert!(matches!(
            restore_custody_description(&bytes, description.id, &wrong),
            Err(ControlError::Corrupt)
        ));
        let mut altered = bytes.clone();
        altered.push(b' ');
        assert!(matches!(
            restore_custody_description(&altered, description.id, &scope),
            Err(ControlError::Corrupt)
        ));
        assert!(matches!(
            restore_custody_description(
                b"{\"kind\":\"object_custody_v1\",",
                description.id,
                &scope
            ),
            Err(ControlError::Corrupt)
        ));
        assert!(matches!(
            restore_custody_description(
                b"{\"kind\":\"object_custody_v1\",\"kind\":\"opaque\"}",
                description.id,
                &scope
            ),
            Err(ControlError::Corrupt)
        ));
        assert_eq!(
            restore_custody_description(b"opaque original source cursor", description.id, &scope)?,
            None
        );
        Ok(())
    }
}
