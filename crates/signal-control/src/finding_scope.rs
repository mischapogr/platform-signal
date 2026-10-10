//! Explicit stopped host authority over the supplemental scope schema.
//! Neither these records nor a WAL sequence authenticate a newly admitted event.
use crate::{
    AdministrativeScope, ConnectionSettings, ControlClient, ControlContext, ControlError, Scope,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_postgres::Client;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const SCOPE_PROFILE_BYTES: u64 = 256;
pub const SCOPE_ACTIVATION_BYTES: u64 = 144;
pub const SCOPE_PRODUCER_BYTES: u64 = 320;
pub const SCOPE_FACT_BYTES: u64 = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingScopeProfile {
    Catalog4,
    RestoredCatalog5,
    Catalog4Scoped,
    RestoredCatalog5Scoped,
}
impl FindingScopeProfile {
    fn revision(self) -> u8 {
        match self {
            Self::Catalog4 | Self::Catalog4Scoped => 4,
            Self::RestoredCatalog5 | Self::RestoredCatalog5Scoped => 5,
        }
    }
    fn routines(self) -> [u8; 32] {
        match self {
            Self::Catalog4 | Self::Catalog4Scoped => crate::catalog_schema_identity().1,
            Self::RestoredCatalog5 | Self::RestoredCatalog5Scoped => {
                crate::restored_catalog_schema_identity().1
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FindingScopeLimits {
    pub producers: u32,
    pub rows: u32,
    pub bytes: u64,
}
impl FindingScopeLimits {
    fn validate(self) -> Result<(), ControlError> {
        if !(1..=128).contains(&self.producers)
            || !(1..=65536).contains(&self.rows)
            || !(4096..=67108864).contains(&self.bytes)
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}
/// Host report only; no deserialization or credential-verification semantics.
#[derive(Clone)]
pub struct ProducerEnrollment {
    pub scope: Scope,
    pub scope_generation: Uuid,
    pub startup: Uuid,
    pub wal_floor: u64,
}
#[derive(Clone)]
pub(crate) enum Action {
    Activate {
        scope: AdministrativeScope,
        generation: Uuid,
        limits: FindingScopeLimits,
    },
    Enroll(ProducerEnrollment),
    Inspect {
        scope: Scope,
        generation: Uuid,
    },
}
impl Action {
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        match self {
            Self::Activate {
                scope,
                generation,
                limits,
            } => {
                scope.validate()?;
                limits.validate()?;
                if generation.is_nil() {
                    return Err(ControlError::Invalid);
                }
            }
            Self::Enroll(i) => {
                i.scope.validate()?;
                if i.scope_generation.is_nil()
                    || i.startup.is_nil()
                    || i.wal_floor > i64::MAX as u64
                {
                    return Err(ControlError::Invalid);
                }
            }
            Self::Inspect { scope, generation } => {
                scope.validate()?;
                if generation.is_nil() {
                    return Err(ControlError::Invalid);
                }
            }
        }
        Ok(())
    }
    fn store(&self) -> (Uuid, Uuid) {
        match self {
            Self::Activate { scope, .. } => (scope.store_id, scope.generation),
            Self::Enroll(i) => (i.scope.store_id, i.scope.generation),
            Self::Inspect { scope, .. } => (scope.store_id, scope.generation),
        }
    }
    fn generation(&self) -> Uuid {
        match self {
            Self::Activate { generation, .. } | Self::Inspect { generation, .. } => *generation,
            Self::Enroll(i) => i.scope_generation,
        }
    }
}
/// Retained configuration evidence; borrowing it requires the original capability.
/// Does not authenticate events, grant READ/READY or authorize source ACK.
pub struct FindingScopeBinding {
    pub store: Uuid,
    pub store_generation: Uuid,
    pub scope_generation: Uuid,
    pub prefix: signal_protocol::findings_feed::FindingsCursor,
    pub limits: FindingScopeLimits,
    pub producer: Option<ProducerEnrollment>,
    pub checkpoint: Option<u64>,
}
pub struct FindingScopePin {
    binding: FindingScopeBinding,
    context: ControlContext,
    stopping: CancellationToken,
}
impl FindingScopePin {
    pub(crate) fn new(
        binding: FindingScopeBinding,
        context: ControlContext,
        stopping: CancellationToken,
    ) -> Result<Self, ControlError> {
        let pin = Self {
            binding,
            context,
            stopping,
        };
        pin.binding()?;
        Ok(pin)
    }
    pub fn binding(&self) -> Result<&FindingScopeBinding, ControlError> {
        self.context.check()?;
        if self.stopping.is_cancelled() {
            return Err(ControlError::Cancelled);
        }
        Ok(&self.binding)
    }
}
pub struct FindingScopeAdministrator {
    client: Arc<ControlClient>,
    owner: String,
    profile: FindingScopeProfile,
}
impl FindingScopeAdministrator {
    pub fn new(
        settings: ConnectionSettings,
        owner: String,
        profile: FindingScopeProfile,
    ) -> Result<Self, ControlError> {
        if owner.is_empty()
            || owner.len() > 63
            || owner.capacity() > 63
            || !owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(ControlError::Invalid);
        }
        let client = match profile {
            FindingScopeProfile::Catalog4 | FindingScopeProfile::Catalog4Scoped => {
                ControlClient::catalog(settings)?
            }
            FindingScopeProfile::RestoredCatalog5 | FindingScopeProfile::RestoredCatalog5Scoped => {
                ControlClient::restored_catalog(settings)?
            }
        };
        Ok(Self {
            client: Arc::new(client),
            owner,
            profile,
        })
    }
    pub async fn activate(
        &self,
        scope: AdministrativeScope,
        generation: Uuid,
        limits: FindingScopeLimits,
        context: ControlContext,
    ) -> Result<FindingScopePin, ControlError> {
        self.client
            .administer_finding_scope(
                self.owner.clone(),
                self.profile,
                Action::Activate {
                    scope,
                    generation,
                    limits,
                },
                context,
            )
            .await
    }
    pub async fn enroll(
        &self,
        input: ProducerEnrollment,
        context: ControlContext,
    ) -> Result<FindingScopePin, ControlError> {
        self.client
            .administer_finding_scope(
                self.owner.clone(),
                self.profile,
                Action::Enroll(input),
                context,
            )
            .await
    }
    pub async fn inspect(
        &self,
        scope: Scope,
        generation: Uuid,
        context: ControlContext,
    ) -> Result<FindingScopePin, ControlError> {
        self.client
            .administer_finding_scope(
                self.owner.clone(),
                self.profile,
                Action::Inspect { scope, generation },
                context,
            )
            .await
    }
    pub async fn shutdown(&self, context: ControlContext) -> Result<(), ControlError> {
        self.client.shutdown(context).await
    }
    pub fn metrics(&self) -> crate::ControlMetrics {
        self.client.metrics()
    }
}

fn db_error(error: tokio_postgres::Error) -> ControlError {
    crate::client::database_error(error)
}
fn field<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    n: usize,
) -> Result<T, ControlError> {
    row.try_get(n).map_err(|_| ControlError::Corrupt)
}
async fn supplemental(
    db: &Client,
    owner: &str,
    profile: FindingScopeProfile,
) -> Result<(), ControlError> {
    let tables=db.query("SELECT c.relname,pg_get_userbyid(c.relowner)::text,EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_finding_scope' AND c.relkind IN ('r','v','m','f','p') ORDER BY c.relname LIMIT 6",&[]).await.map_err(db_error)?;
    let scoped = matches!(
        profile,
        FindingScopeProfile::Catalog4Scoped | FindingScopeProfile::RestoredCatalog5Scoped
    );
    let expected: &[&str] = if scoped {
        &["activation", "facts", "producers", "profile", "requests"]
    } else {
        &["activation", "facts", "producers", "profile"]
    };
    if tables.len() != expected.len() {
        return Err(ControlError::Corrupt);
    }
    for (row, name) in tables.iter().zip(expected.iter().copied()) {
        if field::<String>(row, 0)? != name
            || field::<String>(row, 1)? != owner
            || field::<bool>(row, 2)?
        {
            return Err(ControlError::Corrupt);
        }
    }
    let routines=db.query("SELECT pg_get_functiondef(p.oid),pg_get_userbyid(p.proowner)::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='signal_finding_scope' ORDER BY p.proname,pg_get_function_identity_arguments(p.oid) LIMIT 2",&[]).await.map_err(db_error)?;
    if scoped {
        if routines.len() != 1
            || field::<String>(&routines[0], 1)? != owner
            || crate::publication::hex(&Sha256::digest(
                field::<String>(&routines[0], 0)?.as_bytes(),
            )) != include_str!(
                "../../../schemas/shared-control/008-scoped-publication-functions.sha256"
            )
            .trim()
        {
            return Err(ControlError::Corrupt);
        }
    } else if !routines.is_empty() {
        return Err(ControlError::Corrupt);
    }
    let query = include_str!("../../../schemas/shared-control/catalog-query.sql").replace(
        "n.nspname='signal_control'",
        "n.nspname='signal_finding_scope'",
    );
    let expected_catalog = if scoped {
        include_str!("../../../schemas/shared-control/008-scoped-publication-catalog.sha256")
    } else {
        include_str!("../../../schemas/shared-control/007-finding-scope-catalog.sha256")
    };
    if field::<String>(&db.query_one(&query, &[]).await.map_err(db_error)?, 0)?
        != expected_catalog.trim()
    {
        return Err(ControlError::Corrupt);
    }
    Ok(())
}
async fn history(db: &Client, profile: FindingScopeProfile) -> Result<(), ControlError> {
    let mut expected = vec![
        ("001.sql", crate::schema_identity().0),
        ("002-functions.sql", crate::legacy_identity()),
        ("003-administration.sql", crate::schema_identity().1),
        ("005-catalog.sql", crate::catalog_schema_identity().1),
    ];
    if profile.revision() == 5 {
        expected.push((
            "006-catalog-restore.sql",
            crate::restored_catalog_schema_identity().1,
        ));
    }
    let rows=db.query("SELECT ordinal,artifact,sha256 FROM signal_control.migrations ORDER BY ordinal LIMIT 6",&[]).await.map_err(db_error)?;
    if rows.len() != expected.len() {
        return Err(ControlError::Corrupt);
    }
    for (index, (row, (artifact, digest))) in rows.iter().zip(expected).enumerate() {
        if field::<i32>(row, 0)? != (index + 1) as i32
            || field::<String>(row, 1)? != artifact
            || field::<Vec<u8>>(row, 2)? != digest
        {
            return Err(ControlError::Corrupt);
        }
    }
    Ok(())
}
async fn prefix(
    db: &Client,
    store: Uuid,
    position: u64,
    expected: &[u8],
    context: &ControlContext,
) -> Result<signal_protocol::findings_feed::FindingsCursor, ControlError> {
    use signal_protocol::findings_feed::FindingsCursor;
    if position > 65536 || expected.len() != 32 {
        return Err(ControlError::Corrupt);
    }
    let mut cursor = FindingsCursor::initial(store).map_err(|_| ControlError::Corrupt)?;
    let mut total = 0usize;
    for at in 1..=position {
        context.check()?;
        let row=db.query_opt("SELECT id,content,content_sha256,cursor_digest FROM signal_control.findings WHERE position=$1 AND octet_length(content)<=65536",&[&(at as i64)]).await.map_err(db_error)?.ok_or(ControlError::Corrupt)?;
        let body: Vec<u8> = field(&row, 1)?;
        total = total.checked_add(body.len()).ok_or(ControlError::Full)?;
        if total > 67108864 || body.is_empty() {
            return Err(ControlError::Full);
        }
        let finding: signal_findings::Finding =
            serde_json::from_slice(&body).map_err(|_| ControlError::Corrupt)?;
        finding.validate().map_err(|_| ControlError::Corrupt)?;
        if finding.id != field::<Uuid>(&row, 0)?
            || Sha256::digest(&body).as_slice() != field::<Vec<u8>>(&row, 2)?
        {
            return Err(ControlError::Corrupt);
        }
        cursor = cursor.advance(&body).map_err(|_| ControlError::Corrupt)?;
        if cursor
            != FindingsCursor::from_retained_parts(
                store,
                at,
                field::<Vec<u8>>(&row, 3)?
                    .try_into()
                    .map_err(|_| ControlError::Corrupt)?,
            )
            .map_err(|_| ControlError::Corrupt)?
        {
            return Err(ControlError::Corrupt);
        }
    }
    if cursor
        != FindingsCursor::from_retained_parts(
            store,
            position,
            expected.try_into().map_err(|_| ControlError::Corrupt)?,
        )
        .map_err(|_| ControlError::Corrupt)?
    {
        return Err(ControlError::Corrupt);
    }
    context.check()?;
    Ok(cursor)
}
async fn counters(
    db: &Client,
    generation: Uuid,
    limits: FindingScopeLimits,
    profile: FindingScopeProfile,
) -> Result<(), ControlError> {
    let row=db.query_one("SELECT (SELECT count(*) FROM (SELECT 1 FROM signal_finding_scope.producers LIMIT 129) p),(SELECT count(*) FROM (SELECT 1 FROM signal_finding_scope.facts LIMIT 65537) f)",&[]).await.map_err(db_error)?;
    let producers: i64 = field(&row, 0)?;
    let facts: i64 = field(&row, 1)?;
    if producers > i64::from(limits.producers) || facts > i64::from(limits.rows) {
        return Err(ControlError::Corrupt);
    }
    let row=db.query_one("SELECT COALESCE(sum($1::bigint+COALESCE(octet_length(source),0)+COALESCE(octet_length(account),0)+COALESCE(octet_length(resource),0)),0)::bigint FROM signal_finding_scope.facts",&[&(SCOPE_FACT_BYTES as i64)]).await.map_err(db_error)?;
    let fact_bytes: i64 = field(&row, 0)?;
    let scoped = matches!(
        profile,
        FindingScopeProfile::Catalog4Scoped | FindingScopeProfile::RestoredCatalog5Scoped
    );
    let (requests, request_bytes) = if scoped {
        let row = db.query_one("SELECT count(*)::bigint,COALESCE(sum(256+octet_length(claims)),0)::bigint FROM (SELECT claims,claims_sha256 FROM signal_finding_scope.requests LIMIT 65537) x",&[]).await.map_err(db_error)?;
        if !db.query("SELECT 1 FROM signal_finding_scope.requests WHERE claims_sha256<>sha256(claims) LIMIT 1",&[]).await.map_err(db_error)?.is_empty() { return Err(ControlError::Corrupt); }
        (field::<i64>(&row, 0)?, field::<i64>(&row, 1)?)
    } else {
        (0, 0)
    };
    if requests + facts > i64::from(limits.rows) {
        return Err(ControlError::Corrupt);
    }
    let used = SCOPE_PROFILE_BYTES
        + SCOPE_ACTIVATION_BYTES
        + (producers as u64) * SCOPE_PRODUCER_BYTES
        + fact_bytes as u64
        + request_bytes as u64;
    if used > limits.bytes {
        return Err(ControlError::Corrupt);
    }
    let bad=db.query("SELECT 1 FROM signal_finding_scope.producers p JOIN signal_control.partitions c ON c.id=p.partition_id WHERE p.scope_generation<>$1 OR p.stream<>c.stream OR c.kind<>'pipeline' LIMIT 1",&[&generation]).await.map_err(db_error)?;
    if !bad.is_empty() {
        return Err(ControlError::Corrupt);
    }
    let bad=db.query("SELECT 1 FROM signal_finding_scope.facts s JOIN signal_control.findings f ON f.partition_id=s.partition_id AND f.id=s.finding_id JOIN signal_finding_scope.activation a ON a.singleton WHERE s.scope_generation<>a.scope_generation OR f.position<=a.prefix_position OR s.finding_sha256<>f.content_sha256 OR f.content_sha256<>sha256(f.content) OR (convert_from(f.content,'UTF8')::jsonb->'attributes'->'signal.scope.v1') IS DISTINCT FROM jsonb_build_object('schema_version',1,'generation',s.scope_generation::text,'binding_digest',encode(s.binding_digest,'hex'),'source',s.source,'account',s.account,'resource',s.resource) OR (convert_from(f.content,'UTF8')::jsonb->'event_ids') IS DISTINCT FROM jsonb_build_array(s.event_id) LIMIT 1",&[]).await.map_err(db_error)?;
    if !bad.is_empty() {
        return Err(ControlError::Corrupt);
    }
    let row=db.query_one("SELECT used_producers,used_rows,used_bytes FROM signal_finding_scope.profile WHERE singleton",&[]).await.map_err(db_error)?;
    if field::<i32>(&row, 0)? != producers as i32
        || field::<i64>(&row, 1)? != facts + requests
        || field::<i64>(&row, 2)? != used as i64
    {
        return Err(ControlError::Corrupt);
    }
    Ok(())
}
pub(crate) async fn run(
    db: &Client,
    owner: &str,
    profile: FindingScopeProfile,
    action: &Action,
    context: &ControlContext,
) -> Result<FindingScopeBinding, ControlError> {
    context.check()?;
    db.batch_execute(&format!(
        "SET LOCAL ROLE \"{owner}\"; SET LOCAL search_path=pg_catalog,signal_control,pg_temp"
    ))
    .await
    .map_err(db_error)?;
    let head=db.query_one("SELECT store_id,generation,revision,ready,schema_sha256,routines_sha256,feed_position,feed_digest FROM signal_control.store WHERE singleton FOR UPDATE",&[]).await.map_err(db_error)?;
    crate::administration::inspect_profile(db, owner, profile.revision()).await?;
    history(db, profile).await?;
    supplemental(db, owner, profile).await?;
    let (store, generation) = action.store();
    if field::<Uuid>(&head, 0)? != store || field::<Uuid>(&head, 1)? != generation {
        return Err(ControlError::Fenced);
    }
    if field::<i32>(&head, 2)? != i32::from(profile.revision())
        || field::<Vec<u8>>(&head, 4)? != crate::schema_identity().0
        || field::<Vec<u8>>(&head, 5)? != profile.routines()
    {
        return Err(ControlError::Corrupt);
    }
    if !matches!(action, Action::Inspect { .. }) && field::<bool>(&head, 3)? {
        return Err(ControlError::Fenced);
    }
    let position = field::<i64>(&head, 6)?;
    if position < 0 {
        return Err(ControlError::Corrupt);
    }
    prefix(
        db,
        store,
        position as u64,
        &field::<Vec<u8>>(&head, 7)?,
        context,
    )
    .await?;
    let roots=db.query("SELECT store_id,store_generation,scope_generation,prefix_position,prefix_digest FROM signal_finding_scope.activation WHERE singleton LIMIT 2",&[]).await.map_err(db_error)?;
    let profiles=db.query("SELECT artifact_sha256,max_producers,max_rows,max_bytes FROM signal_finding_scope.profile WHERE singleton LIMIT 2",&[]).await.map_err(db_error)?;
    if roots.is_empty() && profiles.is_empty() {
        let Action::Activate {
            generation: scope_generation,
            limits,
            ..
        } = action
        else {
            return Err(ControlError::Corrupt);
        };
        let digest: Vec<u8> = field(&head, 7)?;
        prefix(db, store, position as u64, &digest, context).await?;
        let artifact: Vec<u8> = Sha256::digest(include_bytes!(
            "../../../schemas/shared-control/007-finding-scope.sql"
        ))
        .to_vec();
        db.execute("INSERT INTO signal_finding_scope.profile(singleton,schema_version,artifact_sha256,max_producers,max_rows,max_bytes,used_bytes) VALUES(true,1,$1,$2,$3,$4,$5)",&[&artifact,&(limits.producers as i32),&(i64::from(limits.rows)),&(limits.bytes as i64),&((SCOPE_PROFILE_BYTES+SCOPE_ACTIVATION_BYTES) as i64)]).await.map_err(db_error)?;
        db.execute(
            "INSERT INTO signal_finding_scope.activation VALUES(true,$1,$2,$3,$4,$5)",
            &[&store, &generation, scope_generation, &position, &digest],
        )
        .await
        .map_err(db_error)?;
    } else if roots.len() != 1 || profiles.len() != 1 {
        return Err(ControlError::Corrupt);
    }
    let root=db.query_one("SELECT store_id,store_generation,scope_generation,prefix_position,prefix_digest FROM signal_finding_scope.activation WHERE singleton",&[]).await.map_err(db_error)?;
    if field::<Uuid>(&root, 0)? != store
        || field::<Uuid>(&root, 1)? != generation
        || field::<Uuid>(&root, 2)? != action.generation()
    {
        return Err(ControlError::Fenced);
    }
    let floor = field::<i64>(&root, 3)?;
    if floor < 0 || floor > position {
        return Err(ControlError::Corrupt);
    }
    let cursor = prefix(
        db,
        store,
        floor as u64,
        &field::<Vec<u8>>(&root, 4)?,
        context,
    )
    .await?;
    let row=db.query_one("SELECT artifact_sha256,max_producers,max_rows,max_bytes FROM signal_finding_scope.profile WHERE singleton",&[]).await.map_err(db_error)?;
    let artifact: Vec<u8> = Sha256::digest(include_bytes!(
        "../../../schemas/shared-control/007-finding-scope.sql"
    ))
    .to_vec();
    if field::<Vec<u8>>(&row, 0)? != artifact {
        return Err(ControlError::Corrupt);
    }
    let limits = FindingScopeLimits {
        producers: field::<i32>(&row, 1)? as u32,
        rows: field::<i64>(&row, 2)? as u32,
        bytes: field::<i64>(&row, 3)? as u64,
    };
    limits.validate().map_err(|_| ControlError::Corrupt)?;
    if let Action::Activate {
        limits: requested, ..
    } = action
        && *requested != limits
    {
        return Err(ControlError::Conflict);
    }
    counters(db, action.generation(), limits, profile).await?;
    let mut producer = None;
    let mut checkpoint = None;
    if matches!(action, Action::Enroll(_) | Action::Inspect { .. }) {
        let scope = match action {
            Action::Enroll(i) => &i.scope,
            Action::Inspect { scope, .. } => scope,
            _ => return Err(ControlError::Corrupt),
        };
        let part = db
            .query_opt(
                "SELECT tenant,stream,kind,checkpoint FROM signal_control.partitions WHERE id=$1",
                &[&scope.partition_id],
            )
            .await
            .map_err(db_error)?
            .ok_or(ControlError::Fenced)?;
        if field::<String>(&part, 0)? != scope.tenant
            || field::<Uuid>(&part, 1)? != scope.stream
            || field::<String>(&part, 2)? != "pipeline"
        {
            return Err(ControlError::Fenced);
        }
        checkpoint =
            Some(u64::try_from(field::<i64>(&part, 3)?).map_err(|_| ControlError::Corrupt)?);
        let existing=db.query_opt("SELECT stream,startup_id,wal_floor,scope_generation FROM signal_finding_scope.producers WHERE partition_id=$1",&[&scope.partition_id]).await.map_err(db_error)?;
        if let Action::Enroll(i) = action {
            if i.wal_floor < field::<i64>(&part, 3)? as u64 {
                return Err(ControlError::Fenced);
            }
            if let Some(ref old) = existing {
                if field::<Uuid>(old, 0)? != scope.stream
                    || field::<Uuid>(old, 3)? != i.scope_generation
                {
                    return Err(ControlError::Corrupt);
                }
                let old_floor = field::<i64>(old, 2)? as u64;
                if i.wal_floor < old_floor {
                    return Err(ControlError::Fenced);
                }
                if field::<Uuid>(old, 1)? == i.startup && i.wal_floor != old_floor {
                    return Err(ControlError::Conflict);
                }
                db.execute("UPDATE signal_finding_scope.producers SET startup_id=$2,wal_floor=$3 WHERE partition_id=$1",&[&scope.partition_id,&i.startup,&(i.wal_floor as i64)]).await.map_err(db_error)?;
            } else {
                let counts=db.query_one("SELECT used_producers,used_bytes FROM signal_finding_scope.profile WHERE singleton",&[]).await.map_err(db_error)?;
                if field::<i32>(&counts, 0)? as u32 >= limits.producers
                    || field::<i64>(&counts, 1)? as u64 + SCOPE_PRODUCER_BYTES > limits.bytes
                {
                    return Err(ControlError::Full);
                }
                db.execute(
                    "INSERT INTO signal_finding_scope.producers VALUES($1,$2,$3,$4,$5)",
                    &[
                        &scope.partition_id,
                        &i.scope_generation,
                        &scope.stream,
                        &i.startup,
                        &(i.wal_floor as i64),
                    ],
                )
                .await
                .map_err(db_error)?;
                db.execute("UPDATE signal_finding_scope.profile SET used_producers=used_producers+1,used_bytes=used_bytes+$1 WHERE singleton",&[&(SCOPE_PRODUCER_BYTES as i64)]).await.map_err(db_error)?;
            }
            producer = Some(i.clone());
        } else {
            let old = existing.ok_or(ControlError::Fenced)?;
            producer = Some(ProducerEnrollment {
                scope: scope.clone(),
                scope_generation: field(&old, 3)?,
                startup: field(&old, 1)?,
                wal_floor: field::<i64>(&old, 2)? as u64,
            });
        }
    }
    counters(db, action.generation(), limits, profile).await?;
    context.check()?;
    Ok(FindingScopeBinding {
        store,
        store_generation: generation,
        scope_generation: action.generation(),
        prefix: cursor,
        limits,
        producer,
        checkpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn binding() -> Result<FindingScopeBinding, ControlError> {
        let store = Uuid::new_v4();
        Ok(FindingScopeBinding {
            store,
            store_generation: Uuid::new_v4(),
            scope_generation: Uuid::new_v4(),
            prefix: signal_protocol::findings_feed::FindingsCursor::initial(store)
                .map_err(|_| ControlError::Invalid)?,
            limits: FindingScopeLimits {
                producers: 1,
                rows: 1,
                bytes: 4096,
            },
            producer: None,
            checkpoint: None,
        })
    }
    #[test]
    fn original_scope_context_and_shutdown_cannot_be_renewed() -> Result<(), ControlError> {
        let context = ControlContext::new(Duration::from_secs(1))?;
        let stop = CancellationToken::new();
        let pin = FindingScopePin::new(binding()?, context.clone(), stop.child_token())?;
        pin.binding()?;
        context.cancel();
        assert!(matches!(pin.binding(), Err(ControlError::Cancelled)));
        let pin = FindingScopePin::new(
            binding()?,
            ControlContext::new(Duration::from_secs(1))?,
            stop.child_token(),
        )?;
        stop.cancel();
        assert!(matches!(pin.binding(), Err(ControlError::Cancelled)));
        let expired = ControlContext::new(Duration::from_secs(1))?
            .limited_to(tokio::time::Instant::now() - Duration::from_millis(1));
        assert!(matches!(
            FindingScopePin::new(binding()?, expired, CancellationToken::new()),
            Err(ControlError::Timeout)
        ));
        Ok(())
    }
    #[test]
    fn invalid_scope_configuration_fails_before_transport() -> Result<(), ControlError> {
        let settings = ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
            1,
            "unreachable".into(),
            "unreachable".into(),
            b"synthetic".to_vec(),
        )?;
        assert!(matches!(
            FindingScopeAdministrator::new(
                settings,
                "bad\"role".into(),
                FindingScopeProfile::Catalog4
            ),
            Err(ControlError::Invalid)
        ));
        for limits in [
            FindingScopeLimits {
                producers: 0,
                rows: 1,
                bytes: 4096,
            },
            FindingScopeLimits {
                producers: 129,
                rows: 1,
                bytes: 4096,
            },
            FindingScopeLimits {
                producers: 1,
                rows: 65537,
                bytes: 4096,
            },
            FindingScopeLimits {
                producers: 1,
                rows: 1,
                bytes: 4095,
            },
        ] {
            assert!(matches!(limits.validate(), Err(ControlError::Invalid)));
        }
        Ok(())
    }
}
