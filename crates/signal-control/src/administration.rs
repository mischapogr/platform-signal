//! Explicit administration only; runtime opens never install, reset or upgrade.
use crate::{ConnectionSettings, ControlClient, ControlContext, ControlError, ControlMetrics};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Row};
use uuid::Uuid;

const CATALOG_QUERY: &str = include_str!("../../../schemas/shared-control/catalog-query.sql");
const LEGACY_CATALOG: &str = include_str!("../../../schemas/shared-control/002-catalog.sha256");
const BASE: &str = include_str!("../../../schemas/shared-control/001.sql");
const LEGACY: &str = include_str!("../../../schemas/shared-control/002-functions.sql");
const MIGRATION: &str = include_str!("../../../schemas/shared-control/003-administration.sql");
const CATALOG_PROFILE: &str = include_str!("../../../schemas/shared-control/005-catalog.sql");
pub(crate) const VALIDATE_SOURCE: &str = r#"SELECT signal_control.assert_retention_integrity();
DO $$
DECLARE w signal_control.outbox; f signal_control.findings; h signal_control.store;
    position bigint:=0; digest bytea; rows_total bigint; bytes_total bigint;
BEGIN
    SELECT * INTO h FROM signal_control.store WHERE singleton;
    FOR w IN SELECT * FROM signal_control.outbox LOOP PERFORM signal_control.check_notification(w); END LOOP;
    digest:=sha256(convert_to('SIGNAL-FINDINGS-CURSOR-V1','UTF8')||uuid_send(h.store_id));
    FOR f IN SELECT * FROM signal_control.findings ORDER BY findings.position LOOP
        position:=position+1;
        digest:=sha256(convert_to('SIGNAL-FINDINGS-RECORD-V1','UTF8')||digest||int8send(position)||int4send(octet_length(f.content))||f.content);
        IF f.position<>position OR f.content_sha256<>sha256(f.content) OR f.cursor_digest<>digest THEN
            RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    END LOOP;
    IF h.feed_position<>position OR h.feed_digest<>digest OR EXISTS(SELECT 1 FROM signal_control.receipts r
        WHERE r.reference_sha256<>sha256(r.reference) OR decode(convert_from(r.retained_request,'UTF8')::jsonb->>'reference','hex') IS DISTINCT FROM r.reference
        OR (convert_from(r.retained_request,'UTF8')::jsonb->>'id')::uuid IS DISTINCT FROM r.id
        OR (convert_from(r.retained_request,'UTF8')::jsonb->>'prepared_count')::bigint IS DISTINCT FROM r.prepared_count
        OR (convert_from(r.retained_request,'UTF8')::jsonb->>'source_record_count')::bigint IS DISTINCT FROM r.source_record_count) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    IF EXISTS(SELECT 1 FROM signal_control.commits c WHERE
        decode(convert_from(c.request,'UTF8')::jsonb->>'rule_revision','hex') IS DISTINCT FROM c.rule_revision
        OR convert_from(c.request,'UTF8')::jsonb->>'normalizer_revision' IS DISTINCT FROM c.normalizer_revision
        OR (convert_from(c.request,'UTF8')::jsonb->>'id')::uuid IS DISTINCT FROM c.id
        OR (convert_from(c.request,'UTF8')::jsonb->>'first_sequence')::bigint IS DISTINCT FROM c.first_sequence
        OR (convert_from(c.request,'UTF8')::jsonb->>'last_sequence')::bigint IS DISTINCT FROM c.last_sequence) THEN
        RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
    SELECT ((SELECT count(*) FROM signal_control.commits)+(SELECT count(*) FROM signal_control.receipts)+(SELECT count(*) FROM signal_control.state)+(SELECT count(*) FROM signal_control.findings)+(SELECT count(*) FROM signal_control.outbox)+(SELECT count(*) FROM signal_control.snapshots)+(SELECT count(*) FROM signal_control.object_pins)+(SELECT count(*) FROM signal_control.tombstones)+(SELECT count(*) FROM signal_control.notification_attempts)),
    ((SELECT coalesce(sum(512+octet_length(request)+octet_length(manifest)+octet_length(normalizer_revision)+32*cardinality(object_hashes)),0) FROM signal_control.commits)+(SELECT coalesce(sum(256+octet_length(reference)+octet_length(retained_request)),0) FROM signal_control.receipts)+(SELECT coalesce(sum(192+octet_length(key)+octet_length(value)),0) FROM signal_control.state)+(SELECT coalesce(sum(256+octet_length(content)),0) FROM signal_control.findings)+(SELECT coalesce(sum(256+octet_length(plan)),0) FROM signal_control.outbox)+(SELECT coalesce(sum(320+octet_length(manifest_ids)+32*cardinality(object_hashes)),0) FROM signal_control.snapshots)+(SELECT coalesce(sum(512+octet_length(object_reference)+octet_length(request)+coalesce(octet_length(release_request),0)),0) FROM signal_control.object_pins)+(SELECT coalesce(sum(512+octet_length(object_reference)+octet_length(request)),0) FROM signal_control.tombstones)+(SELECT coalesce(sum(512+octet_length(claim_request)+coalesce(octet_length(completion_request),0)),0) FROM signal_control.notification_attempts)) INTO rows_total,bytes_total;
    IF h.used_rows<>rows_total OR h.used_bytes<>bytes_total THEN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT'; END IF;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR character_not_in_repertoire THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='SIGNAL_CORRUPT';
END $$;
"#;
pub(crate) const TABLES: &[&str] = &[
    "store",
    "partitions",
    "commits",
    "receipts",
    "state",
    "findings",
    "outbox",
    "snapshots",
    "tombstones",
    "principals",
    "object_backends",
    "object_scopes",
    "object_pins",
    "notification_attempts",
];
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeScope {
    pub schema_version: u32,
    pub store_id: Uuid,
    pub generation: Uuid,
}
impl AdministrativeScope {
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        if self.schema_version != 1 || self.store_id.is_nil() || self.generation.is_nil() {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeInput {
    pub scope: AdministrativeScope,
    pub max_rows: u32,
    pub max_bytes: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationInput {
    pub scope: AdministrativeScope,
    pub source_revision: u32,
    pub source_sha256: [u8; 32],
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdministrativeResult {
    pub schema_version: u32,
    pub store_id: Uuid,
    pub generation: Uuid,
    pub revision: u32,
    pub ready: bool,
    pub routines_sha256: String,
}
#[derive(Clone)]
pub(crate) enum AdministrativeAction {
    Initialize(InitializeInput),
    Migrate(MigrationInput),
    Inspect(AdministrativeScope),
    CatalogMigrate(MigrationInput),
    CatalogInspect(AdministrativeScope),
}
impl AdministrativeAction {
    pub(crate) fn scope(&self) -> &AdministrativeScope {
        match self {
            Self::Initialize(i) => &i.scope,
            Self::Migrate(i) | Self::CatalogMigrate(i) => &i.scope,
            Self::Inspect(s) | Self::CatalogInspect(s) => s,
        }
    }
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        self.scope().validate()?;
        match self {
            Self::Initialize(i)
                if i.max_rows == 0
                    || i.max_rows > 65536
                    || i.max_bytes == 0
                    || i.max_bytes > 67108864 =>
            {
                Err(ControlError::Invalid)
            }
            Self::Migrate(i) if i.source_revision != 1 || i.source_sha256 != legacy_identity() => {
                Err(ControlError::Invalid)
            }
            Self::CatalogMigrate(i)
                if i.source_revision != 2 || i.source_sha256 != crate::schema_identity().1 =>
            {
                Err(ControlError::Invalid)
            }
            _ => Ok(()),
        }
    }
    pub(crate) fn revision(&self) -> u32 {
        if matches!(self, Self::CatalogMigrate(_) | Self::CatalogInspect(_)) {
            4
        } else {
            2
        }
    }
    pub(crate) fn identity(&self) -> [u8; 32] {
        if self.revision() == 4 {
            crate::catalog_schema_identity().1
        } else {
            crate::schema_identity().1
        }
    }
    pub(crate) fn inspection(&self) -> bool {
        matches!(self, Self::Inspect(_) | Self::CatalogInspect(_))
    }
}
/// Captured administrator transport and explicitly selected schema-owning role.
/// Uses the same bounded owned workers/cancellation/uncertain-COMMIT seats as runtime.
/// No environmental credential fallback or startup invocation exists.
pub struct ControlAdministrator {
    client: ControlClient,
    owner: String,
}
impl ControlAdministrator {
    pub fn new(settings: ConnectionSettings, schema_owner: String) -> Result<Self, ControlError> {
        if schema_owner.is_empty()
            || schema_owner.len() > 63
            || schema_owner.capacity() > 63
            || !schema_owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(ControlError::Invalid);
        }
        Ok(Self {
            client: ControlClient::new(settings)?,
            owner: schema_owner,
        })
    }
    pub async fn initialize(
        &self,
        input: InitializeInput,
        context: ControlContext,
    ) -> Result<AdministrativeResult, ControlError> {
        self.client
            .administer(
                self.owner.clone(),
                AdministrativeAction::Initialize(input),
                context,
            )
            .await
    }
    /// Only the exact supported populated001+002 bundle upgrades. Caller must stop
    /// writers, clear leases and set readiness false first; this method cannot infer
    /// operational quiescence or current restore authority from restored metadata.
    pub async fn migrate(
        &self,
        input: MigrationInput,
        context: ControlContext,
    ) -> Result<AdministrativeResult, ControlError> {
        self.client
            .administer(
                self.owner.clone(),
                AdministrativeAction::Migrate(input),
                context,
            )
            .await
    }
    /// Read-only resolution after an uncertain administrative COMMIT, never a retry.
    pub async fn inspect(
        &self,
        scope: AdministrativeScope,
        context: ControlContext,
    ) -> Result<AdministrativeResult, ControlError> {
        self.client
            .administer(
                self.owner.clone(),
                AdministrativeAction::Inspect(scope),
                context,
            )
            .await
    }
    pub fn metrics(&self) -> ControlMetrics {
        self.client.metrics()
    }
    /// Explicit stopped revision2-to4 upgrade. Does not support restored revision3.
    pub async fn migrate_catalog(
        &self,
        input: MigrationInput,
        context: ControlContext,
    ) -> Result<AdministrativeResult, ControlError> {
        self.client
            .administer(
                self.owner.clone(),
                AdministrativeAction::CatalogMigrate(input),
                context,
            )
            .await
    }
    /// Read-only exact revision4 inspection for uncertain migration resolution.
    pub async fn inspect_catalog(
        &self,
        scope: AdministrativeScope,
        context: ControlContext,
    ) -> Result<AdministrativeResult, ControlError> {
        self.client
            .administer(
                self.owner.clone(),
                AdministrativeAction::CatalogInspect(scope),
                context,
            )
            .await
    }
    pub async fn shutdown(&self, context: ControlContext) -> Result<(), ControlError> {
        self.client.shutdown(context).await
    }
}
pub fn legacy_identity() -> [u8; 32] {
    Sha256::digest(LEGACY.as_bytes()).into()
}
fn body(sql: &str) -> Result<&str, ControlError> {
    let (_, sql) = sql.split_once("BEGIN;\n").ok_or(ControlError::Corrupt)?;
    sql.strip_suffix("COMMIT;\n").ok_or(ControlError::Corrupt)
}
fn field<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a Row,
    index: usize,
) -> Result<T, ControlError> {
    row.try_get(index).map_err(|_| ControlError::Corrupt)
}
async fn execute(client: &Client, sql: &str) -> Result<(), ControlError> {
    client
        .batch_execute(sql)
        .await
        .map_err(crate::client::database_error)
}
async fn inspect_source(client: &Client, owner: &str) -> Result<(), ControlError> {
    inspect_catalog(client, owner, false).await
}
pub(crate) async fn inspect_catalog(
    client: &Client,
    owner: &str,
    revision2: bool,
) -> Result<(), ControlError> {
    inspect_profile(client, owner, if revision2 { 2 } else { 1 }).await
}
pub(crate) async fn inspect_restored_catalog(
    client: &Client,
    owner: &str,
) -> Result<(), ControlError> {
    inspect_profile(client, owner, 3).await
}
pub(crate) async fn inspect_profile(
    client: &Client,
    owner: &str,
    revision: u8,
) -> Result<(), ControlError> {
    let rows=client.query("SELECT c.relname,pg_get_userbyid(c.relowner)::text,EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_control' AND c.relkind IN ('r','v','m','f','p') ORDER BY c.relname LIMIT 18",&[]).await.map_err(crate::client::database_error)?;
    let mut expected: Vec<_> = TABLES.iter().map(|s| s.to_string()).collect();
    if revision >= 2 {
        expected.push("migrations".into());
    }
    if matches!(revision, 3 | 5) {
        expected.push("restore_record".into());
    }
    if matches!(revision, 4 | 5) {
        expected.push("catalog_snapshots".into());
    }
    expected.sort();
    let actual: Vec<String> = rows.iter().map(|r| r.get(0)).collect();
    if actual != expected
        || rows
            .iter()
            .any(|r| r.get::<_, String>(1) != owner || r.get::<_, bool>(2))
    {
        return Err(ControlError::Corrupt);
    }
    let catalog = client
        .query_one(CATALOG_QUERY, &[])
        .await
        .map_err(crate::client::database_error)?
        .get::<_, String>(0);
    let expected_catalog = if revision == 5 {
        include_str!("../../../schemas/shared-control/006-catalog.sha256")
    } else if revision == 4 {
        include_str!("../../../schemas/shared-control/005-catalog.sha256")
    } else if revision == 3 {
        include_str!("../../../schemas/shared-control/004-catalog.sha256")
    } else if revision == 2 {
        include_str!("../../../schemas/shared-control/003-catalog.sha256")
    } else {
        LEGACY_CATALOG
    };
    if catalog != expected_catalog.trim() {
        return Err(ControlError::Corrupt);
    }
    let rows=client.query("SELECT p.proname,CASE WHEN octet_length(p.prosrc)<=32768 THEN p.prosrc ELSE '' END,p.prosecdef,pg_get_userbyid(p.proowner)::text,CASE WHEN cardinality(p.proconfig)=1 AND octet_length(p.proconfig[1])<=256 THEN p.proconfig ELSE NULL END,CASE WHEN p.pronargs<=16 THEN p.proargnames ELSE NULL END,left(oidvectortypes(p.proargtypes),1024),left(format_type(p.prorettype,NULL),256),p.proisstrict,p.provolatile::text,p.prokind::text,(SELECT lanname FROM pg_language WHERE oid=p.prolang),p.pronargdefaults FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='signal_control' ORDER BY p.proname LIMIT 27",&[]).await.map_err(crate::client::database_error)?;
    let mut definitions: Vec<_> = LEGACY
        .split("CREATE FUNCTION signal_control.")
        .skip(1)
        .collect();
    if revision >= 2 {
        definitions.retain(|d| !d.starts_with("check_scope("));
        definitions.push(
            MIGRATION
                .split_once("CREATE OR REPLACE FUNCTION signal_control.")
                .ok_or(ControlError::Corrupt)?
                .1,
        );
    }
    // Compare trusted compiled replacements, never restored function bodies.
    let restored = include_str!("../../../schemas/shared-control/004-restore.sql")
        .replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION");
    if revision == 3 {
        for definition in restored.split("CREATE FUNCTION signal_control.").skip(1) {
            let (name, _) = definition.split_once('(').ok_or(ControlError::Corrupt)?;
            definitions.retain(|d| !d.starts_with(&format!("{name}(")));
            definitions.push(definition);
        }
    }
    let catalog = CATALOG_PROFILE.replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION");
    if matches!(revision, 4 | 5) {
        for definition in catalog.split("CREATE FUNCTION signal_control.").skip(1) {
            let (name, _) = definition.split_once('(').ok_or(ControlError::Corrupt)?;
            definitions.retain(|d| !d.starts_with(&format!("{name}(")));
            definitions.push(definition);
        }
    }
    let restored_catalog = include_str!("../../../schemas/shared-control/006-catalog-restore.sql")
        .replace("CREATE OR REPLACE FUNCTION", "CREATE FUNCTION");
    if revision == 5 {
        for definition in restored_catalog
            .split("CREATE FUNCTION signal_control.")
            .skip(1)
        {
            let (name, _) = definition.split_once('(').ok_or(ControlError::Corrupt)?;
            definitions.retain(|d| !d.starts_with(&format!("{name}(")));
            definitions.push(definition);
        }
    }
    if rows.len() != definitions.len() {
        return Err(ControlError::Corrupt);
    }
    for definition in definitions {
        let (name, _) = definition.split_once('(').ok_or(ControlError::Corrupt)?;
        let (header, tail) = definition
            .split_once("AS $$")
            .ok_or(ControlError::Corrupt)?;
        let (source, _) = tail.split_once("$$;").ok_or(ControlError::Corrupt)?;
        let matches: Vec<_> = rows
            .iter()
            .filter(|r| r.get::<_, String>(0) == name)
            .collect();
        if matches.len() != 1 {
            return Err(ControlError::Corrupt);
        }
        let parameters = header
            .split_once('(')
            .and_then(|(_, s)| s.split_once(')'))
            .ok_or(ControlError::Corrupt)?
            .0;
        let parameters: Vec<_> = parameters
            .split(',')
            .filter(|p| !p.trim().is_empty())
            .collect();
        let argument_names: Vec<String> = parameters
            .iter()
            .filter_map(|p| p.split_whitespace().next().map(str::to_string))
            .collect();
        let normalize_type = |s: &str| {
            s.replace("signal_control.", "")
                .replace("timestamptz", "timestamp with time zone")
        };
        let argument_types = parameters
            .iter()
            .map(|p| normalize_type(&p.split_whitespace().skip(1).collect::<Vec<_>>().join(" ")))
            .collect::<Vec<_>>()
            .join(", ");
        let return_type = normalize_type(
            header
                .split_once("RETURNS ")
                .and_then(|(_, s)| s.split_once("LANGUAGE"))
                .ok_or(ControlError::Corrupt)?
                .0
                .trim(),
        );
        let r = matches[0];
        if r.get::<_, Option<Vec<String>>>(5).unwrap_or_default() != argument_names
            || r.get::<_, String>(6) != argument_types
            || r.get::<_, String>(7) != return_type
            || r.get::<_, bool>(8) != header.contains("STRICT")
            || r.get::<_, String>(9)
                != (if header.contains("IMMUTABLE") {
                    "i"
                } else if header.contains("STABLE") {
                    "s"
                } else {
                    "v"
                })
            || r.get::<_, String>(10) != "f"
            || r.get::<_, String>(11)
                != (if header.contains("LANGUAGE plpgsql") {
                    "plpgsql"
                } else {
                    "sql"
                })
            || r.get::<_, i16>(12) != 0
        {
            return Err(ControlError::Corrupt);
        }

        if r.get::<_, String>(1) != source
            || r.get::<_, bool>(2) != header.contains("SECURITY DEFINER")
            || r.get::<_, String>(3) != owner
            || r.get::<_, Option<Vec<String>>>(4)
                != Some(vec![
                    "search_path=pg_catalog, signal_control, pg_temp".into(),
                ])
        {
            return Err(ControlError::Corrupt);
        }
    }
    Ok(())
}
async fn run_catalog(
    client: &Client,
    owner: &str,
    action: &AdministrativeAction,
) -> Result<Row, ControlError> {
    let scope = action.scope();
    let (base, target) = crate::catalog_schema_identity();
    let current = crate::schema_identity().1;
    execute(
        client,
        "LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT",
    )
    .await?;
    let row=client.query_one("SELECT store_id,generation,revision,ready,CASE WHEN octet_length(schema_sha256)=32 THEN schema_sha256 ELSE NULL END,CASE WHEN octet_length(routines_sha256)=32 THEN routines_sha256 ELSE NULL END,max_rows,max_bytes FROM signal_control.store WHERE singleton LIMIT 2",&[]).await.map_err(crate::client::database_error)?;
    if field::<Uuid>(&row, 0)? != scope.store_id || field::<Uuid>(&row, 1)? != scope.generation {
        return Err(ControlError::Fenced);
    }
    if field::<Vec<u8>>(&row, 4)? != base
        || !(1..=65536).contains(&field::<i64>(&row, 6)?)
        || !(1..=67108864).contains(&field::<i64>(&row, 7)?)
    {
        return Err(ControlError::Corrupt);
    }
    let revision = field::<i32>(&row, 2)?;
    let routines = field::<Vec<u8>>(&row, 5)?;
    if action.inspection() {
        if revision != 4 || routines != target {
            return Err(ControlError::Corrupt);
        }
    } else {
        if revision == 4 && routines == target {
            return Err(ControlError::Conflict);
        }
        if revision != 2 || routines != current {
            return Err(ControlError::Corrupt);
        }
        if field::<bool>(&row, 3)? {
            return Err(ControlError::Fenced);
        }
        let locks = TABLES
            .iter()
            .filter(|name| **name != "store")
            .map(|name| format!("signal_control.{name}"))
            .chain(std::iter::once("signal_control.migrations".into()))
            .collect::<Vec<_>>()
            .join(",");
        execute(
            client,
            &format!("LOCK TABLE {locks} IN ACCESS EXCLUSIVE MODE NOWAIT"),
        )
        .await?;
        if client.query_one("SELECT EXISTS(SELECT 1 FROM signal_control.partitions WHERE owner IS NOT NULL OR lease_until IS NOT NULL)",&[]).await.map_err(crate::client::database_error)?.get::<_,bool>(0) {
            return Err(ControlError::Fenced);
        }
        inspect_profile(client, owner, 2).await?;
        let history=client.query_one("SELECT count(*)=3 AND bool_and((ordinal=1 AND artifact='001.sql' AND sha256=$1) OR (ordinal=2 AND artifact='002-functions.sql' AND sha256=$2) OR (ordinal=3 AND artifact='003-administration.sql' AND sha256=$3)) FROM signal_control.migrations",&[&base.as_slice(),&legacy_identity().as_slice(),&current.as_slice()]).await.map_err(crate::client::database_error)?;
        if !history.get::<_, bool>(0) {
            return Err(ControlError::Corrupt);
        }
        execute(client, VALIDATE_SOURCE).await?;
        execute(client, CATALOG_PROFILE).await?;
        client.execute("INSERT INTO signal_control.migrations(ordinal,artifact,sha256) VALUES(4,'005-catalog.sql',$1)",&[&target.as_slice()]).await.map_err(crate::client::database_error)?;
        client.execute("UPDATE signal_control.store SET revision=4,routines_sha256=$1 WHERE singleton AND NOT ready",&[&target.as_slice()]).await.map_err(crate::client::database_error)?;
    }
    inspect_profile(client, owner, 4).await?;
    let history=client.query_one("SELECT count(*)=4 AND bool_and((ordinal=1 AND artifact='001.sql' AND sha256=$1) OR (ordinal=2 AND artifact='002-functions.sql' AND sha256=$2) OR (ordinal=3 AND artifact='003-administration.sql' AND sha256=$3) OR (ordinal=4 AND artifact='005-catalog.sql' AND sha256=$4)) FROM signal_control.migrations",&[&base.as_slice(),&legacy_identity().as_slice(),&current.as_slice(),&target.as_slice()]).await.map_err(crate::client::database_error)?;
    if !history.get::<_, bool>(0) {
        return Err(ControlError::Corrupt);
    }
    validate_catalog_state(client).await?;
    client.query_one("SELECT jsonb_build_object('schema_version',1,'store_id',store_id,'generation',generation,'revision',revision,'ready',ready,'routines_sha256',encode(routines_sha256,'hex')) FROM signal_control.store WHERE singleton",&[]).await.map_err(crate::client::database_error)
}

pub(crate) async fn validate_catalog_state(client: &Client) -> Result<(), ControlError> {
    // Reuse the original full census, adding exactly the new immutable framing.
    let rows = "(SELECT count(*) FROM signal_control.notification_attempts))";
    let bytes = "FROM signal_control.notification_attempts)) INTO rows_total,bytes_total";
    if !VALIDATE_SOURCE.contains(rows) || !VALIDATE_SOURCE.contains(bytes) {
        return Err(ControlError::Corrupt);
    }
    let census=VALIDATE_SOURCE.replace(rows,"(SELECT count(*) FROM signal_control.notification_attempts)+(SELECT count(*) FROM signal_control.catalog_snapshots))")
        .replace(bytes,"FROM signal_control.notification_attempts)+(SELECT 320*count(*) FROM signal_control.catalog_snapshots)) INTO rows_total,bytes_total");
    execute(client, &census).await?;
    execute(client,r#"DO $$
BEGIN
    IF EXISTS(SELECT 1 FROM signal_control.catalog_snapshots q LEFT JOIN signal_control.snapshots p ON p.id=q.id
        WHERE p.id IS NULL OR q.partition_id<>p.partition_id OR q.generation<>p.generation
        OR q.seal<>signal_control.catalog_snapshot_seal(q)
        OR (p.expires_at>clock_timestamp() AND q.manifest_ids_sha256<>sha256(p.manifest_ids))) THEN
        RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_CORRUPT';
    END IF;
END $$;"#).await
}

pub(crate) async fn run(
    client: &Client,
    owner: &str,
    action: &AdministrativeAction,
) -> Result<Row, ControlError> {
    // Identifier is bounded ASCII alphanumeric/underscore, validated before admission.
    execute(
        client,
        &format!(
            "SET LOCAL ROLE \"{owner}\"; SET LOCAL search_path=pg_catalog,signal_control,pg_temp"
        ),
    )
    .await?;
    let scope = action.scope();
    if action.revision() == 4 {
        return run_catalog(client, owner, action).await;
    }
    let (base, current) = crate::schema_identity();
    let legacy = legacy_identity();
    if let AdministrativeAction::Initialize(input) = action {
        let exists = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='signal_control')",
                &[],
            )
            .await
            .map_err(crate::client::database_error)?
            .get::<_, bool>(0);
        if exists {
            return Err(ControlError::Conflict);
        }
        execute(client, body(BASE)?).await?;
        execute(client, body(LEGACY)?).await?;
        let feed: Vec<u8> = Sha256::digest(
            [
                b"SIGNAL-FINDINGS-CURSOR-V1".as_slice(),
                scope.store_id.as_bytes(),
            ]
            .concat(),
        )
        .to_vec();
        client.execute("INSERT INTO signal_control.store(singleton,store_id,generation,revision,ready,feed_digest,schema_sha256,routines_sha256,max_rows,max_bytes) VALUES(true,$1,$2,1,false,$3,$4,$5,$6,$7)",&[&scope.store_id,&scope.generation,&feed,&base.as_slice(),&legacy.as_slice(),&i64::from(input.max_rows),&(input.max_bytes as i64)]).await.map_err(crate::client::database_error)?;
    }
    // Store lock first, then all known data tables; no reader/writer can cross DDL.
    execute(
        client,
        "LOCK TABLE signal_control.store IN ACCESS EXCLUSIVE MODE NOWAIT",
    )
    .await?;
    let frame=client.query_one("SELECT count(*)=8 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='signal_control' AND c.relname='store' AND c.relkind='r' AND NOT a.attisdropped AND ((a.attname IN ('store_id','generation') AND a.atttypid='uuid'::regtype) OR (a.attname='revision' AND a.atttypid='integer'::regtype) OR (a.attname='ready' AND a.atttypid='boolean'::regtype) OR (a.attname IN ('schema_sha256','routines_sha256') AND a.atttypid='bytea'::regtype) OR (a.attname IN ('max_rows','max_bytes') AND a.atttypid='bigint'::regtype))",&[]).await.map_err(crate::client::database_error)?;
    if !field::<bool>(&frame, 0)? {
        return Err(ControlError::Corrupt);
    }
    let head=client.query_one("SELECT store_id,generation,revision,ready,CASE WHEN octet_length(schema_sha256)=32 THEN schema_sha256 ELSE NULL END,CASE WHEN octet_length(routines_sha256)=32 THEN routines_sha256 ELSE NULL END,max_rows,max_bytes FROM signal_control.store WHERE singleton LIMIT 2",&[]).await.map_err(crate::client::database_error)?;
    if field::<Uuid>(&head, 0)? != scope.store_id || field::<Uuid>(&head, 1)? != scope.generation {
        return Err(ControlError::Fenced);
    }
    if field::<Vec<u8>>(&head, 4)? != base
        || field::<i64>(&head, 6)? > 65536
        || field::<i64>(&head, 7)? > 67108864
    {
        return Err(ControlError::Corrupt);
    }
    let revision = field::<i32>(&head, 2)?;
    if matches!(action, AdministrativeAction::Inspect(_)) {
        if revision != 2 || field::<Vec<u8>>(&head, 5)? != current {
            return Err(ControlError::Corrupt);
        }
        let row=client.query_one("SELECT count(*)=3 AND bool_and((ordinal=1 AND artifact='001.sql' AND sha256=$1) OR (ordinal=2 AND artifact='002-functions.sql' AND sha256=$2) OR (ordinal=3 AND artifact='003-administration.sql' AND sha256=$3)) FROM signal_control.migrations",&[&base.as_slice(),&legacy.as_slice(),&current.as_slice()]).await.map_err(crate::client::database_error)?;
        if !row.get::<_, bool>(0) {
            return Err(ControlError::Corrupt);
        }
    } else {
        if revision == 2 && field::<Vec<u8>>(&head, 5)? == current {
            return Err(ControlError::Conflict);
        }
        if revision != 1 || field::<Vec<u8>>(&head, 5)? != legacy {
            return Err(ControlError::Corrupt);
        }
        if field::<bool>(&head, 3)? {
            return Err(ControlError::Fenced);
        }
        let sql = format!(
            "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE NOWAIT",
            TABLES
                .iter()
                .map(|n| format!("signal_control.{n}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        execute(client, &sql).await?;
        let active=client.query_one("SELECT EXISTS(SELECT 1 FROM signal_control.partitions WHERE owner IS NOT NULL OR lease_until IS NOT NULL)",&[]).await.map_err(crate::client::database_error)?.get::<_,bool>(0);
        if active {
            return Err(ControlError::Fenced);
        }
        inspect_source(client, owner).await?;
        // This exact qualified migration changes schema/control identity only;
        // retained payload/receipt/state/feed/attempt rows are never rewritten.
        execute(client, VALIDATE_SOURCE).await?;
        execute(client, MIGRATION).await?;
        for (ordinal, artifact, hash) in [
            (1, "001.sql", base),
            (2, "002-functions.sql", legacy),
            (3, "003-administration.sql", current),
        ] {
            client.execute("INSERT INTO signal_control.migrations(ordinal,artifact,sha256) VALUES($1,$2,$3)",&[&ordinal,&artifact,&hash.as_slice()]).await.map_err(crate::client::database_error)?;
        }
        client.execute("UPDATE signal_control.store SET revision=2,routines_sha256=$1 WHERE singleton AND NOT ready",&[&current.as_slice()]).await.map_err(crate::client::database_error)?;
    }
    client.query_one("SELECT jsonb_build_object('schema_version',1,'store_id',store_id,'generation',generation,'revision',revision,'ready',ready,'routines_sha256',encode(routines_sha256,'hex')) FROM signal_control.store WHERE singleton",&[]).await.map_err(crate::client::database_error)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn administration_bounds_and_source_order_are_explicit() {
        let scope = AdministrativeScope {
            schema_version: 1,
            store_id: Uuid::from_u128(1),
            generation: Uuid::from_u128(2),
        };
        assert!(
            AdministrativeAction::Initialize(InitializeInput {
                scope: scope.clone(),
                max_rows: 65537,
                max_bytes: 1
            })
            .validate()
            .is_err()
        );
        assert!(
            AdministrativeAction::Migrate(MigrationInput {
                scope,
                source_revision: 2,
                source_sha256: legacy_identity()
            })
            .validate()
            .is_err()
        );
        let settings = ConnectionSettings::fixture_loopback(
            std::net::IpAddr::from([127, 0, 0, 1]),
            5432,
            "fixture".into(),
            "fixture".into(),
            b"synthetic".to_vec(),
        );
        assert!(settings.is_ok());
        if let Ok(settings) = settings {
            assert!(matches!(
                ControlAdministrator::new(settings, "owner\";RESET ROLE".into()),
                Err(ControlError::Invalid)
            ));
        }
        assert!(body(BASE).is_ok());
        assert!(body(LEGACY).is_ok());
        assert!(body("BEGIN;\nCOMMIT;malformed").is_err());
    }
}
