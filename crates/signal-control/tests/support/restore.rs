//! Actual owned PostgreSQL and immutable local files; authority remains synthetic.
use sha2::{Digest, Sha256};
use signal_control::*;
use signal_storage::object_manifest::{QueryFile, QueryManifest, QueryObjectRef, data_key};
use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio_postgres::Client;
use uuid::Uuid;
type Error = Box<dyn std::error::Error>;
fn settings(f: &super::Fixture, db: &str, user: &str) -> Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        IpAddr::from([127, 0, 0, 1]),
        f.port,
        db.into(),
        user.into(),
        f.password.as_bytes().to_vec(),
    )
}
async fn idle(restore: &PostgresStoppedRestore) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(4), async {
        while restore.metrics().active != 0 || restore.metrics().queue_depth != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}
struct Authority {
    approved: AtomicBool,
    checkpoint: Mutex<Option<[u8; 32]>>,
    binding: [u8; 32],
    destination: Uuid,
}
impl RestoreAuthority for Authority {
    fn authorize<'a>(
        &'a self,
        c: &'a RestoreChallenge,
        i: &'a RestoreInventory,
        _: ControlContext,
    ) -> RestoreFuture<'a, RestoreDecision> {
        Box::pin(async move {
            // This current decision is held outside both databases and backup bytes.
            if !self.approved.load(Ordering::SeqCst)
                || c.destination_id != self.destination
                || self
                    .checkpoint
                    .lock()
                    .map_err(|_| ControlError::Unavailable)?
                    .as_ref()
                    != Some(&i.checkpoint_sha256)
            {
                return Err(ControlError::Fenced);
            }
            if i.revisions.iter().any(|r| {
                r.rule_sha256 != Sha256::digest(b"synthetic exact rule bytes").as_slice()
                    || r.normalizer != "synthetic-exact-v1"
            }) {
                return Err(ControlError::Fenced);
            }
            Ok(RestoreDecision {
                challenge: c.clone(),
                approval_id: Uuid::from_u128(0xa10),
                custody_sha256: Sha256::digest(b"independently held current synthetic custody")
                    .into(),
                credential_binding_sha256: self.binding,
                expires_at: tokio::time::Instant::now() + Duration::from_secs(5),
            })
        })
    }
}
struct Consumers {
    current: Mutex<Vec<RestoreConsumerCursor>>,
}
impl RestoreConsumers for Consumers {
    fn reconcile<'a>(
        &'a self,
        c: &'a RestoreChallenge,
        expected: &'a [RestoreConsumerCursor],
        _: ControlContext,
    ) -> RestoreFuture<'a, ReconciledConsumers> {
        Box::pin(async move {
            let actual = self
                .current
                .lock()
                .map_err(|_| ControlError::Unavailable)?
                .clone();
            if actual != expected {
                return Err(ControlError::Fenced);
            }
            Ok(ReconciledConsumers {
                challenge: c.clone(),
                consumers: actual,
            })
        })
    }
}
struct Custody {
    root: std::path::PathBuf,
    references: std::collections::BTreeMap<[u8; 32], (&'static str, &'static str)>,
    protected: AtomicBool,
}
impl RestoreCustody for Custody {
    fn verify<'a>(
        &'a self,
        o: &'a RestoreObject,
        protected: bool,
        _: &'a RestoreDecision,
        context: ControlContext,
    ) -> RestoreFuture<'a, ()> {
        Box::pin(async move {
            context.check()?;
            let (version, file) = self
                .references
                .get(&o.object.digest()?)
                .ok_or(ControlError::Fenced)?;
            if o.object.version != *version || (protected && !self.protected.load(Ordering::SeqCst))
            {
                return Err(ControlError::Fenced);
            }
            let bytes =
                std::fs::read(self.root.join(file)).map_err(|_| ControlError::Unavailable)?;
            context.check()?;
            if bytes.len() as u64 != o.bytes || Sha256::digest(&bytes).as_slice() != o.sha256 {
                return Err(ControlError::Corrupt);
            }
            Ok(())
        })
    }
}
fn command(work: Uuid, attempt: Uuid, action: NotificationAction) -> NotificationInput {
    NotificationInput {
        schema_version: 1,
        work_id: work,
        attempt_id: attempt,
        action,
    }
}
pub async fn qualify(root: &Client, f: &super::Fixture) -> Result<(), Error> {
    eprintln!("phase: stopped-restore-owned-source-and-destination");
    for name in ["signal_restore_source", "signal_restore_destination"] {
        root.batch_execute(&format!("CREATE DATABASE {name}"))
            .await?;
        root.batch_execute(&format!(
            "GRANT CREATE ON DATABASE {name} TO signal_control_owner"
        ))
        .await?;
    }
    let scope = AdministrativeScope {
        schema_version: 1,
        store_id: Uuid::from_u128(0xa01),
        generation: Uuid::from_u128(0xa02),
    };
    let source_admin = ControlAdministrator::new(
        settings(f, "signal_restore_source", "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    source_admin
        .initialize(
            InitializeInput {
                scope: scope.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            super::context()?,
        )
        .await?;
    let (source, source_driver) = super::admin_database(f, "signal_restore_source").await?;
    let part = Uuid::from_u128(0xa03);
    let stream = Uuid::from_u128(0xa04);
    let backend_id = Uuid::from_u128(0xa05);
    let consumer = Uuid::from_u128(0xa06);
    source.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,'synthetic-restore',$2,'pipeline'),($3,'synthetic-restore',$2,'notification')",&[&part,&stream,&consumer]).await?;
    source.execute("INSERT INTO signal_control.principals(role_name,tenant,stream,partition_id) VALUES('signal_runtime','synthetic-restore',$1,$2),('signal_runtime','synthetic-restore',$1,$3)",&[&stream,&part,&consumer]).await?;
    source.execute("INSERT INTO signal_control.object_backends(id,canonical_id) VALUES($1,'owned-local-restore-version-store')",&[&backend_id]).await?;
    source.execute("INSERT INTO signal_control.object_scopes(partition_id,backend_id,key_prefix) VALUES($1,$2,$3)",&[&part,&backend_id,&format!("query/{stream}/")]).await?;
    source.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    let runtime = ControlClient::new(settings(f, "signal_restore_source", "signal_runtime")?)?;
    let s = Scope {
        schema_version: 1,
        store_id: scope.store_id,
        generation: scope.generation,
        tenant: "synthetic-restore".into(),
        stream,
        partition_id: part,
    };
    let token = runtime
        .acquire(s.clone(), Uuid::from_u128(0xa07), 60000, super::context()?)
        .await?;
    let temp = tempfile::tempdir()?;
    let object_bytes = b"actual immutable local restore object bytes";
    std::fs::write(temp.path().join("immutable-version-1"), object_bytes)?;
    let sha: [u8; 32] = Sha256::digest(object_bytes).into();
    let object = RestoreObject {
        object: CanonicalObjectRef {
            schema_version: 1,
            backend_id,
            key: data_key(stream, "2026-10-10", 0, sha),
            version: "exact-local-version-1".into(),
        },
        sha256: sha,
        bytes: object_bytes.len() as u64,
    };
    let custody_bytes = b"independent custody-only original";
    std::fs::write(temp.path().join("immutable-version-2"), custody_bytes)?;
    let custody_object = RestoreObject {
        object: CanonicalObjectRef {
            schema_version: 1,
            backend_id,
            key: format!("query/{stream}/original/custody-only"),
            version: "exact-local-version-2".into(),
        },
        bytes: custody_bytes.len() as u64,
        sha256: Sha256::digest(custody_bytes).into(),
    };
    let custody_description = ObjectCustodyDescription {
        schema_version: 1,
        id: Uuid::from_u128(0xa29),
        scope: s.clone(),
        object: custody_object.object.clone(),
        bytes: custody_object.bytes,
        sha256: custody_object.sha256,
        retain_until: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    #[derive(serde::Serialize)]
    struct CustodyReference<'a> {
        kind: &'static str,
        description: &'a ObjectCustodyDescription,
    }
    let custody_reference = serde_json::to_vec(&CustodyReference {
        kind: "object_custody_v1",
        description: &custody_description,
    })?;
    runtime
        .record_receipt(
            token.clone(),
            ReceiptInput {
                schema_version: 1,
                id: custody_description.id,
                prepared_count: 0,
                source_record_count: 0,
                reference: custody_reference.clone(),
            },
            super::context()?,
        )
        .await?;
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: stream,
        normalizer_revision: "synthetic-exact-v1".into(),
        first_sequence: 1,
        last_sequence: 1,
        events: 1,
        previous: None,
        files: vec![QueryFile {
            date: "2026-10-10".into(),
            hour: 0,
            object: QueryObjectRef {
                key: object.object.key.clone(),
                version: Some(object.object.version.clone()),
                etag: None,
                bytes: object.bytes,
                sha256: sha,
            },
            rows: 1,
            decoded_bytes: 256,
        }],
    };
    let rule: [u8; 32] = Sha256::digest(b"synthetic exact rule bytes").into();
    let commit = Uuid::from_u128(0xa08);
    let works = [Uuid::from_u128(0xa20), Uuid::from_u128(0xa21)];
    let findings = [Uuid::from_u128(0xa22), Uuid::from_u128(0xa23)];
    let attempts = [Uuid::from_u128(0xa24), Uuid::from_u128(0xa25)];
    let receipt = Uuid::from_u128(0xa26);
    runtime
        .record_receipt(
            token.clone(),
            ReceiptInput {
                schema_version: 1,
                id: receipt,
                prepared_count: 1,
                source_record_count: 1,
                reference: b"original exact synthetic source cursor custody".to_vec(),
            },
            super::context()?,
        )
        .await?;
    runtime.publish(token.clone(),PublicationInput{schema_version:1,id:commit,previous:None,first_sequence:1,last_sequence:1,manifest:serde_json::to_vec(&manifest)?,rule_revision:rule,normalizer_revision:"synthetic-exact-v1".into(),states:vec![RevisionedState{key:"synthetic-state".into(),revision:rule,bytes:b"exact historical detector state".to_vec()}],findings:findings.iter().map(|id|Ok(FindingInput{id:*id,bytes:serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":id,"rule_id":"synthetic-restore","created_at":"2026-10-10T00:00:00Z","severity":"high","title":"synthetic-restore","event_ids":[Uuid::from_u128(0xa27)],"attributes":{}}))?})).collect::<Result<_,serde_json::Error>>()?,work:works.iter().zip(findings).map(|(id,finding_id)|WorkInput{id:*id,finding_id,bytes:b"original opaque delivery key and exact plan".to_vec()}).collect(),receipts:vec![ReceiptProgress{id:receipt,expected_prefix:0,verified_prefix:1}]},super::context()?).await?;
    for (work, attempt) in works.into_iter().zip(attempts) {
        runtime
            .notification(
                token.clone(),
                command(work, attempt, NotificationAction::Claim {}),
                super::context()?,
            )
            .await?;
    }
    runtime
        .notification(
            token.clone(),
            command(
                works[0],
                attempts[0],
                NotificationAction::Finish {
                    outcome: NotificationOutcome::Delivered,
                    evidence: b"original delivered evidence".to_vec(),
                },
            ),
            super::context()?,
        )
        .await?;
    runtime
        .pin_object(
            token.clone(),
            RetentionPinInput {
                schema_version: 1,
                id: Uuid::from_u128(0xa28),
                object: object.object.clone(),
                kind: RetentionKind::Evidence,
                reference: b"original protected evidence policy reference".to_vec(),
            },
            super::context()?,
        )
        .await?;
    // Freeze before the coherent checkpoint. Original epochs and attempt evidence remain.
    source.batch_execute("UPDATE signal_control.store SET ready=false; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL; UPDATE signal_control.partitions SET feed_position=1 WHERE kind='notification'").await?;
    runtime.shutdown(super::context()?).await?;
    source_admin.shutdown(super::context()?).await?;
    let destination_admin = ControlAdministrator::new(
        settings(f, "signal_restore_destination", "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    destination_admin
        .initialize(
            InitializeInput {
                scope: scope.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            super::context()?,
        )
        .await?;
    destination_admin.shutdown(super::context()?).await?;
    let (destination, destination_driver) =
        super::admin_database(f, "signal_restore_destination").await?;
    // Import rows only into trusted compiled schema. Source is stopped for the whole
    // explicit transaction; no dump DDL, backup credential or readiness is executed.
    source.batch_execute("BEGIN; SET LOCAL TimeZone='UTC'; SET LOCAL bytea_output='hex'; SET LOCAL DateStyle='ISO,YMD'; LOCK TABLE signal_control.store,signal_control.partitions,signal_control.commits,signal_control.receipts,signal_control.state,signal_control.findings,signal_control.outbox,signal_control.snapshots,signal_control.tombstones,signal_control.principals,signal_control.object_backends,signal_control.object_scopes,signal_control.object_pins,signal_control.notification_attempts,signal_control.migrations IN ACCESS EXCLUSIVE MODE NOWAIT").await?;
    // Anchor approval to the source's locked coherent checkpoint, before copying.
    // The later staged database cannot manufacture its own approval checkpoint.
    let mut checkpoint_rows = Vec::new();
    for table in [
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
        "migrations",
    ] {
        let query = format!(
            "SELECT sha256(convert_to(coalesce(jsonb_agg(h ORDER BY h),'[]'::jsonb)::text,'UTF8')) FROM (SELECT encode(sha256(convert_to(to_jsonb(t)::text,'UTF8')),'hex') AS h FROM signal_control.{table} t) s"
        );
        let hash: Vec<u8> = source.query_one(&query, &[]).await?.get(0);
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| "source checkpoint hash frame")?;
        checkpoint_rows.push((table, hash));
    }
    let independently_captured_checkpoint: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&checkpoint_rows)?).into();
    destination
        .batch_execute("BEGIN; TRUNCATE signal_control.store,signal_control.migrations")
        .await?;
    for table in [
        "store",
        "object_backends",
        "partitions",
        "object_scopes",
        "principals",
        "commits",
        "receipts",
        "state",
        "findings",
        "outbox",
        "snapshots",
        "tombstones",
        "object_pins",
        "notification_attempts",
        "migrations",
    ] {
        let selection = if table == "partitions" {
            "to_jsonb(t)||jsonb_build_object('head',NULL)"
        } else {
            "to_jsonb(t)"
        };
        let rows:serde_json::Value=source.query_one(&format!("SELECT coalesce(jsonb_agg({selection}),'[]'::jsonb) FROM signal_control.{table} t"),&[]).await?.get(0);
        destination.execute(&format!("INSERT INTO signal_control.{table} SELECT * FROM jsonb_populate_recordset(NULL::signal_control.{table},$1)"),&[&rows]).await?;
    }
    destination
        .execute(
            "UPDATE signal_control.partitions SET head=$1 WHERE id=$2",
            &[&commit, &part],
        )
        .await?;
    destination.batch_execute("COMMIT").await?;
    source.batch_execute("COMMIT").await?;
    let history_before: serde_json::Value = source
        .query_one(
            "SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM signal_control.notification_attempts a",
            &[],
        )
        .await?
        .get(0);
    let source_before:serde_json::Value=source.query_one("SELECT jsonb_build_object('store',(SELECT to_jsonb(s) FROM signal_control.store s),'parts',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM signal_control.partitions p))",&[]).await?.get(0);
    let enrollment = RestoreDestination {
        id: Uuid::from_u128(0xa09),
        credential_binding_sha256: Sha256::digest(
            b"separately enrolled synthetic current credential binding",
        )
        .into(),
    };
    let consumers = Arc::new(Consumers {
        current: Mutex::new(vec![]),
    });
    let incomplete = PostgresStoppedRestore::new(
        settings(f, "signal_restore_destination", "signal_migrator")?,
        "signal_control_owner".into(),
        scope.clone(),
        enrollment.clone(),
        vec![object.clone()],
        consumers.clone(),
    )?;
    assert!(matches!(
        incomplete.stage(super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    incomplete.shutdown(super::context()?).await?;
    let mut retained = std::collections::BTreeMap::new();
    retained.insert(object.object.digest()?, object.clone());
    retained.insert(custody_object.object.digest()?, custody_object.clone());
    let restore = PostgresStoppedRestore::new(
        settings(f, "signal_restore_destination", "signal_migrator")?,
        "signal_control_owner".into(),
        scope.clone(),
        enrollment.clone(),
        retained.into_values().collect(),
        consumers.clone(),
    )?;
    eprintln!("phase: stopped-restore-source-staged-rows-copied");
    let inventory = restore.stage(super::context()?).await?;
    assert_eq!(inventory.objects.len(), 2);
    assert!(
        inventory
            .protected_objects
            .contains(&custody_object.object.digest()?)
    );
    assert_eq!(
        inventory.checkpoint_sha256,
        independently_captured_checkpoint
    );
    *consumers
        .current
        .lock()
        .map_err(|_| "consumer fixture mutex")? = inventory.consumers.clone();
    let authority = Authority {
        approved: AtomicBool::new(false),
        checkpoint: Mutex::new(Some(independently_captured_checkpoint)),
        binding: enrollment.credential_binding_sha256,
        destination: enrollment.id,
    };
    let restored_objects = temp.path().join("restored-version-store");
    std::fs::create_dir(&restored_objects)?;
    std::fs::copy(
        temp.path().join("immutable-version-1"),
        restored_objects.join("immutable-version-1"),
    )?;
    std::fs::copy(
        temp.path().join("immutable-version-2"),
        restored_objects.join("immutable-version-2"),
    )?;
    let custody = Custody {
        root: restored_objects.clone(),
        references: [
            (
                object.object.digest()?,
                ("exact-local-version-1", "immutable-version-1"),
            ),
            (
                custody_object.object.digest()?,
                ("exact-local-version-2", "immutable-version-2"),
            ),
        ]
        .into(),
        protected: AtomicBool::new(true),
    };
    let generation = Uuid::from_u128(0xa11);
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(
        destination
            .query_one("SELECT generation FROM signal_control.store", &[])
            .await?
            .get::<_, Uuid>(0),
        scope.generation
    );
    authority.approved.store(true, Ordering::SeqCst);
    eprintln!("phase: stopped-restore-current-approval-object-failure-gates");
    std::fs::remove_file(restored_objects.join("immutable-version-2"))?;
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await,
        Err(ControlError::Unavailable)
    ));
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    std::fs::write(restored_objects.join("immutable-version-2"), custody_bytes)?;
    let copied: Vec<u8> = destination
        .query_one(
            "SELECT reference FROM signal_control.receipts WHERE id=$1",
            &[&custody_description.id],
        )
        .await?
        .get(0);
    assert_eq!(copied, custody_reference);
    eprintln!(
        "phase: stopped-restore-custody-only-original-root-missing-inventory-object-refusal-exact-reference-qualified"
    );

    std::fs::write(
        restored_objects.join("immutable-version-1"),
        b"corrupt immutable bytes",
    )?;
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    std::fs::remove_file(restored_objects.join("immutable-version-1"))?;
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await,
        Err(ControlError::Unavailable)
    ));
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    std::fs::write(restored_objects.join("immutable-version-1"), object_bytes)?;
    custody.protected.store(false, Ordering::SeqCst);
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    custody.protected.store(true, Ordering::SeqCst);
    destination
        .execute(
            "UPDATE signal_control.store SET routines_sha256=$1",
            &[&[0u8; 32].as_slice()],
        )
        .await?;
    assert!(matches!(
        restore.stage(super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    destination
        .execute(
            "UPDATE signal_control.store SET routines_sha256=$1",
            &[&schema_identity().1.as_slice()],
        )
        .await?;
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    eprintln!("phase: stopped-restore-current-credential-binding-refused");
    let foreign_credentials = Authority {
        approved: AtomicBool::new(true),
        checkpoint: Mutex::new(Some(independently_captured_checkpoint)),
        binding: Sha256::digest(b"different currently supplied credentials").into(),
        destination: enrollment.id,
    };
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &foreign_credentials,
            &custody,
            enrollment.id,
            generation,
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    eprintln!("phase: stopped-restore-inconsistent-source-cursors-refused");
    for (tamper, repair) in [
        (
            "UPDATE signal_control.partitions SET checkpoint=2 WHERE kind='pipeline'".to_string(),
            "UPDATE signal_control.partitions SET checkpoint=1 WHERE kind='pipeline'".to_string(),
        ),
        (
            "UPDATE signal_control.partitions SET epoch=0 WHERE kind='pipeline'".to_string(),
            "UPDATE signal_control.partitions SET epoch=1 WHERE kind='pipeline'".to_string(),
        ),
        (
            "UPDATE signal_control.partitions SET feed_position=0 WHERE kind='pipeline'"
                .to_string(),
            "UPDATE signal_control.partitions SET feed_position=2 WHERE kind='pipeline'"
                .to_string(),
        ),
        (
            "UPDATE signal_control.state SET revision=decode(repeat('00',32),'hex')".to_string(),
            format!(
                "UPDATE signal_control.state SET revision=decode('{}','hex')",
                rule.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
        ),
    ] {
        destination.batch_execute(&tamper).await?;
        let before: serde_json::Value = destination.query_one("SELECT jsonb_build_object('parts',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM signal_control.partitions p),'state',(SELECT jsonb_agg(to_jsonb(s) ORDER BY key) FROM signal_control.state s))", &[]).await?.get(0);
        assert!(matches!(
            coordinate_stopped_restore(
                &restore,
                &authority,
                &custody,
                enrollment.id,
                generation,
                super::context()?
            )
            .await,
            Err(ControlError::Corrupt)
        ));
        let after: serde_json::Value = destination.query_one("SELECT jsonb_build_object('parts',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM signal_control.partitions p),'state',(SELECT jsonb_agg(to_jsonb(s) ORDER BY key) FROM signal_control.state s))", &[]).await?.get(0);
        assert_eq!(before, after);
        assert!(
            !destination
                .query_one("SELECT ready FROM signal_control.store", &[])
                .await?
                .get::<_, bool>(0)
        );
        destination.batch_execute(&repair).await?;
        assert_eq!(restore.stage(super::context()?).await?, inventory);
    }
    eprintln!("phase: stopped-restore-ddl-cancellation-rollback");
    destination.batch_execute("CREATE FUNCTION public.synthetic_restore_ddl_pause() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF to_regclass('signal_control.restore_record') IS NOT NULL THEN PERFORM pg_sleep(1); END IF; END $$; CREATE EVENT TRIGGER synthetic_restore_ddl_pause ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.synthetic_restore_ddl_pause()").await?;
    let c = super::context()?;
    let observer = async {
        let observed = tokio::time::timeout(Duration::from_secs(2), async { loop {
            if destination.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='signal-control' AND datname='signal_restore_destination' AND wait_event='PgSleep' AND query<>'COMMIT')", &[]).await?.get::<_,bool>(0) {
                return Ok::<(),tokio_postgres::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }}).await;
        c.cancel();
        observed??;
        Ok::<(), Error>(())
    };
    let (result, observed) = tokio::join!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            c.clone()
        ),
        observer
    );
    observed.map_err(|e| format!("restore DDL observer: {e}; result: {result:?}"))?;
    assert!(matches!(result, Err(ControlError::Uncertain)));
    idle(&restore).await?;
    destination.batch_execute("DROP EVENT TRIGGER synthetic_restore_ddl_pause; DROP FUNCTION public.synthetic_restore_ddl_pause()").await?;
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    assert!(
        destination
            .query_one(
                "SELECT to_regclass('signal_control.restore_record') IS NULL",
                &[]
            )
            .await?
            .get::<_, bool>(0)
    );

    eprintln!("phase: stopped-restore-lost-commit-reply");
    // A public fixture hook inserts once at the last replacement. Its deferred
    // pause lets the observer cancel only after the actual COMMIT has begun.
    destination.batch_execute("CREATE TABLE public.synthetic_restore_commit_signal(id integer); CREATE FUNCTION public.synthetic_restore_commit_signal() RETURNS event_trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN IF EXISTS(SELECT 1 FROM pg_event_trigger_ddl_commands() d JOIN pg_proc p ON p.oid=d.objid WHERE d.classid='pg_proc'::regclass AND p.proname='read_snapshot') THEN INSERT INTO public.synthetic_restore_commit_signal VALUES(1); END IF; END $$; CREATE EVENT TRIGGER synthetic_restore_commit_signal ON ddl_command_end WHEN TAG IN ('CREATE FUNCTION') EXECUTE FUNCTION public.synthetic_restore_commit_signal(); CREATE FUNCTION public.synthetic_restore_commit_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_restore_commit_pause AFTER INSERT ON public.synthetic_restore_commit_signal DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_restore_commit_pause()").await?;
    let c = super::context()?;
    let (result, observed) = tokio::join!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            enrollment.id,
            generation,
            c.clone()
        ),
        super::cancel_delayed_commit(&destination, &c)
    );
    observed.map_err(|e| format!("restore COMMIT observer: {e}; result: {result:?}"))?;
    assert!(matches!(result, Err(ControlError::Uncertain)));
    idle(&restore).await?;
    destination.batch_execute("DROP EVENT TRIGGER synthetic_restore_commit_signal; DROP FUNCTION public.synthetic_restore_commit_signal(); DROP TABLE public.synthetic_restore_commit_signal; DROP FUNCTION public.synthetic_restore_commit_pause()").await?;
    let resolved_barrier = restore.resolve(super::context()?).await?;
    assert!(!resolved_barrier.ready);
    assert_eq!(resolved_barrier.challenge.new_generation, generation);
    consumers
        .current
        .lock()
        .map_err(|_| "consumer fixture mutex")?[0]
        .position = inventory.feed_position + 1;
    eprintln!("phase: stopped-restore-cursor-refusal-after-generation-barrier");
    assert!(matches!(
        resume_stopped_restore(
            &restore,
            &authority,
            &custody,
            inventory.clone(),
            resolved_barrier.clone(),
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert!(
        !destination
            .query_one("SELECT ready FROM signal_control.store", &[])
            .await?
            .get::<_, bool>(0)
    );
    *consumers
        .current
        .lock()
        .map_err(|_| "consumer fixture mutex")? = inventory.consumers.clone();
    eprintln!("phase: stopped-restore-restored-catalog-tampering-refused");
    let trusted_function: String = destination.query_one(
        "SELECT pg_get_functiondef('signal_control.restore_work_seal(signal_control.outbox)'::regprocedure)", &[]
    ).await?.get(0);
    for (tamper, repair) in [
        (
            "SET ROLE signal_control_owner; CREATE TABLE signal_control.unexpected_restore_object(id integer); RESET ROLE".to_string(),
            "DROP TABLE signal_control.unexpected_restore_object".to_string(),
        ),
        (
            "ALTER TABLE signal_control.restore_record ADD CONSTRAINT unexpected_restore_constraint CHECK(attempted_work>=0)".to_string(),
            "ALTER TABLE signal_control.restore_record DROP CONSTRAINT unexpected_restore_constraint".to_string(),
        ),
        (
            "ALTER FUNCTION signal_control.restore_work_seal(signal_control.outbox) IMMUTABLE".to_string(),
            "ALTER FUNCTION signal_control.restore_work_seal(signal_control.outbox) STABLE".to_string(),
        ),
        (
            "CREATE OR REPLACE FUNCTION signal_control.restore_work_seal(w signal_control.outbox) RETURNS bytea LANGUAGE sql STABLE SET search_path=pg_catalog,signal_control,pg_temp AS $$ SELECT decode(repeat('00',32),'hex') $$".to_string(),
            trusted_function,
        ),
        (
            "UPDATE signal_control.migrations SET sha256=decode(repeat('00',32),'hex') WHERE ordinal=4".to_string(),
            format!("UPDATE signal_control.migrations SET sha256=decode('{}','hex') WHERE ordinal=4", restored_schema_identity().1.iter().map(|b| format!("{b:02x}")).collect::<String>()),
        ),
    ] {
        destination.batch_execute(&tamper).await?;
        assert!(matches!(restore.resolve(super::context()?).await, Err(ControlError::Corrupt)));
        assert!(matches!(
            resume_stopped_restore(&restore, &authority, &custody, inventory.clone(), resolved_barrier.clone(), super::context()?).await,
            Err(ControlError::Corrupt)
        ));
        assert!(!destination.query_one("SELECT ready FROM signal_control.store", &[]).await?.get::<_, bool>(0));
        destination.batch_execute(&repair).await?;
        assert_eq!(restore.resolve(super::context()?).await?, resolved_barrier);
    }
    authority.approved.store(false, Ordering::SeqCst);
    assert!(matches!(
        resume_stopped_restore(
            &restore,
            &authority,
            &custody,
            inventory.clone(),
            resolved_barrier.clone(),
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    assert!(!restore.resolve(super::context()?).await?.ready);
    authority.approved.store(true, Ordering::SeqCst);
    eprintln!("phase: stopped-restore-explicit-reauthorized-readiness-continuation");
    let result = resume_stopped_restore(
        &restore,
        &authority,
        &custody,
        inventory.clone(),
        resolved_barrier,
        super::context()?,
    )
    .await?;
    assert!(result.ready);
    destination
        .batch_execute("SET search_path=pg_catalog,signal_control,pg_temp")
        .await?;
    let restored_catalog: String = destination
        .query_one(
            include_str!("../../../../schemas/shared-control/catalog-query.sql"),
            &[],
        )
        .await?
        .get(0);
    eprintln!("restored-catalog: {restored_catalog}");

    assert_eq!(result.uncertain_work, 2);
    let history_after: serde_json::Value = destination
        .query_one(
            "SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM signal_control.notification_attempts a",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(history_before, history_after);
    let source_after:serde_json::Value=source.query_one("SELECT jsonb_build_object('store',(SELECT to_jsonb(s) FROM signal_control.store s),'parts',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM signal_control.partitions p))",&[]).await?.get(0);
    assert_eq!(source_before, source_after);
    destination.batch_execute("GRANT USAGE ON SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_control.acquire(jsonb,uuid,integer,bytea,bytea),signal_control.renew(jsonb,integer,bytea,bytea),signal_control.notification(jsonb,bytea,bytea,bytea),signal_control.read_snapshot(jsonb,uuid,uuid[],integer,bytea,bytea) TO signal_runtime").await?;
    let current =
        ControlClient::restored(settings(f, "signal_restore_destination", "signal_runtime")?)?;
    assert!(matches!(
        current.renew(token.clone(), 60000, super::context()?).await,
        Err(ControlError::Fenced)
    ));
    let mut fresh_scope = s.clone();
    fresh_scope.generation = generation;
    let fresh = current
        .acquire(
            fresh_scope.clone(),
            Uuid::from_u128(0xa12),
            60000,
            super::context()?,
        )
        .await?;
    assert_eq!(fresh.epoch, 2);
    let mut rolled_back_handle = token.clone();
    rolled_back_handle.owner = fresh.owner;
    rolled_back_handle.epoch = fresh.epoch;
    assert!(matches!(
        current
            .renew(rolled_back_handle, 60000, super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let resolved = current
        .notification(
            fresh.clone(),
            command(works[0], attempts[0], NotificationAction::Resolve {}),
            super::context()?,
        )
        .await?;
    assert_eq!(resolved.outcome, NotificationState::Delivered);
    assert_eq!(resolved.work_status, NotificationState::Uncertain);
    assert!(matches!(
        current
            .notification(
                fresh.clone(),
                command(
                    works[1],
                    attempts[1],
                    NotificationAction::Interrupt {
                        evidence: b"must not replace old intent evidence".to_vec()
                    }
                ),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    eprintln!("phase: stopped-restore-fresh-attempt-preserves-original-history");
    let fresh_attempt_id = Uuid::from_u128(0xa30);
    let fresh_attempt = current
        .notification(
            fresh.clone(),
            command(works[0], fresh_attempt_id, NotificationAction::Claim {}),
            super::context()?,
        )
        .await?;
    assert_eq!(fresh_attempt.ordinal, 2);
    assert_eq!(fresh_attempt.claim_authority, fresh);
    assert_eq!(
        fresh_attempt.plan,
        b"original opaque delivery key and exact plan"
    );
    assert_eq!(fresh_attempt.outcome, NotificationState::Intent);
    let original_history: serde_json::Value = destination.query_one("SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM signal_control.notification_attempts a WHERE id<>$1", &[&fresh_attempt_id]).await?.get(0);
    assert_eq!(original_history, history_before);
    assert_eq!(
        destination
            .query_one(
                "SELECT status FROM signal_control.outbox WHERE id=$1",
                &[&works[1]]
            )
            .await?
            .get::<_, String>(0),
        "uncertain"
    );
    let pin = current
        .read_snapshot(
            fresh_scope,
            SnapshotInput {
                schema_version: 1,
                id: Uuid::from_u128(0xa13),
                manifest_ids: vec![commit],
                pin_ms: 5000,
            },
            super::context()?,
        )
        .await?;
    assert_eq!(pin.manifests()?.len(), 1);
    assert_eq!(
        destination
            .query_one(
                "SELECT generation FROM signal_control.commits WHERE id=$1",
                &[&commit]
            )
            .await?
            .get::<_, Uuid>(0),
        scope.generation
    );
    current.shutdown(super::context()?).await?;
    restore.shutdown(super::context()?).await?;
    source_driver.abort();
    destination_driver.abort();
    eprintln!("matrix-case:old_backup_restored passed");
    eprintln!("matrix-case:object_missing_on_restore passed");
    eprintln!("phase: coordinated-stopped-restore-qualification-complete");
    Ok(())
}
