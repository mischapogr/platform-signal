//! Actual stopped PostgreSQL restore with real checksum-verified local Parquet.
//! Authority, immutable version and retention policy are explicit fixture simulations.
use sha2::{Digest, Sha256};
use signal_control::*;
use signal_findings::{DerivedFinding, DetectionSeverity, Finding};
use signal_storage::{
    OperationContext, StorageConfig, StoredEvent,
    object_codec::ObjectCodec,
    object_io::ObjectIo,
    object_manifest::{ManifestLimits, QueryFile, QueryManifest, QueryObjectRef, data_key},
};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use tokio_postgres::Client;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SOURCE: &str = "signal_multi_restore_source";
const DEST: &str = "signal_multi_restore_destination";
fn settings(
    f: &super::Fixture,
    database: &str,
    user: &str,
) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
        f.port,
        database.into(),
        user.into(),
        f.password.as_bytes().to_vec(),
    )
}
fn io_context() -> OperationContext {
    OperationContext::new(std::time::Duration::from_secs(5))
}
struct Consumers;
impl RestoreConsumers for Consumers {
    fn reconcile<'a>(
        &'a self,
        c: &'a RestoreChallenge,
        expected: &'a [RestoreConsumerCursor],
        context: ControlContext,
    ) -> RestoreFuture<'a, ReconciledConsumers> {
        Box::pin(async move {
            context.check()?;
            if !expected.is_empty() {
                return Err(ControlError::Fenced);
            }
            Ok(ReconciledConsumers {
                challenge: c.clone(),
                consumers: vec![],
            })
        })
    }
}
struct Authority {
    inventory: [u8; 32],
    checkpoint: [u8; 32],
    destination: RestoreDestination,
}
impl RestoreAuthority for Authority {
    fn authorize<'a>(
        &'a self,
        c: &'a RestoreChallenge,
        i: &'a RestoreInventory,
        context: ControlContext,
    ) -> RestoreFuture<'a, RestoreDecision> {
        Box::pin(async move {
            context.check()?;
            if i.digest()? != self.inventory
                || i.checkpoint_sha256 != self.checkpoint
                || c.destination_id != self.destination.id
            {
                return Err(ControlError::Fenced);
            }
            Ok(RestoreDecision {
                challenge: c.clone(),
                approval_id: Uuid::from_u128(0xe520),
                custody_sha256: Sha256::digest(b"separately captured synthetic local custody")
                    .into(),
                credential_binding_sha256: self.destination.credential_binding_sha256,
                expires_at: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            })
        })
    }
}
struct Custody {
    io: ObjectIo,
    expected: RestoreObject,
}
impl RestoreCustody for Custody {
    fn verify<'a>(
        &'a self,
        o: &'a RestoreObject,
        _protected: bool,
        _decision: &'a RestoreDecision,
        context: ControlContext,
    ) -> RestoreFuture<'a, ()> {
        Box::pin(async move {
            context.check()?;
            if o != &self.expected {
                return Err(ControlError::Corrupt);
            }
            let reference = QueryObjectRef {
                key: o.object.key.clone(),
                version: Some(o.object.version.clone()),
                etag: None,
                bytes: o.bytes,
                sha256: o.sha256,
            };
            self.io
                .read_exact(
                    &reference,
                    OperationContext {
                        deadline: context.deadline(),
                        cancellation: context.cancellation_token(),
                    },
                )
                .await
                .map_err(|_| ControlError::Corrupt)?;
            context.check()
        })
    }
}
fn backend(
    f: &super::Fixture,
    database: &str,
    scope: &Scope,
    destination: &RestoreDestination,
    object: &RestoreObject,
) -> Result<PostgresStoppedRestore> {
    Ok(PostgresStoppedRestore::scoped_catalog(
        settings(f, database, "signal_migrator")?,
        "signal_control_owner".into(),
        AdministrativeScope {
            schema_version: 1,
            store_id: scope.store_id,
            generation: scope.generation,
        },
        destination.clone(),
        vec![object.clone()],
        Arc::new(Consumers),
    )?)
}
async fn copy(root: &Client) -> Result {
    root.batch_execute(
        "CREATE DATABASE signal_multi_restore_destination TEMPLATE signal_multi_restore_source",
    )
    .await?;
    Ok(())
}
async fn remove(root: &Client) -> Result {
    root.batch_execute("DROP DATABASE signal_multi_restore_destination")
        .await?;
    Ok(())
}

pub async fn qualify(root: &Client, f: &super::Fixture) -> Result {
    root.batch_execute("CREATE DATABASE signal_multi_restore_source")
        .await?;
    root.batch_execute(
        "GRANT CREATE ON DATABASE signal_multi_restore_source TO signal_control_owner",
    )
    .await?;
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::from_u128(0xe501),
        generation: Uuid::from_u128(0xe502),
        partition_id: Uuid::from_u128(0xe503),
        tenant: "owned-multi-restore".into(),
        stream: Uuid::from_u128(0xe504),
    };
    super::catalog_restore::initialize(
        f,
        SOURCE,
        &AdministrativeScope {
            schema_version: 1,
            store_id: scope.store_id,
            generation: scope.generation,
        },
    )
    .await?;
    let (db, driver) = super::admin_database(f, SOURCE).await?;
    let backend_id = Uuid::from_u128(0xe505);
    db.execute(
        "INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,$2,$3,'pipeline')",
        &[&scope.partition_id, &scope.tenant, &scope.stream],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.principals VALUES('signal_runtime',$1,$2,$3)",
        &[&scope.tenant, &scope.stream, &scope.partition_id],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_backends VALUES($1,'owned-multi-restore-local-version')",
        &[&backend_id],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_scopes VALUES($1,$2,$3)",
        &[
            &scope.partition_id,
            &backend_id,
            &format!("query/{}/", scope.stream),
        ],
    )
    .await?;
    db.batch_execute("SET ROLE signal_control_owner").await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/007-finding-scope.sql"
    ))
    .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/008-scoped-publication.sql"
    ))
    .await?;
    db.batch_execute("RESET ROLE").await?;
    let producer = ProducerEnrollment {
        scope: scope.clone(),
        scope_generation: Uuid::from_u128(0xe506),
        startup: Uuid::from_u128(0xe507),
        wal_floor: 0,
    };
    let admin = FindingScopeAdministrator::new(
        settings(f, SOURCE, "signal_migrator")?,
        "signal_control_owner".into(),
        FindingScopeProfile::Catalog4Scoped,
    )?;
    admin
        .activate(
            AdministrativeScope {
                schema_version: 1,
                store_id: scope.store_id,
                generation: scope.generation,
            },
            producer.scope_generation,
            FindingScopeLimits {
                producers: 16,
                rows: 128,
                bytes: 1048576,
            },
            super::context()?,
        )
        .await?;
    admin.enroll(producer.clone(), super::context()?).await?;
    admin.shutdown(super::context()?).await?;
    db.batch_execute("SET ROLE signal_control_owner").await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/009-state-read.sql"
    ))
    .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/010-multi-event-publication.sql"
    ))
    .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/012-window-history.sql"
    ))
    .await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_control,signal_state_read,signal_multi_event TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control,signal_state_read,signal_multi_event TO signal_runtime").await?;
    db.execute("INSERT INTO signal_multi_event.profile(singleton,scope_generation,max_rows,max_bytes) VALUES(true,$1,128,1048576)",&[&producer.scope_generation]).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    let runtime = ControlClient::catalog(settings(f, SOURCE, "signal_runtime")?)?;
    let token = runtime
        .acquire(
            scope.clone(),
            Uuid::from_u128(0xe508),
            60000,
            super::context()?,
        )
        .await?;
    let mut rows = Vec::new();
    for sequence in 1..=2 {
        let event = serde_json::from_value(
            serde_json::json!({"schema_version":1,"id":Uuid::from_u128(0xe510+sequence),"timestamp":"2026-10-15T00:00:00Z","observed_at":"2026-10-15T00:00:00Z","source":{"type":"owned-multi-restore"},"severity":"info","message":"actual retained Parquet","attributes":{"nested":{"array":[true,null,42]}},"tags":[]}),
        )?;
        rows.push(StoredEvent {
            sequence: sequence as u64,
            event,
        });
    }
    let directory = PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?)
        .parent()
        .ok_or("fixture parent")?
        .join("multi-restore-objects");
    std::fs::create_dir(&directory)?;
    let writer = super::catalog_restore::io(&directory)?;
    let codec = ObjectCodec::new(StorageConfig::default(), ManifestLimits::default())?;
    let prepared = codec.prepare(&rows, io_context()).await?;
    assert_eq!(prepared.files().len(), 1);
    let file = prepared.files().first().ok_or("Parquet file")?;
    let reference = writer
        .create(
            &data_key(scope.stream, file.date(), file.hour(), file.sha256()),
            file.bytes(),
            io_context(),
        )
        .await?;
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: scope.stream,
        normalizer_revision: "owned-fixture-v1".into(),
        first_sequence: 1,
        last_sequence: 2,
        events: 2,
        previous: None,
        files: vec![QueryFile {
            date: file.date().into(),
            hour: file.hour(),
            object: reference.clone(),
            rows: file.rows(),
            decoded_bytes: file.decoded_bytes(),
        }],
    };
    let state = MultiEventStateEnvelope {
        schema_version: 1,
        scope_generation: producer.scope_generation,
        checkpoint: 2,
        metadata: serde_json::json!({"canonical_sha256":{},"scope":scope,"pending_outputs":[{"id":"fixture-original","body":[1,2,3]}]}),
        canonical_sequences: BTreeMap::new(),
    }
    .encode()?;
    let publication = PublicationInput {
        schema_version: 1,
        id: Uuid::from_u128(0xe509),
        previous: None,
        first_sequence: 1,
        last_sequence: 2,
        manifest: manifest.encode(ManifestLimits::default(), scope.stream)?,
        rule_revision: [1; 32],
        normalizer_revision: "owned-fixture-v1".into(),
        states: vec![RevisionedState {
            key: "window-fixture".into(),
            revision: [1; 32],
            bytes: state.clone(),
        }],
        findings: vec![],
        work: vec![],
        receipts: vec![],
    };
    let mut finding = Finding::for_event(
        "window-fixture",
        &rows[1].event,
        DetectionSeverity::High,
        "Owned restore fixture",
    )?;
    finding.event_ids = rows.iter().map(|r| r.event.id).collect();
    let finding_id = finding.id;
    let scoped = DerivedFinding::from_events(
        finding,
        &rows.iter().map(|r| &r.event).collect::<Vec<_>>(),
        true,
    )?
    .into_scoped(producer.scope_generation)?;
    let input = MultiEventFindingClaims::from_host(&producer, &rows, &[], None, vec![(2, scoped)])?
        .bind(publication.clone(), "window-fixture")?;
    input.verify(&producer, &rows, &[])?;
    let original_result = runtime
        .publish_multi_event(token.clone(), input.clone(), super::context()?)
        .await?;
    runtime.shutdown(super::context()?).await?;
    // Explicit owner-seeded expired metadata qualifies restore custody only;
    // detector-to-archive derivation is exercised by the separate server gate.
    let history_payload = serde_json::to_vec(&serde_json::json!({
        "schema_version":1,"scope_generation":producer.scope_generation,
        "assessment":{"outcome":"match","event_ids":rows.iter().map(|r|r.event.id).collect::<Vec<_>>()}
    }))?;
    let history_id: Vec<u8> = Sha256::digest(&history_payload).to_vec();
    let recorded_at_ms = chrono::Utc::now().timestamp_millis() - 60001;
    let expires_at_ms = recorded_at_ms + 60000;
    db.execute("INSERT INTO signal_window_history.profile(partition_id,state_key,scope_generation,max_rows,max_bytes,retention_ms,used_rows,used_bytes) VALUES($1,'window-fixture',$2,32,262144,60000,1,$3)", &[&scope.partition_id,&producer.scope_generation,&(256+history_payload.len() as i64)]).await?;
    db.execute("INSERT INTO signal_window_history.assessments VALUES($1,'window-fixture',$2,2,$3,$4,$5,$2)", &[&scope.partition_id,&history_id,&recorded_at_ms,&expires_at_ms,&history_payload]).await?;
    drop(prepared);
    codec.shutdown(io_context()).await?;
    writer.shutdown(io_context()).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=false; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL").await?;
    let destination = RestoreDestination {
        id: Uuid::from_u128(0xe521),
        credential_binding_sha256: Sha256::digest(
            b"separately enrolled owned multi restore destination",
        )
        .into(),
    };
    let object = RestoreObject {
        object: CanonicalObjectRef {
            schema_version: 1,
            backend_id,
            key: reference.key.clone(),
            version: reference
                .version
                .clone()
                .ok_or("immutable fixture version")?,
        },
        bytes: reference.bytes,
        sha256: reference.sha256,
    };
    let capture = backend(f, SOURCE, &scope, &destination, &object)?;
    let inventory = capture.stage(super::context()?).await?;
    assert!(inventory.consumers.is_empty());
    capture.shutdown(super::context()?).await?;
    let authority = Authority {
        inventory: inventory.digest()?,
        checkpoint: inventory.checkpoint_sha256,
        destination: destination.clone(),
    };
    let custody = Custody {
        io: super::catalog_restore::io(&directory)?,
        expected: object.clone(),
    };
    let original_finding: Vec<u8> = db
        .query_one(
            "SELECT content FROM signal_control.findings WHERE id=$1",
            &[&finding_id],
        )
        .await?
        .try_get(0)?;
    drop(db);
    driver.await?;
    // Omission must not match the separately captured source checkpoint.
    copy(root).await?;
    let (bad, bad_driver) = super::admin_database(f, DEST).await?;
    bad.batch_execute(
        "DROP SCHEMA signal_window_history CASCADE; DROP SCHEMA signal_multi_event CASCADE",
    )
    .await?;
    let restore = backend(f, DEST, &scope, &destination, &object)?;
    assert!(matches!(
        coordinate_stopped_restore(
            &restore,
            &authority,
            &custody,
            destination.id,
            Uuid::from_u128(0xe522),
            super::context()?
        )
        .await,
        Err(ControlError::Fenced)
    ));
    restore.shutdown(super::context()?).await?;
    drop(bad);
    bad_driver.await?;
    remove(root).await?;
    // Source-bound approval must refuse missing or self-consistently rewritten
    // archive bytes and custody times, even with recomputed hashes/counters.
    for mutation in [
        "DROP SCHEMA signal_window_history CASCADE",
        "UPDATE signal_window_history.assessments SET payload=convert_to(jsonb_set(convert_from(payload,'UTF8')::jsonb,'{assessment,outcome}','\"indeterminate\"'::jsonb)::text,'UTF8'),payload_sha256=sha256(convert_to(jsonb_set(convert_from(payload,'UTF8')::jsonb,'{assessment,outcome}','\"indeterminate\"'::jsonb)::text,'UTF8')); UPDATE signal_window_history.assessments SET id=payload_sha256; UPDATE signal_window_history.profile SET used_bytes=(SELECT sum(256+octet_length(payload)) FROM signal_window_history.assessments)",
        "UPDATE signal_window_history.assessments SET recorded_at_ms=recorded_at_ms+1,expires_at_ms=expires_at_ms+1",
        "DELETE FROM signal_window_history.assessments; UPDATE signal_window_history.profile SET used_rows=0,used_bytes=0",
    ] {
        copy(root).await?;
        let (bad, bad_driver) = super::admin_database(f, DEST).await?;
        bad.batch_execute(mutation).await?;
        let restore = backend(f, DEST, &scope, &destination, &object)?;
        assert!(matches!(
            coordinate_stopped_restore(
                &restore,
                &authority,
                &custody,
                destination.id,
                Uuid::from_u128(0xe522),
                super::context()?
            )
            .await,
            Err(ControlError::Fenced)
        ));
        restore.shutdown(super::context()?).await?;
        drop(bad);
        bad_driver.await?;
        remove(root).await?;
    }
    // A recomputed fact hash cannot authorize changed selectors.
    copy(root).await?;
    let (bad, bad_driver) = super::admin_database(f, DEST).await?;
    bad.execute("UPDATE signal_multi_event.facts SET fact=convert_to(jsonb_set(convert_from(fact,'UTF8')::jsonb,'{source}','\"changed-fixture\"'::jsonb)::text,'UTF8') WHERE finding_id=$1",&[&finding_id]).await?;
    bad.batch_execute("UPDATE signal_multi_event.facts SET fact_sha256=sha256(fact); UPDATE signal_multi_event.profile SET used_bytes=(SELECT coalesce(sum(512+octet_length(fact)),0) FROM signal_multi_event.facts)+(SELECT coalesce(sum(256+octet_length(claims)),0) FROM signal_multi_event.requests)").await?;
    let restore = backend(f, DEST, &scope, &destination, &object)?;
    assert!(matches!(
        restore.stage(super::context()?).await,
        Err(ControlError::Corrupt)
    ));
    restore.shutdown(super::context()?).await?;
    drop(bad);
    bad_driver.await?;
    remove(root).await?;
    copy(root).await?;
    let restore = backend(f, DEST, &scope, &destination, &object)?;
    assert_eq!(restore.stage(super::context()?).await?, inventory);
    let generation = Uuid::from_u128(0xe522);
    let receipt = coordinate_stopped_restore(
        &restore,
        &authority,
        &custody,
        destination.id,
        generation,
        super::context()?,
    )
    .await?;
    assert!(receipt.ready);
    assert_eq!(restore.resolve(super::context()?).await?, receipt);
    let state = if std::env::var("SIGNAL_CONTROL_SCOPE_REBIND_ONLY").as_deref() == Ok("true") {
        qualify_scope_rebind(f, &scope, generation, &state).await?
    } else {
        state
    };
    let current = ControlClient::restored_catalog(settings(f, DEST, "signal_runtime")?)?;
    assert!(matches!(
        current.renew(token, 15000, super::context()?).await,
        Err(ControlError::Fenced)
    ));
    let mut fresh_scope = scope.clone();
    fresh_scope.generation = generation;
    let fresh = current
        .acquire(
            fresh_scope.clone(),
            Uuid::from_u128(0xe523),
            60000,
            super::context()?,
        )
        .await?;
    let recovered = current
        .read_state(
            fresh.clone(),
            StateReadInput {
                key: "window-fixture".into(),
                expected_head: Some(publication.id),
            },
            super::context()?,
        )
        .await?;
    assert_eq!(recovered.checkpoint, 2);
    assert_eq!(recovered.state.ok_or("restored state")?.bytes, state);
    // Rebind only the current control scope for existing-only historical resolution.
    let mut retained = serde_json::to_value(&input)?;
    retained["claims"]["scope"]["generation"] = serde_json::json!(generation);
    let retained: MultiEventPublicationInput = serde_json::from_value(retained)?;
    assert_eq!(
        current
            .resolve_multi_event_publication(fresh, retained, super::context()?)
            .await?,
        original_result
    );
    let (db, driver) = super::admin_database(f, DEST).await?;
    assert_eq!(
        db.query_one(
            "SELECT content FROM signal_control.findings WHERE id=$1",
            &[&finding_id]
        )
        .await?
        .try_get::<_, Vec<u8>>(0)?,
        original_finding
    );
    assert_eq!(db.query_one("SELECT (SELECT count(*) FROM signal_multi_event.facts),(SELECT count(*) FROM signal_multi_event.requests)",&[]).await?.try_get::<_,i64>(0)?,1);
    let archived = db.query_one("SELECT id,checkpoint,recorded_at_ms,expires_at_ms,payload,payload_sha256 FROM signal_window_history.assessments", &[]).await?;
    assert_eq!(archived.try_get::<_, Vec<u8>>(0)?, history_id);
    assert_eq!(archived.try_get::<_, i64>(1)?, 2);
    assert_eq!(archived.try_get::<_, i64>(2)?, recorded_at_ms);
    assert_eq!(archived.try_get::<_, i64>(3)?, expires_at_ms);
    assert_eq!(archived.try_get::<_, Vec<u8>>(4)?, history_payload);
    assert_eq!(archived.try_get::<_, Vec<u8>>(5)?, history_id);
    current.shutdown(super::context()?).await?;
    restore.shutdown(super::context()?).await?;
    drop(db);
    driver.await?;
    remove(root).await?;
    root.batch_execute("DROP DATABASE signal_multi_restore_source")
        .await?;
    custody.io.shutdown(io_context()).await?;
    println!(
        "phase: populated-multi-event-and-history-restore-real-Parquet-omission-corruption-custody-and-fresh-generation-qualified"
    );
    Ok(())
}

async fn qualify_scope_rebind(
    f: &super::Fixture,
    old: &Scope,
    generation: Uuid,
    source: &[u8],
) -> Result<Vec<u8>> {
    let (db, driver) = super::admin_database(f, DEST).await?;
    let mut current = old.clone();
    current.generation = generation;
    let request = StateScopeRebindInput::new(
        current.clone(),
        old.generation,
        RevisionedState {
            key: "window-fixture".into(),
            revision: [1; 32],
            bytes: source.to_vec(),
        },
    )?;
    let owner = ControlAdministrator::new(
        settings(f, DEST, "signal_migrator")?,
        "signal_control_owner".into(),
    )?;
    assert!(matches!(
        owner
            .rebind_state_scope(request.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let runtime = ControlAdministrator::new(
        settings(f, DEST, "signal_runtime")?,
        "signal_control_owner".into(),
    )?;
    assert!(matches!(
        runtime
            .rebind_state_scope(request.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    runtime.shutdown(super::context()?).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=false; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL").await?;
    let original:serde_json::Value=db.query_one("SELECT jsonb_build_object('findings',(SELECT jsonb_agg(encode(content,'hex') ORDER BY position) FROM signal_control.findings),'commits',(SELECT count(*) FROM signal_control.commits),'checkpoint',(SELECT checkpoint FROM signal_control.partitions WHERE kind='pipeline'),'used_rows',(SELECT used_rows FROM signal_control.store),'used_bytes',(SELECT used_bytes FROM signal_control.store))",&[]).await?.get(0);
    db.batch_execute("UPDATE signal_control.restore_record SET seal=decode(repeat('00',32),'hex')")
        .await?;
    assert!(matches!(
        owner
            .rebind_state_scope(request.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute(
        "UPDATE signal_control.restore_record r SET seal=signal_control.restore_record_seal(r)",
    )
    .await?;
    db.batch_execute("UPDATE signal_control.restore_record SET complete=false; UPDATE signal_control.restore_record r SET seal=signal_control.restore_record_seal(r)").await?;
    assert!(matches!(
        owner
            .rebind_state_scope(request.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("UPDATE signal_control.restore_record SET complete=true; UPDATE signal_control.restore_record r SET seal=signal_control.restore_record_seal(r)").await?;
    let stale = StateScopeRebindInput::new(current.clone(), old.generation, {
        let mut state = request.source.clone();
        let mut value: serde_json::Value = serde_json::from_slice(&state.bytes)?;
        value["metadata"]["pending_outputs"] = serde_json::json!([]);
        state.bytes = serde_json::to_vec(&value)?;
        state
    })?;
    let stale_result = owner.rebind_state_scope(stale, super::context()?).await;
    assert!(
        matches!(stale_result, Err(ControlError::Conflict)),
        "stale result: {stale_result:?}"
    );
    db.batch_execute("UPDATE signal_control.partitions SET owner='00000000-0000-0000-0000-000000000099',lease_until=clock_timestamp()+interval '1 second' WHERE kind='pipeline'").await?;
    assert!(matches!(
        owner
            .rebind_state_scope(request.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL")
        .await?;
    let cancelled = super::context()?;
    cancelled.cancel();
    assert!(matches!(
        owner.rebind_state_scope(request.clone(), cancelled).await,
        Err(ControlError::Cancelled)
    ));
    db.batch_execute("UPDATE signal_control.store SET used_bytes=used_bytes+1")
        .await?;
    assert!(matches!(
        owner
            .rebind_state_scope(request.clone(), super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    db.batch_execute("UPDATE signal_control.store SET used_bytes=used_bytes-1")
        .await?;
    let result = owner
        .rebind_state_scope(request.clone(), super::context()?)
        .await
        .map_err(|error| format!("scope rebind apply: {error}"))?;
    assert!(!result.ready);
    assert_eq!(result.generation, generation);
    owner
        .rebind_state_scope(request.clone(), super::context()?)
        .await?;
    let actual: Vec<u8> = db
        .query_one(
            "SELECT value FROM signal_control.state WHERE key='window-fixture'",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(actual, request.target.bytes);
    let after:serde_json::Value=db.query_one("SELECT jsonb_build_object('findings',(SELECT jsonb_agg(encode(content,'hex') ORDER BY position) FROM signal_control.findings),'commits',(SELECT count(*) FROM signal_control.commits),'checkpoint',(SELECT checkpoint FROM signal_control.partitions WHERE kind='pipeline'),'used_rows',(SELECT used_rows FROM signal_control.store),'used_bytes',(SELECT used_bytes FROM signal_control.store))",&[]).await?.get(0);
    for key in ["findings", "commits", "checkpoint", "used_rows"] {
        assert_eq!(original[key], after[key], "{key}");
    }
    assert_eq!(
        after["used_bytes"].as_i64().ok_or("bytes")?
            - original["used_bytes"].as_i64().ok_or("bytes")?,
        request.target.bytes.len() as i64 - source.len() as i64
    );
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    owner.shutdown(super::context()?).await?;
    drop(db);
    driver.await?;
    println!(
        "phase: stopped-state-physical-scope-rebind-sealed-lineage-owner-CAS-quota-output-preservation-and-idempotence-qualified"
    );
    Ok(request.target.bytes)
}
