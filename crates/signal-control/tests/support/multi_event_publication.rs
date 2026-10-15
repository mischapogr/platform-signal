//! Stopped additive installation checks; runtime publication is not yet qualified.
use tokio_postgres::Client;

pub async fn qualify_installation(db: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let source = include_str!("../../../../schemas/shared-control/010-multi-event-publication.sql");
    db.batch_execute("UPDATE signal_control.store SET ready=true; SET ROLE signal_control_owner")
        .await?;
    let error = db
        .batch_execute(source)
        .await
        .err()
        .ok_or("ready install accepted")?;
    assert_eq!(
        error.as_db_error().ok_or("non-db error")?.message(),
        "SIGNAL_FENCED"
    );
    db.batch_execute("ROLLBACK; RESET ROLE; UPDATE signal_control.store SET ready=false; SET ROLE signal_control_owner")
        .await?;
    // Roll back the complete installation so subsequent existing qualification
    // sees exactly its original schema and profile inventory.
    let body = source
        .strip_suffix("COMMIT;\n")
        .ok_or("missing installer terminator")?;
    db.batch_execute(body).await?;
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_multi_event.profile", &[])
            .await?
            .try_get::<_, i64>(0)?,
        0
    );
    let row = db.query_one("SELECT proowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control'),prosecdef,proconfig FROM pg_proc WHERE oid='signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea)'::regprocedure", &[]).await?;
    assert!(row.try_get::<_, bool>(0)?);
    assert!(row.try_get::<_, bool>(1)?);
    assert_eq!(
        row.try_get::<_, Vec<String>>(2)?,
        vec!["search_path=pg_catalog, signal_control, pg_temp"]
    );
    db.batch_execute("SET ROLE signal_runtime").await?;
    let error = db
        .query_one("SELECT * FROM signal_multi_event.profile", &[])
        .await
        .err()
        .ok_or("runtime table access accepted")?;
    assert_eq!(
        error.as_db_error().ok_or("non-db denial")?.code().code(),
        "42501"
    );
    db.batch_execute("ROLLBACK; RESET ROLE").await?;
    assert!(
        db.query_one("SELECT to_regnamespace('signal_multi_event') IS NULL", &[])
            .await?
            .try_get::<_, bool>(0)?
    );
    println!("phase: stopped-additive-multi-event-installation-qualified");
    Ok(())
}

async fn call(
    db: &Client,
    token: &signal_control::LeaseToken,
    raw: &[u8],
    claims: &[u8],
    resolve: bool,
) -> Result<serde_json::Value, tokio_postgres::Error> {
    db.batch_execute("SAVEPOINT publication_case; SET SESSION AUTHORIZATION signal_runtime")
        .await?;
    let schema = signal_control::schema_identity().0.to_vec();
    let routines = signal_control::catalog_schema_identity().1.to_vec();
    let token = serde_json::json!({"scope":token.scope,"owner":token.owner,"epoch":token.epoch});
    let result = db
        .query_one(
            "SELECT signal_multi_event.publish($1,$2,$3,$4,$5,$6)",
            &[&token, &raw, &claims, &resolve, &schema, &routines],
        )
        .await;
    if result.is_err() {
        db.batch_execute("ROLLBACK TO SAVEPOINT publication_case")
            .await?;
    }
    db.batch_execute("RESET SESSION AUTHORIZATION; RELEASE SAVEPOINT publication_case")
        .await?;
    result.map(|row| row.get(0))
}

async fn witness(db: &Client) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let core = super::publication::witness(db).await?;
    let companion: serde_json::Value = db.query_one("SELECT jsonb_build_object('profile',(SELECT to_jsonb(p) FROM signal_multi_event.profile p),'requests',(SELECT jsonb_agg(to_jsonb(r)) FROM signal_multi_event.requests r),'facts',(SELECT jsonb_agg(to_jsonb(f)) FROM signal_multi_event.facts f))", &[]).await?.try_get(0)?;
    Ok(serde_json::json!({"core":core,"companion":companion}))
}

pub async fn qualify_publication(
    db: &Client,
    fixture: &super::Fixture,
    producer: &signal_control::ProducerEnrollment,
) -> Result<(), Box<dyn std::error::Error>> {
    use signal_control::{LeaseToken, MultiEventFindingClaims, PublicationInput, RevisionedState};
    use signal_findings::{DerivedFinding, DetectionSeverity, Finding};
    use signal_storage::{StoredEvent, object_manifest::QueryManifest};
    use uuid::Uuid;
    let source = include_str!("../../../../schemas/shared-control/010-multi-event-publication.sql");
    db.batch_execute("SET ROLE signal_control_owner").await?;
    db.batch_execute(
        source
            .strip_suffix("COMMIT;\n")
            .ok_or("installer terminator")?,
    )
    .await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_multi_event TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea) TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    db.execute("INSERT INTO signal_multi_event.profile(singleton,scope_generation,max_rows,max_bytes) VALUES(true,$1,128,1048576)", &[&producer.scope_generation]).await?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()+interval '60 seconds' WHERE id=$1", &[&producer.scope.partition_id]).await?;
    let row = db.query_one("SELECT p.owner,p.epoch,c.id,c.first_sequence,c.last_sequence,c.manifest FROM signal_control.partitions p JOIN signal_control.commits c ON c.partition_id=p.id AND c.id=p.head WHERE p.id=$1", &[&producer.scope.partition_id]).await?;
    let token = LeaseToken {
        scope: producer.scope.clone(),
        owner: row.try_get(0)?,
        epoch: row.try_get::<_, i64>(1)? as u64,
    };
    let prior = PublicationInput {
        schema_version: 1,
        id: row.try_get(2)?,
        previous: None,
        first_sequence: row.try_get::<_, i64>(3)? as u64,
        last_sequence: row.try_get::<_, i64>(4)? as u64,
        manifest: row.try_get(5)?,
        rule_revision: [1; 32],
        normalizer_revision: "synthetic-v1".into(),
        states: vec![],
        findings: vec![],
        work: vec![],
        receipts: vec![],
    };
    let first = prior.last_sequence + 1;
    let mut publication = super::publication::request(&token, 8890, first, Some(&prior))?;
    publication.last_sequence = first + 1;
    let mut manifest: QueryManifest = serde_json::from_slice(&publication.manifest)?;
    manifest.last_sequence = first + 1;
    manifest.events = 2;
    manifest.files[0].rows = 2;
    publication.manifest = serde_json::to_vec(&manifest)?;
    publication.states.push(RevisionedState {
        key: "window-fixture".into(),
        revision: [1; 32],
        bytes: serde_json::to_vec(&serde_json::json!({"schema_version":1,"scope_generation":producer.scope_generation,"checkpoint":first+1,"metadata":{"canonical_sha256":{Uuid::from_u128(8891).to_string():vec![1;32],Uuid::from_u128(8892).to_string():vec![2;32]}},"canonical_sequences":{Uuid::from_u128(8891).to_string():first,Uuid::from_u128(8892).to_string():first+1}}))?,
    });
    let mut rows = Vec::new();
    for offset in 0..2 {
        let event = serde_json::from_value(
            serde_json::json!({"schema_version":1,"id":Uuid::from_u128(8891+offset),"timestamp":"2026-10-15T00:00:00Z","observed_at":"2026-10-15T00:00:00Z","source":{"type":"fixture"},"severity":"info","message":"fixture","attributes":{},"tags":[]}),
        )?;
        rows.push(StoredEvent {
            sequence: first + offset as u64,
            event,
        });
    }
    let mut finding = Finding::for_event(
        "window-fixture",
        &rows[1].event,
        DetectionSeverity::High,
        "Window fixture",
    )?;
    finding.event_ids = rows.iter().map(|r| r.event.id).collect();
    let original_id = finding.id;
    let scoped = DerivedFinding::from_events(
        finding,
        &rows.iter().map(|r| &r.event).collect::<Vec<_>>(),
        true,
    )?
    .into_scoped(producer.scope_generation)?;
    let bound =
        MultiEventFindingClaims::from_host(producer, &rows, &[], None, vec![(first + 1, scoped)])?
            .bind(publication.clone(), "window-fixture")?;
    bound.verify(producer, &rows, &[])?;
    let raw = bound.encode_sql_publication()?;
    let claims = bound.encode_sql_claims()?;
    let before = witness(db).await?;
    let error = call(db, &token, &raw, &claims, true)
        .await
        .err()
        .ok_or("absent resolution accepted")?;
    assert_eq!(
        error.as_db_error().ok_or("non-db refusal")?.message(),
        "SIGNAL_UNCERTAIN"
    );
    assert_eq!(before, witness(db).await?);
    let mut stale = token.clone();
    stale.epoch += 1;
    assert_eq!(
        call(db, &stale, &raw, &claims, false)
            .await
            .err()
            .ok_or("stale accepted")?
            .as_db_error()
            .ok_or("non-db error")?
            .message(),
        "SIGNAL_FENCED"
    );
    assert_eq!(before, witness(db).await?);
    db.batch_execute("UPDATE signal_multi_event.profile SET max_rows=1")
        .await?;
    let quota = witness(db).await?;
    assert_eq!(
        call(db, &token, &raw, &claims, false)
            .await
            .err()
            .ok_or("quota accepted")?
            .as_db_error()
            .ok_or("non-db error")?
            .message(),
        "SIGNAL_FULL"
    );
    assert_eq!(quota, witness(db).await?);
    db.batch_execute("UPDATE signal_multi_event.profile SET max_rows=128; CREATE FUNCTION public.synthetic_multi_event_late_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END $$; CREATE TRIGGER synthetic_late_failure BEFORE INSERT ON signal_multi_event.requests FOR EACH ROW EXECUTE FUNCTION public.synthetic_multi_event_late_failure()").await?;
    let late = witness(db).await?;
    assert_eq!(
        call(db, &token, &raw, &claims, false)
            .await
            .err()
            .ok_or("late failure accepted")?
            .as_db_error()
            .ok_or("non-db error")?
            .message(),
        "SIGNAL_INVALID"
    );
    assert_eq!(late, witness(db).await?);
    db.batch_execute("DROP TRIGGER synthetic_late_failure ON signal_multi_event.requests; DROP FUNCTION public.synthetic_multi_event_late_failure()").await?;
    let result = call(db, &token, &raw, &claims, false).await?;
    let committed = witness(db).await?;
    assert_eq!(call(db, &token, &raw, &claims, true).await?, result);
    assert_eq!(call(db, &token, &raw, &claims, false).await?, result);
    assert_eq!(committed, witness(db).await?);
    let mut changed: serde_json::Value = serde_json::from_slice(&claims)?;
    changed["startup"] = serde_json::json!(Uuid::from_u128(8899));
    assert_eq!(
        call(db, &token, &raw, &serde_json::to_vec(&changed)?, true)
            .await
            .err()
            .ok_or("changed replay accepted")?
            .as_db_error()
            .ok_or("non-db error")?
            .message(),
        "SIGNAL_CONFLICT"
    );
    assert_eq!(committed, witness(db).await?);
    let row=db.query_one("SELECT p.checkpoint,(SELECT count(*) FROM signal_multi_event.requests),(SELECT count(*) FROM signal_multi_event.facts),(SELECT content FROM signal_control.findings WHERE id=$2) FROM signal_control.partitions p WHERE p.id=$1", &[&producer.scope.partition_id,&original_id]).await?;
    assert_eq!(row.try_get::<_, i64>(0)?, (first + 1) as i64);
    assert_eq!(row.try_get::<_, i64>(1)?, 1);
    assert_eq!(row.try_get::<_, i64>(2)?, 1);
    let stored: serde_json::Value = serde_json::from_slice(&row.try_get::<_, Vec<u8>>(3)?)?;
    assert_eq!(stored["event_ids"].as_array().map(Vec::len), Some(2));
    let mut next = super::publication::request(&token, 8893, first + 2, Some(&publication))?;
    next.states.push(RevisionedState {
        key: "window-fixture".into(),
        revision: [1; 32],
        bytes: serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"scope_generation":producer.scope_generation,
            "checkpoint":first+2,"metadata":{"canonical_sha256":{}},"canonical_sequences":{}
        }))?,
    });
    let mut current = rows[1].clone();
    current.sequence = first + 2;
    current.event.id = Uuid::from_u128(8894);
    let mut finding = Finding::for_event(
        "window-fixture",
        &current.event,
        DetectionSeverity::High,
        "Retained window fixture",
    )?;
    finding.event_ids = rows
        .iter()
        .map(|r| r.event.id)
        .chain(std::iter::once(current.event.id))
        .collect();
    let events = rows
        .iter()
        .map(|r| &r.event)
        .chain(std::iter::once(&current.event))
        .collect::<Vec<_>>();
    let scoped = DerivedFinding::from_events(finding, &events, true)?
        .into_scoped(producer.scope_generation)?;
    use sha2::{Digest, Sha256};
    let provenance = signal_control::PriorStateProvenance {
        schema_version: 1,
        key: "window-fixture".into(),
        checkpoint: first + 1,
        revision: [1; 32],
        value_sha256: Sha256::digest(&publication.states[0].bytes).into(),
        scope_generation: producer.scope_generation,
    };
    let next = MultiEventFindingClaims::from_host(
        producer,
        std::slice::from_ref(&current),
        &rows,
        Some(provenance),
        vec![(first + 2, scoped)],
    )?
    .bind(next, "window-fixture")?;
    next.verify(producer, std::slice::from_ref(&current), &rows)?;
    let next_raw = next.encode_sql_publication()?;
    let next_claims = next.encode_sql_claims()?;
    let unchanged = witness(db).await?;
    let value: serde_json::Value = serde_json::from_slice(&next_claims)?;
    for (field, changed) in [
        ("checkpoint", serde_json::json!(first)),
        ("revision", serde_json::json!("ff".repeat(32))),
        ("value_sha256", serde_json::json!("ff".repeat(32))),
        ("scope_generation", serde_json::json!(Uuid::from_u128(8895))),
    ] {
        let mut bad = value.clone();
        bad["prior"][field] = changed;
        assert_eq!(
            call(db, &token, &next_raw, &serde_json::to_vec(&bad)?, false)
                .await
                .err()
                .ok_or("bad prior accepted")?
                .as_db_error()
                .ok_or("non-db refusal")?
                .message(),
            "SIGNAL_FENCED"
        );
        assert_eq!(unchanged, witness(db).await?);
    }
    let mut bad = value.clone();
    bad["facts"][0]["references"][0]["event_id"] = serde_json::json!(Uuid::from_u128(8895));
    assert_eq!(
        call(db, &token, &next_raw, &serde_json::to_vec(&bad)?, false)
            .await
            .err()
            .ok_or("unprotected old ID accepted")?
            .as_db_error()
            .ok_or("non-db refusal")?
            .message(),
        "SIGNAL_FENCED"
    );
    assert_eq!(unchanged, witness(db).await?);
    let mut bad = value;
    bad["facts"][0]["references"][0]["sequence"] = serde_json::json!(first - 1);
    assert_eq!(
        call(db, &token, &next_raw, &serde_json::to_vec(&bad)?, false)
            .await
            .err()
            .ok_or("false old sequence accepted")?
            .as_db_error()
            .ok_or("non-db refusal")?
            .message(),
        "SIGNAL_FENCED"
    );
    assert_eq!(unchanged, witness(db).await?);
    let next_result = call(db, &token, &next_raw, &next_claims, false).await?;
    let advanced = witness(db).await?;
    assert_eq!(
        call(db, &token, &next_raw, &next_claims, true).await?,
        next_result
    );
    // Resolving an older committed request does not need the now-replaced state.
    assert_eq!(call(db, &token, &raw, &claims, true).await?, result);
    assert_eq!(advanced, witness(db).await?);
    db.batch_execute("ROLLBACK; RESET ROLE").await?;
    qualify_client(db, fixture, producer, token, bound).await?;
    println!("phase: atomic-multi-event-publication-replay-quota-and-late-rollback-qualified");
    println!("phase: protected-prior-state-multi-event-references-qualified");
    Ok(())
}

async fn qualify_client(
    db: &Client,
    fixture: &super::Fixture,
    producer: &signal_control::ProducerEnrollment,
    token: signal_control::LeaseToken,
    input: signal_control::MultiEventPublicationInput,
) -> Result<(), Box<dyn std::error::Error>> {
    use signal_control::{ConnectionSettings, ControlClient, ControlError};
    let before = super::publication::witness(db).await?;
    let deadline: String = db
        .query_one(
            "SELECT lease_until::text FROM signal_control.partitions WHERE id=$1",
            &[&producer.scope.partition_id],
        )
        .await?
        .try_get(0)?;
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()+interval '60 seconds' WHERE id=$1", &[&producer.scope.partition_id]).await?;
    let runtime = ControlClient::catalog(ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse()?,
        fixture.port,
        "signal_finding_scope_fixture".into(),
        "signal_runtime".into(),
        fixture.password.as_bytes().to_vec(),
    )?)?;
    assert!(matches!(
        runtime
            .publish_multi_event(token.clone(), input.clone(), super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    db.batch_execute("UPDATE signal_control.store SET ready=false; SET ROLE signal_control_owner")
        .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/010-multi-event-publication.sql"
    ))
    .await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_multi_event TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea) TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    db.execute("INSERT INTO signal_multi_event.profile(singleton,scope_generation,max_rows,max_bytes) VALUES(true,$1,1,1048576)", &[&producer.scope_generation]).await?;
    assert!(matches!(
        runtime
            .resolve_multi_event_publication(token.clone(), input.clone(), super::context()?)
            .await,
        Err(ControlError::Uncertain)
    ));
    let stable = witness(db).await?;
    assert!(matches!(
        runtime
            .publish_multi_event(token.clone(), input.clone(), super::context()?)
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(stable, witness(db).await?);
    db.batch_execute("ALTER TABLE signal_multi_event.profile ADD COLUMN unexpected boolean")
        .await?;
    assert!(matches!(
        runtime
            .publish_multi_event(token.clone(), input.clone(), super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    // Dropping a column leaves a catalog tombstone; recreate this owned module.
    db.batch_execute("UPDATE signal_control.store SET ready=false; DROP SCHEMA signal_multi_event CASCADE; SET ROLE signal_control_owner").await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/010-multi-event-publication.sql"
    ))
    .await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_multi_event TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea) TO signal_runtime; UPDATE signal_control.store SET ready=true").await?;
    db.execute("INSERT INTO signal_multi_event.profile(singleton,scope_generation,max_rows,max_bytes) VALUES(true,$1,1,1048576)", &[&producer.scope_generation]).await?;
    db.batch_execute("ALTER FUNCTION signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea) SET search_path=pg_catalog").await?;
    assert!(matches!(
        runtime
            .publish_multi_event(token.clone(), input, super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    runtime.shutdown(super::context()?).await?;
    db.batch_execute(
        "UPDATE signal_control.store SET ready=false; DROP SCHEMA signal_multi_event CASCADE",
    )
    .await?;
    db.execute(
        "UPDATE signal_control.partitions SET lease_until=$2::text::timestamptz WHERE id=$1",
        &[&producer.scope.partition_id, &deadline],
    )
    .await?;
    assert_eq!(before, super::publication::witness(db).await?);
    println!("phase: bounded-multi-event-client-module-identity-and-drift-refusal-qualified");
    Ok(())
}

/// Successful worker commits use a clone with no impact on existing scoped
/// restore/restart fixtures. The parent owns and removes the entire database.
pub async fn qualify_isolated_client(
    root: &Client,
    fixture: &super::Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    use signal_control::*;
    use signal_findings::{DerivedFinding, DetectionSeverity, Finding};
    use signal_storage::{StoredEvent, object_manifest::QueryManifest};
    use std::collections::BTreeMap;
    use uuid::Uuid;
    const DATABASE: &str = "signal_multi_event_client_fixture";
    root.batch_execute(
        "CREATE DATABASE signal_multi_event_client_fixture TEMPLATE signal_finding_scope_fixture",
    )
    .await?;
    root.batch_execute(
        "GRANT CREATE ON DATABASE signal_multi_event_client_fixture TO signal_control_owner",
    )
    .await?;
    let (db, driver) = super::admin_database(fixture, DATABASE).await?;
    let row=db.query_one("SELECT h.store_id,h.generation,p.id,p.tenant,p.stream,a.scope_generation,e.startup_id,e.wal_floor FROM signal_control.store h JOIN signal_finding_scope.activation a ON a.singleton=h.singleton JOIN signal_finding_scope.producers e ON e.scope_generation=a.scope_generation JOIN signal_control.partitions p ON p.id=e.partition_id",&[]).await?;
    let producer = ProducerEnrollment {
        scope: Scope {
            schema_version: 1,
            store_id: row.try_get(0)?,
            generation: row.try_get(1)?,
            partition_id: row.try_get(2)?,
            tenant: row.try_get(3)?,
            stream: row.try_get(4)?,
        },
        scope_generation: row.try_get(5)?,
        startup: row.try_get(6)?,
        wal_floor: row.try_get::<_, i64>(7)? as u64,
    };
    db.batch_execute("SET ROLE signal_control_owner").await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/010-multi-event-publication.sql"
    ))
    .await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_multi_event TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea) TO signal_runtime; UPDATE signal_control.store SET ready=true; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL").await?;
    db.execute("INSERT INTO signal_multi_event.profile(singleton,scope_generation,max_rows,max_bytes) VALUES(true,$1,128,1048576)",&[&producer.scope_generation]).await?;
    let runtime = ControlClient::catalog(ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse()?,
        fixture.port,
        DATABASE.into(),
        "signal_runtime".into(),
        fixture.password.as_bytes().to_vec(),
    )?)?;
    let token = runtime
        .acquire(
            producer.scope.clone(),
            Uuid::from_u128(8910),
            60000,
            super::context()?,
        )
        .await?;
    let row=db.query_one("SELECT c.id,c.first_sequence,c.last_sequence,c.manifest FROM signal_control.partitions p JOIN signal_control.commits c ON c.partition_id=p.id AND c.id=p.head WHERE p.id=$1",&[&producer.scope.partition_id]).await?;
    let prior = PublicationInput {
        schema_version: 1,
        id: row.try_get(0)?,
        previous: None,
        first_sequence: row.try_get::<_, i64>(1)? as u64,
        last_sequence: row.try_get::<_, i64>(2)? as u64,
        manifest: row.try_get(3)?,
        rule_revision: [1; 32],
        normalizer_revision: "synthetic-v1".into(),
        states: vec![],
        findings: vec![],
        work: vec![],
        receipts: vec![],
    };
    let first = prior.last_sequence + 1;
    let mut publication = super::publication::request(&token, 8911, first, Some(&prior))?;
    publication.last_sequence = first + 1;
    let mut manifest: QueryManifest = serde_json::from_slice(&publication.manifest)?;
    manifest.last_sequence = first + 1;
    manifest.events = 2;
    manifest.files[0].rows = 2;
    publication.manifest = serde_json::to_vec(&manifest)?;
    publication.states.push(RevisionedState {
        key: "window-fixture".into(),
        revision: [1; 32],
        bytes: MultiEventStateEnvelope {
            schema_version: 1,
            scope_generation: producer.scope_generation,
            checkpoint: first + 1,
            metadata: serde_json::json!({"canonical_sha256":{}}),
            canonical_sequences: BTreeMap::new(),
        }
        .encode()?,
    });
    let mut rows = Vec::new();
    for offset in 0..2 {
        let event = serde_json::from_value(
            serde_json::json!({"schema_version":1,"id":Uuid::from_u128(8912+offset),"timestamp":"2026-10-15T00:00:00Z","observed_at":"2026-10-15T00:00:00Z","source":{"type":"fixture"},"resource":{"kind":"host","id":"fixture","account_id":"fixture"},"severity":"info","message":"fixture","attributes":{},"tags":[]}),
        )?;
        rows.push(StoredEvent {
            sequence: first + offset as u64,
            event,
        });
    }
    let mut finding = Finding::for_event(
        "window-fixture",
        &rows[1].event,
        DetectionSeverity::High,
        "Isolated worker fixture",
    )?;
    finding.event_ids = rows.iter().map(|r| r.event.id).collect();
    let finding_id = finding.id;
    let scoped = DerivedFinding::from_events(
        finding,
        &rows.iter().map(|r| &r.event).collect::<Vec<_>>(),
        true,
    )?
    .into_scoped(producer.scope_generation)?;
    let input =
        MultiEventFindingClaims::from_host(&producer, &rows, &[], None, vec![(first + 1, scoped)])?
            .bind(publication.clone(), "window-fixture")?;
    input.verify(&producer, &rows, &[])?;
    let result = runtime
        .publish_multi_event(token.clone(), input.clone(), super::context()?)
        .await?;
    assert_eq!(result.id, publication.id);
    assert_eq!(result.last_sequence, first + 1);
    let committed = witness(&db).await?;
    assert_eq!(
        runtime
            .publish_multi_event(token.clone(), input.clone(), super::context()?)
            .await?,
        result
    );
    assert_eq!(
        runtime
            .resolve_multi_event_publication(token.clone(), input.clone(), super::context()?)
            .await?,
        result
    );
    assert_eq!(committed, witness(&db).await?);
    let row=db.query_one("SELECT p.checkpoint,s.value,m.finding_sha256,f.content FROM signal_control.partitions p JOIN signal_control.state s ON s.partition_id=p.id AND s.key='window-fixture' JOIN signal_multi_event.facts m ON m.partition_id=p.id AND m.finding_id=$2 JOIN signal_control.findings f ON f.partition_id=m.partition_id AND f.id=m.finding_id WHERE p.id=$1",&[&producer.scope.partition_id,&finding_id]).await?;
    assert_eq!(row.try_get::<_, i64>(0)?, (first + 1) as i64);
    assert_eq!(row.try_get::<_, Vec<u8>>(1)?, publication.states[0].bytes);
    use sha2::{Digest, Sha256};
    let finding_bytes: Vec<u8> = row.try_get(3)?;
    assert_eq!(
        row.try_get::<_, Vec<u8>>(2)?,
        Sha256::digest(&finding_bytes).to_vec()
    );
    let finding: Finding = serde_json::from_slice(&finding_bytes)?;
    assert_eq!(
        finding.event_ids,
        rows.iter().map(|r| r.event.id).collect::<Vec<_>>()
    );
    let mut stale = token.clone();
    stale.epoch += 1;
    assert!(matches!(
        runtime
            .publish_multi_event(stale, input.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let mut changed = serde_json::to_value(&input)?;
    changed["claims"]["startup"] = serde_json::json!(Uuid::from_u128(8915));
    let changed: MultiEventPublicationInput = serde_json::from_value(changed)?;
    assert!(matches!(
        runtime
            .resolve_multi_event_publication(token, changed, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(committed, witness(&db).await?);
    qualify_scoped_reader(&db, fixture, &producer, finding_id).await?;
    runtime.shutdown(super::context()?).await?;
    drop(db);
    driver.await?;
    root.batch_execute("DROP DATABASE signal_multi_event_client_fixture")
        .await?;
    println!("phase: bounded-multi-event-client-original-commit-replay-and-fencing-qualified");
    Ok(())
}

async fn qualify_scoped_reader(
    db: &Client,
    fixture: &super::Fixture,
    producer: &signal_control::ProducerEnrollment,
    finding_id: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    use signal_control::*;
    use signal_protocol::access::{AccessPolicy, AuthenticatedIdentity};
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    let reader = ControlClient::catalog(ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse()?,
        fixture.port,
        "signal_multi_event_client_fixture".into(),
        "signal_denied".into(),
        fixture.password.as_bytes().to_vec(),
    )?)?;
    db.batch_execute("GRANT USAGE ON SCHEMA signal_control,signal_finding_scope TO signal_denied; GRANT SELECT ON signal_control.store,signal_control.migrations,signal_control.findings,signal_control.partitions,signal_finding_scope.activation,signal_finding_scope.profile,signal_finding_scope.producers,signal_finding_scope.facts,signal_finding_scope.requests TO signal_denied").await?;
    let binding = ScopedFindingsBinding {
        store: producer.scope.store_id,
        generation: producer.scope.generation,
        scope_generation: producer.scope_generation,
        schema_owner: "signal_control_owner".into(),
    };
    let query = signal_findings::FindingQuery {
        rule_id: Some("window-fixture".into()),
        limit: 128,
        ..Default::default()
    };
    let grant = |pairs: Vec<(&str, &str)>| -> Result<
        Arc<signal_protocol::access::RequestGrant>,
        Box<dyn std::error::Error>,
    > {
        let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let roles=pairs.into_iter().enumerate().map(|(index,(account,resource))|serde_json::json!({"id":format!("reader-{index}"),"permissions":[{"operation":"read_findings","scope":{"sources":{"mode":"all"},"accounts":{"mode":"only","values":[account]},"resources":{"mode":"only","values":[resource]}}}]})).collect::<Vec<_>>();
        let policy=AccessPolicy::from_json(&serde_json::to_vec(&serde_json::json!({"schema_version":1,"roles":roles,"bindings":[{"issuer":"fixture","subject":"reader","roles":roles.iter().filter_map(|r|r.get("id")).collect::<Vec<_>>()}]}))?)?.compile()?;
        Ok(Arc::new(policy.grant(
            AuthenticatedIdentity::from_verified_backend(
                "fixture".into(),
                "reader".into(),
                at,
                at + 60,
            )?,
            at,
        )?))
    };
    assert!(matches!(
        reader
            .read_scoped_findings(
                binding.clone(),
                query.clone(),
                grant(vec![("fixture", "fixture")])?,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("GRANT USAGE ON SCHEMA signal_multi_event TO signal_denied; GRANT SELECT ON signal_multi_event.profile,signal_multi_event.facts,signal_multi_event.requests,signal_control.commits TO signal_denied").await?;
    println!("phase: multi-event-scoped-positive-start");
    let pin = reader
        .inspect_existing_finding_scope(producer.scope.clone(), binding.clone(), super::context()?)
        .await?;
    assert_eq!(
        pin.binding()?
            .producer
            .as_ref()
            .ok_or("missing read-only producer")?
            .startup,
        producer.startup
    );
    let admin = FindingScopeAdministrator::new(
        ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse()?,
            fixture.port,
            "signal_multi_event_client_fixture".into(),
            "signal_migrator".into(),
            fixture.password.as_bytes().to_vec(),
        )?,
        "signal_control_owner".into(),
        FindingScopeProfile::Catalog4Scoped,
    )?;
    assert_eq!(
        admin
            .inspect(
                producer.scope.clone(),
                producer.scope_generation,
                super::context()?
            )
            .await?
            .binding()?
            .checkpoint,
        pin.binding()?.checkpoint
    );
    let page = reader
        .read_scoped_findings(
            binding.clone(),
            query.clone(),
            grant(vec![("fixture", "fixture")])?,
            super::context()?,
        )
        .await
        .map_err(|error| format!("multi-event positive scoped read: {error}"))?;
    assert_eq!(page.findings()?.len(), 1);
    assert_eq!(page.findings()?[0].id, finding_id);
    assert_eq!(page.findings()?[0].event_ids.len(), 2);
    println!("phase: multi-event-scoped-paired-negative-start");
    let cross = reader
        .read_scoped_findings(
            binding.clone(),
            query.clone(),
            grant(vec![("fixture", "foreign"), ("foreign", "fixture")])?,
            super::context()?,
        )
        .await
        .map_err(|error| format!("multi-event crossed-pair scoped read: {error}"))?;
    assert!(cross.findings()?.is_empty());
    let original: Vec<u8> = db
        .query_one(
            "SELECT fact FROM signal_multi_event.facts WHERE finding_id=$1",
            &[&finding_id],
        )
        .await?
        .try_get(0)?;
    db.execute("UPDATE signal_multi_event.facts SET fact=convert_to(jsonb_set(convert_from(fact,'UTF8')::jsonb,'{source}','\"foreign\"'::jsonb)::text,'UTF8') WHERE finding_id=$1",&[&finding_id]).await?;
    db.execute(
        "UPDATE signal_multi_event.facts SET fact_sha256=sha256(fact) WHERE finding_id=$1",
        &[&finding_id],
    )
    .await?;
    assert!(matches!(
        reader
            .inspect_existing_finding_scope(
                producer.scope.clone(),
                binding.clone(),
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    assert!(matches!(
        admin
            .inspect(
                producer.scope.clone(),
                producer.scope_generation,
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    assert!(matches!(
        reader
            .read_scoped_findings(
                binding.clone(),
                query.clone(),
                grant(vec![("fixture", "fixture")])?,
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    db.execute(
        "UPDATE signal_multi_event.facts SET fact=$2,fact_sha256=sha256($2) WHERE finding_id=$1",
        &[&finding_id, &original],
    )
    .await?;
    assert_eq!(
        reader
            .read_scoped_findings(
                binding.clone(),
                query,
                grant(vec![("fixture", "fixture")])?,
                super::context()?
            )
            .await?
            .findings()?
            .len(),
        1
    );
    db.batch_execute("GRANT UPDATE ON signal_multi_event.facts TO signal_denied")
        .await?;
    assert!(matches!(
        reader
            .inspect_existing_finding_scope(
                producer.scope.clone(),
                binding.clone(),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("REVOKE UPDATE ON signal_multi_event.facts FROM signal_denied; GRANT EXECUTE ON FUNCTION signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea) TO signal_denied").await?;
    assert!(matches!(
        reader
            .inspect_existing_finding_scope(
                producer.scope.clone(),
                binding.clone(),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("REVOKE EXECUTE ON FUNCTION signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea) FROM signal_denied").await?;
    reader
        .inspect_existing_finding_scope(producer.scope.clone(), binding, super::context()?)
        .await?;
    admin.shutdown(super::context()?).await?;
    reader.shutdown(super::context()?).await?;
    println!("phase: multi-event-scoped-reader-paired-grants-privileges-and-corruption-qualified");
    println!("phase: multi-event-administrative-and-readonly-producer-inspection-qualified");
    Ok(())
}
