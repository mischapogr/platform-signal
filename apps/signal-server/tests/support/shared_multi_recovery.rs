//! Synthetic host admission and version backend; actual detector, Parquet, WAL and PostgreSQL.
use super::{Fixture, Result, context, database, draft, recovery_support, versions};
use sha2::{Digest, Sha256};
use signal_buffer::{BufferConfig, DurableBuffer};
use signal_control::*;
use signal_protocol::EventSink;
use signal_rules::window::{Policy, State};
use signal_server::{
    shared_multi_event::MultiEventPublicationDraft,
    shared_recovery::{RECOVERY_BYTES, SharedRecovery},
    shared_window::SharedWindowBinding,
};
use signal_storage::StoredEvent;
use std::sync::Arc;
use uuid::Uuid;
const DB: &str = "signal_shared_multi_recovery";
pub(super) fn connection(f: &Fixture) -> std::result::Result<ConnectionSettings, ControlError> {
    ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse().map_err(|_| ControlError::Invalid)?,
        f.port,
        DB.into(),
        "signal_runtime".into(),
        f.password.as_bytes().to_vec(),
    )
}
// Owner-side parser oracle; the runtime credential deliberately cannot call this helper.
async fn qualify_timestamp_pairs(db: &tokio_postgres::Client) -> Result {
    use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
    let mut clocks = Vec::new();
    for year in [
        -262143, -10000, -400, -100, -1, 0, 1, 400, 1969, 1970, 2000, 10000, 262142,
    ] {
        for (month, day) in [(1, 1), (3, 1), (12, 31)] {
            let date = NaiveDate::from_ymd_opt(year, month, day).ok_or("clock fixture date")?;
            clocks.push(DateTime::<Utc>::from_naive_utc_and_offset(
                date.and_hms_nano_opt(23, 59, 59, 999_999_999)
                    .ok_or("clock fixture time")?,
                Utc,
            ));
        }
    }
    for value in [
        "2016-12-31T23:59:59.999999999Z",
        "2016-12-31T23:59:60Z",
        "2016-12-31T23:59:60.000000001Z",
        "2016-12-31T23:59:60.999999999Z",
        "2017-01-01T00:00:00Z",
        "1970-01-01T00:00:00Z",
        "2000-02-29T00:00:00.1Z",
    ] {
        clocks.push(value.parse::<DateTime<Utc>>()?);
    }
    clocks.sort();
    let mut previous = None;
    for clock in clocks {
        let text = clock.to_rfc3339_opts(SecondsFormat::AutoSi, true);
        let pair: Vec<i64> = db
            .query_one("SELECT signal_window_history.timestamp_pair($1)", &[&text])
            .await?
            .try_get(0)?;
        assert_eq!(
            pair,
            vec![clock.timestamp(), i64::from(clock.timestamp_subsec_nanos())],
            "{text}"
        );
        if let Some(prior) = previous {
            assert!(prior <= pair, "Chrono ordering: {text}");
        }
        previous = Some(pair);
    }
    for invalid in [
        "1900-02-29T00:00:00Z",
        "2000-02-30T00:00:00Z",
        "0000-00-01T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:61Z",
        "2026-01-01T00:00:00.1234567890Z",
        "2026-01-01T00:00:00+01:00",
        "+262143-01-01T00:00:00Z",
        "-262144-01-01T00:00:00Z",
        "invalid",
    ] {
        let error = db
            .query_one(
                "SELECT signal_window_history.timestamp_pair($1)",
                &[&invalid],
            )
            .await
            .err()
            .ok_or("invalid canonical clock accepted")?;
        assert_eq!(
            error.as_db_error().map(|e| e.message()),
            Some("SIGNAL_INVALID"),
            "{invalid}"
        );
    }
    Ok(())
}

pub(super) async fn qualify(f: &Fixture) -> Result {
    let root = tempfile::tempdir()?;
    let cfg = BufferConfig {
        directory: root.path().join("wal"),
        ..Default::default()
    };
    let initial = DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?;
    let scope = Scope {
        schema_version: 1,
        store_id: Uuid::from_u128(0xfc00),
        generation: Uuid::from_u128(0xfc01),
        tenant: "synthetic-multi-recovery".into(),
        stream: initial.snapshot().stream_id,
        partition_id: Uuid::from_u128(0xfc03),
    };
    initial.shutdown().await?;
    let (root_db, root_driver) = database(f, "postgres").await?;
    root_db
        .batch_execute(&format!("CREATE DATABASE {DB}"))
        .await?;
    root_db
        .batch_execute(&format!(
            "GRANT CREATE ON DATABASE {DB} TO signal_control_owner"
        ))
        .await?;
    drop(root_db);
    root_driver.await??;
    let migrator = ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse()?,
        f.port,
        DB.into(),
        "signal_migrator".into(),
        f.password.as_bytes().to_vec(),
    )?;
    let installer = ControlAdministrator::new(migrator.clone(), "signal_control_owner".into())?;
    let authority = AdministrativeScope {
        schema_version: 1,
        store_id: scope.store_id,
        generation: scope.generation,
    };
    installer
        .initialize(
            InitializeInput {
                scope: authority.clone(),
                max_rows: 65536,
                max_bytes: 67108864,
            },
            context()?,
        )
        .await?;
    installer
        .migrate_catalog(
            MigrationInput {
                scope: authority.clone(),
                source_revision: 2,
                source_sha256: schema_identity().1,
            },
            context()?,
        )
        .await?;
    installer.shutdown(context()?).await?;
    let (db, driver) = database(f, DB).await?;
    let backend = Uuid::from_u128(0xfc04);
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
        "INSERT INTO signal_control.object_backends VALUES($1,'owned-multi-recovery-versions')",
        &[&backend],
    )
    .await?;
    db.execute(
        "INSERT INTO signal_control.object_scopes VALUES($1,$2,$3)",
        &[
            &scope.partition_id,
            &backend,
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
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/017-window-replay-pin.sql"
    ))
    .await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_control,signal_finding_scope TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_control TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) TO signal_runtime").await?;
    let admin = FindingScopeAdministrator::new(
        migrator,
        "signal_control_owner".into(),
        FindingScopeProfile::Catalog4Scoped,
    )?;
    let producer = ProducerEnrollment {
        scope: scope.clone(),
        scope_generation: Uuid::from_u128(0xfc05),
        startup: Uuid::new_v4(),
        wal_floor: 0,
    };
    admin
        .activate(
            authority,
            producer.scope_generation,
            FindingScopeLimits {
                producers: 1,
                rows: 128,
                bytes: 131072,
            },
            context()?,
        )
        .await?;
    admin.enroll(producer.clone(), context()?).await?;
    admin.shutdown(context()?).await?;
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
        "../../../../schemas/shared-control/011-replay-pin-transfer.sql"
    ))
    .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/012-window-history.sql"
    ))
    .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/013-window-history-read.sql"
    ))
    .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/014-obsolete-replay-pin.sql"
    ))
    .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/015-window-profile.sql"
    ))
    .await?;
    db.batch_execute(include_str!(
        "../../../../schemas/shared-control/016-known-findings.sql"
    ))
    .await?;
    qualify_timestamp_pairs(&db).await?;
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_state_read,signal_multi_event,signal_replay_transfer,signal_replay_release,signal_window_profile,signal_finding_lookup,signal_window_pin TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_state_read,signal_multi_event,signal_replay_transfer,signal_replay_release,signal_window_profile,signal_finding_lookup,signal_window_pin TO signal_runtime").await?;
    db.execute("INSERT INTO signal_multi_event.profile(singleton,scope_generation,max_rows,max_bytes) VALUES(true,$1,128,1048576)",&[&producer.scope_generation]).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    let mut control = Arc::new(ControlClient::catalog(connection(f)?)?);
    let token = control
        .acquire(scope.clone(), Uuid::new_v4(), 60000, context()?)
        .await?;
    let objects = Arc::new(versions::Versions(object_store::memory::InMemory::new()));
    let mut publisher = recovery_support::publisher(control.clone(), &scope, backend, &objects)?;
    let mut wal = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
    let mut recovery = SharedRecovery::new(publisher.clone(), wal.clone())?;
    let policy = Policy {
        schema_version: 1,
        partition: scope.partition_id,
        rule_id: "fixture-window".into(),
        revision: "fixture-v1".into(),
        title: "Recovery fixture".into(),
        severity: signal_findings::DetectionSeverity::High,
        threshold: 2,
        window_ms: 60000,
        lateness_ms: 10000,
        ttl_ms: 70000,
        max_keys: 4,
        max_attempts_per_key: 16,
        max_attempts: 32,
        max_outputs: 32,
        max_state_bytes: 65536,
        max_history_assessments: 32,
        max_history_bytes: 262144,
        history_retention_ms: 60000,
    };
    db.execute("INSERT INTO signal_window_history.profile(partition_id,state_key,scope_generation,max_rows,max_bytes,retention_ms) VALUES($1,'window-fixture',$2,32,262144,60000)",&[&scope.partition_id,&producer.scope_generation]).await?;
    let profile = WindowProfile {
        schema_version: 1,
        scope_generation: producer.scope_generation,
        history_rows: 32,
        history_bytes: 262144,
        retention_ms: 60000,
        bootstrap_checkpoint: Some(0),
    };
    let initial = StateReadInput {
        key: "window-fixture".into(),
        expected_head: None,
    };
    assert!(matches!(
        control
            .read_window_state(token.clone(), initial.clone(), profile.clone(), context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("GRANT USAGE ON SCHEMA signal_window_history_read TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_window_history_read TO signal_runtime").await?;
    let empty = control
        .read_window_state(token.clone(), initial.clone(), profile.clone(), context()?)
        .await?;
    assert!(empty.state.is_none());
    assert_eq!(empty.checkpoint, 0);
    let mut denied = profile.clone();
    denied.bootstrap_checkpoint = None;
    assert!(matches!(
        control
            .read_window_state(token.clone(), initial.clone(), denied, context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let mut denied = profile.clone();
    denied.bootstrap_checkpoint = Some(1);
    assert!(matches!(
        control
            .read_window_state(token.clone(), initial.clone(), denied, context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let mut denied = profile.clone();
    denied.history_rows = 31;
    assert!(matches!(
        control
            .read_window_state(token.clone(), initial, denied, context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_window_history_read FROM signal_runtime; REVOKE USAGE ON SCHEMA signal_window_history_read FROM signal_runtime").await?;
    let binding = SharedWindowBinding {
        producer: producer.clone(),
        source_binding: [1; 32],
        rule_revision: [1; 32],
        key: "window-fixture".into(),
    };
    let mut state = State::new(policy.clone())?;
    let mut all = Vec::new();
    let mut head = None;
    let recovery_io = super::io(objects.clone())?;
    let recovery_codec = signal_storage::object_codec::ObjectCodec::new(
        signal_storage::StorageConfig::default(),
        signal_storage::object_manifest::ManifestLimits::default(),
    )?;
    let mut replay_pins = std::collections::BTreeSet::new();
    let mut released_pins = std::collections::BTreeSet::new();
    for scenario in 0..5 {
        let prior = if head.is_some() {
            let recovered = signal_server::shared_window::SharedWindowRecovery {
                binding: &binding,
                control: &control,
                objects: &recovery_io,
                codec: &recovery_codec,
                limits: CanonicalRecoveryLimits {
                    backend,
                    files: 128,
                    object_bytes: 67108864,
                    decoded_bytes: 67108864,
                    scanned_rows: 65536,
                    result_bytes: 1048576,
                },
            }
            .recover(token.clone(), &policy, context()?)
            .await?;
            assert_eq!(recovered.prior.checkpoint, all.len() as u64);
            for row in recovered.canonical.rows()? {
                assert!(all.iter().any(|original| original == row));
            }
            assert!(!recovered.replay_pins.is_empty());
            if scenario == 1 {
                let id = recovered.replay_pins[0];
                let pin = db.query_one("SELECT convert_from(request,'UTF8')::jsonb->'object',decode(convert_from(request,'UTF8')::jsonb->>'reference','hex') FROM signal_control.object_pins WHERE id=$1", &[&id]).await?;
                let original = RetentionPinInput {
                    schema_version: 1,
                    id,
                    object: serde_json::from_value(pin.try_get(0)?)?,
                    kind: RetentionKind::Replay,
                    reference: pin.try_get(1)?,
                };
                assert_eq!(
                    control
                        .pin_window_object(token.clone(), original.clone(), context()?)
                        .await?
                        .id,
                    id
                );
                for field in [
                    "state_key",
                    "metadata_sha256",
                    "object_bytes",
                    "object_sha256",
                ] {
                    let mut changed = original.clone();
                    let mut proof: serde_json::Value = serde_json::from_slice(&changed.reference)?;
                    proof[field] = match field {
                        "state_key" => serde_json::json!("foreign-window"),
                        "object_bytes" => serde_json::json!(1),
                        _ => serde_json::json!(vec![0; 32]),
                    };
                    changed.reference = serde_json::to_vec(&proof)?.into_boxed_slice().into_vec();
                    assert!(matches!(
                        control
                            .pin_window_object(token.clone(), changed, context()?)
                            .await,
                        Err(ControlError::Fenced)
                    ));
                }
                let mut changed = original;
                changed.kind = RetentionKind::Evidence;
                assert!(matches!(
                    control
                        .pin_window_object(token.clone(), changed, context()?)
                        .await,
                    Err(ControlError::Invalid)
                ));
            }
            if let Some(pair)=db.query_opt("SELECT o.id,n.id FROM signal_control.object_pins o JOIN signal_control.object_pins n ON n.partition_id=o.partition_id AND n.object_reference=o.object_reference AND n.id<>o.id WHERE o.state='retained' AND n.state='retained' AND o.id=ANY($1) AND n.id=ANY($2) ORDER BY o.id,n.id LIMIT 1",&[&replay_pins.iter().copied().collect::<Vec<Uuid>>(),&recovered.replay_pins]).await? {
                let old:Uuid=pair.try_get(0)?;let replacement:Uuid=pair.try_get(1)?;
                let transfer=ReplayPinReplacement{id:old,replacement,state_key:binding.key.clone(),expected_head:head.ok_or("confirmed head")?,revision:binding.rule_revision,value_sha256:recovered.prior.value_sha256};
                let mut bad=transfer.clone();bad.expected_head=Uuid::new_v4();assert!(matches!(control.release_replaced_replay_pin(token.clone(),bad,context()?).await,Err(ControlError::Conflict)));
                let mut bad=transfer.clone();bad.value_sha256=[0;32];assert!(matches!(control.release_replaced_replay_pin(token.clone(),bad,context()?).await,Err(ControlError::Fenced)));
                let released=control.release_replaced_replay_pin(token.clone(),transfer.clone(),context()?).await?;assert_eq!(released.state,ObjectControlState::Released);
                assert_eq!(control.release_replaced_replay_pin(token.clone(),transfer.clone(),context()?).await?,released);
                let mut reverse=transfer;reverse.id=replacement;reverse.replacement=old;assert!(matches!(control.release_replaced_replay_pin(token.clone(),reverse,context()?).await,Err(ControlError::Fenced)));
                assert_eq!(db.query_one("SELECT state FROM signal_control.object_pins WHERE partition_id=$1 AND id=$2",&[&scope.partition_id,&replacement]).await?.try_get::<_,String>(0)?,"retained");
                released_pins.insert(old);
            }

            replay_pins.extend(recovered.replay_pins);
            state = recovered.state;
            state.retire_assessments(state.assessments().len())?;
            Some(recovered.prior)
        } else {
            None
        };
        let old = all.clone();
        let first = all.len() as u64 + 1;
        for offset in 0..2 {
            let sequence = first + offset;
            let at = chrono::DateTime::from_timestamp(1791972000 + (sequence as i64 - 1) * 20, 0)
                .ok_or("fixture time")?;
            let input: signal_event::IngestEvent = serde_json::from_value(
                serde_json::json!({"timestamp":at,"source":{"type":"authentication","name":"fixture"},"message":"multi recovery fixture","attributes":{"authentication":{"identity_authority":"fixture","principal_id":"fixture","target_id":"fixture","outcome":if sequence==1 {"success"} else {"failure"}},"producer":{"boot_id":"fixture","sequence":sequence}}}),
            )?;
            let mut event = input.normalize(at)?;
            event.id = Uuid::from_u128(0xfc10 + u128::from(sequence));
            wal.admit(event.clone()).await?;
            state.admit(&event, true)?;
            all.push(StoredEvent { sequence, event });
        }
        if scenario != 0 {
            state.seal(
                all.last().ok_or("current row")?.event.timestamp,
                scenario != 4,
            )?;
        }
        if scenario == 1 {
            assert!(
                state
                    .assessments()
                    .iter()
                    .any(|a| a.outcome == signal_rules::window::Outcome::NoMatch
                        && a.event_ids.is_empty())
            );
        }
        let current = &all[(first - 1) as usize..];
        let last = current.last().ok_or("batch")?.sequence;
        let mut derived = Vec::new();
        for assessment in state.assessments() {
            if let Some(finding) = assessment.finding(&policy)? {
                let anchor = all
                    .iter()
                    .find(|r| {
                        r.event.timestamp == assessment.anchor
                            && assessment.event_ids.contains(&r.event.id)
                    })
                    .ok_or("assessment anchor")?
                    .sequence;
                let events = assessment.canonical_events().iter().collect::<Vec<_>>();
                let scoped = signal_findings::DerivedFinding::from_events(finding, &events, true)?
                    .into_scoped(producer.scope_generation)?;
                derived.push((anchor, scoped));
            }
        }
        let mut plan = draft();
        plan.id = Uuid::from_u128(0xfc20 + scenario);
        plan.previous = head;
        plan.states = vec![binding.encode(&state, &policy, last, &all)?];
        let original_id = plan.id;
        let make = if scenario == 1 {
            MultiEventPublicationDraft::from_retained_anchor_host
        } else {
            MultiEventPublicationDraft::from_host
        };
        let multi = make(plan, &producer, current, &old, prior, &binding.key, derived)?;
        let budget = context()?;
        let prepared = if scenario == 4 {
            db.batch_execute("UPDATE signal_control.store SET ready=false")
                .await?;
            let before = publisher.metrics().objects.processed;
            assert!(matches!(
                recovery
                    .prepare_multi_event(token.clone(), multi, 2, budget.clone())
                    .await,
                Err(signal_server::shared_recovery::RecoveryError::Shared(
                    super::SharedError::Control(ControlError::Fenced)
                ))
            ));
            assert_eq!(publisher.metrics().objects.processed, before);
            db.batch_execute("UPDATE signal_control.store SET ready=true")
                .await?;
            None
        } else {
            Some(
                recovery
                    .prepare_multi_event(token.clone(), multi, 2, budget.clone())
                    .await?,
            )
        };
        let original = prepared
            .as_ref()
            .and_then(|p| p.multi_event_request())
            .cloned();
        let record = wal
            .read_recovery(context()?.deadline())
            .await?
            .ok_or("synced record")?;
        let wire: serde_json::Value = serde_json::from_slice(&record.bytes)?;
        assert_eq!(wire["schema_version"], 3);
        assert_eq!(
            wire["phase"]["state"],
            if scenario == 4 {
                "multi_draft"
            } else {
                "multi_prepared"
            }
        );
        let expected_findings: Vec<FindingInput> = serde_json::from_value(if scenario == 4 {
            wire["phase"]["draft"]["claims"]["findings"].clone()
        } else {
            wire["phase"]["request"]["publication"]["findings"].clone()
        })?;
        if scenario == 1 {
            let original_input = original.as_ref().ok_or("quota candidate")?;
            let mut quota = serde_json::to_value(original_input)?;
            let bytes: Vec<u8> =
                serde_json::from_value(quota["publication"]["states"][0]["bytes"].clone())?;
            let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
            value["metadata"]["window"]["state"]["policy"]["max_history_assessments"] =
                serde_json::json!(1);
            quota["publication"]["states"][0]["bytes"] =
                serde_json::to_value(serde_json::to_vec(&value)?)?;
            let quota: MultiEventPublicationInput = serde_json::from_value(quota)?;
            db.batch_execute("UPDATE signal_window_history.profile SET max_rows=1")
                .await?;
            let error = control
                .publish_multi_event(token.clone(), quota, context()?)
                .await
                .err()
                .ok_or("history quota unexpectedly accepted")?;
            assert!(
                matches!(error, ControlError::Full),
                "history quota refusal: {error}"
            );
            let row=db.query_one("SELECT (SELECT checkpoint FROM signal_control.partitions WHERE id=$1),(SELECT count(*) FROM signal_window_history.assessments),(SELECT count(*) FROM signal_multi_event.requests),(SELECT count(*) FROM signal_control.findings)",&[&scope.partition_id]).await?;
            assert_eq!(row.try_get::<_, i64>(0)?, 2);
            assert_eq!(row.try_get::<_, i64>(1)?, 0);
            assert_eq!(row.try_get::<_, i64>(2)?, 1);
            assert_eq!(row.try_get::<_, i64>(3)?, 0);
            db.batch_execute("UPDATE signal_window_history.profile SET max_rows=32")
                .await?;
        }
        if scenario == 3 {
            db.batch_execute("CREATE FUNCTION public.synthetic_multi_commit_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(.5); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_multi_commit_pause AFTER INSERT ON signal_control.commits DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_multi_commit_pause()").await?;
            let observed = async {
                tokio::time::timeout(std::time::Duration::from_secs(4),async {
                loop {let active:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND query='COMMIT' AND wait_event='PgSleep')",&[&DB]).await?.try_get(0)?;
                    if active {budget.cancel();return Ok::<(),tokio_postgres::Error>(());}
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }).await
            };
            let (uncertain, observed) = tokio::join!(
                recovery.commit(prepared.ok_or("prepared operation")?),
                observed
            );
            observed??;
            assert!(matches!(
                uncertain,
                Err(signal_server::shared_recovery::RecoveryError::Shared(
                    super::SharedError::Control(ControlError::Uncertain)
                ))
            ));
            assert_eq!(wal.snapshot().checkpoint, first - 1);
            assert!(wal.read_recovery(context()?.deadline()).await?.is_some());
            db.batch_execute("DROP TRIGGER synthetic_multi_commit_pause ON signal_control.commits; DROP FUNCTION public.synthetic_multi_commit_pause()").await?;
        } else {
            drop(prepared);
            drop(recovery);
            publisher.shutdown(context()?).await?;
            control.shutdown(context()?).await?;
            wal.shutdown().await?;
            let mode = match scenario {
                0 => "multi-before-commit",
                1 => "multi-after-commit",
                2 => "multi-after-ack",
                4 => "multi-draft",
                _ => return Err("scenario bounds".into()),
            };
            recovery_support::kill_worker(root.path(), mode, &cfg.directory, &token).await?;
            wal = Arc::new(DurableBuffer::open_with_recovery(cfg.clone(), RECOVERY_BYTES).await?);
            control = Arc::new(ControlClient::catalog(connection(f)?)?);
            publisher = recovery_support::publisher(control.clone(), &scope, backend, &objects)?;
            recovery = SharedRecovery::new(publisher.clone(), wal.clone())?;
            let expected = if scenario == 2 { last } else { first - 1 };
            assert_eq!(wal.snapshot().checkpoint, expected);
            assert!(wal.read_recovery(context()?.deadline()).await?.is_some());
        }
        let result = recovery
            .resume(token.clone(), context()?)
            .await?
            .ok_or("recovered publication")?;
        assert_eq!(result.id, original_id);
        assert_eq!(wal.snapshot().checkpoint, last);
        assert!(wal.read_recovery(context()?.deadline()).await?.is_none());
        assert!(recovery.resume(token.clone(), context()?).await?.is_none());
        let row=db.query_one("SELECT p.checkpoint,c.request_sha256 FROM signal_control.partitions p JOIN signal_control.commits c ON c.partition_id=p.id AND c.id=p.head WHERE p.id=$1",&[&scope.partition_id]).await?;
        assert_eq!(row.try_get::<_, i64>(0)?, last as i64);
        use sha2::{Digest, Sha256};
        if let Some(original) = original {
            assert_eq!(
                row.try_get::<_, Vec<u8>>(1)?,
                Sha256::digest(original.encode_sql_publication()?).to_vec()
            );
        }
        for expected in expected_findings {
            assert_eq!(
                control
                    .known_findings(
                        token.clone(),
                        Some(original_id),
                        vec![expected.clone()],
                        context()?,
                    )
                    .await?,
                vec![expected.id]
            );
            let mut changed: signal_findings::Finding = serde_json::from_slice(&expected.bytes)?;
            changed.title.push_str(" changed");
            assert!(matches!(
                control
                    .known_findings(
                        token.clone(),
                        Some(original_id),
                        vec![FindingInput {
                            id: expected.id,
                            bytes: serde_json::to_vec(&changed)?,
                        }],
                        context()?,
                    )
                    .await,
                Err(ControlError::Conflict)
            ));
            changed.id = Uuid::new_v4();
            assert!(
                control
                    .known_findings(
                        token.clone(),
                        Some(original_id),
                        vec![FindingInput {
                            id: changed.id,
                            bytes: serde_json::to_vec(&changed)?
                        }],
                        context()?,
                    )
                    .await?
                    .is_empty()
            );
            assert!(matches!(
                control
                    .known_findings(token.clone(), None, vec![expected.clone()], context()?)
                    .await,
                Err(ControlError::Conflict)
            ));
            assert_eq!(
                db.query_one(
                    "SELECT content FROM signal_control.findings WHERE id=$1",
                    &[&expected.id]
                )
                .await?
                .try_get::<_, Vec<u8>>(0)?,
                expected.bytes
            );
        }
        let saved: Vec<u8> = db
            .query_one(
                "SELECT value FROM signal_control.state WHERE partition_id=$1 AND key=$2",
                &[&scope.partition_id, &binding.key],
            )
            .await?
            .try_get(0)?;
        assert_eq!(saved, binding.encode(&state, &policy, last, &all)?.bytes);
        head = Some(original_id);
        println!(
            "multi-ledger-scenario: {scenario} exact identity state and WAL checkpoint preserved"
        );
    }
    let row = db
        .query_one("SELECT count(*) FROM signal_multi_event.requests", &[])
        .await?;
    assert_eq!(row.try_get::<_, i64>(0)?, 5);
    assert!(db.query_one("SELECT EXISTS(SELECT 1 FROM signal_window_history.assessments WHERE convert_from(payload,'UTF8')::jsonb#>>'{assessment,outcome}'='no_match' AND convert_from(payload,'UTF8')::jsonb#>'{assessment,event_ids}'='[]'::jsonb AND convert_from(payload,'UTF8')::jsonb->'canonical_sha256'='{}'::jsonb AND convert_from(payload,'UTF8')::jsonb->'canonical_sequences'='{}'::jsonb)", &[]).await?.try_get::<_,bool>(0)?);
    let archived=db.query("SELECT convert_from(payload,'UTF8')::jsonb->'assessment'->>'outcome',count(*) FROM signal_window_history.assessments GROUP BY 1",&[]).await?;
    assert!(
        archived
            .iter()
            .any(|r| r.try_get::<_, String>(0).ok().as_deref() == Some("match"))
    );
    assert!(
        archived
            .iter()
            .any(|r| r.try_get::<_, String>(0).ok().as_deref() == Some("no_match"))
    );
    assert!(
        archived
            .iter()
            .any(|r| r.try_get::<_, String>(0).ok().as_deref() == Some("indeterminate"))
    );
    let row=db.query_one("SELECT p.used_rows,p.used_bytes,(SELECT count(*) FROM signal_window_history.assessments),(SELECT coalesce(sum(256+octet_length(payload)),0) FROM signal_window_history.assessments) FROM signal_window_history.profile p",&[]).await?;
    assert_eq!(row.try_get::<_, i64>(0)?, row.try_get::<_, i64>(2)?);
    assert_eq!(row.try_get::<_, i64>(1)?, row.try_get::<_, i64>(3)?);
    let history_input = HistoryInput {
        schema_version: 1,
        key: binding.key.clone(),
        head: head.ok_or("history head")?,
        limit: 1,
        max_bytes: 65536,
        cursor: None,
    };
    assert!(matches!(
        control
            .read_window_history(token.clone(), history_input.clone(), context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("GRANT USAGE ON SCHEMA signal_window_history_read TO signal_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA signal_window_history_read TO signal_runtime").await?;
    let present = control
        .read_window_state(
            token.clone(),
            StateReadInput {
                key: binding.key.clone(),
                expected_head: head,
            },
            profile,
            context()?,
        )
        .await?;
    assert!(present.state.is_some());
    assert_eq!(present.checkpoint, 10);
    let first_page = control
        .read_window_history(token.clone(), history_input.clone(), context()?)
        .await?;
    let first_export: serde_json::Value = serde_json::from_slice(&first_page.export_json()?)?;
    assert_eq!(
        first_export["records"]
            .as_array()
            .ok_or("history records")?
            .len(),
        1
    );
    assert!(!first_export["records"][0]["metadata"].is_null());
    assert_eq!(
        first_export["records"][0]["metadata"]["assessment"]["outcome"],
        "indeterminate"
    );
    assert_eq!(first_export["truncated"], true);
    let cursor = first_page.cursor()?.ok_or("history continuation")?;
    let mut next = history_input.clone();
    next.cursor = Some(cursor.clone());
    let second = control
        .read_window_history(token.clone(), next.clone(), context()?)
        .await?;
    let second: serde_json::Value = serde_json::from_slice(&second.export_json()?)?;
    assert_ne!(first_export["records"][0]["id"], second["records"][0]["id"]);
    let mut foreign = token.clone();
    foreign.scope.stream = Uuid::new_v4();
    assert!(matches!(
        control
            .read_window_history(foreign, history_input.clone(), context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let mut stale = history_input.clone();
    stale.head = Uuid::new_v4();
    assert!(matches!(
        control
            .read_window_history(token.clone(), stale, context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    let mut changed = serde_json::to_value(&cursor)?;
    changed["profile_sha"] = serde_json::json!("00".repeat(32));
    let mut stale = history_input.clone();
    stale.cursor = Some(serde_json::from_value(changed)?);
    assert!(matches!(
        control
            .read_window_history(token.clone(), stale, context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    let cancelled = context()?;
    cancelled.cancel();
    assert!(matches!(
        control
            .read_window_history(token.clone(), history_input.clone(), cancelled)
            .await,
        Err(ControlError::Cancelled)
    ));
    let held = context()?;
    let held_page = control
        .read_window_history(token.clone(), history_input.clone(), held.clone())
        .await?;
    held.cancel();
    assert!(matches!(
        held_page.export_json(),
        Err(ControlError::Cancelled)
    ));
    db.batch_execute("CREATE TEMP TABLE history_reader_original AS SELECT * FROM signal_window_history.assessments;
        WITH clock AS (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now)
        UPDATE signal_window_history.assessments SET recorded_at_ms=clock.now-60001,expires_at_ms=clock.now-1 FROM clock;").await?;
    assert!(matches!(
        control
            .read_window_history(token.clone(), next, context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    let mut expired_input = history_input.clone();
    expired_input.limit = 128;
    expired_input.max_bytes = 262144;
    let expired = control
        .read_window_history(token.clone(), expired_input, context()?)
        .await?;
    let expired: serde_json::Value = serde_json::from_slice(&expired.export_json()?)?;
    assert_eq!(expired["missing_evidence"], true);
    assert!(
        expired["records"]
            .as_array()
            .ok_or("expired records")?
            .iter()
            .all(|r| r["metadata"].is_null() && r["expired"] == true)
    );
    db.batch_execute("UPDATE signal_window_history.assessments a SET recorded_at_ms=o.recorded_at_ms,expires_at_ms=o.expires_at_ms FROM history_reader_original o WHERE a.id=o.id; DROP TABLE history_reader_original;
        UPDATE signal_window_history.assessments SET id=decode(repeat('00',32),'hex') WHERE id=(SELECT id FROM signal_window_history.assessments ORDER BY id LIMIT 1);").await?;
    assert!(matches!(
        control
            .read_window_history(token.clone(), history_input.clone(), context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    db.batch_execute("UPDATE signal_window_history.assessments SET id=sha256(payload);
        ALTER FUNCTION signal_window_history_read.read_page(jsonb,jsonb,bytea,bytea) SET search_path=pg_catalog;").await?;
    assert!(matches!(
        control
            .read_window_history(token.clone(), history_input.clone(), context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    db.batch_execute("ALTER FUNCTION signal_window_history_read.read_page(jsonb,jsonb,bytea,bytea) SET search_path=pg_catalog,signal_control,pg_temp").await?;
    let old_pin:Uuid=db.query_one("SELECT op.id FROM signal_control.object_pins op JOIN signal_control.commits c ON c.partition_id=op.partition_id AND op.reference_sha256=ANY(c.object_hashes) WHERE op.kind='replay' AND op.state='retained' AND c.first_sequence=1 ORDER BY op.id LIMIT 1",&[]).await?.try_get(0)?;
    let read = control
        .read_state(
            token.clone(),
            StateReadInput {
                key: binding.key.clone(),
                expected_head: head,
            },
            context()?,
        )
        .await?;
    let prior_sha: [u8; 32] =
        Sha256::digest(&read.state.as_ref().ok_or("current detector")?.bytes).into();
    let obsolete = ObsoleteReplayPin {
        id: old_pin,
        state_key: binding.key.clone(),
        expected_head: head.ok_or("confirmed head")?,
        revision: binding.rule_revision,
        value_sha256: prior_sha,
    };
    assert!(db.query_one("SELECT NOT EXISTS(SELECT 1 FROM signal_control.state s CROSS JOIN LATERAL jsonb_each(convert_from(s.value,'UTF8')::jsonb->'canonical_sequences') m WHERE m.value::text::bigint<=2)",&[]).await?.try_get::<_,bool>(0)?);
    assert!(matches!(
        control
            .release_obsolete_replay_pin(token.clone(), obsolete, context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    // Exercise the installed archive trigger with retained outputs after expiry.
    // Owner-only fixture changes are rolled back; no wall-clock sleep or renewal.
    db.batch_execute("BEGIN;
        UPDATE signal_window_history.assessments SET
            recorded_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint-60001,
            expires_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint-1;
        CREATE TEMP TABLE history_original ON COMMIT DROP AS SELECT * FROM signal_window_history.assessments;
        CREATE TEMP TABLE history_state ON COMMIT DROP AS SELECT value FROM signal_control.state;
        CREATE TEMP TABLE history_replay ON COMMIT DROP AS SELECT * FROM signal_multi_event.requests LIMIT 0;
        CREATE TRIGGER history_replay AFTER INSERT ON history_replay FOR EACH ROW EXECUTE FUNCTION signal_window_history.archive_publication();
        INSERT INTO history_replay SELECT * FROM signal_multi_event.requests LIMIT 1;")
        .await?;
    let row = db.query_one("SELECT count(*),coalesce(bool_and(a.recorded_at_ms=o.recorded_at_ms AND a.expires_at_ms=o.expires_at_ms AND a.checkpoint=o.checkpoint AND a.payload=o.payload AND a.expires_at_ms<floor(extract(epoch FROM clock_timestamp())*1000)::bigint),false) FROM signal_window_history.assessments a LEFT JOIN history_original o USING(partition_id,state_key,id)", &[]).await?;
    assert!(row.try_get::<_, i64>(0)? > 0);
    assert!(row.try_get::<_, bool>(1)?);
    db.batch_execute("UPDATE signal_control.state SET value=convert_to(jsonb_set(convert_from(value,'UTF8')::jsonb,'{metadata,window,state,outputs}','[]'::jsonb)::text,'UTF8');
        INSERT INTO history_replay SELECT * FROM signal_multi_event.requests LIMIT 1;")
        .await?;
    let row = db.query_one("SELECT (SELECT count(*) FROM signal_window_history.assessments),used_rows,used_bytes FROM signal_window_history.profile", &[]).await?;
    assert_eq!(row.try_get::<_, i64>(0)?, 0);
    assert_eq!(row.try_get::<_, i64>(1)?, 0);
    assert_eq!(row.try_get::<_, i64>(2)?, 0);
    let refused = db
        .batch_execute(
            "SAVEPOINT history_resurrection;
        UPDATE signal_control.state SET value=(SELECT value FROM history_state);
        INSERT INTO history_replay SELECT * FROM signal_multi_event.requests LIMIT 1;",
        )
        .await
        .err()
        .ok_or("retired assessment unexpectedly resurrected")?;
    assert_eq!(
        refused.as_db_error().map(|e| e.message()),
        Some("SIGNAL_FENCED")
    );
    db.batch_execute("ROLLBACK TO SAVEPOINT history_resurrection")
        .await?;
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM signal_window_history.assessments",
            &[]
        )
        .await?
        .try_get::<_, i64>(0)?,
        0
    );
    let advanced = state
        .watermark()
        .ok_or("sealed fixture watermark")?
        .checked_add_signed(chrono::Duration::nanoseconds(1))
        .ok_or("watermark overflow")?
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    db.execute("UPDATE signal_control.state SET value=convert_to(jsonb_set(convert_from(value,'UTF8')::jsonb,'{metadata,window,state,watermark}',to_jsonb($1::text))::text,'UTF8')", &[&advanced]).await?;
    db.batch_execute(
        "INSERT INTO history_replay SELECT * FROM signal_multi_event.requests LIMIT 1",
    )
    .await?;
    assert_eq!(
        db.query_one(
            "SELECT watermark_nanos FROM signal_window_history.profile",
            &[]
        )
        .await?
        .try_get::<_, i32>(0)?,
        1
    );
    let refused = db.batch_execute("SAVEPOINT history_watermark;
        UPDATE signal_control.state SET value=convert_to(jsonb_set(convert_from(value,'UTF8')::jsonb,'{metadata,window,state,watermark}',(SELECT convert_from(value,'UTF8')::jsonb#>'{metadata,window,state,watermark}' FROM history_state))::text,'UTF8');
        INSERT INTO history_replay SELECT * FROM signal_multi_event.requests LIMIT 1;")
        .await.err().ok_or("nanosecond watermark regression unexpectedly accepted")?;
    assert_eq!(
        refused.as_db_error().map(|e| e.message()),
        Some("SIGNAL_FENCED")
    );
    db.batch_execute("ROLLBACK TO SAVEPOINT history_watermark")
        .await?;
    db.batch_execute("ROLLBACK").await?;
    // Actual installed archive trigger, owner-only rollback fixture: this checks
    // clock guards, not authority or detector derivation for these synthetic dates.
    db.batch_execute("BEGIN;
        UPDATE signal_window_history.profile SET watermark_seconds=NULL,watermark_nanos=NULL;
        UPDATE signal_control.state SET value=convert_to(jsonb_set(convert_from(value,'UTF8')::jsonb,'{metadata,window,state,outputs}','[]'::jsonb)::text,'UTF8');
        CREATE TEMP TABLE clock_replay ON COMMIT DROP AS SELECT * FROM signal_multi_event.requests LIMIT 0;
        CREATE TRIGGER clock_replay AFTER INSERT ON clock_replay FOR EACH ROW EXECUTE FUNCTION signal_window_history.archive_publication();").await?;
    for text in [
        "-10000-01-01T00:00:00Z",
        "0000-01-01T00:00:00Z",
        "2016-12-31T23:59:59.999999999Z",
        "2016-12-31T23:59:60Z",
        "2016-12-31T23:59:60.999999999Z",
        "2017-01-01T00:00:00Z",
        "+10000-01-01T00:00:00.000000001Z",
    ] {
        db.execute("UPDATE signal_control.state SET value=convert_to(jsonb_set(convert_from(value,'UTF8')::jsonb,'{metadata,window,state,watermark}',to_jsonb($1::text))::text,'UTF8')", &[&text]).await?;
        db.batch_execute(
            "INSERT INTO clock_replay SELECT * FROM signal_multi_event.requests LIMIT 1",
        )
        .await?;
        let expected = text.parse::<chrono::DateTime<chrono::Utc>>()?;
        let row = db
            .query_one(
                "SELECT watermark_seconds,watermark_nanos FROM signal_window_history.profile",
                &[],
            )
            .await?;
        assert_eq!(row.try_get::<_, i64>(0)?, expected.timestamp());
        assert_eq!(
            row.try_get::<_, i32>(1)?,
            expected.timestamp_subsec_nanos() as i32
        );
        db.batch_execute("SAVEPOINT clock_regression").await?;
        let earlier = expected
            .checked_sub_signed(chrono::Duration::nanoseconds(1))
            .ok_or("clock decrement")?
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        db.execute("UPDATE signal_control.state SET value=convert_to(jsonb_set(convert_from(value,'UTF8')::jsonb,'{metadata,window,state,watermark}',to_jsonb($1::text))::text,'UTF8')", &[&earlier]).await?;
        let error = db
            .batch_execute(
                "INSERT INTO clock_replay SELECT * FROM signal_multi_event.requests LIMIT 1",
            )
            .await
            .err()
            .ok_or("clock regression accepted")?;
        assert_eq!(
            error.as_db_error().map(|e| e.message()),
            Some("SIGNAL_FENCED")
        );
        db.batch_execute(
            "ROLLBACK TO SAVEPOINT clock_regression; RELEASE SAVEPOINT clock_regression",
        )
        .await?;
    }
    db.batch_execute("ROLLBACK").await?;
    // A real sixth publication retires expired history and moves beyond every
    // old attempt's TTL. The old immutable commit remains independently retained.
    let read = control
        .read_state(
            token.clone(),
            StateReadInput {
                key: binding.key.clone(),
                expected_head: head,
            },
            context()?,
        )
        .await?;
    let ids = binding.required_event_ids(&read, &policy)?;
    let inputs = all
        .iter()
        .filter(|r| ids.contains(&r.event.id))
        .cloned()
        .collect::<Vec<_>>();
    let (mut next_state, prior) = binding.restore(&read, &policy, &inputs)?;
    next_state.retire_assessments(next_state.assessments().len())?;
    let old = all.clone();
    let first = all.len() as u64 + 1;
    for offset in 0..2 {
        let sequence = first + offset;
        let at = chrono::DateTime::from_timestamp(1791972000 + 600 + offset as i64 * 20, 0)
            .ok_or("fixture gap time")?;
        let input: signal_event::IngestEvent = serde_json::from_value(
            serde_json::json!({"timestamp":at,"source":{"type":"authentication","name":"fixture"},"message":"post-retention fixture","attributes":{"authentication":{"identity_authority":"fixture","principal_id":"fixture","target_id":"fixture","outcome":"failure"},"producer":{"boot_id":"fixture","sequence":sequence}}}),
        )?;
        let mut event = input.normalize(at)?;
        event.id = Uuid::from_u128(0xfc10 + u128::from(sequence));
        wal.admit(event.clone()).await?;
        next_state.admit(&event, true)?;
        all.push(StoredEvent { sequence, event });
    }
    next_state.seal(all.last().ok_or("gap row")?.event.timestamp, true)?;
    let mut derived = Vec::new();
    for assessment in next_state.assessments() {
        if let Some(finding) = assessment.finding(&policy)? {
            let anchor = all
                .iter()
                .find(|r| {
                    r.sequence >= first
                        && r.event.timestamp == assessment.anchor
                        && assessment.event_ids.contains(&r.event.id)
                })
                .ok_or("gap anchor")?
                .sequence;
            derived.push((
                anchor,
                signal_findings::DerivedFinding::from_events(
                    finding,
                    &assessment.canonical_events().iter().collect::<Vec<_>>(),
                    true,
                )?
                .into_scoped(producer.scope_generation)?,
            ));
        }
    }
    db.batch_execute("WITH clock AS (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now) UPDATE signal_window_history.assessments SET recorded_at_ms=clock.now-60001,expires_at_ms=clock.now-1 FROM clock").await?;
    let last = all.last().ok_or("gap checkpoint")?.sequence;
    let mut plan = draft();
    plan.id = Uuid::from_u128(0xfc30);
    plan.previous = head;
    plan.states = vec![binding.encode(&next_state, &policy, last, &all)?];
    let multi = MultiEventPublicationDraft::from_host(
        plan,
        &producer,
        &all[(first - 1) as usize..],
        &old,
        Some(prior),
        &binding.key,
        derived,
    )?;
    let prepared = recovery
        .prepare_multi_event(token.clone(), multi, 2, context()?)
        .await?;
    assert_eq!(recovery.commit(prepared).await?.id, Uuid::from_u128(0xfc30));
    assert_eq!(wal.snapshot().checkpoint, last);
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM signal_window_history.assessments WHERE checkpoint<11",
            &[]
        )
        .await?
        .try_get::<_, i64>(0)?,
        0
    );
    head = Some(Uuid::from_u128(0xfc30));
    let recovered = signal_server::shared_window::SharedWindowRecovery {
        binding: &binding,
        control: &control,
        objects: &recovery_io,
        codec: &recovery_codec,
        limits: CanonicalRecoveryLimits {
            backend,
            files: 128,
            object_bytes: 67108864,
            decoded_bytes: 67108864,
            scanned_rows: 65536,
            result_bytes: 1048576,
        },
    }
    .recover(token.clone(), &policy, context()?)
    .await?;
    let release = ObsoleteReplayPin {
        id: old_pin,
        state_key: binding.key.clone(),
        expected_head: head.ok_or("advanced head")?,
        revision: binding.rule_revision,
        value_sha256: recovered.prior.value_sha256,
    };
    let mut stale = release.clone();
    stale.expected_head = Uuid::new_v4();
    assert!(matches!(
        control
            .release_obsolete_replay_pin(token.clone(), stale, context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    let mut stale = release.clone();
    stale.value_sha256 = [0; 32];
    assert!(matches!(
        control
            .release_obsolete_replay_pin(token.clone(), stale, context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let mut protected = release.clone();
    protected.id = *recovered.replay_pins.first().ok_or("current object pin")?;
    assert!(matches!(
        control
            .release_obsolete_replay_pin(token.clone(), protected, context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    let released = control
        .release_obsolete_replay_pin(token.clone(), release.clone(), context()?)
        .await?;
    assert_eq!(released.state, ObjectControlState::Released);
    assert_eq!(
        control
            .release_obsolete_replay_pin(token.clone(), release, context()?)
            .await?,
        released
    );
    released_pins.insert(old_pin);
    replay_pins.extend(recovered.replay_pins);
    assert!(!replay_pins.is_empty());
    let retained:i64=db.query_one("SELECT count(*) FROM signal_control.object_pins WHERE state='retained' AND kind='replay'",&[]).await?.try_get(0)?;
    assert!(!released_pins.is_empty());
    assert_eq!(retained, (replay_pins.len() - released_pins.len()) as i64);
    recovery_codec
        .shutdown(signal_storage::OperationContext::new(
            std::time::Duration::from_secs(5),
        ))
        .await?;
    recovery_io
        .shutdown(signal_storage::OperationContext::new(
            std::time::Duration::from_secs(5),
        ))
        .await?;
    publisher.shutdown(context()?).await?;
    control.shutdown(context()?).await?;
    wal.shutdown().await?;
    drop(db);
    driver.await??;
    let (root_db, root_driver) = database(f, "postgres").await?;
    root_db
        .batch_execute("DROP DATABASE signal_shared_multi_recovery")
        .await?;
    drop(root_db);
    root_driver.await??;
    println!(
        "phase: actual-server-multi-event-publisher-ledger-original-reconciliation-and-WAL-ack-qualified"
    );
    println!(
        "phase: actual-server-multi-event-observed-COMMIT-cancellation-and-exact-reconciliation-qualified"
    );
    println!(
        "phase: actual-server-multi-event-prepared-SIGKILL-boundaries-and-original-recovery-qualified"
    );
    println!(
        "phase: actual-server-multi-event-preupload-draft-SIGKILL-and-original-recovery-qualified"
    );
    println!(
        "phase: actual-server-shared-WINDOW-fenced-state-canonical-Parquet-and-replay-pins-qualified"
    );
    println!(
        "phase: actual-server-replay-pin-same-version-transfer-confirmed-state-and-last-protection-qualified"
    );
    println!(
        "phase: actual-server-shared-WINDOW-history-atomic-quota-outcome-expiry-pending-replay-and-retired-resurrection-qualified"
    );
    println!(
        "phase: actual-server-shared-WINDOW-history-read-scope-cursor-expiry-corruption-and-cancellation-qualified"
    );
    println!(
        "phase: actual-server-WINDOW-indeterminate-history-and-complete-obsolete-pin-accounting-qualified"
    );
    println!(
        "phase: actual-server-WINDOW-profile-explicit-bootstrap-grants-quotas-and-protected-delayed-anchor-qualified"
    );
    Ok(())
}
