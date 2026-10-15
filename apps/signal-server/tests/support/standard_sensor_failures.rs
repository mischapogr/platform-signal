//! Typed maintenance failures using actual Main frames and the native engine.
use super::{Fixture, Result, context};
use sha2::{Digest, Sha256};
use signal_control::{
    ControlClient, ControlContext, ControlError, LeaseToken, PriorStateProvenance, RevisionedState,
    SensorMaintenance,
};
use std::{fs, path::Path, time::Duration};

async fn witness(db: &tokio_postgres::Client) -> Result<serde_json::Value> {
    Ok(db.query_one("SELECT jsonb_build_object('head',head,'checkpoint',checkpoint,'commits',(SELECT count(*) FROM signal_control.commits),'findings',(SELECT jsonb_agg(encode(content,'hex') ORDER BY position) FROM signal_control.findings),'used_bytes',(SELECT used_bytes FROM signal_control.store),'used_rows',(SELECT used_rows FROM signal_control.store),'value',(SELECT encode(value,'hex') FROM signal_control.state WHERE key='standard-sensor')) FROM signal_control.partitions WHERE kind='pipeline'", &[]).await?.get(0))
}
fn input(
    token: &LeaseToken,
    revision: [u8; 32],
    head: Option<uuid::Uuid>,
    prior: &[u8],
    target: Vec<u8>,
) -> Result<SensorMaintenance> {
    let frame: serde_json::Value = serde_json::from_slice(prior)?;
    assert_eq!(
        token.scope.stream,
        serde_json::from_value::<uuid::Uuid>(frame["metadata"]["scope"]["stream"].clone())?
    );
    Ok(SensorMaintenance {
        head,
        prior: PriorStateProvenance {
            schema_version: 1,
            key: "standard-sensor".into(),
            checkpoint: frame["checkpoint"].as_u64().ok_or("checkpoint")?,
            revision,
            value_sha256: Sha256::digest(prior).into(),
            scope_generation: serde_json::from_value(frame["scope_generation"].clone())?,
        },
        state: RevisionedState {
            key: "standard-sensor".into(),
            revision,
            bytes: target,
        },
        retired: Vec::new(),
    })
}
pub async fn qualify(db: &tokio_postgres::Client, root: &Path, fixture: &Fixture) -> Result {
    let document: serde_json::Value = serde_json::from_slice(&fs::read(root.join("shared.json"))?)?;
    let row = db
        .query_one(
            "SELECT owner,epoch,head FROM signal_control.partitions WHERE kind='pipeline'",
            &[],
        )
        .await?;
    let token = LeaseToken {
        scope: serde_json::from_value(document["scope"].clone())?,
        owner: row.get(0),
        epoch: u64::try_from(row.get::<_, i64>(1))?,
    };
    let head = row.get(2);
    let revision: Vec<u8> = db
        .query_one(
            "SELECT revision FROM signal_control.state WHERE key='standard-sensor'",
            &[],
        )
        .await?
        .get(0);
    let revision: [u8; 32] = revision.try_into().map_err(|_| "revision")?;
    let prior = fs::read(root.join("sensor-maintenance-prior.bin"))?;
    let target = fs::read(root.join("sensor-maintenance-committed.bin"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(fs::read(
        &fixture.root_der,
    )?))?;
    let worker = ControlClient::catalog(signal_control::ConnectionSettings::tls(
        "signal-control.invalid".into(),
        Some("127.0.0.1".parse()?),
        fixture.port,
        super::DB.into(),
        "signal_standard_producer".into(),
        fixture.password.as_bytes().to_vec(),
        roots,
    )?)?;
    for deadline in [false, true] {
        let original = witness(db).await?;
        // Only this owned fixture is rewound, with the exact original Main CAS
        // bytes and matching charge. No live native writer remains after SIGKILL.
        db.batch_execute("BEGIN").await?;
        db.execute("UPDATE signal_control.store SET used_bytes=used_bytes+$1-(SELECT octet_length(value) FROM signal_control.state WHERE key='standard-sensor')",&[&(prior.len() as i64)]).await?;
        db.execute(
            "UPDATE signal_control.state SET value=$1 WHERE key='standard-sensor'",
            &[&prior],
        )
        .await?;
        db.batch_execute("COMMIT; SELECT pg_advisory_lock(7382,20261015); CREATE FUNCTION public.synthetic_sensor_late_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ BEGIN PERFORM pg_advisory_xact_lock(7382,20261015); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_sensor_late_commit AFTER UPDATE ON signal_control.state DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.key='standard-sensor') EXECUTE FUNCTION public.synthetic_sensor_late_commit()").await?;
        let prepared = witness(db).await?;
        let budget = ControlContext::new(if deadline {
            Duration::from_millis(1500)
        } else {
            Duration::from_secs(5)
        })?;
        let candidate = input(&token, revision, head, &prior, target.clone())?;
        let (reply, observed) = tokio::join!(
            worker.maintain_sensor_state(token.clone(), candidate, budget.clone()),
            async {
                let pid=tokio::time::timeout(Duration::from_secs(2),async {
                loop {
                    let rows=db.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename='signal_standard_producer' AND application_name='signal-control' AND state='active' AND query='COMMIT' AND wait_event_type='Lock' AND pg_backend_pid()=ANY(pg_blocking_pids(pid))",&[]).await?;
                    if rows.len()==1 {return Ok::<_,tokio_postgres::Error>(rows[0].get::<_,i32>(0));}
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await??;
                if deadline {
                    tokio::time::sleep_until(budget.deadline()).await;
                } else {
                    budget.cancel();
                }
                db.batch_execute("SELECT pg_advisory_unlock(7382,20261015)")
                    .await?;
                Ok::<_, Box<dyn std::error::Error>>(pid)
            }
        );
        let pid = observed?;
        assert!(matches!(reply, Err(ControlError::Uncertain)));
        assert!(budget.check().is_err());
        db.batch_execute("DROP TRIGGER synthetic_sensor_late_commit ON signal_control.state; DROP FUNCTION public.synthetic_sensor_late_commit()").await?;
        let actual = witness(db).await?;
        let outcome = if actual == original {
            "committed"
        } else {
            assert_eq!(
                actual, prepared,
                "uncertain COMMIT must leave exactly the prior or target inventory"
            );
            "rolled_back"
        };
        let resolved = worker
            .maintain_sensor_state(
                token.clone(),
                input(&token, revision, head, &prior, target.clone())?,
                context()?,
            )
            .await?;
        assert_eq!(resolved.state.ok_or("resolved state")?.bytes, target);
        assert_eq!(witness(db).await?, original);
        let label = if deadline { "deadline" } else { "cancelled" };
        fs::write(
            root.join(format!("sensor-maintenance-late-{label}.json")),
            serde_json::to_vec(
                &serde_json::json!({"status":"passed_simulated","observed_commit_pid":pid,"reply":"uncertain","original_context_invalid":true,"database_outcome":outcome,"observed_inventory":actual,"exact_target_reconciled":true,"inventory":original}),
            )?,
        )?;
    }
    growth_quota(db, root, &worker, &token, revision, head, &target).await?;
    worker.shutdown(context()?).await?;
    println!(
        "phase: Standard-SENSOR-native-frame-observed-COMMIT-cancel-deadline-uncertain-target-reconciliation-and-engine-growth-quota-qualified"
    );
    Ok(())
}
async fn growth_quota(
    db: &tokio_postgres::Client,
    root: &Path,
    worker: &ControlClient,
    token: &LeaseToken,
    revision: [u8; 32],
    head: Option<uuid::Uuid>,
    target: &[u8],
) -> Result {
    use signal_rules::RuleContext;
    use signal_server::sensor_health::native::{Config, Engine, Epoch, SharedBinding};
    let cfg: serde_json::Value = serde_json::from_slice(&fs::read(root.join("sensor.json"))?)?;
    let config: Config = serde_json::from_value(cfg["detector"].clone())?;
    let envelope: signal_control::MultiEventStateEnvelope = serde_json::from_slice(target)?;
    let metadata = &envelope.metadata["sensor"];
    let control = context()?;
    let rules = RuleContext {
        deadline: control.deadline(),
        cancellation: control.cancellation_token(),
    };
    let mut engine = Engine::new(
        config,
        Epoch {
            schema_version: 1,
            source_stream: token.scope.stream,
            source_binding: serde_json::from_value(metadata["snapshot"]["source_binding"].clone())?,
            checkpoint: envelope.checkpoint,
            last_sequence: envelope.checkpoint,
            now_ms: chrono::Utc::now().timestamp_millis(),
        },
        None,
        &rules,
    )?;
    let events: Vec<signal_event::SignalEvent> =
        serde_json::from_slice(&fs::read(root.join("sensor-canonical-events.json"))?)?;
    let rows = envelope
        .canonical_sequences
        .iter()
        .map(|(id, sequence)| {
            Ok(signal_storage::StoredEvent {
                sequence: *sequence,
                event: events
                    .iter()
                    .find(|e| e.id == *id)
                    .ok_or("canonical event")?
                    .clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut current = engine.hydrate(metadata, &envelope.canonical_sequences, &rows, &rules)?;
    let producer = db
        .query_one(
            "SELECT startup_id,wal_floor FROM signal_finding_scope.producers WHERE partition_id=$1",
            &[&token.scope.partition_id],
        )
        .await?;
    let binding = SharedBinding {
        producer: signal_control::ProducerEnrollment {
            scope: token.scope.clone(),
            scope_generation: envelope.scope_generation,
            startup: producer.get(0),
            wal_floor: u64::try_from(producer.get::<_, i64>(1))?,
        },
        key: "standard-sensor".into(),
        rule_revision: revision,
    };
    let mut prior = target.to_vec();
    for attempt in 0..128 {
        let context = context()?;
        let rules = RuleContext {
            deadline: context.deadline(),
            cancellation: context.cancellation_token(),
        };
        let candidate = engine
            .prepare_retiring(
                &current,
                0,
                chrono::Utc::now().timestamp_millis(),
                rules.clone(),
            )
            .await?;
        let next = candidate.snapshot().clone();
        let (value, _) = binding.encode(&engine, &next, &rules)?;
        let input = input(token, revision, head, &prior, value.bytes.clone())?;
        let growth = value.bytes.len() as i64 - prior.len() as i64;
        if growth > 0 {
            let original = witness(db).await?;
            let maximum: i64 = db
                .query_one("SELECT max_bytes FROM signal_control.store", &[])
                .await?
                .get(0);
            db.batch_execute("UPDATE signal_control.store SET max_bytes=used_bytes")
                .await?;
            let refused = worker
                .maintain_sensor_state(token.clone(), input.clone(), context.clone())
                .await;
            db.execute("UPDATE signal_control.store SET max_bytes=$1", &[&maximum])
                .await?;
            assert!(matches!(refused, Err(ControlError::Full)));
            assert_eq!(witness(db).await?, original);
            worker
                .maintain_sensor_state(token.clone(), input, context.clone())
                .await?;
            engine.confirm(candidate, next.record(), &rules)?;
            let after = witness(db).await?;
            for key in ["head", "checkpoint", "commits", "findings", "used_rows"] {
                assert_eq!(original[key], after[key], "{key}");
            }
            assert_eq!(
                after["used_bytes"].as_i64().ok_or("bytes")?
                    - original["used_bytes"].as_i64().ok_or("bytes")?,
                growth
            );
            fs::write(
                root.join("sensor-maintenance-growth-quota.json"),
                serde_json::to_vec(
                    &serde_json::json!({"status":"passed_simulated","engine_candidates":attempt+1,"growth_bytes":growth,"refused":"full","rollback_inventory":original,"committed_inventory":after}),
                )?,
            )?;
            return Ok(());
        }
        worker
            .maintain_sensor_state(token.clone(), input, context.clone())
            .await?;
        engine.confirm(candidate, next.record(), &rules)?;
        current = next;
        prior = value.bytes;
    }
    Err("native engine did not produce bounded growth candidate".into())
}
