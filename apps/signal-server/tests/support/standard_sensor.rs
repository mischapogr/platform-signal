//! Explicit fixture owner provisioning/read-only oracle for enabled sensor Main.
use super::{Fixture, Result};
use std::{fs, path::Path};
pub async fn bootstrap_quota(db: &tokio_postgres::Client, root: &Path, restore: bool) -> Result {
    let witness:serde_json::Value=db.query_one("SELECT jsonb_build_object('head',head,'checkpoint',checkpoint,'commits',(SELECT count(*) FROM signal_control.commits),'findings',(SELECT count(*) FROM signal_control.findings),'states',(SELECT count(*) FROM signal_control.state),'used_bytes',(SELECT used_bytes FROM signal_control.store),'used_rows',(SELECT used_rows FROM signal_control.store)) FROM signal_control.partitions WHERE kind='pipeline'",&[]).await?.get(0);
    let path = root.join("sensor-bootstrap-quota-before.json");
    if restore {
        let before: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        assert_eq!(witness, before["inventory"]);
        let maximum = before["max_bytes"].as_i64().ok_or("maximum bytes")?;
        db.execute("UPDATE signal_control.store SET max_bytes=$1", &[&maximum])
            .await?;
    } else {
        assert_eq!(witness["states"], 0);
        assert_eq!(witness["checkpoint"], 0);
        let maximum: i64 = db
            .query_one("SELECT max_bytes FROM signal_control.store", &[])
            .await?
            .get(0);
        fs::write(
            path,
            serde_json::to_vec(&serde_json::json!({"inventory":witness,"max_bytes":maximum}))?,
        )?;
        db.batch_execute("UPDATE signal_control.store SET max_bytes=greatest(1,used_bytes)")
            .await?;
    }
    println!(
        "phase: Standard-SENSOR-native-bootstrap-quota-{restore}-original-inventory-qualified"
    );
    Ok(())
}
/// Own an isolated fixture lock; interrupt the native caller only after COMMIT
/// is observed waiting on this exact session, then inspect the database outcome.
pub async fn maintenance_commit(
    db: &tokio_postgres::Client,
    root: &Path,
    fixture: &Fixture,
) -> Result {
    use sha2::{Digest, Sha256};
    use std::time::Duration;
    let before: serde_json::Value = db.query_one("SELECT jsonb_build_object('head',head,'checkpoint',checkpoint,'commits',(SELECT count(*) FROM signal_control.commits),'findings',(SELECT jsonb_agg(encode(content,'hex') ORDER BY position) FROM signal_control.findings),'used_bytes',(SELECT used_bytes FROM signal_control.store),'state_bytes',(SELECT octet_length(value) FROM signal_control.state WHERE key='standard-sensor')) FROM signal_control.partitions WHERE kind='pipeline'", &[]).await?.try_get(0)?;
    assert_eq!(before["checkpoint"], 2);
    db.batch_execute("SELECT pg_advisory_lock(7381,20261015); CREATE TABLE public.synthetic_sensor_commit_target(singleton boolean PRIMARY KEY CHECK(singleton),value bytea NOT NULL,prior_value bytea NOT NULL); CREATE FUNCTION public.synthetic_sensor_commit_pause() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ BEGIN INSERT INTO public.synthetic_sensor_commit_target VALUES(true,NEW.value,OLD.value); PERFORM pg_advisory_xact_lock(7381,20261015); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_sensor_commit_pause AFTER UPDATE ON signal_control.state DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.key='standard-sensor') EXECUTE FUNCTION public.synthetic_sensor_commit_pause()").await?;
    fs::write(root.join("sensor-maintenance-lock-ready"), b"held")?;
    let producer_pid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let rows=db.query("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename='signal_standard_producer' AND application_name='signal-control' AND state='active' AND query='COMMIT' AND wait_event_type='Lock' AND pg_backend_pid()=ANY(pg_blocking_pids(pid))", &[]).await?;
            if rows.len() == 1 {
                return Ok::<_, tokio_postgres::Error>(rows[0].get::<_, i32>(0));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    fs::write(
        root.join("sensor-maintenance-commit-observed"),
        producer_pid.to_string(),
    )?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !root.join("sensor-maintenance-caller-killed").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    db.batch_execute("SELECT pg_advisory_unlock(7381,20261015)")
        .await?;
    let target: Vec<u8> = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(row) = db
                .query_opt(
                    "SELECT value FROM public.synthetic_sensor_commit_target WHERE singleton",
                    &[],
                )
                .await?
            {
                return Ok::<_, tokio_postgres::Error>(row.get(0));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let stored: Vec<u8> = db
        .query_one(
            "SELECT value FROM signal_control.state WHERE key='standard-sensor'",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(stored, target);
    let after: serde_json::Value = db.query_one("SELECT jsonb_build_object('head',head,'checkpoint',checkpoint,'commits',(SELECT count(*) FROM signal_control.commits),'findings',(SELECT jsonb_agg(encode(content,'hex') ORDER BY position) FROM signal_control.findings),'used_bytes',(SELECT used_bytes FROM signal_control.store),'state_bytes',(SELECT octet_length(value) FROM signal_control.state WHERE key='standard-sensor')) FROM signal_control.partitions WHERE kind='pipeline'", &[]).await?.try_get(0)?;
    for key in ["head", "checkpoint", "commits", "findings"] {
        assert_eq!(before[key], after[key], "{key}");
    }
    assert_eq!(
        after["used_bytes"].as_i64().ok_or("used bytes")?
            - before["used_bytes"].as_i64().ok_or("used bytes")?,
        after["state_bytes"].as_i64().ok_or("state bytes")?
            - before["state_bytes"].as_i64().ok_or("state bytes")?
    );
    let frame: serde_json::Value = serde_json::from_slice(&target)?;
    let digest = Sha256::digest(&target)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    fs::write(root.join("sensor-maintenance-committed.bin"), &target)?;
    fs::write(
        root.join("sensor-maintenance-committed.json"),
        serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"producer_pid":producer_pid,"observed_commit":true,"target_sha256":digest,"target_revision":frame["metadata"]["sensor"]["snapshot"]["record"]["revision"],"before":before,"after":after}),
        )?,
    )?;
    let prior: Vec<u8> = db
        .query_one(
            "SELECT prior_value FROM public.synthetic_sensor_commit_target WHERE singleton",
            &[],
        )
        .await?
        .get(0);
    fs::write(root.join("sensor-maintenance-prior.bin"), prior)?;
    db.batch_execute("DROP TRIGGER synthetic_sensor_commit_pause ON signal_control.state; DROP FUNCTION public.synthetic_sensor_commit_pause(); DROP TABLE public.synthetic_sensor_commit_target").await?;
    // Retain the original CAS prior, not a reconstructed later state.
    replay_guards(db, root, fixture, false).await?;
    super::standard_sensor_failures::qualify(db, root, fixture).await?;
    println!(
        "phase: Standard-SENSOR-observed-maintenance-COMMIT-SIGKILL-original-target-bytes-head-checkpoint-findings-quota-qualified"
    );
    Ok(())
}
pub async fn replay_guards(
    db: &tokio_postgres::Client,
    root: &Path,
    fixture: &Fixture,
    diverged: bool,
) -> Result {
    use sha2::{Digest, Sha256};
    use signal_control::{
        ConnectionSettings, ControlClient, ControlError, LeaseToken, PriorStateProvenance,
        RevisionedState, SensorMaintenance,
    };
    let before:serde_json::Value=db.query_one("SELECT jsonb_build_object('head',head,'checkpoint',checkpoint,'commits',(SELECT count(*) FROM signal_control.commits),'findings',(SELECT jsonb_agg(encode(content,'hex') ORDER BY position) FROM signal_control.findings),'used_bytes',(SELECT used_bytes FROM signal_control.store),'value',(SELECT encode(value,'hex') FROM signal_control.state WHERE key='standard-sensor')) FROM signal_control.partitions WHERE kind='pipeline'",&[]).await?.get(0);
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
    let original = fs::read(root.join("sensor-maintenance-prior.bin"))?;
    let prior: serde_json::Value = serde_json::from_slice(&original)?;
    let revision: Vec<u8> = db
        .query_one(
            "SELECT revision FROM signal_control.state WHERE key='standard-sensor'",
            &[],
        )
        .await?
        .get(0);
    let revision: [u8; 32] = revision.try_into().map_err(|_| "revision length")?;
    let target = fs::read(root.join("sensor-maintenance-committed.bin"))?;
    let input = SensorMaintenance {
        head: row.get(2),
        prior: PriorStateProvenance {
            schema_version: 1,
            key: "standard-sensor".into(),
            checkpoint: prior["checkpoint"].as_u64().ok_or("checkpoint")?,
            revision,
            value_sha256: Sha256::digest(&original).into(),
            scope_generation: serde_json::from_value(prior["scope_generation"].clone())?,
        },
        state: RevisionedState {
            key: "standard-sensor".into(),
            revision,
            bytes: target.clone(),
        },
        retired: Vec::new(),
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(fs::read(
        &fixture.root_der,
    )?))?;
    let worker = ControlClient::catalog(ConnectionSettings::tls(
        "signal-control.invalid".into(),
        Some("127.0.0.1".parse()?),
        fixture.port,
        super::DB.into(),
        "signal_standard_producer".into(),
        fixture.password.as_bytes().to_vec(),
        roots,
    )?)?;
    if diverged {
        assert!(matches!(
            worker
                .maintain_sensor_state(token, input, super::context()?)
                .await,
            Err(ControlError::Conflict)
        ));
    } else {
        let cancelled = super::context()?;
        cancelled.cancel();
        assert!(matches!(
            worker
                .maintain_sensor_state(token.clone(), input.clone(), cancelled)
                .await,
            Err(ControlError::Cancelled)
        ));
        let mut stale = token.clone();
        stale.owner = uuid::Uuid::new_v4();
        assert!(matches!(
            worker
                .maintain_sensor_state(stale, input.clone(), super::context()?)
                .await,
            Err(ControlError::Fenced)
        ));
        let echo = worker
            .maintain_sensor_state(token, input, super::context()?)
            .await?;
        assert_eq!(echo.state.ok_or("echo state")?.bytes, target);
    }
    worker.shutdown(super::context()?).await?;
    let after:serde_json::Value=db.query_one("SELECT jsonb_build_object('head',head,'checkpoint',checkpoint,'commits',(SELECT count(*) FROM signal_control.commits),'findings',(SELECT jsonb_agg(encode(content,'hex') ORDER BY position) FROM signal_control.findings),'used_bytes',(SELECT used_bytes FROM signal_control.store),'value',(SELECT encode(value,'hex') FROM signal_control.state WHERE key='standard-sensor')) FROM signal_control.partitions WHERE kind='pipeline'",&[]).await?.get(0);
    if diverged {
        for key in ["head", "checkpoint", "commits", "findings"] {
            assert_eq!(before[key], after[key], "{key}");
        }
        let actual: Vec<u8> = db
            .query_one(
                "SELECT value FROM signal_control.state WHERE key='standard-sensor'",
                &[],
            )
            .await?
            .get(0);
        assert_ne!(actual, target);
    } else {
        assert_eq!(before, after);
    }
    let label = if diverged { "diverged" } else { "exact" };
    fs::write(
        root.join(format!("sensor-maintenance-{label}-guards.json")),
        serde_json::to_vec(
            &serde_json::json!({"status":"passed_simulated","before":before,"after":after}),
        )?,
    )?;
    println!(
        "phase: Standard-SENSOR-native-frame-typed-maintenance-{label}-replay-cancel-stale-owner-guards-qualified"
    );
    Ok(())
}

pub async fn prepare(db: &tokio_postgres::Client) -> Result {
    db.batch_execute("SET ROLE signal_control_owner").await?;
    for source in [
        include_str!("../../../../schemas/shared-control/019-sensor-replay-pin.sql"),
        include_str!("../../../../schemas/shared-control/020-sensor-maintenance.sql"),
        include_str!("../../../../schemas/shared-control/021-sensor-bootstrap.sql"),
    ] {
        db.batch_execute(source).await?;
    }
    db.batch_execute("RESET ROLE; GRANT USAGE ON SCHEMA signal_sensor_pin,signal_sensor_maintenance,signal_sensor_bootstrap TO signal_standard_producer; GRANT EXECUTE ON FUNCTION signal_control.check_token(jsonb,bytea,bytea),signal_sensor_pin.retain(jsonb,bytea,bytea,bytea),signal_sensor_maintenance.apply(jsonb,bytea,bytea,bytea),signal_sensor_bootstrap.initialize(jsonb,bytea,bytea,bytea) TO signal_standard_producer").await?;
    Ok(())
}
pub async fn snapshot(db: &tokio_postgres::Client, root: &Path) -> Result {
    let threshold = root.join("sensor-minimum-revision.json");
    let minimum = if threshold.exists() {
        serde_json::from_slice::<u64>(&fs::read(threshold)?)?
    } else {
        0
    };
    let value:serde_json::Value=tokio::time::timeout(std::time::Duration::from_secs(5),async {
        loop {
            let value:serde_json::Value=db.query_one("SELECT jsonb_build_object('partition',(SELECT to_jsonb(p) FROM signal_control.partitions p WHERE kind='pipeline'),'state',(SELECT convert_from(value,'UTF8')::jsonb FROM signal_control.state WHERE key='standard-sensor'),'state_sha256',(SELECT encode(sha256(value),'hex') FROM signal_control.state WHERE key='standard-sensor'),'states',(SELECT jsonb_object_agg(key,convert_from(value,'UTF8')::jsonb) FROM signal_control.state),'state_keys',(SELECT jsonb_agg(key ORDER BY key) FROM signal_control.state),'commits',(SELECT count(*) FROM signal_control.commits),'findings',coalesce((SELECT jsonb_agg(convert_from(content,'UTF8')::jsonb ORDER BY position) FROM signal_control.findings),'[]'::jsonb),'finding_bytes',coalesce((SELECT jsonb_agg(encode(content,'hex') ORDER BY position) FROM signal_control.findings),'[]'::jsonb))",&[]).await?.try_get(0)?;
            if value["state"]["metadata"]["sensor"]["snapshot"]["record"]["revision"].as_u64().is_some_and(|n|n>=minimum) {
                return Ok::<_,tokio_postgres::Error>(value);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await??;
    fs::write(
        root.join("sensor-snapshot.json"),
        serde_json::to_vec(&value)?,
    )?;
    println!("phase: Standard-SENSOR-read-only-state-finding-checkpoint-snapshot-qualified");
    Ok(())
}
