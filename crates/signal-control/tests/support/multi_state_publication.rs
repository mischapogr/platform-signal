//! Real transactional multiple-state provenance and upgrade regressions.
use super::multi_event_publication::{call, witness};
use sha2::{Digest, Sha256};
use signal_control::{
    LeaseToken, MultiEventFindingClaims, MultiEventStateEnvelope, PriorStateProvenance,
    ProducerEnrollment, PublicationInput, RevisionedState, StateFindingGroup,
};
use signal_findings::{DerivedFinding, DetectionSeverity, Finding, ScopedFinding};
use signal_storage::{StoredEvent, object_manifest::QueryManifest};
use std::collections::BTreeMap;
use tokio_postgres::Client;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn state(
    key: &str,
    producer: &ProducerEnrollment,
    checkpoint: u64,
    rows: &[StoredEvent],
) -> Result<RevisionedState> {
    let mut hashes = BTreeMap::<Uuid, [u8; 32]>::new();
    let mut sequences = BTreeMap::new();
    for row in rows {
        hashes.insert(
            row.event.id,
            Sha256::digest(serde_json::to_vec(&row.event)?).into(),
        );
        sequences.insert(row.event.id, row.sequence);
    }
    Ok(RevisionedState {
        key: key.into(),
        revision: [1; 32],
        bytes: MultiEventStateEnvelope {
            schema_version: 1,
            scope_generation: producer.scope_generation,
            checkpoint,
            metadata: if key == "sensor-fixture" {
                serde_json::json!({"schema_version":1,"scope":producer.scope,"key":key,
                    "rule_revision":vec![1u8;32],"sensor":{"schema_version":1},"canonical_sha256":hashes})
            } else { serde_json::json!({"canonical_sha256":hashes}) },
            canonical_sequences: sequences,
        }
        .encode()?,
    })
}
fn finding(
    rule: &str,
    producer: &ProducerEnrollment,
    rows: &[StoredEvent],
) -> Result<ScopedFinding> {
    let mut base = Finding::for_event(
        rule,
        &rows[0].event,
        DetectionSeverity::High,
        "Multiple state fixture",
    )?;
    base.event_ids = rows.iter().map(|r| r.event.id).collect();
    Ok(DerivedFinding::from_events(
        base,
        &rows.iter().map(|r| &r.event).collect::<Vec<_>>(),
        true,
    )?
    .into_scoped(producer.scope_generation)?)
}
fn prior(
    key: &str,
    producer: &ProducerEnrollment,
    publication: &PublicationInput,
) -> Result<PriorStateProvenance> {
    let item = publication
        .states
        .iter()
        .find(|s| s.key == key)
        .ok_or("missing previous state")?;
    Ok(PriorStateProvenance {
        schema_version: 1,
        key: key.into(),
        checkpoint: publication.last_sequence,
        revision: item.revision,
        value_sha256: Sha256::digest(&item.bytes).into(),
        scope_generation: producer.scope_generation,
    })
}
pub async fn qualify(
    db: &Client,
    producer: &ProducerEnrollment,
    token: &LeaseToken,
    previous: &PublicationInput,
    template: &StoredEvent,
) -> Result {
    let first = previous.last_sequence + 1;
    let mut publication = super::publication::request(token, 8910, first, Some(previous))?;
    publication.last_sequence = first + 1;
    let mut manifest: QueryManifest = serde_json::from_slice(&publication.manifest)?;
    manifest.last_sequence = first + 1;
    manifest.events = 2;
    manifest.files[0].rows = 2;
    publication.manifest = serde_json::to_vec(&manifest)?;
    let rows = (0..2)
        .map(|offset| {
            let mut row = template.clone();
            row.sequence = first + offset;
            row.event.id = Uuid::from_u128(8911 + offset as u128);
            row
        })
        .collect::<Vec<_>>();
    publication.states = vec![
        state("window-fixture", producer, first + 1, &rows[..1])?,
        state("sensor-fixture", producer, first + 1, &rows[1..])?,
    ];
    let input = MultiEventFindingClaims::from_state_groups(
        producer,
        &rows,
        vec![
            StateFindingGroup {
                state_key: "window-fixture".into(),
                prior: Some(prior("window-fixture", producer, previous)?),
                retained: vec![],
                derived: vec![(first, finding("window-multiple", producer, &rows[..1])?)],
            },
            StateFindingGroup {
                state_key: "sensor-fixture".into(),
                prior: None,
                retained: vec![],
                derived: vec![(first + 1, finding("sensor-multiple", producer, &rows[1..])?)],
            },
        ],
    )?
    .bind(publication, "window-fixture")?;
    let raw = input.encode_sql_publication()?;
    let claims = input.encode_sql_claims()?;
    let published = call(db, token, &raw, &claims, false).await?;
    assert_eq!(call(db, token, &raw, &claims, true).await?, published);
    let committed = input.publication();
    let mut current = template.clone();
    current.sequence = first + 2;
    current.event.id = Uuid::from_u128(8913);
    let mut next = super::publication::request(token, 8914, current.sequence, Some(committed))?;
    let window = vec![rows[0].clone(), current.clone()];
    let sensor = vec![rows[1].clone(), current.clone()];
    next.states = vec![
        state("window-fixture", producer, current.sequence, &window)?,
        state("sensor-fixture", producer, current.sequence, &sensor)?,
    ];
    let next = MultiEventFindingClaims::from_state_groups(
        producer,
        std::slice::from_ref(&current),
        vec![
            StateFindingGroup {
                state_key: "window-fixture".into(),
                prior: Some(prior("window-fixture", producer, committed)?),
                retained: rows[..1].to_vec(),
                derived: vec![(
                    current.sequence,
                    finding("window-retained-multiple", producer, &window)?,
                )],
            },
            StateFindingGroup {
                state_key: "sensor-fixture".into(),
                prior: Some(prior("sensor-fixture", producer, committed)?),
                retained: rows[1..].to_vec(),
                derived: vec![(
                    current.sequence,
                    finding("sensor-retained-multiple", producer, &sensor)?,
                )],
            },
        ],
    )?
    .bind(next, "window-fixture")?;
    let raw = next.encode_sql_publication()?;
    let claims = next.encode_sql_claims()?;
    let original: serde_json::Value = serde_json::from_slice(&claims)?;
    let before = witness(db).await?;
    for mode in [
        "cross-key",
        "missing-prior",
        "changed-hash",
        "changed-generation",
        "missing-state",
    ] {
        let mut bad = original.clone();
        match mode {
            "cross-key" => bad["facts"][0]["state_key"] = serde_json::json!("sensor-fixture"),
            "missing-prior" => {
                bad["priors"]
                    .as_object_mut()
                    .ok_or("prior map")?
                    .remove("window-fixture");
            }
            "changed-hash" => {
                bad["priors"]["sensor-fixture"]["value_sha256"] = serde_json::json!("ff".repeat(32))
            }
            "changed-generation" => {
                bad["priors"]["sensor-fixture"]["scope_generation"] =
                    serde_json::json!(Uuid::from_u128(999))
            }
            _ => bad["state_keys"] = serde_json::json!(["window-fixture"]),
        }
        let error = call(db, token, &raw, &serde_json::to_vec(&bad)?, false)
            .await
            .err()
            .ok_or("invalid multiple-state claim accepted")?;
        assert_eq!(
            error.as_db_error().ok_or("non-db refusal")?.message(),
            if mode == "missing-state" {
                "SIGNAL_INVALID"
            } else {
                "SIGNAL_FENCED"
            },
            "{mode}"
        );
        assert_eq!(before, witness(db).await?, "{mode}");
    }
    db.batch_execute("UPDATE signal_multi_event.profile SET max_rows=used_rows+1")
        .await?;
    let quota = witness(db).await?;
    assert_eq!(
        call(db, token, &raw, &claims, false)
            .await
            .err()
            .ok_or("quota accepted")?
            .as_db_error()
            .ok_or("non-db quota")?
            .message(),
        "SIGNAL_FULL"
    );
    assert_eq!(quota, witness(db).await?);
    db.batch_execute("UPDATE signal_multi_event.profile SET max_rows=128; CREATE FUNCTION public.synthetic_multiple_late_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_INVALID'; END $$; CREATE TRIGGER synthetic_multiple_late_failure BEFORE INSERT ON signal_multi_event.requests FOR EACH ROW EXECUTE FUNCTION public.synthetic_multiple_late_failure()").await?;
    let late = witness(db).await?;
    assert_eq!(
        call(db, token, &raw, &claims, false)
            .await
            .err()
            .ok_or("late mutation accepted")?
            .as_db_error()
            .ok_or("non-db late failure")?
            .message(),
        "SIGNAL_INVALID"
    );
    assert_eq!(late, witness(db).await?);
    db.batch_execute("DROP TRIGGER synthetic_multiple_late_failure ON signal_multi_event.requests; DROP FUNCTION public.synthetic_multiple_late_failure()").await?;
    let result = call(db, token, &raw, &claims, false).await?;
    assert_eq!(call(db, token, &raw, &claims, true).await?, result);
    let actual:Vec<(String,i64)>=db.query("SELECT key,(convert_from(value,'UTF8')::jsonb->>'checkpoint')::bigint FROM signal_control.state WHERE partition_id=$1 AND key IN ('window-fixture','sensor-fixture') ORDER BY key",&[&producer.scope.partition_id]).await?.into_iter().map(|r|(r.get(0),r.get(1))).collect();
    assert_eq!(
        actual,
        vec![
            ("sensor-fixture".into(), current.sequence as i64),
            ("window-fixture".into(), current.sequence as i64)
        ]
    );
    println!(
        "phase: atomic-multiple-state-independent-priors-quota-late-rollback-and-exact-replay-qualified"
    );
    qualify_upgrade(db).await?;
    super::sensor_replay_pin::qualify(db, producer, token, next.publication()).await?;
    super::sensor_maintenance::qualify(db, producer, token, next.publication()).await?;
    super::sensor_bootstrap::qualify(db, producer, token).await?;
    Ok(())
}

async fn procedure(db: &Client) -> Result<(u32, String, Option<String>, Vec<u8>)> {
    let row=db.query_one("SELECT p.oid,p.proowner::regrole::text,p.proacl::text,sha256(convert_to(p.prosrc,'UTF8')) FROM pg_proc p WHERE p.oid='signal_multi_event.publish(jsonb,bytea,bytea,boolean,bytea,bytea)'::regprocedure",&[]).await?;
    Ok((row.get(0), row.get(1), row.get(2), row.get(3)))
}
async fn qualify_upgrade(db: &Client) -> Result {
    let original = witness(db).await?;
    let before = procedure(db).await?;
    let legacy =
        include_str!("../../../../schemas/shared-control/010-v3-multi-event-publication.sql");
    let suffix = legacy
        .split_once("CREATE FUNCTION signal_multi_event.publish")
        .ok_or("legacy routine")?
        .1;
    let suffix = suffix
        .split_once("\nREVOKE ALL ON FUNCTION")
        .ok_or("legacy end")?
        .0;
    let legacy_routine = format!("CREATE OR REPLACE FUNCTION signal_multi_event.publish{suffix}");
    db.batch_execute("UPDATE signal_control.store SET ready=false; SET ROLE signal_control_owner")
        .await?;
    db.batch_execute(&legacy_routine).await?;
    db.batch_execute("RESET ROLE").await?;
    let old = procedure(db).await?;
    assert_eq!((&old.0, &old.1, &old.2), (&before.0, &before.1, &before.2));
    let upgrade =
        include_str!("../../../../schemas/shared-control/018-multi-state-publication-upgrade.sql")
            .strip_suffix("COMMIT;\n")
            .ok_or("upgrade terminator")?;
    for mode in ["ready", "runtime", "unknown"] {
        if mode == "ready" {
            db.batch_execute("UPDATE signal_control.store SET ready=true")
                .await?;
        }
        let data = witness(db).await?;
        db.batch_execute("SAVEPOINT upgrade_case").await?;
        if mode == "runtime" {
            db.batch_execute("SET ROLE signal_runtime").await?;
        } else {
            db.batch_execute("SET ROLE signal_control_owner").await?;
        }
        if mode == "unknown" {
            db.batch_execute(&legacy_routine.replacen(
                "BEGIN\n",
                "BEGIN\n -- unknown fixture variant\n",
                1,
            ))
            .await?;
        }
        let error = db
            .batch_execute(upgrade)
            .await
            .err()
            .ok_or("unsupported upgrade accepted")?;
        let error = error.as_db_error().ok_or("non-db upgrade refusal")?;
        if mode == "runtime" {
            assert_eq!(error.code().code(), "42501");
        } else {
            assert_eq!(error.message(), "SIGNAL_FENCED", "{mode}");
        }
        db.batch_execute(
            "ROLLBACK TO SAVEPOINT upgrade_case; RELEASE SAVEPOINT upgrade_case; RESET ROLE",
        )
        .await?;
        assert_eq!(data, witness(db).await?, "{mode}");
        assert_eq!(old, procedure(db).await?, "{mode}");
        if mode == "ready" {
            db.batch_execute("UPDATE signal_control.store SET ready=false")
                .await?;
        }
    }
    let stopped = witness(db).await?;
    db.batch_execute("SET ROLE signal_control_owner").await?;
    db.batch_execute(upgrade).await?;
    db.batch_execute("RESET ROLE").await?;
    assert_eq!(stopped, witness(db).await?);
    assert_eq!(before, procedure(db).await?);
    db.batch_execute("SAVEPOINT upgrade_case; SET ROLE signal_control_owner")
        .await?;
    let error = db
        .batch_execute(upgrade)
        .await
        .err()
        .ok_or("repeated upgrade accepted")?;
    assert_eq!(
        error
            .as_db_error()
            .ok_or("non-db repeated upgrade")?
            .message(),
        "SIGNAL_FENCED"
    );
    db.batch_execute("ROLLBACK TO SAVEPOINT upgrade_case; RELEASE SAVEPOINT upgrade_case; RESET ROLE; UPDATE signal_control.store SET ready=true").await?;
    assert_eq!(original, witness(db).await?);
    assert_eq!(before, procedure(db).await?);
    println!(
        "phase: stopped-multi-state-exact-upgrade-ready-role-unknown-repeat-refusal-preserves-data-and-ACL-qualified"
    );
    Ok(())
}
