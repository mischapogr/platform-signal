use signal_control::{
    ControlClient, ControlError, FindingInput, LeaseToken, NotificationAction as Action,
    NotificationInput, NotificationOutcome as Outcome, NotificationState as State,
    PublicationInput, WorkInput,
};
use signal_storage::object_manifest::{QueryFile, QueryManifest, QueryObjectRef, data_key};
use tokio_postgres::Client;
use uuid::Uuid;
type Error = Box<dyn std::error::Error>;
fn command(work_id: Uuid, attempt_id: Uuid, action: Action) -> NotificationInput {
    NotificationInput {
        schema_version: 1,
        work_id,
        attempt_id,
        action,
    }
}
fn finish(work: Uuid, attempt: Uuid, outcome: Outcome) -> NotificationInput {
    command(
        work,
        attempt,
        Action::Finish {
            outcome,
            evidence: b"synthetic-outcome-evidence".to_vec(),
        },
    )
}
fn interrupt(work: Uuid, attempt: Uuid) -> NotificationInput {
    command(
        work,
        attempt,
        Action::Interrupt {
            evidence: b"explicit-interrupted-intent".to_vec(),
        },
    )
}
async fn witness(db: &Client) -> Result<serde_json::Value, Error> {
    Ok(db.query_one("SELECT jsonb_build_object('store',(SELECT to_jsonb(s) FROM signal_control.store s),'outbox',(SELECT jsonb_agg(to_jsonb(w) ORDER BY id) FROM signal_control.outbox w),'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM signal_control.notification_attempts a))",&[]).await?.get(0))
}
pub async fn qualify(
    db: &Client,
    runtime: &ControlClient,
    original: &LeaseToken,
) -> Result<(), Error> {
    eprintln!("phase: notification-immutable-intent-history");
    let part = Uuid::from_u128(0x40);
    db.execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES($1,'synthetic-notifications',$2,'pipeline')",&[&part,&original.scope.stream]).await?;
    db.execute("INSERT INTO signal_control.principals(role_name,tenant,stream,partition_id) VALUES('signal_runtime','synthetic-notifications',$1,$2)",&[&original.scope.stream,&part]).await?;
    db.execute("INSERT INTO signal_control.object_scopes(partition_id,backend_id,key_prefix) VALUES($1,$2,$3)",&[&part,&Uuid::from_u128(0x20),&format!("query/{}/",original.scope.stream)]).await?;
    let mut scope = original.scope.clone();
    scope.partition_id = part;
    scope.tenant = "synthetic-notifications".into();
    let mut token = runtime
        .acquire(
            scope.clone(),
            Uuid::from_u128(0x41),
            60000,
            super::context()?,
        )
        .await?;
    let plan = b"exact-original-synthetic-plan-with-stable-private-delivery-key".to_vec();
    let works: Vec<Uuid> = (0..9).map(|_| Uuid::new_v4()).collect();
    let findings: Vec<_> = works
        .iter()
        .map(|_| -> Result<FindingInput, serde_json::Error> {
            let id=Uuid::new_v4();
            Ok(FindingInput {id,bytes:serde_json::to_vec(&serde_json::json!({"schema_version":1,"id":id,"rule_id":"synthetic-control","created_at":"2026-10-10T00:00:00Z","severity":"high","title":"synthetic-notification","event_ids":[Uuid::from_u128(900)],"attributes":{}}))?})
        })
        .collect::<Result<_,_>>()?;
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: scope.stream,
        normalizer_revision: "synthetic-v1".into(),
        first_sequence: 1,
        last_sequence: 1,
        events: 1,
        previous: None,
        files: vec![QueryFile {
            date: "2026-10-10".into(),
            hour: 0,
            object: QueryObjectRef {
                key: data_key(scope.stream, "2026-10-10", 0, [0x44; 32]),
                version: Some("notification-synthetic-v1".into()),
                etag: None,
                bytes: 128,
                sha256: [0x44; 32],
            },
            rows: 1,
            decoded_bytes: 256,
        }],
    };
    runtime
        .publish(
            token.clone(),
            PublicationInput {
                schema_version: 1,
                id: Uuid::new_v4(),
                previous: None,
                first_sequence: 1,
                last_sequence: 1,
                manifest: serde_json::to_vec(&manifest)?,
                rule_revision: [1; 32],
                normalizer_revision: "synthetic-v1".into(),
                states: vec![],
                work: works
                    .iter()
                    .zip(&findings)
                    .map(|(id, f)| WorkInput {
                        id: *id,
                        finding_id: f.id,
                        bytes: plan.clone(),
                    })
                    .collect(),
                findings,
                receipts: vec![],
            },
            super::context()?,
        )
        .await?;
    eprintln!("phase: notification-plans-published");
    let baseline = db
        .query_one("SELECT used_rows,used_bytes FROM signal_control.store", &[])
        .await?;
    let attempt = Uuid::new_v4();
    let claim = command(works[0], attempt, Action::Claim {});
    let first = runtime
        .notification(token.clone(), claim.clone(), super::context()?)
        .await?;
    assert_eq!(first.plan, plan);
    assert_eq!(first.work_id, works[0]);
    assert_eq!(first.claim_authority, token);
    assert_eq!(first.ordinal, 1);
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .notification(token.clone(), claim.clone(), super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    let resolved = runtime
        .notification(
            token.clone(),
            command(works[0], attempt, Action::Resolve {}),
            super::context()?,
        )
        .await?;
    assert_eq!(resolved.outcome, State::Intent);
    assert_eq!(witness(db).await?, before);
    // Different operation/attempt ID cannot claim while a previous intent is live.
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                command(works[0], Uuid::new_v4(), Action::Claim {}),
                super::context()?
            )
            .await,
        Err(ControlError::Conflict)
    ));
    let complete = finish(works[0], attempt, Outcome::Delivered);
    assert_eq!(
        runtime
            .notification(token.clone(), complete.clone(), super::context()?)
            .await?
            .outcome,
        State::Delivered
    );
    let before = witness(db).await?;
    runtime
        .notification(token.clone(), complete.clone(), super::context()?)
        .await?;
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                finish(works[0], attempt, Outcome::Permanent),
                super::context()?
            )
            .await,
        Err(ControlError::Conflict)
    ));
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                command(works[0], Uuid::new_v4(), Action::Claim {}),
                super::context()?
            )
            .await,
        Err(ControlError::Conflict)
    ));
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                command(works[1], attempt, Action::Claim {}),
                super::context()?
            )
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    // Current claim authority is never replaced in historical rows after takeover.
    let old_token = token.clone();
    let old_attempt = Uuid::new_v4();
    runtime
        .notification(
            token.clone(),
            command(works[1], old_attempt, Action::Claim {}),
            super::context()?,
        )
        .await?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",&[&part]).await?;
    token = runtime
        .acquire(
            scope.clone(),
            Uuid::from_u128(0x42),
            60000,
            super::context()?,
        )
        .await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .notification(
                old_token.clone(),
                finish(works[1], old_attempt, Outcome::Delivered),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                finish(works[1], old_attempt, Outcome::Delivered),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before);
    let recovered = runtime
        .notification(
            token.clone(),
            interrupt(works[1], old_attempt),
            super::context()?,
        )
        .await?;
    assert_eq!(recovered.outcome, State::Uncertain);
    assert_eq!(recovered.claim_authority, old_token);
    let next_attempt = Uuid::new_v4();
    let retried = runtime
        .notification(
            token.clone(),
            command(works[1], next_attempt, Action::Claim {}),
            super::context()?,
        )
        .await?;
    assert_eq!(retried.plan, plan);
    assert_eq!(retried.work_id, works[1]);
    assert_eq!(retried.ordinal, 2);
    runtime
        .notification(
            token.clone(),
            finish(works[1], next_attempt, Outcome::Permanent),
            super::context()?,
        )
        .await?;
    eprintln!("matrix-case:old_attempt_finishes_after_takeover passed");
    // Only this owned loopback receiver accepts opaque synthetic bytes. It
    // records the first acceptance durably, then deliberately closes without
    // replying. A fresh control attempt must reuse the exact delivery key/plan.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let receipt = std::path::PathBuf::from(std::env::var("SIGNAL_CONTROL_FIXTURE")?)
        .parent()
        .ok_or("fixture has no owned parent")?
        .join("synthetic-receiver-acceptance.bin");
    let mut wire = works[8].as_bytes().to_vec();
    wire.extend_from_slice(&plan);
    assert!(wire.len() <= 4096);
    let first_attempt = Uuid::new_v4();
    let second_attempt = Uuid::new_v4();
    let received = async {
        for ordinal in 0..2 {
            let (mut socket, peer) = listener.accept().await?;
            assert!(peer.ip().is_loopback());
            let mut body = vec![0; wire.len()];
            socket.read_exact(&mut body).await?;
            let mut extra = [0; 1];
            assert_eq!(socket.read(&mut extra).await?, 0);
            assert_eq!(body, wire);
            if ordinal == 0 {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&receipt)?;
                file.write_all(&body)?;
                file.sync_all()?;
                std::fs::File::open(receipt.parent().ok_or("receipt parent missing")?)?
                    .sync_all()?;
                // No acceptance reply: the sender observes EOF after acceptance.
            } else {
                assert_eq!(std::fs::read(&receipt)?, body);
                socket.write_all(b"A").await?;
            }
            socket.shutdown().await?;
        }
        Ok::<(), Error>(())
    };
    let sent = async {
        for (ordinal, attempt_id) in [first_attempt, second_attempt].into_iter().enumerate() {
            let claim = runtime
                .notification(
                    token.clone(),
                    command(works[8], attempt_id, Action::Claim {}),
                    super::context()?,
                )
                .await?;
            assert_eq!(claim.work_id, works[8]);
            assert_eq!(claim.plan, plan);
            assert_eq!(claim.ordinal, ordinal as u32 + 1);
            let mut socket = tokio::net::TcpStream::connect(address).await?;
            let mut payload = claim.work_id.as_bytes().to_vec();
            payload.extend_from_slice(&claim.plan);
            socket.write_all(&payload).await?;
            socket.shutdown().await?;
            let mut reply = [0; 1];
            let response = socket.read_exact(&mut reply).await;
            let outcome = if ordinal == 0 {
                assert_eq!(
                    response
                        .err()
                        .ok_or("acceptance reply unexpectedly received")?
                        .kind(),
                    std::io::ErrorKind::UnexpectedEof
                );
                assert_eq!(std::fs::read(&receipt)?, wire);
                Outcome::Uncertain
            } else {
                response?;
                assert_eq!(&reply, b"A");
                Outcome::Delivered
            };
            let result = runtime
                .notification(
                    token.clone(),
                    finish(works[8], attempt_id, outcome),
                    super::context()?,
                )
                .await?;
            assert_eq!(
                result.outcome,
                if ordinal == 0 {
                    State::Uncertain
                } else {
                    State::Delivered
                }
            );
        }
        Ok::<(), Error>(())
    };
    let (received, sent) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(received, sent)
    })
    .await?;
    received?;
    sent?;
    let historical = runtime
        .notification(
            token.clone(),
            command(works[8], first_attempt, Action::Resolve {}),
            super::context()?,
        )
        .await?;
    assert_eq!(historical.outcome, State::Uncertain);
    assert_eq!(historical.work_status, State::Delivered);
    assert_eq!(historical.plan, plan);
    assert_eq!(historical.attempt_id, first_attempt);
    assert_eq!(historical.claim_authority, token);
    assert_eq!(historical.ordinal, 1);
    assert_eq!(std::fs::read(&receipt)?, wire);
    eprintln!("matrix-case:notification_accepted_reply_lost passed");
    // Generation barrier independently fences a token even if its epoch/owner match.
    let gen_attempt = Uuid::new_v4();
    runtime
        .notification(
            token.clone(),
            command(works[2], gen_attempt, Action::Claim {}),
            super::context()?,
        )
        .await?;
    db.execute(
        "UPDATE signal_control.store SET generation=$1",
        &[&Uuid::from_u128(0x45)],
    )
    .await?;
    let mut fresh = token.clone();
    fresh.scope.generation = Uuid::from_u128(0x45);
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                finish(works[2], gen_attempt, Outcome::Delivered),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert!(matches!(
        runtime
            .notification(
                fresh.clone(),
                finish(works[2], gen_attempt, Outcome::Delivered),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before);
    assert_eq!(
        runtime
            .notification(fresh, interrupt(works[2], gen_attempt), super::context()?)
            .await?
            .outcome,
        State::Uncertain
    );
    // Fixture-only restore of store generation leaves original foundation token valid.
    db.execute(
        "UPDATE signal_control.store SET generation=$1",
        &[&original.scope.generation],
    )
    .await?;
    // A real deferred COMMIT delay yields Uncertain, but one intent committed.
    db.batch_execute("CREATE FUNCTION public.synthetic_notification_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_notification_commit_delay AFTER INSERT ON signal_control.notification_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_notification_commit_delay()").await?;
    let lost = Uuid::new_v4();
    let input = command(works[3], lost, Action::Claim {});
    let c = super::context()?;
    let (result, observed) = tokio::join!(
        runtime.notification(token.clone(), input.clone(), c.clone()),
        super::cancel_delayed_commit(db, &c)
    );
    observed?;
    assert!(matches!(result, Err(ControlError::Uncertain)));
    super::idle(runtime).await?;
    db.batch_execute("DROP TRIGGER synthetic_notification_commit_delay ON signal_control.notification_attempts; DROP FUNCTION public.synthetic_notification_commit_delay()").await?;
    let before = witness(db).await?;
    assert_eq!(
        runtime
            .notification(
                token.clone(),
                command(works[3], lost, Action::Resolve {}),
                super::context()?
            )
            .await?
            .outcome,
        State::Intent
    );
    assert!(matches!(
        runtime
            .notification(token.clone(), input, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    runtime
        .notification(token.clone(), interrupt(works[3], lost), super::context()?)
        .await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                finish(works[3], lost, Outcome::Delivered),
                super::context()?
            )
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    // Lost completion reply is resolved as evidence; it never creates another send.
    let delivered_attempt = Uuid::new_v4();
    runtime
        .notification(
            token.clone(),
            command(works[3], delivered_attempt, Action::Claim {}),
            super::context()?,
        )
        .await?;
    db.batch_execute("CREATE FUNCTION public.synthetic_notification_finish_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_notification_finish_delay AFTER UPDATE ON signal_control.notification_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_notification_finish_delay()").await?;
    let delivered = finish(works[3], delivered_attempt, Outcome::Delivered);
    let c = super::context()?;
    let (result, observed) = tokio::join!(
        runtime.notification(token.clone(), delivered.clone(), c.clone()),
        super::cancel_delayed_commit(db, &c)
    );
    observed?;
    assert!(matches!(result, Err(ControlError::Uncertain)));
    super::idle(runtime).await?;
    db.batch_execute("DROP TRIGGER synthetic_notification_finish_delay ON signal_control.notification_attempts; DROP FUNCTION public.synthetic_notification_finish_delay()").await?;
    let before = witness(db).await?;
    assert_eq!(
        runtime
            .notification(
                token.clone(),
                command(works[3], delivered_attempt, Action::Resolve {}),
                super::context()?
            )
            .await?
            .outcome,
        State::Delivered
    );
    runtime
        .notification(token.clone(), delivered, super::context()?)
        .await?;
    assert_eq!(witness(db).await?, before);
    // A valid current fence for another partition cannot resolve this obligation.
    assert!(matches!(
        runtime
            .notification(
                original.clone(),
                command(works[3], delivered_attempt, Action::Resolve {}),
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before);
    // Two concurrent claims have exactly one winner; loser grants no attempt.
    let (a, b) = tokio::join!(
        runtime.notification(
            token.clone(),
            command(works[4], Uuid::new_v4(), Action::Claim {}),
            super::context()?
        ),
        runtime.notification(
            token.clone(),
            command(works[4], Uuid::new_v4(), Action::Claim {}),
            super::context()?
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let winner = match (a, b) {
        (Ok(r), Err(ControlError::Conflict)) | (Err(ControlError::Conflict), Ok(r)) => r,
        _ => return Err("claim race lacked a typed loser".into()),
    };
    runtime
        .notification(
            token.clone(),
            finish(works[4], winner.attempt_id, Outcome::Retryable),
            super::context()?,
        )
        .await?;
    // Ten immutable attempts are retained; further claims never bypass exhaustion.
    for ordinal in 1..=10 {
        let id = Uuid::new_v4();
        let r = runtime
            .notification(
                token.clone(),
                command(works[5], id, Action::Claim {}),
                super::context()?,
            )
            .await?;
        assert_eq!(r.ordinal, ordinal);
        let r = runtime
            .notification(
                token.clone(),
                finish(works[5], id, Outcome::Uncertain),
                super::context()?,
            )
            .await?;
        assert_eq!(
            r.work_status,
            if ordinal == 10 {
                State::Exhausted
            } else {
                State::Uncertain
            }
        );
    }
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                command(works[5], Uuid::new_v4(), Action::Claim {}),
                super::context()?
            )
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    // Both finite row and byte quotas roll back counters and all child writes.
    let budgets = db
        .query_one("SELECT max_rows,max_bytes FROM signal_control.store", &[])
        .await?;
    for column in ["max_rows=used_rows", "max_bytes=used_bytes"] {
        db.batch_execute(&format!("UPDATE signal_control.store SET {column}"))
            .await?;
        let before = witness(db).await?;
        assert!(matches!(
            runtime
                .notification(
                    token.clone(),
                    command(works[6], Uuid::new_v4(), Action::Claim {}),
                    super::context()?
                )
                .await,
            Err(ControlError::Full)
        ));
        assert_eq!(witness(db).await?, before);
        db.execute(
            "UPDATE signal_control.store SET max_rows=$1,max_bytes=$2",
            &[&budgets.get::<_, i64>(0), &budgets.get::<_, i64>(1)],
        )
        .await?;
    }
    let quota_id = Uuid::new_v4();
    runtime
        .notification(
            token.clone(),
            command(works[6], quota_id, Action::Claim {}),
            super::context()?,
        )
        .await?;
    db.batch_execute("UPDATE signal_control.store SET max_bytes=used_bytes")
        .await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                finish(works[6], quota_id, Outcome::Delivered),
                super::context()?
            )
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(witness(db).await?, before);
    db.execute(
        "UPDATE signal_control.store SET max_bytes=$1",
        &[&budgets.get::<_, i64>(1)],
    )
    .await?;
    // Final DB-clock fence catches expiry after child insertion and completion.
    db.batch_execute("CREATE FUNCTION public.synthetic_notification_expiry() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN UPDATE signal_control.partitions SET lease_until=clock_timestamp()+interval '20 milliseconds' WHERE id=NEW.partition_id; PERFORM pg_sleep(0.04); RETURN NEW; END $$; CREATE TRIGGER synthetic_notification_expiry BEFORE INSERT OR UPDATE ON signal_control.notification_attempts FOR EACH ROW EXECUTE FUNCTION public.synthetic_notification_expiry()").await?;
    for input in [
        command(works[7], Uuid::new_v4(), Action::Claim {}),
        finish(works[6], quota_id, Outcome::Delivered),
        interrupt(works[6], quota_id),
    ] {
        let before = witness(db).await?;
        assert!(matches!(
            runtime
                .notification(token.clone(), input, super::context()?)
                .await,
            Err(ControlError::Fenced)
        ));
        assert_eq!(witness(db).await?, before);
    }
    db.batch_execute("DROP TRIGGER synthetic_notification_expiry ON signal_control.notification_attempts; DROP FUNCTION public.synthetic_notification_expiry()").await?;
    // Corruption of history and original plan cannot be laundered by resolution.
    db.execute(
        "UPDATE signal_control.notification_attempts SET owner=$1 WHERE id=$2",
        &[&Uuid::from_u128(0x99), &quota_id],
    )
    .await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                command(works[6], quota_id, Action::Resolve {}),
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(witness(db).await?, before);
    db.execute(
        "UPDATE signal_control.notification_attempts SET owner=$1 WHERE id=$2",
        &[&token.owner, &quota_id],
    )
    .await?;
    db.execute(
        "UPDATE signal_control.outbox SET plan='corrupt'::bytea WHERE id=$1",
        &[&works[6]],
    )
    .await?;
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                command(works[6], quota_id, Action::Resolve {}),
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    db.execute(
        "UPDATE signal_control.outbox SET plan=$1 WHERE id=$2",
        &[&plan, &works[6]],
    )
    .await?;
    db.execute(
        "UPDATE signal_control.outbox SET status='delivered' WHERE id=$1",
        &[&works[6]],
    )
    .await?;
    let before = witness(db).await?;
    assert!(matches!(
        runtime
            .notification(
                token.clone(),
                command(works[6], quota_id, Action::Resolve {}),
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(witness(db).await?, before);
    db.execute(
        "UPDATE signal_control.outbox SET status='intent' WHERE id=$1",
        &[&works[6]],
    )
    .await?;
    assert!(runtime.metrics().notification_uncertain_results >= 2);
    // Canonical audit seals do not depend on the caller's bytea_output setting.
    db.batch_execute("SET SESSION AUTHORIZATION signal_runtime; SET bytea_output='escape'")
        .await?;
    let raw = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"operation":"resolve","work_id":works[6],"attempt_id":quota_id}),
    )?;
    let (schema, routines) = signal_control::schema_identity();
    let reply = db
        .query_one(
            "SELECT signal_control.notification($1,$2,$3,$4)",
            &[
                &serde_json::to_value(&token)?,
                &raw,
                &schema.as_slice(),
                &routines.as_slice(),
            ],
        )
        .await;
    db.batch_execute("RESET bytea_output; RESET SESSION AUTHORIZATION")
        .await?;
    assert!(reply.is_ok());
    // Read-only resolution remains available for an earlier completed attempt.
    let r = runtime
        .notification(
            token.clone(),
            command(works[1], old_attempt, Action::Resolve {}),
            super::context()?,
        )
        .await?;
    assert_eq!(r.claim_authority, old_token);
    assert_eq!(r.outcome, State::Uncertain);
    assert_eq!(r.work_status, State::Permanent);
    let privileges=db.query_one("SELECT has_table_privilege('signal_runtime','signal_control.notification_attempts','UPDATE'),has_function_privilege('signal_runtime','signal_control.notification_seal(signal_control.notification_attempts)','EXECUTE')",&[]).await?;
    assert!(!privileges.get::<_, bool>(0));
    assert!(!privileges.get::<_, bool>(1));
    let (schema, routines) = signal_control::schema_identity();
    let token_json = serde_json::to_value(&token)?;
    for (role, raw, expected) in [
        (
            "signal_runtime",
            serde_json::to_vec(
                &serde_json::json!({"schema_version":1,"operation":"claim","work_id":works[7],"attempt_id":Uuid::new_v4(),"force":true}),
            )?,
            "SIGNAL_INVALID",
        ),
        (
            "signal_denied",
            serde_json::to_vec(
                &serde_json::json!({"schema_version":1,"operation":"claim","work_id":works[7],"attempt_id":Uuid::new_v4()}),
            )?,
            "SIGNAL_FENCED",
        ),
    ] {
        let before = witness(db).await?;
        db.batch_execute(&format!("SET SESSION AUTHORIZATION {role}"))
            .await?;
        let result = db
            .query_one(
                "SELECT signal_control.notification($1,$2,$3,$4)",
                &[&token_json, &raw, &schema.as_slice(), &routines.as_slice()],
            )
            .await;
        db.batch_execute("RESET SESSION AUTHORIZATION").await?;
        assert_eq!(
            result
                .err()
                .ok_or("denied notification accepted")?
                .as_db_error()
                .map(|e| e.message()),
            Some(expected)
        );
        assert_eq!(witness(db).await?, before);
    }
    // Exact incremental charges include every retained history row and completion.
    let counts=db.query_one("SELECT (SELECT count(*) FROM signal_control.notification_attempts),(SELECT sum(512+octet_length(claim_request)+coalesce(octet_length(completion_request),0)) FROM signal_control.notification_attempts),used_rows,used_bytes FROM signal_control.store",&[]).await?;
    assert_eq!(
        counts.get::<_, i64>(2) - baseline.get::<_, i64>(0),
        counts.get::<_, i64>(0)
    );
    assert_eq!(
        counts.get::<_, i64>(3) - baseline.get::<_, i64>(1),
        counts.get::<_, i64>(1)
    );
    eprintln!("phase: notification-fencing-qualification-complete");
    Ok(())
}
