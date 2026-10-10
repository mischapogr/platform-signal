use sha2::{Digest, Sha256};
use signal_control::{
    ControlClient, ControlError, FindingInput, LeaseToken, PublicationInput, ReceiptInput,
    ReceiptProgress, RevisionedState, WorkInput,
};
use signal_storage::object_manifest::{
    PreviousManifest, QueryFile, QueryManifest, QueryObjectRef, data_key, manifest_key,
};
use tokio_postgres::Client;
use uuid::Uuid;

type Error = Box<dyn std::error::Error>;
fn finding(id: Uuid, title: &str) -> Result<FindingInput, Error> {
    Ok(FindingInput {
        id,
        bytes: serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"id":id,"rule_id":"synthetic-control","created_at":"2026-10-10T00:00:00Z","severity":"high","title":title,"event_ids":[Uuid::from_u128(900)],"attributes":{}}),
        )?,
    })
}
pub(super) fn request(
    token: &LeaseToken,
    id: u128,
    sequence: u64,
    prior: Option<&PublicationInput>,
) -> Result<PublicationInput, Error> {
    let previous = prior.map(|prior| PreviousManifest {
        object: QueryObjectRef {
            key: manifest_key(token.scope.stream, prior.first_sequence),
            version: Some("synthetic-v1".into()),
            etag: None,
            bytes: prior.manifest.len() as u64,
            sha256: Sha256::digest(&prior.manifest).into(),
        },
        first_sequence: prior.first_sequence,
        last_sequence: prior.last_sequence,
    });
    let manifest = QueryManifest {
        schema_version: 1,
        storage_schema_version: 1,
        stream_id: token.scope.stream,
        normalizer_revision: "synthetic-v1".into(),
        first_sequence: sequence,
        last_sequence: sequence,
        events: 1,
        previous,
        files: vec![QueryFile {
            date: "2026-10-10".into(),
            hour: 0,
            object: QueryObjectRef {
                key: data_key(token.scope.stream, "2026-10-10", 0, [1; 32]),
                version: Some("synthetic-v1".into()),
                etag: None,
                bytes: 128,
                sha256: [1; 32],
            },
            rows: 1,
            decoded_bytes: 256,
        }],
    };
    Ok(PublicationInput {
        schema_version: 1,
        id: Uuid::from_u128(id),
        previous: prior.map(|p| p.id),
        first_sequence: sequence,
        last_sequence: sequence,
        manifest: serde_json::to_vec(&manifest)?,
        rule_revision: [1; 32],
        normalizer_revision: "synthetic-v1".into(),
        states: vec![],
        findings: vec![],
        work: vec![],
        receipts: vec![],
    })
}
pub(super) async fn witness(db: &Client) -> Result<serde_json::Value, Error> {
    // Complete bounded fixture tables, including counters, prefixes and immutable bytes.
    let row=db.query_one("SELECT jsonb_build_object('store',(SELECT to_jsonb(s) FROM signal_control.store s),'partitions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM signal_control.partitions p),'commits',(SELECT jsonb_agg(to_jsonb(c) ORDER BY partition_id,id) FROM signal_control.commits c),'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY partition_id,id) FROM signal_control.receipts r),'state',(SELECT jsonb_agg(to_jsonb(s) ORDER BY partition_id,key) FROM signal_control.state s),'findings',(SELECT jsonb_agg(to_jsonb(f) ORDER BY position) FROM signal_control.findings f),'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY partition_id,id) FROM signal_control.outbox o),'snapshots',(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_control.snapshots t),'tombstones',(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_control.tombstones t),'principals',(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_control.principals t),'object_backends',(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_control.object_backends t),'object_scopes',(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_control.object_scopes t),'object_pins',(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_control.object_pins t),'notification_attempts',(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_control.notification_attempts t),'migrations',(SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM signal_control.migrations t))",&[]).await?;
    Ok(row.try_get(0)?)
}
pub async fn qualify(
    db: &Client,
    runtime: &ControlClient,
    token: &LeaseToken,
) -> Result<(), Error> {
    eprintln!("phase: zero-prepared-receipt-and-atomic-publication");
    let zero = ReceiptInput {
        schema_version: 1,
        id: Uuid::from_u128(59),
        prepared_count: 0,
        source_record_count: 1,
        reference: b"explicit-synthetic-quarantine-original-and-disposition-pins".to_vec(),
    };
    let z = runtime
        .record_receipt(token.clone(), zero.clone(), super::context()?)
        .await?;
    assert_eq!(z.prepared_count, 0);
    assert_eq!(z.verified_prefix, 0);
    let check=db.query_one("SELECT checkpoint,feed_position,(SELECT count(*) FROM signal_control.commits),(SELECT count(*) FROM signal_control.findings),(SELECT count(*) FROM signal_control.outbox) FROM signal_control.partitions WHERE id=$1",&[&token.scope.partition_id]).await?;
    for i in 0..5 {
        assert_eq!(check.get::<_, i64>(i), 0);
    }
    assert_eq!(
        runtime
            .record_receipt(token.clone(), zero, super::context()?)
            .await?,
        z
    );
    let receipt = ReceiptInput {
        schema_version: 1,
        id: Uuid::from_u128(60),
        prepared_count: 1,
        source_record_count: 1,
        reference: b"synthetic-retained-original-normalizer-disposition-and-custody-pins".to_vec(),
    };
    runtime
        .record_receipt(token.clone(), receipt.clone(), super::context()?)
        .await?;
    let before = witness(db).await?;
    let mut altered = receipt.clone();
    altered.reference.push(1);
    assert!(matches!(
        runtime
            .record_receipt(token.clone(), altered, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    // Exact replay refuses a corrupt retained reference, even when request bytes match.
    db.execute("UPDATE signal_control.receipts SET reference=reference||decode('20','hex') WHERE partition_id=$1 AND id=$2", &[&token.scope.partition_id, &receipt.id]).await?;
    assert!(matches!(
        runtime
            .record_receipt(token.clone(), receipt.clone(), super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    db.execute(
        "UPDATE signal_control.receipts SET reference=$3 WHERE partition_id=$1 AND id=$2",
        &[&token.scope.partition_id, &receipt.id, &receipt.reference],
    )
    .await?;
    assert_eq!(witness(db).await?, before);
    // Bypass the SDK as the restricted SQL principal: malformed records fail closed.
    let (schema, routines) = signal_control::schema_identity();
    let token_json = serde_json::to_value(token)?;
    for malformed in [
        serde_json::json!([]),
        serde_json::json!({"schema_version":1,"id":Uuid::from_u128(400),"prepared_count":0,"source_record_count":null,"reference":"01"}),
        serde_json::json!({"schema_version":1,"id":Uuid::from_u128(400),"prepared_count":"0","source_record_count":1,"reference":"01"}),
        serde_json::json!({"schema_version":1,"id":Uuid::from_u128(400),"prepared_count":0,"source_record_count":1,"reference":"01","extra":true}),
    ] {
        let before = witness(db).await?;
        let raw = serde_json::to_vec(&malformed)?;
        db.batch_execute("SET SESSION AUTHORIZATION signal_runtime")
            .await?;
        let result = db
            .query_one(
                "SELECT signal_control.record_receipt($1,$2,$3,$4)",
                &[&token_json, &raw, &schema.as_slice(), &routines.as_slice()],
            )
            .await;
        db.batch_execute("RESET SESSION AUTHORIZATION").await?;
        let error = result
            .err()
            .ok_or("restricted malformed receipt must fail")?;
        assert_eq!(
            error.as_db_error().map(|error| error.message()),
            Some("SIGNAL_INVALID")
        );
        assert_eq!(witness(db).await?, before);
    }
    let f = finding(Uuid::from_u128(50), "original")?;
    let work = WorkInput {
        id: Uuid::from_u128(51),
        finding_id: f.id,
        bytes: b"immutable-synthetic-notification-plan".to_vec(),
    };
    let mut first = request(token, 100, 1, None)?;
    first.states.push(RevisionedState {
        key: "synthetic-state".into(),
        revision: [1; 32],
        bytes: b"one".to_vec(),
    });
    first.findings.push(f.clone());
    first.work.push(work.clone());
    first.receipts.push(ReceiptProgress {
        id: receipt.id,
        expected_prefix: 0,
        verified_prefix: 1,
    });
    let result = runtime
        .publish(token.clone(), first.clone(), super::context()?)
        .await?;
    let cursor = signal_protocol::findings_feed::FindingsCursor::initial(token.scope.store_id)?
        .advance(&f.bytes)?;
    assert_eq!(result.cursor, cursor.encode());
    let row=db.query_one("SELECT checkpoint,head,(SELECT verified_prefix FROM signal_control.receipts WHERE id=$2),(SELECT value FROM signal_control.state WHERE key='synthetic-state'),(SELECT count(*) FROM signal_control.outbox),(SELECT used_rows FROM signal_control.store) FROM signal_control.partitions WHERE id=$1",&[&token.scope.partition_id,&receipt.id]).await?;
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, Uuid>(1), first.id);
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(row.get::<_, Vec<u8>>(3), b"one");
    assert_eq!(row.get::<_, i64>(4), 1);
    assert_eq!(row.get::<_, i64>(5), 6);
    eprintln!("phase: exact-replay-and-immutable-conflicts");
    let before = witness(db).await?;
    assert_eq!(
        runtime
            .publish(token.clone(), first.clone(), super::context()?)
            .await?,
        result
    );
    assert_eq!(
        runtime
            .resolve_publication(token.clone(), first.clone(), super::context()?)
            .await?,
        result
    );
    assert_eq!(witness(db).await?, before);
    let mut conflict = first.clone();
    conflict.work[0].bytes.push(2);
    assert!(matches!(
        runtime
            .publish(token.clone(), conflict, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    let mut second = request(token, 101, 2, Some(&first))?;
    second.states.push(RevisionedState {
        key: "synthetic-state".into(),
        revision: [1; 32],
        bytes: b"two-is-longer".to_vec(),
    });
    second.findings.push(f.clone());
    second.work.push(work.clone());
    let two = runtime
        .publish(token.clone(), second.clone(), super::context()?)
        .await?;
    assert_eq!(two.cursor, result.cursor);
    assert_eq!(
        runtime
            .resolve_publication(token.clone(), first.clone(), super::context()?)
            .await?,
        result
    );
    let before = witness(db).await?;
    let mut rejected = request(token, 102, 3, Some(&second))?;
    rejected.findings.push(finding(f.id, "conflicting")?);
    assert!(matches!(
        runtime
            .publish(token.clone(), rejected, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    let mut bad_revision = request(token, 103, 3, Some(&second))?;
    bad_revision.rule_revision = [2; 32];
    bad_revision.states.push(RevisionedState {
        key: "synthetic-state".into(),
        revision: [2; 32],
        bytes: b"changed-rule".to_vec(),
    });
    assert!(matches!(
        runtime
            .publish(token.clone(), bad_revision, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(witness(db).await?, before);
    eprintln!("phase: whole-transaction-row-and-byte-quota");
    let mut candidate = request(token, 104, 3, Some(&second))?;
    candidate
        .findings
        .push(finding(Uuid::from_u128(55), "new")?);
    candidate.work.push(WorkInput {
        id: Uuid::from_u128(56),
        finding_id: Uuid::from_u128(55),
        bytes: b"another-work-plan".to_vec(),
    });
    for sql in [
        "UPDATE signal_control.store SET max_rows=used_rows",
        "UPDATE signal_control.store SET max_bytes=used_bytes+1",
    ] {
        db.batch_execute(sql).await?;
        let before = witness(db).await?;
        assert!(matches!(
            runtime
                .publish(token.clone(), candidate.clone(), super::context()?)
                .await,
            Err(ControlError::Full)
        ));
        assert_eq!(witness(db).await?, before);
        db.batch_execute("UPDATE signal_control.store SET max_rows=65536,max_bytes=67108864")
            .await?;
    }
    eprintln!("phase: concurrent-publication-and-global-deduplication");
    let mut competing = candidate.clone();
    competing.id = Uuid::from_u128(105);
    let (a, b) = tokio::join!(
        runtime.publish(token.clone(), candidate.clone(), super::context()?),
        runtime.publish(token.clone(), competing.clone(), super::context()?)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let winner = if a.is_ok() {
        assert!(matches!(b, Err(ControlError::Conflict)));
        candidate
    } else {
        assert!(matches!(a, Err(ControlError::Conflict)));
        competing
    };
    let row=db.query_one("SELECT feed_position,(SELECT count(*) FROM signal_control.findings),(SELECT count(*) FROM signal_control.outbox) FROM signal_control.store",&[]).await?;
    for i in 0..3 {
        assert_eq!(row.get::<_, i64>(i), 2);
    }
    let before = witness(db).await?;
    let missing = request(token, 999, 4, Some(&winner))?;
    assert!(matches!(
        runtime
            .resolve_publication(token.clone(), missing, super::context()?)
            .await,
        Err(ControlError::Uncertain)
    ));
    assert_eq!(witness(db).await?, before);
    let mut stale = token.clone();
    stale.epoch += 1;
    assert!(matches!(
        runtime
            .publish(
                stale,
                request(token, 106, 4, Some(&winner))?,
                super::context()?
            )
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before);
    // Independently enrolled partition: identical finding/obligation reuses global identity.
    db.batch_execute("INSERT INTO signal_control.partitions(id,tenant,stream,kind) VALUES('00000000-0000-0000-0000-000000000005','synthetic','00000000-0000-0000-0000-000000000006','pipeline'); INSERT INTO signal_control.principals(role_name,tenant,stream,partition_id) VALUES('signal_runtime','synthetic','00000000-0000-0000-0000-000000000006','00000000-0000-0000-0000-000000000005'); INSERT INTO signal_control.object_scopes(partition_id,backend_id,key_prefix) VALUES('00000000-0000-0000-0000-000000000005','00000000-0000-0000-0000-000000000020','query/00000000-0000-0000-0000-000000000006/');").await?;
    let mut other_scope = token.scope.clone();
    other_scope.partition_id = Uuid::from_u128(5);
    other_scope.stream = Uuid::from_u128(6);
    let other = runtime
        .acquire(other_scope, Uuid::from_u128(70), 15000, super::context()?)
        .await?;
    let mut other_request = request(&other, 107, 1, None)?;
    other_request.findings.push(f);
    other_request.work.push(work);
    let other_result = runtime
        .publish(other, other_request, super::context()?)
        .await?;
    assert_eq!(
        signal_protocol::findings_feed::FindingsCursor::decode(&other_result.cursor)?.position(),
        2
    );
    eprintln!("phase: delayed-commit-reply-exact-reconciliation");
    db.batch_execute("CREATE FUNCTION public.synthetic_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.checkpoint=4 THEN PERFORM pg_sleep(1); END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_commit_delay AFTER UPDATE ON signal_control.partitions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_commit_delay()").await?;
    let fourth = request(token, 108, 4, Some(&winner))?;
    let c = super::context()?;
    let (result, observed) = tokio::join!(
        runtime.publish(token.clone(), fourth.clone(), c.clone()),
        super::cancel_delayed_commit(db, &c)
    );
    observed?;
    assert!(matches!(result, Err(ControlError::Uncertain)));
    super::idle(runtime).await?;
    let committed = db
        .query_one(
            "SELECT checkpoint FROM signal_control.partitions WHERE id=$1",
            &[&token.scope.partition_id],
        )
        .await?;
    assert_eq!(committed.get::<_, i64>(0), 4);
    db.batch_execute("DROP TRIGGER synthetic_commit_delay ON signal_control.partitions; DROP FUNCTION public.synthetic_commit_delay()").await?;
    let before = witness(db).await?;
    let final_result = runtime
        .resolve_publication(token.clone(), fourth.clone(), super::context()?)
        .await?;
    assert_eq!(final_result.id, fourth.id);
    assert_eq!(witness(db).await?, before);
    db.execute("UPDATE signal_control.commits SET manifest=manifest||decode('20','hex') WHERE partition_id=$1 AND id=$2",&[&token.scope.partition_id,&fourth.id]).await?;
    assert!(matches!(
        runtime
            .resolve_publication(token.clone(), fourth.clone(), super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    db.execute(
        "UPDATE signal_control.commits SET manifest=$3 WHERE partition_id=$1 AND id=$2",
        &[&token.scope.partition_id, &fourth.id, &fourth.manifest],
    )
    .await?;
    assert_eq!(witness(db).await?, before);
    // Same-length corruption of a predecessor cannot authorize the next manifest.
    let fifth = request(token, 109, 5, Some(&fourth))?;
    db.execute("UPDATE signal_control.commits SET manifest=set_byte(manifest,0,32) WHERE partition_id=$1 AND id=$2", &[&token.scope.partition_id, &fourth.id]).await?;
    let corrupt_before = witness(db).await?;
    assert!(matches!(
        runtime
            .publish(token.clone(), fifth, super::context()?)
            .await,
        Err(ControlError::Corrupt)
    ));
    assert_eq!(witness(db).await?, corrupt_before);
    db.execute(
        "UPDATE signal_control.commits SET manifest=$3 WHERE partition_id=$1 AND id=$2",
        &[&token.scope.partition_id, &fourth.id, &fourth.manifest],
    )
    .await?;
    eprintln!("phase: lease-expiry-before-final-publication");
    // Expiry occurs after children are written but before the final eligibility check.
    db.batch_execute("CREATE FUNCTION public.synthetic_publication_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.12); RETURN NEW; END $$; CREATE TRIGGER synthetic_publication_delay BEFORE INSERT ON signal_control.commits FOR EACH ROW EXECUTE FUNCTION public.synthetic_publication_delay()").await?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()+interval '80 milliseconds' WHERE id=$1", &[&token.scope.partition_id]).await?;
    let before_expiry = witness(db).await?;
    let fifth = request(token, 109, 5, Some(&fourth))?;
    assert!(matches!(
        runtime
            .publish(token.clone(), fifth, super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(witness(db).await?, before_expiry);
    db.batch_execute("DROP TRIGGER synthetic_publication_delay ON signal_control.commits; DROP FUNCTION public.synthetic_publication_delay()").await?;
    db.execute("UPDATE signal_control.partitions SET lease_until=clock_timestamp()+interval '60 seconds' WHERE id=$1", &[&token.scope.partition_id]).await?;
    let exact=db.query_one("SELECT used_rows = ((SELECT count(*) FROM signal_control.commits)+(SELECT count(*) FROM signal_control.receipts)+(SELECT count(*) FROM signal_control.state)+(SELECT count(*) FROM signal_control.findings)+(SELECT count(*) FROM signal_control.outbox)), used_bytes = ((SELECT coalesce(sum(512+octet_length(request)+octet_length(manifest)+octet_length(normalizer_revision)+32*cardinality(object_hashes)),0) FROM signal_control.commits)+(SELECT coalesce(sum(256+octet_length(reference)+octet_length(retained_request)),0) FROM signal_control.receipts)+(SELECT coalesce(sum(192+octet_length(key)+octet_length(value)),0) FROM signal_control.state)+(SELECT coalesce(sum(256+octet_length(content)),0) FROM signal_control.findings)+(SELECT coalesce(sum(256+octet_length(plan)),0) FROM signal_control.outbox)) FROM signal_control.store",&[]).await?;
    assert!(exact.get::<_, bool>(0));
    assert!(exact.get::<_, bool>(1));
    eprintln!("matrix-case:request_id_conflicting_payload passed");
    eprintln!("matrix-case:quota_at_commit passed");
    eprintln!("matrix-case:zero_prepared_quarantined_receipt passed");
    eprintln!("phase: atomic-publication-qualification-complete");
    Ok(())
}
