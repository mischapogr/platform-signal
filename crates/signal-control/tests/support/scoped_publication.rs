//! Actual atomic scoped SQL with explicit fixture owner grants, never host auth.
use signal_control::{
    ConnectionSettings, ControlClient, ControlError, ProducerEnrollment, PublicationInput,
    ScopedPublicationInput,
};
use signal_findings::{DerivedFinding, DetectionSeverity, Finding};
use tokio_postgres::Client;
use uuid::Uuid;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SQL: &str = include_str!("../../../../schemas/shared-control/008-scoped-publication.sql");

fn event(account: &str, id: u128) -> Result<signal_event::SignalEvent> {
    Ok(serde_json::from_value(serde_json::json!({
        "schema_version":1,"id":Uuid::from_u128(id),"timestamp":"2026-10-11T00:00:00Z",
        "observed_at":"2026-10-11T00:00:00Z","source":{"type":"audit"},"severity":"info",
        "message":"synthetic","attributes":{"account":"spoof"},
        "resource":{"kind":"host","id":"fixture","account_id":account},"tags":[]
    }))?)
}
fn derived(
    producer: &ProducerEnrollment,
    sequence: u64,
    base: PublicationInput,
    account: &str,
    id: u128,
) -> Result<ScopedPublicationInput> {
    let event = event(account, id)?;
    let base_finding = Finding::for_event(
        "scoped-fixture",
        &event,
        DetectionSeverity::High,
        "Scoped fixture",
    )?;
    let sealed = DerivedFinding::from_event(base_finding, &event, true)?
        .into_scoped(producer.scope_generation)?;
    Ok(ScopedPublicationInput::from_host(
        base,
        producer,
        vec![(sequence, sealed)],
    )?)
}
pub async fn qualify(
    db: &Client,
    f: &super::Fixture,
    producer: ProducerEnrollment,
) -> Result<ProducerEnrollment> {
    db.batch_execute("SET ROLE signal_runtime").await?;
    let denied = db
        .batch_execute(SQL)
        .await
        .err()
        .ok_or("runtime scope8 migration unexpectedly accepted")?;
    assert_eq!(
        denied
            .as_db_error()
            .ok_or("non-db migration denial")?
            .code()
            .code(),
        "42501"
    );
    db.batch_execute("ROLLBACK; RESET ROLE; UPDATE signal_control.store SET ready=true; SET ROLE signal_control_owner").await?;
    let live = db
        .batch_execute(SQL)
        .await
        .err()
        .ok_or("live scope8 migration unexpectedly accepted")?;
    assert_eq!(
        live.as_db_error()
            .ok_or("non-db live migration denial")?
            .message(),
        "SIGNAL_FENCED"
    );
    db.batch_execute("ROLLBACK; RESET ROLE; UPDATE signal_control.store SET ready=false; SET ROLE signal_control_owner").await?;
    let (_, body) = SQL
        .split_once("BEGIN;\n")
        .ok_or("scope8 transaction begin")?;
    let body = body
        .strip_suffix("COMMIT;\n")
        .ok_or("scope8 transaction commit")?;
    db.batch_execute(&format!("BEGIN; {body} ROLLBACK; RESET ROLE"))
        .await?;
    assert!(db.query_one("SELECT to_regclass('signal_finding_scope.requests') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='signal_finding_scope')",&[]).await?.try_get::<_,bool>(0)?);
    db.batch_execute("SET ROLE signal_control_owner").await?;
    db.batch_execute(SQL).await?;
    db.batch_execute("RESET ROLE; SET search_path=pg_catalog,signal_control,pg_temp")
        .await?;
    let catalog_query = include_str!("../../../../schemas/shared-control/catalog-query.sql")
        .replace(
            "n.nspname='signal_control'",
            "n.nspname='signal_finding_scope'",
        );
    let catalog: String = db.query_one(&catalog_query, &[]).await?.try_get(0)?;
    let functions:String=db.query_one("SELECT encode(sha256(convert_to(string_agg(pg_get_functiondef(p.oid),E'\n' ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)),'UTF8')),'hex') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='signal_finding_scope'",&[]).await?.try_get(0)?;
    println!("scope8-catalog: {catalog}");
    println!("scope8-functions: {functions}");
    assert_eq!(
        catalog,
        include_str!("../../../../schemas/shared-control/008-scoped-publication-catalog.sha256")
            .trim()
    );
    assert_eq!(
        functions,
        include_str!("../../../../schemas/shared-control/008-scoped-publication-functions.sha256")
            .trim()
    );
    let older = signal_control::FindingScopeAdministrator::new(
        ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse()?,
            f.port,
            "signal_finding_scope_fixture".into(),
            "signal_migrator".into(),
            f.password.as_bytes().to_vec(),
        )?,
        "signal_control_owner".into(),
        signal_control::FindingScopeProfile::Catalog4,
    )?;
    assert!(matches!(
        older
            .inspect(
                producer.scope.clone(),
                producer.scope_generation,
                super::context()?
            )
            .await,
        Err(ControlError::Corrupt)
    ));
    older.shutdown(super::context()?).await?;
    db.batch_execute("GRANT USAGE ON SCHEMA signal_finding_scope TO signal_runtime; GRANT EXECUTE ON FUNCTION signal_finding_scope.publish(jsonb,bytea,bytea,boolean,bytea,bytea,text,text) TO signal_runtime; UPDATE signal_control.store SET ready=true; UPDATE signal_control.partitions SET owner=NULL,lease_until=NULL").await?;
    let runtime = ControlClient::catalog(ConnectionSettings::fixture_loopback(
        "127.0.0.1".parse()?,
        f.port,
        "signal_finding_scope_fixture".into(),
        "signal_runtime".into(),
        f.password.as_bytes().to_vec(),
    )?)?;
    let token = runtime
        .acquire(
            producer.scope.clone(),
            Uuid::new_v4(),
            15000,
            super::context()?,
        )
        .await
        .map_err(|e| format!("scope8 acquire: {e}"))?;
    let row=db.query_one("SELECT id,first_sequence,last_sequence,manifest FROM signal_control.commits WHERE partition_id=$1 AND id=(SELECT head FROM signal_control.partitions WHERE id=$1)",&[&producer.scope.partition_id]).await?;
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
    // The original retained sequence at the floor remains unscoped.
    let mut unknown =
        super::publication::request(&token, 8810, prior.last_sequence + 1, Some(&prior))?;
    let legacy = Finding::for_event(
        "scoped-fixture",
        &event("canonical-account", 8802)?,
        DetectionSeverity::High,
        "Scoped fixture",
    )?;
    let legacy = signal_control::FindingInput {
        id: legacy.id,
        bytes: serde_json::to_vec(&legacy)?,
    };
    unknown.findings.push(legacy.clone());
    let input = ScopedPublicationInput::from_host(unknown.clone(), &producer, vec![])?;
    if let Err(error) = runtime
        .publish_scoped(token.clone(), input.clone(), super::context()?)
        .await
    {
        super::idle(&runtime).await?;
        let p = input.publication();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let raw = serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"id":p.id,"previous":p.previous,"first_sequence":p.first_sequence,"last_sequence":p.last_sequence,"manifest":hex(&p.manifest),"rule_revision":hex(&p.rule_revision),"normalizer_revision":p.normalizer_revision,"states":[],"findings":p.findings.iter().map(|f|serde_json::json!({"id":f.id,"bytes":hex(&f.bytes)})).collect::<Vec<_>>(),"work":[],"receipts":[]}),
        )?;
        let claims = serde_json::to_vec(&serde_json::to_value(&input)?["claims"])?;
        let schema = signal_control::schema_identity().0.to_vec();
        let routines = signal_control::catalog_schema_identity().1.to_vec();
        let catalog = include_str!(
            "../../../../schemas/shared-control/008-scoped-publication-catalog.sha256"
        )
        .trim();
        let functions = include_str!(
            "../../../../schemas/shared-control/008-scoped-publication-functions.sha256"
        )
        .trim();
        db.batch_execute("SET SESSION AUTHORIZATION signal_runtime")
            .await?;
        let diagnostic = db
            .query_one(
                "SELECT signal_finding_scope.publish($1,$2,$3,$4,$5,$6,$7,$8)",
                &[
                    &serde_json::to_value(&token)?,
                    &raw,
                    &claims,
                    &false,
                    &schema,
                    &routines,
                    &catalog,
                    &functions,
                ],
            )
            .await;
        db.batch_execute("RESET SESSION AUTHORIZATION").await?;
        let diagnostic = match diagnostic {
            Ok(_) => "SQL succeeded; client reply verification needs inspection".to_owned(),
            Err(e) => e
                .as_db_error()
                .map(|d| format!("{}: {}", d.code().code(), d.message()))
                .unwrap_or_else(|| "non-database fixture failure".into()),
        };
        return Err(format!("scope8 original unknown publication: {error}; explicit fixture SQL diagnostic: {diagnostic}").into());
    }
    assert_eq!(
        db.query_one("SELECT count(*) FROM signal_finding_scope.facts", &[])
            .await?
            .try_get::<_, i64>(0)?,
        0
    );
    let sequence = unknown.last_sequence + 1;
    let base = super::publication::request(&token, 8811, sequence, Some(&unknown))?;
    let scoped = derived(&producer, sequence, base.clone(), "canonical-account", 8801)?;
    // Retained serialization is exact evidence and must not be re-derived.
    let retained = serde_json::to_vec(&scoped)?;
    let roundtrip: ScopedPublicationInput = serde_json::from_slice(&retained)?;
    assert!(roundtrip == scoped);
    // Fail after the core has inserted original bytes but before the outer
    // transaction can publish any checkpoint, facts, claims or counters.
    let before_failed = super::publication::witness(db).await?;
    let before_scope:serde_json::Value=db.query_one("SELECT jsonb_build_object('profile',(SELECT to_jsonb(p) FROM signal_finding_scope.profile p),'facts',(SELECT jsonb_agg(to_jsonb(f)) FROM signal_finding_scope.facts f),'requests',(SELECT jsonb_agg(to_jsonb(r)) FROM signal_finding_scope.requests r))",&[]).await?.try_get(0)?;
    db.batch_execute(&format!("CREATE FUNCTION public.synthetic_scope_late_rejection() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.checkpoint={sequence} THEN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SIGNAL_FULL'; END IF; RETURN NEW; END $$; CREATE TRIGGER synthetic_scope_late_rejection BEFORE UPDATE ON signal_control.partitions FOR EACH ROW EXECUTE FUNCTION public.synthetic_scope_late_rejection()")).await?;
    assert!(matches!(
        runtime
            .publish_scoped(token.clone(), scoped.clone(), super::context()?)
            .await,
        Err(ControlError::Full)
    ));
    super::idle(&runtime).await?;
    assert_eq!(before_failed, super::publication::witness(db).await?);
    let after_scope:serde_json::Value=db.query_one("SELECT jsonb_build_object('profile',(SELECT to_jsonb(p) FROM signal_finding_scope.profile p),'facts',(SELECT jsonb_agg(to_jsonb(f)) FROM signal_finding_scope.facts f),'requests',(SELECT jsonb_agg(to_jsonb(r)) FROM signal_finding_scope.requests r))",&[]).await?.try_get(0)?;
    assert_eq!(before_scope, after_scope);
    db.batch_execute("DROP TRIGGER synthetic_scope_late_rejection ON signal_control.partitions; DROP FUNCTION public.synthetic_scope_late_rejection()").await?;
    db.batch_execute(&format!("CREATE FUNCTION public.synthetic_scope_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.checkpoint={sequence} THEN PERFORM pg_sleep(1); END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER synthetic_scope_commit_delay AFTER UPDATE ON signal_control.partitions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.synthetic_scope_commit_delay()")).await?;
    let original = super::context()?;
    let (uncertain, observed) = tokio::join!(
        runtime.publish_scoped(token.clone(), scoped.clone(), original.clone()),
        super::cancel_delayed_commit(db, &original)
    );
    observed?;
    assert!(matches!(uncertain, Err(ControlError::Uncertain)));
    super::idle(&runtime).await?;
    db.batch_execute("DROP TRIGGER synthetic_scope_commit_delay ON signal_control.partitions; DROP FUNCTION public.synthetic_scope_commit_delay()").await?;
    let result = runtime
        .resolve_scoped_publication(token.clone(), roundtrip.clone(), super::context()?)
        .await?;
    assert_eq!(
        runtime
            .resolve_scoped_publication(token.clone(), roundtrip.clone(), super::context()?)
            .await?,
        result
    );
    let finding = &scoped.publication().findings[0];
    let row=db.query_one("SELECT f.content,s.account,s.source,s.resource FROM signal_control.findings f JOIN signal_finding_scope.facts s ON s.finding_id=f.id WHERE f.id=$1",&[&finding.id]).await?;
    assert_eq!(row.try_get::<_, Vec<u8>>(0)?, finding.bytes);
    assert_eq!(row.try_get::<_, String>(1)?, "canonical-account");
    assert_eq!(row.try_get::<_, String>(2)?, "audit");
    assert_eq!(row.try_get::<_, String>(3)?, "fixture");
    let before = super::publication::witness(db).await?;
    let divergent = derived(&producer, sequence, base, "different-account", 8801)?;
    assert!(matches!(
        runtime
            .publish_scoped(token.clone(), divergent, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(before, super::publication::witness(db).await?);
    // The whole request is rejected before the core cursor/checkpoint can advance.
    let mut next =
        super::publication::request(&token, 8812, sequence + 1, Some(scoped.publication()))?;
    let upgraded = derived(
        &producer,
        sequence + 1,
        next.clone(),
        "canonical-account",
        8802,
    )?;
    assert!(matches!(
        runtime
            .publish_scoped(token.clone(), upgraded, super::context()?)
            .await,
        Err(ControlError::Conflict)
    ));
    assert_eq!(before, super::publication::witness(db).await?);
    next.findings.push(legacy.clone());
    let input = ScopedPublicationInput::from_host(next, &producer, vec![])?;
    db.batch_execute("UPDATE signal_finding_scope.profile SET max_rows=used_rows")
        .await?;
    assert!(matches!(
        runtime
            .publish_scoped(token.clone(), input.clone(), super::context()?)
            .await,
        Err(ControlError::Full)
    ));
    assert_eq!(before, super::publication::witness(db).await?);
    db.batch_execute("UPDATE signal_finding_scope.profile SET max_rows=65536")
        .await?;
    // Replacing startup fences missing operations but preserves exact committed
    // original history under independently current lease authority.
    db.batch_execute("UPDATE signal_control.store SET ready=false")
        .await?;
    let administrator = signal_control::FindingScopeAdministrator::new(
        ConnectionSettings::fixture_loopback(
            "127.0.0.1".parse()?,
            f.port,
            "signal_finding_scope_fixture".into(),
            "signal_migrator".into(),
            f.password.as_bytes().to_vec(),
        )?,
        "signal_control_owner".into(),
        signal_control::FindingScopeProfile::Catalog4Scoped,
    )?;
    let replacement = ProducerEnrollment {
        scope: producer.scope.clone(),
        scope_generation: producer.scope_generation,
        startup: Uuid::new_v4(),
        wal_floor: sequence,
    };
    administrator
        .enroll(replacement.clone(), super::context()?)
        .await?;
    administrator.shutdown(super::context()?).await?;
    db.batch_execute("UPDATE signal_control.store SET ready=true")
        .await?;
    assert!(matches!(
        runtime
            .publish_scoped(token.clone(), input.clone(), super::context()?)
            .await,
        Err(ControlError::Fenced)
    ));
    assert_eq!(
        runtime
            .resolve_scoped_publication(token.clone(), scoped, super::context()?)
            .await?,
        result
    );

    let exact_unknown =
        ScopedPublicationInput::from_host(input.publication().clone(), &replacement, vec![])?;
    runtime
        .publish_scoped(token.clone(), exact_unknown, super::context()?)
        .await?;
    let original=db.query_one("SELECT f.content,EXISTS(SELECT 1 FROM signal_finding_scope.facts s WHERE s.finding_id=f.id) FROM signal_control.findings f WHERE f.id=$1",&[&legacy.id]).await?;
    assert_eq!(original.try_get::<_, Vec<u8>>(0)?, legacy.bytes);
    assert!(!original.try_get::<_, bool>(1)?);
    db.batch_execute("SET ROLE signal_runtime").await?;
    assert_eq!(
        db.query("SELECT * FROM signal_finding_scope.facts", &[])
            .await
            .err()
            .ok_or("runtime SELECT unexpectedly allowed")?
            .as_db_error()
            .ok_or("non-db denial")?
            .code()
            .code(),
        "42501"
    );
    db.batch_execute("RESET ROLE; UPDATE signal_control.store SET ready=false")
        .await?;
    runtime.shutdown(super::context()?).await?;
    println!(
        "phase: atomic-original-scoped-publication-facts-counters-and-startup-fencing-qualified"
    );
    Ok(replacement)
}
