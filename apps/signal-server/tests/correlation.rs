#[path = "../../../crates/signal-rules/tests/support/correlation.rs"]
mod support;
use signal_collector_sdk::host_auth::normalize_authentication_json;
use signal_event::Source;
use signal_rules::correlation::*;
use support::*;

#[test]
fn actual_native_authentication_composes_multistream_episode_and_redelivery() -> Result {
    let b = Binding::new(config(), &context())?;
    let ep = epoch(&b, time(100), true)?;
    let mut state = State::new(&b);
    let mut originals = Vec::new();
    for (source, sequence, second, success) in [
        (0, 1, 1, false),
        (0, 2, 2, false),
        (0, 3, 3, false),
        (1, 1, 10, true),
    ] {
        let spec = &b.config().sources[source];
        let raw = serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"timestamp":time(second),"outcome":if success{"success"}else{"failure"},"identity_authority":"fixture-authority","principal_id":"fixture-user","target_id":"fixture-target","method":"password","session_id":format!("session-{sequence}"),"producer":{"boot_id":"fixture-boot","sequence":sequence,"checkpoint":sequence,"dropped_events":0}}),
        )?;
        let selected = Source {
            source_type: spec.source_type.clone(),
            name: Some(spec.source_name.clone()),
        };
        let event = normalize_authentication_json(&raw, selected.clone(), time(500))?;
        state.admit(&b, spec.stream, sequence, &event, &ep, &context())?;
        let replay = normalize_authentication_json(&raw, selected, time(550))?;
        assert_ne!(event.id, replay.id);
        assert_eq!(
            state.admit(&b, spec.stream, sequence, &replay, &ep, &context())?,
            Admission::Duplicate
        );
        originals.push(event);
    }
    state.seal(&b, &seal_epoch(&b, &state, time(50), true)?, &context())?;
    let episode = &state.episodes()[0];
    assert_eq!(episode.status, Status::Match);
    assert_eq!(episode.originals, originals);
    assert_eq!(episode.contributors.len(), 2);
    assert!(
        episode
            .originals
            .iter()
            .all(|e| e.attributes["evidence"]["profile"] == "host-auth-json-v1")
    );
    let decoded = State::decode(&b, &state.encode(&b, &context())?, &context())?;
    assert_eq!(decoded.episodes(), state.episodes());
    Ok(())
}
#[test]
fn native_source_rejects_secret_fields_and_no_episode_is_joined_only_by_ip() -> Result {
    let b = Binding::new(config(), &context())?;
    let mut events = inputs()?;
    events[3].attributes["authentication"]["principal_id"] = serde_json::json!("other-user");
    for event in &mut events {
        event.attributes["authentication"]["client_ip"] = serde_json::json!("198.51.100.1");
    }
    let mut state = load(&b, &events, &[0, 1, 2, 3])?;
    state.seal(&b, &seal_epoch(&b, &state, time(50), true)?, &context())?;
    assert_eq!(state.episodes()[0].status, Status::NoMatch);
    let spec = &b.config().sources[0];
    let raw = serde_json::to_vec(
        &serde_json::json!({"schema_version":1,"timestamp":time(1),"outcome":"failure","identity_authority":"fixture-authority","principal_id":"fixture-user","target_id":"fixture-target","method":"password","session_id":"one","password":"never-copy","producer":{"boot_id":"boot","sequence":1,"checkpoint":1,"dropped_events":0}}),
    )?;
    assert!(
        normalize_authentication_json(
            &raw,
            Source {
                source_type: spec.source_type.clone(),
                name: Some(spec.source_name.clone())
            },
            time(500)
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn catalog_d11_outcomes_use_real_failure_records_and_explicit_projection_augmentation() -> Result {
    let catalog: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/security-requirements/catalog.json"
    ))?;
    let mapping: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/correlation/contract.json"
    ))?;
    assert_eq!(mapping["schema_version"], 1);
    let detection = catalog["detections"]
        .as_array()
        .ok_or("detections")?
        .iter()
        .find(|d| d["id"] == "SIG-D11")
        .ok_or("D11")?;
    for mapped in mapping["cases"].as_array().ok_or("cases")? {
        let fixture = detection["fixtures"]
            .as_array()
            .ok_or("fixtures")?
            .iter()
            .find(|f| f["id"] == mapped["catalog_fixture"])
            .ok_or("fixture")?;
        let original: signal_event::SignalEvent =
            serde_json::from_value(fixture["events"][0].clone())?;
        let mut cfg = config();
        cfg.sources[1].source_type = original.source.source_type.clone();
        cfg.sources[1].source_name = original.source.name.clone().ok_or("source name")?;
        assert_eq!(
            cfg.correlation_ms,
            fixture["parameters"]["correlation_seconds"]
                .as_i64()
                .ok_or("C")?
                * 1000
        );
        let b = Binding::new(cfg, &context())?;
        let principal = original.attributes["security"].get("principal").cloned();
        let target = original.attributes["security"]["target"].clone();
        let boot = fixture["id"].as_str().ok_or("id")?;
        let now = original.timestamp + chrono::TimeDelta::seconds(600);
        let proofs = |state: Option<&State>| {
            b.config()
                .sources
                .iter()
                .map(|s| {
                    let mut p =
                        verification(s, original.timestamp + chrono::TimeDelta::seconds(30), true);
                    p.verified_at = now - chrono::TimeDelta::seconds(10);
                    p.now = now;
                    p.verified_until = now + chrono::TimeDelta::seconds(300);
                    p.coverage_from = original.timestamp - chrono::TimeDelta::seconds(240);
                    p.position = state.map_or(100, |state| {
                        state
                            .source_positions()
                            .iter()
                            .find(|(id, _)| *id == s.stream)
                            .map_or(0, |(_, n)| *n)
                    });
                    p
                })
                .collect()
        };
        let ep = Epoch::new(&b, proofs(None), &context())?;
        let mut state = State::new(&b);
        let source = |s: &signal_rules::correlation::Source| Source {
            source_type: s.source_type.clone(),
            name: Some(s.source_name.clone()),
        };
        let raw = |sequence: u64, timestamp: chrono::DateTime<chrono::Utc>, success: bool| serde_json::json!({"schema_version":1,"timestamp":timestamp,"outcome":if success{"success"}else{"failure"},"identity_authority":"fixture-authority","principal_id":principal,"target_id":target,"method":"password","session_id":format!("{boot}-session-{sequence}"),"producer":{"boot_id":boot,"sequence":sequence,"checkpoint":sequence,"dropped_events":0}});
        let count = mapped["native_failures"].as_u64().ok_or("count")?;
        for sequence in 1..=count {
            let bytes = serde_json::to_vec(&raw(
                sequence,
                original.timestamp - chrono::TimeDelta::seconds(13 - sequence as i64),
                false,
            ))?;
            let native = normalize_authentication_json(
                &bytes,
                source(&b.config().sources[0]),
                original.observed_at,
            )?;
            state.admit(
                &b,
                b.config().sources[0].stream,
                sequence,
                &native,
                &ep,
                &context(),
            )?;
        }
        let raw_success = serde_json::to_vec(&raw(1, original.timestamp, true))?;
        let normalized = normalize_authentication_json(
            &raw_success,
            source(&b.config().sources[1]),
            original.observed_at,
        );
        let mut augmented = original.clone();
        if principal.is_some() {
            augmented.attributes.extend(normalized?.attributes);
        } else {
            assert!(
                normalized.is_err(),
                "selected native source refuses missing principal"
            );
            augmented.attributes.insert("authentication".into(),serde_json::json!({"identity_authority":"fixture-authority","target_id":target,"outcome":"success","method":"password","session_id":format!("{boot}-session-1")}));
            augmented.attributes.insert(
                "producer".into(),
                serde_json::json!({"boot_id":boot,"sequence":1,"checkpoint":1,"dropped_events":0}),
            );
            augmented.attributes.insert(
                "evidence".into(),
                serde_json::json!({"profile":"host-auth-json-v1"}),
            );
        }
        for (key, value) in &original.attributes {
            assert_eq!(augmented.attributes.get(key), Some(value));
        }
        assert_eq!(augmented.id, original.id);
        assert_eq!(augmented.timestamp, original.timestamp);
        assert_eq!(augmented.observed_at, original.observed_at);
        assert_eq!(augmented.source, original.source);
        assert!(
            augmented
                .attributes
                .get("qualifying_failure_burst")
                .is_none()
        );
        state.admit(
            &b,
            b.config().sources[1].stream,
            1,
            &augmented,
            &ep,
            &context(),
        )?;
        state.seal(
            &b,
            &Epoch::new(&b, proofs(Some(&state)), &context())?,
            &context(),
        )?;
        let episode = &state.episodes()[0];
        assert_eq!(serde_json::to_value(episode.status)?, mapped["expected"]);
        assert_eq!(mapped["expected"], fixture["expected_assessment"]);
        assert_eq!(episode.originals.last(), Some(&augmented));
        assert_eq!(
            episode.originals.len(),
            if count > 0 { count as usize + 1 } else { 1 }
        );
    }
    Ok(())
}
