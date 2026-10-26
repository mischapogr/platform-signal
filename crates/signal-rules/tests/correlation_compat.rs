#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/correlation.rs"]
mod support;
use signal_rules::{correlation::*, state_journal::Record};
use support::*;
fn golden() -> Result<serde_json::Value> {
    // Dependency feature unification selects the existing map representation.
    // Each fixture was captured from verified pre-refactor D11 source. Do not
    // choose by whether bytes match, or regenerate from the implementation.
    let mut probe = serde_json::Map::new();
    probe.insert("z".into(), serde_json::Value::Null);
    probe.insert("a".into(), serde_json::Value::Null);
    let name = if probe.keys().next().map(String::as_str) == Some("z") {
        "d11-v1-insertion-golden.json"
    } else {
        "d11-v1-golden.json"
    };
    Ok(serde_json::from_slice(&std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/correlation")
            .join(name),
    )?)?)
}

#[test]
fn runtime_capture_evidence_cannot_be_injected_into_d11_v1_history() -> Result {
    let golden = golden()?;
    let original: serde_json::Value =
        serde_json::from_str(golden["state_utf8"].as_str().ok_or("state")?)?;
    let c = context();
    let b = Binding::new(config(), &c)?;
    for path in [
        "/observations/0/verification",
        "/last_seal_evidence/0",
        "/episodes/0/verification/0",
    ] {
        let mut state = original.clone();
        let p = state.pointer_mut(path).ok_or("proof")?;
        p["runtime"] = serde_json::json!({"enrollment_sha256":vec![1;32],"metadata_only":true,"execution_continuity":true,"clock_continuity":true});
        assert!(
            State::decode(&b, &serde_json::to_vec(&state)?, &c).is_err(),
            "{path}"
        );
        state.pointer_mut(path).ok_or("proof")?["runtime"] = serde_json::Value::Null;
        assert!(
            State::decode(&b, &serde_json::to_vec(&state)?, &c).is_err(),
            "null {path}"
        );
    }
    Ok(())
}

#[test]
fn d11_v1_config_state_episode_archive_and_enrollment_remain_byte_exact() -> Result {
    let golden = golden()?;
    let c = context();
    let b = Binding::new(config(), &c)?;
    let mut state = load(&b, &inputs()?, &[0, 1, 2, 3])?;
    state.seal(&b, &seal_epoch(&b, &state, time(50), true)?, &c)?;
    let config_bytes = serde_json::to_string(b.config())?;
    let state_bytes = state.encode(&b, &c)?;
    assert_eq!(
        config_bytes,
        golden["config_utf8"].as_str().ok_or("config golden")?
    );
    assert_eq!(
        state_bytes,
        golden["state_utf8"]
            .as_str()
            .ok_or("state golden")?
            .as_bytes()
    );
    assert_eq!(
        serde_json::to_value(b.journal_config())?,
        golden["journal_config"]
    );
    let old = State::decode(
        &b,
        golden["state_utf8"]
            .as_str()
            .ok_or("state golden")?
            .as_bytes(),
        &c,
    )?;
    assert_eq!(old.encode(&b, &c)?, state_bytes);
    assert_eq!(
        serde_json::to_string(&old.episodes()[0])?,
        golden["episode_utf8"].as_str().ok_or("episode golden")?
    );
    assert_eq!(old.episodes()[0].status, Status::Match);
    let effect = old
        .original_effect(old.episodes()[0].id)
        .ok_or("original effect")?;
    assert_eq!(
        effect.bytes,
        golden["episode_utf8"]
            .as_str()
            .ok_or("effect golden")?
            .as_bytes()
    );
    let record = Record {
        schema_version: 1,
        revision: 1,
        checkpoint: 4,
        state: state_bytes,
        outbox: vec![],
    };
    let archive = history::export(&b, &record, &c)?;
    assert_eq!(
        archive.bytes(),
        golden["archive_utf8"]
            .as_str()
            .ok_or("archive golden")?
            .as_bytes()
    );
    let hash: [u8; 32] = serde_json::from_value(golden["archive_domain_sha256"].clone())?;
    assert_eq!(archive.sha256(), hash);
    let decoded = history::Archive::from_bytes(
        golden["archive_utf8"]
            .as_str()
            .ok_or("archive golden")?
            .as_bytes(),
        hash,
        &c,
    )?;
    assert_eq!(decoded.bytes(), archive.bytes());
    assert_eq!(decoded.identities().len(), 4);
    Ok(())
}
