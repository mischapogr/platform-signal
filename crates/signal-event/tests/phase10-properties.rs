//! Bounded deterministic event properties. Seed 0x51a10e01; no external corpus.
use serde_json::{Value, json};
use signal_event::{IngestEvent, SignalEvent};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
const SEED: u64 = 0x51a10e01;
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn seeded_nested_attributes_and_precision_roundtrip() -> Result {
    let mut state = SEED;
    for iteration in 0..512 {
        let integer = format!("{}{}{}", next(&mut state), next(&mut state), iteration);
        let precise: Value = serde_json::from_str(&integer)?;
        let mut nested =
            json!({"number":precise,"null":null,"text":"+% ü\n","bool":iteration % 2 == 0});
        for depth in 0..next(&mut state) % 12 {
            nested = if depth % 2 == 0 {
                json!({"inner":nested})
            } else {
                json!([nested, false])
            };
        }
        let input = json!({"id":"00000000-0000-4000-8000-000000000001",
            "timestamp":"2026-10-06T12:00:00.123456789Z","source":{"type":"test"},
            "attributes":{"namespace.key":nested}});
        let bytes = serde_json::to_vec(&input)?;
        assert!(bytes.len() <= 65536);
        let event = serde_json::from_slice::<IngestEvent>(&bytes)?
            .normalize("2026-10-06T12:00:01Z".parse()?)?;
        let serialized = serde_json::to_vec(&event)?;
        assert!(
            serialized
                .windows(integer.len())
                .any(|part| part == integer.as_bytes())
        );
        let restored: SignalEvent = serde_json::from_slice(&serialized)?;
        restored.validate()?;
        assert_eq!(restored, event, "seed {SEED:x}, iteration {iteration}");
    }
    Ok(())
}

#[test]
fn bounded_invalid_wire_and_semantic_errors() -> Result {
    let canonical =
        br#"{"timestamp":"2026-10-06T12:00:00Z","source":{"type":"test"},"message":"ok"}"#;
    // Every proper byte prefix is an incomplete JSON object, never an admitted event.
    for end in 0..canonical.len() {
        assert!(serde_json::from_slice::<IngestEvent>(&canonical[..end]).is_err());
    }
    for input in [vec![0xff; 65536], b"[".repeat(128), vec![0; 4096]] {
        assert!(serde_json::from_slice::<IngestEvent>(&input).is_err());
    }
    for timestamp in [
        "not-a-time",
        "2026-02-30T00:00:00Z",
        "+10000-01-01T00:00:00Z",
        "2026-10-06",
    ] {
        let raw = json!({"timestamp":timestamp,"source":{"type":"test"},"message":"ok"});
        assert!(serde_json::from_value::<IngestEvent>(raw).is_err());
    }
    let input: IngestEvent = serde_json::from_slice(canonical)?;
    let valid = input.normalize("2026-10-06T12:00:01Z".parse()?)?;
    for size in [1, 31, 32, 33, 1024, 65000] {
        let mut event = valid.clone();
        let text = "SENTINEL_PRIVATE_VALUE".repeat(size / 22 + 1);
        event.trace_id = Some(text[..size].to_owned());
        assert!(serde_json::to_vec(&event)?.len() <= 65536);
        let error = event.validate().err().ok_or("invalid trace accepted")?;
        assert!(!error.to_string().contains("SENTINEL_PRIVATE_VALUE"));
    }
    for schema in [0, 2, 255, u16::MAX] {
        let mut event = valid.clone();
        event.schema_version = schema;
        assert!(event.validate().is_err());
    }
    Ok(())
}
