//! URL decode/value properties. Seed 0x51a10e02; 512 inputs, <=64 KiB each.
use serde_json::Value;
use signal_protocol::{EventQuery, QueryValidationError, parse_event_query};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn encode(text: &str) -> String {
    text.bytes().map(|byte| format!("%{byte:02X}")).collect()
}
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn seeded_url_transport_preserves_filter_types_and_precision() -> Result {
    let mut state = 0x51a10e02;
    let dictionary = [
        "a+b c",
        "ü字",
        "&=%\n",
        "true",
        "null",
        "\"quoted\"",
        "\\path",
        "",
    ];
    for iteration in 0..512 {
        let text = dictionary[(next(&mut state) as usize) % dictionary.len()];
        let integer = format!("{}{}", next(&mut state), next(&mut state));
        let payload = format!(
            r#"{{"n":{integer},"array":[null,true,1],"s":{}}}"#,
            serde_json::to_string(text)?
        );
        let expected: Value = serde_json::from_str(&payload)?;
        let limit = (next(&mut state) % 1000 + 1) as usize;
        let raw = format!(
            "contains={}&attribute.owner.payload={}&limit={limit}",
            encode(text),
            encode(&payload)
        );
        assert!(raw.len() <= 65536);
        let parsed = parse_event_query(&raw, 1000)?;
        assert_eq!(parsed.contains.as_deref(), Some(text));
        assert_eq!(
            parsed.attributes[0].value, expected,
            "iteration {iteration}"
        );
        assert_eq!(parsed.limit, limit);
        let roundtrip: EventQuery = serde_json::from_slice(&serde_json::to_vec(&parsed)?)?;
        assert_eq!(roundtrip, parsed);
        roundtrip.validate(1000)?;
        // Percent-encoding a duplicate name cannot bypass duplicate-key validation.
        let repeated = format!("{raw}&%6c%69%6d%69%74={limit}");
        assert_eq!(
            parse_event_query(&repeated, 1000),
            Err(QueryValidationError::DuplicateParameter)
        );
    }
    Ok(())
}

#[test]
fn adversarial_url_dictionary_fails_with_static_diagnostics() -> Result {
    for prefix in ["unknown=", "severity=", "order=", "limit=", "from="] {
        for length in [1, 16, 255, 4096, 65500] {
            let sentinel = "SENTINEL_PRIVATE_VALUE";
            let suffix = sentinel.repeat(length / sentinel.len() + 1);
            let raw = format!("{prefix}{}", &suffix[..length]);
            assert!(raw.len() <= 65536);
            let error = parse_event_query(&raw, 1000)
                .err()
                .ok_or("invalid filter accepted")?;
            assert!(!error.to_string().contains(sentinel));
        }
    }
    for malformed in ["%", "%0", "%GG", "%FF", "%C0%AF", "%ED%A0%80"] {
        assert_eq!(
            parse_event_query(&format!("contains={malformed}"), 1000),
            Err(QueryValidationError::InvalidEncoding)
        );
    }
    for path in ["", ".a", "a.", "a..b", "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q"] {
        assert!(parse_event_query(&format!("attribute.{path}=null"), 1000).is_err());
    }
    for depth in [33, 64] {
        let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert!(parse_event_query(&format!("attribute.value={}", encode(&nested)), 1000).is_err());
    }
    // The documented plain-string fallback applies when JSON itself is invalid.
    // Serde's recursion limit rejects this spelling before typed-value validation.
    let raw = format!("{}0{}", "[".repeat(128), "]".repeat(128));
    let fallback = parse_event_query(&format!("attribute.value={}", encode(&raw)), 1000)?;
    assert_eq!(fallback.attributes[0].value, Value::String(raw));
    Ok(())
}
