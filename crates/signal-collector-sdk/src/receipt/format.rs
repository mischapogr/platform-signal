use super::*;
use chrono::{DateTime, Datelike, Timelike, Utc};
use sha2::{Digest, Sha256};
use signal_event::SignalEvent;

const MIB: usize = 1024 * 1024;
fn invalid(s: &'static str) -> ReceiptError {
    ReceiptError::Invalid(s)
}
fn need(ok: bool, s: &'static str) -> Result<(), ReceiptError> {
    if ok { Ok(()) } else { Err(invalid(s)) }
}
fn fields(v: &Value, names: &str) -> Result<(), ReceiptError> {
    let m = v.as_object().ok_or(invalid("object"))?;
    need(
        m.len() == names.split_whitespace().count()
            && names.split_whitespace().all(|k| m.contains_key(k)),
        "fields",
    )
}
fn string(v: &Value, cap: usize, empty: bool) -> Result<&str, ReceiptError> {
    let s = v.as_str().ok_or(invalid("string"))?;
    need(s.len() <= cap && (empty || !s.is_empty()), "string bytes")?;
    Ok(s)
}
fn number(v: &Value, max: u64) -> Result<u64, ReceiptError> {
    let n = v.as_u64().ok_or(invalid("unsigned integer"))?;
    need(n <= max, "integer bound")?;
    Ok(n)
}
fn array(v: &Value, cap: usize) -> Result<&Vec<Value>, ReceiptError> {
    let a = v.as_array().ok_or(invalid("array"))?;
    need(a.len() <= cap, "array bound")?;
    Ok(a)
}
pub(super) fn uuid(v: &Value) -> Result<Uuid, ReceiptError> {
    let s = string(v, 36, false)?;
    let u = Uuid::parse_str(s).map_err(|_| invalid("uuid"))?;
    need(!u.is_nil() && u.to_string() == s, "uuid form")?;
    Ok(u)
}
pub(super) fn hash(v: &Value) -> Result<[u8; 32], ReceiptError> {
    let s = string(v, 64, false)?;
    need(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "hash form",
    )?;
    let mut bytes = [0; 32];
    for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
        let a = (chunk[0] as char).to_digit(16).ok_or(invalid("hash"))?;
        let b = (chunk[1] as char).to_digit(16).ok_or(invalid("hash"))?;
        bytes[i] = (a * 16 + b) as u8;
    }
    Ok(bytes)
}
pub(super) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
pub(super) fn time(v: &Value) -> Result<DateTime<Utc>, ReceiptError> {
    let s = string(v, 30, false)?;
    need(
        s.len() == 30
            && s.is_ascii()
            && s.as_bytes()[19] == b'.'
            && s.ends_with('Z')
            && s.as_bytes()[20..29].iter().all(u8::is_ascii_digit),
        "time form",
    )?;
    let t = DateTime::parse_from_rfc3339(s)
        .map_err(|_| invalid("time calendar"))?
        .with_timezone(&Utc);
    need(
        (1..=9999).contains(&t.year())
            && t.nanosecond() < 1_000_000_000
            && t.format("%Y-%m-%dT%H:%M:%S.%9fZ").to_string() == s,
        "time form",
    )?;
    Ok(t)
}
fn account(v: &Value) -> Result<(), ReceiptError> {
    let s = string(v, 12, false)?;
    need(
        s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit()),
        "account",
    )
}
fn choices(v: &Value, list: &[&str]) -> Result<(), ReceiptError> {
    need(v.as_str().is_some_and(|s| list.contains(&s)), "enum")
}
fn reasons(v: &Value, allowed: &[&str], minimum: usize) -> Result<(), ReceiptError> {
    let a = array(v, 4)?;
    need(a.len() >= minimum, "reasons")?;
    for (i, x) in a.iter().enumerate() {
        choices(x, allowed)?;
        need(!a[..i].contains(x), "duplicate reason")?;
    }
    Ok(())
}

pub(super) fn canonical(v: &Value, cap: usize) -> Result<Vec<u8>, ReceiptError> {
    fn put(out: &mut Vec<u8>, b: &[u8], cap: usize) -> Result<(), ReceiptError> {
        need(
            out.len().checked_add(b.len()).is_some_and(|n| n <= cap),
            "canonical bytes",
        )?;
        out.extend_from_slice(b);
        Ok(())
    }
    fn quote(out: &mut Vec<u8>, s: &str, cap: usize) -> Result<(), ReceiptError> {
        put(out, b"\"", cap)?;
        for c in s.chars() {
            match c {
                '"' => put(out, b"\\\"", cap)?,
                '\\' => put(out, b"\\\\", cap)?,
                c if (c as u32) < 32 => put(out, format!("\\u{:04x}", c as u32).as_bytes(), cap)?,
                c => {
                    let mut b = [0; 4];
                    put(out, c.encode_utf8(&mut b).as_bytes(), cap)?;
                }
            }
        }
        put(out, b"\"", cap)
    }
    fn encode(out: &mut Vec<u8>, v: &Value, cap: usize) -> Result<(), ReceiptError> {
        match v {
            Value::Null => put(out, b"null", cap),
            Value::Bool(b) => put(out, if *b { b"true" } else { b"false" }, cap),
            Value::Number(n) => put(
                out,
                n.as_u64()
                    .ok_or(invalid("canonical integer"))?
                    .to_string()
                    .as_bytes(),
                cap,
            ),
            Value::String(s) => quote(out, s, cap),
            Value::Array(a) => {
                put(out, b"[", cap)?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        put(out, b",", cap)?;
                    }
                    encode(out, v, cap)?;
                }
                put(out, b"]", cap)
            }
            Value::Object(m) => {
                put(out, b"{", cap)?;
                let mut keys: Vec<_> = m.keys().collect();
                keys.sort();
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        put(out, b",", cap)?;
                    }
                    quote(out, k, cap)?;
                    put(out, b":", cap)?;
                    encode(out, &m[*k], cap)?;
                }
                put(out, b"}", cap)
            }
        }
    }
    let mut out = Vec::new();
    encode(&mut out, v, cap)?;
    Ok(out)
}
pub(super) fn json(
    raw: &[u8],
    cap: usize,
    depth: usize,
    nodes: usize,
) -> Result<Value, ReceiptError> {
    let v = crate::cloudtrail::decode_json(raw, cap, depth, nodes)
        .map_err(|_| invalid("bounded JSON"))?;
    need(canonical(&v, cap)? == raw, "canonical JSON")?;
    Ok(v)
}
pub(super) fn validate_binding(b: &Value) -> Result<(), ReceiptError> {
    fields(
        b,
        "tenant_id collector_id source_id config_revision authority_revision queue_arn trail_arn queue_owner bucket_owner bucket key_prefix stream profile_id profile_revision recipient_accounts regions custody_mode ack_requires_m2",
    )?;
    for k in [
        "tenant_id",
        "collector_id",
        "source_id",
        "config_revision",
        "authority_revision",
        "stream",
        "profile_id",
        "profile_revision",
    ] {
        string(&b[k], 128, false)?;
    }
    for k in ["queue_arn", "trail_arn"] {
        string(&b[k], 512, false)?;
    }
    for k in ["queue_owner", "bucket_owner"] {
        account(&b[k])?;
    }
    string(&b["bucket"], 63, false)?;
    string(&b["key_prefix"], 1024, true)?;
    need(
        b["profile_id"] == "cloudtrail-management" && b["profile_revision"] == "v1",
        "profile",
    )?;
    choices(
        &b["custody_mode"],
        &["process_local", "independent_durable", "protected_replay"],
    )?;
    need(b["ack_requires_m2"].is_boolean(), "ACK bool")?;
    for (name, cap) in [("recipient_accounts", 128), ("regions", 64)] {
        let a = array(&b[name], cap)?;
        need(!a.is_empty(), "scope empty")?;
        let mut previous = None;
        for v in a {
            let s = string(v, 64, false)?;
            if name == "recipient_accounts" {
                account(v)?;
            } else {
                need(
                    s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                    "region",
                )?;
            }
            need(previous.is_none_or(|p: &str| p < s), "scope ordering")?;
            previous = Some(s);
        }
    }
    Ok(())
}
pub(super) fn metadata(m: &Value) -> Result<Vec<&Value>, ReceiptError> {
    fields(
        m,
        "schema_version receipt_id binding original prepared_at normalizer_sha256 retention object_disposition object_reasons records",
    )?;
    need(number(&m["schema_version"], 1)? == 1, "version")?;
    uuid(&m["receipt_id"])?;
    hash(&m["normalizer_sha256"])?;
    validate_binding(&m["binding"])?;
    let o = &m["original"];
    fields(
        o,
        "bucket key version_id etag compression length sha256 decoded_length captured_at discovery_sha256 delivery_id reference_count",
    )?;
    string(&o["bucket"], 63, false)?;
    let key = string(&o["key"], 1024, false)?;
    need(
        string(&o["version_id"], 1024, false)? != "null",
        "versionless original",
    )?;
    if !o["etag"].is_null() {
        string(&o["etag"], 1024, false)?;
    }
    string(&o["delivery_id"], 128, false)?;
    hash(&o["sha256"])?;
    hash(&o["discovery_sha256"])?;
    need(
        o["compression"] == "gzip" && number(&o["reference_count"], 1)? == 1,
        "original kind",
    )?;
    need(
        o["bucket"] == m["binding"]["bucket"]
            && key.starts_with(string(&m["binding"]["key_prefix"], 1024, true)?),
        "namespace",
    )?;
    need(number(&o["length"], 8 * MIB as u64)? > 0, "original length")?;
    let decoded = number(&o["decoded_length"], 32 * MIB as u64)?;
    let at = time(&m["prepared_at"])?;
    need(time(&o["captured_at"])? <= at, "capture time")?;
    let r = &m["retention"];
    fields(
        r,
        "retain_until source_replay_until recovery_budget_seconds",
    )?;
    let seconds = number(&r["recovery_budget_seconds"], u32::MAX as u64)?;
    need(seconds > 0, "recovery budget")?;
    let end = at
        .checked_add_signed(chrono::Duration::seconds(seconds as i64))
        .ok_or(invalid("time overflow"))?;
    need(
        end.year() <= 9999
            && time(&r["retain_until"])? >= end
            && time(&r["source_replay_until"])? >= end,
        "retention budget",
    )?;
    let records = array(&m["records"], 1024)?;
    if m["object_disposition"] == "quarantine_object" {
        reasons(
            &m["object_reasons"],
            &[
                "invalid_compression",
                "invalid_object_json",
                "object_limits_exceeded",
                "unsupported_object",
                "empty_records",
            ],
            1,
        )?;
        need(records.is_empty(), "object quarantine")?;
    } else {
        need(
            m["object_disposition"] == "prepared"
                && !records.is_empty()
                && decoded > 0
                && array(&m["object_reasons"], 0)?.is_empty(),
            "object disposition",
        )?;
    }
    let mut end = 0;
    let mut emitted = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for (i, r) in records.iter().enumerate() {
        fields(
            r,
            "ordinal start length sha256 native_event_id disposition reasons prepared_index prepared_id prepared_sha256",
        )?;
        need(number(&r["ordinal"], 1023)? == i as u64, "ordinal")?;
        let start = number(&r["start"], 32 * MIB as u64)?;
        let len = number(&r["length"], 256 * 1024)?;
        need(len > 0 && start >= end && start + len <= decoded, "span")?;
        end = start + len;
        hash(&r["sha256"])?;
        if !r["native_event_id"].is_null() {
            uuid(&r["native_event_id"])?;
        }
        choices(
            &r["disposition"],
            &["emit", "emit_indeterminate", "quarantine_record"],
        )?;
        let min = if r["disposition"] == "emit" { 0 } else { 1 };
        reasons(
            &r["reasons"],
            &[
                "missing_required_native",
                "malformed_required_native",
                "unsupported_native_version",
                "unsupported_event_category",
                "recipient_route_not_authorized",
                "missing_actor",
                "unsupported_operation",
                "missing_or_unsupported_mfa",
                "unsupported_actor_mfa",
                "unknown_operation_outcome",
                "prepared_event_bytes_exceeded",
            ],
            min,
        )?;
        if min == 0 {
            need(array(&r["reasons"], 0)?.is_empty(), "emit reason")?;
        }
        if r["disposition"] == "quarantine_record" {
            need(
                ["prepared_index", "prepared_id", "prepared_sha256"]
                    .iter()
                    .all(|k| r[*k].is_null()),
                "quarantine mapping",
            )?;
        } else {
            need(
                number(&r["prepared_index"], 1023)? == emitted.len() as u64,
                "prepared order",
            )?;
            need(ids.insert(uuid(&r["prepared_id"])?), "duplicate identity")?;
            hash(&r["prepared_sha256"])?;
            emitted.push(r);
        }
    }
    Ok(emitted)
}
fn sha(bytes: &[u8], ctx: &ExtensionContext) -> Result<[u8; 32], ReceiptError> {
    let mut h = Sha256::new();
    for b in bytes.chunks(65536) {
        check(ctx)?;
        h.update(b);
    }
    Ok(h.finalize().into())
}
fn be(raw: &[u8]) -> Result<u64, ReceiptError> {
    match raw.len() {
        4 => Ok(u32::from_be_bytes(raw.try_into().map_err(|_| invalid("header"))?) as u64),
        8 => Ok(u64::from_be_bytes(
            raw.try_into().map_err(|_| invalid("header"))?,
        )),
        _ => Err(invalid("header")),
    }
}
pub(super) fn decode(
    bytes: Vec<u8>,
    ctx: &ExtensionContext,
) -> Result<StoredReceipt, ReceiptError> {
    check(ctx)?;
    need(
        (68..=MAX_RECEIPT_BYTES).contains(&bytes.len()) && bytes[..8] == *b"SIGSRC01",
        "receipt frame",
    )?;
    let ml = be(&bytes[8..12])?;
    let ol = be(&bytes[12..20])?;
    let count = be(&bytes[20..28])?;
    let total = be(&bytes[28..36])?;
    need(
        ml <= MIB as u64
            && (1..=8 * MIB as u64).contains(&ol)
            && count <= 1024
            && total <= 16 * MIB as u64,
        "header bounds",
    )?;
    need(
        bytes.len() as u64 == 36 + ml + ol + count * 52 + total + 32,
        "section sum",
    )?;
    let checksum = sha(&bytes[..bytes.len() - 32], ctx)?;
    need(bytes[bytes.len() - 32..] == checksum, "receipt checksum")?;
    let me = 36 + ml as usize;
    let oe = me + ol as usize;
    let m = json(&bytes[36..me], MIB, 16, 65536)?;
    let emitted = metadata(&m)?;
    need(
        ol == number(&m["original"]["length"], 8 * MIB as u64)?
            && sha(&bytes[me..oe], ctx)? == hash(&m["original"]["sha256"])?
            && emitted.len() == count as usize,
        "section correspondence",
    )?;
    let mut pos = oe;
    let mut events = Vec::new();
    for r in emitted {
        check(ctx)?;
        need(pos + 52 <= bytes.len() - 32, "event frame")?;
        let len = be(&bytes[pos..pos + 4])?;
        need(
            (1..=65536).contains(&len) && pos + 52 + len as usize <= bytes.len() - 32,
            "event bytes",
        )?;
        let end = pos + 52 + len as usize;
        let data = &bytes[pos + 52..end];
        let h = sha(data, ctx)?;
        need(
            bytes[pos + 4..pos + 20] == *uuid(&r["prepared_id"])?.as_bytes()
                && bytes[pos + 20..pos + 52] == h
                && h == hash(&r["prepared_sha256"])?,
            "event witness",
        )?;
        let mut v = crate::cloudtrail::decode_json(data, 65536, 32, 16384)
            .map_err(|_| invalid("event JSON"))?;
        need(
            uuid(&v["id"])? == uuid(&r["prepared_id"])?
                && v["attributes"]["evidence_ref"]
                    == format!(
                        "receipt://{}/record/{}",
                        m["receipt_id"].as_str().ok_or(invalid("receipt id"))?,
                        r["ordinal"]
                    )
                && v["attributes"]["normalizer"]
                    == serde_json::json!({"id":"cloudtrail-management","revision":"v1"}),
            "event pins",
        )?;
        need(
            v["source"]["type"] == "cloudtrail"
                && v["resource"]["kind"] == "aws_account"
                && v["resource"]["id"] == v["resource"]["account_id"]
                && m["binding"]["recipient_accounts"]
                    .as_array()
                    .is_some_and(|a| a.contains(&v["resource"]["account_id"]))
                && m["binding"]["regions"]
                    .as_array()
                    .is_some_and(|a| a.contains(&v["resource"]["region"])),
            "event recipient scope",
        )?;
        // Keep arbitrary attributes literal: Value deserialization under serde's
        // arbitrary_precision feature may reinterpret a private number-map key.
        let attributes = std::mem::take(
            v.get_mut("attributes")
                .and_then(Value::as_object_mut)
                .ok_or(invalid("event attributes"))?,
        );
        let mut event: SignalEvent = serde_json::from_value(v).map_err(|_| invalid("event v1"))?;
        event.attributes = attributes;
        // Event v1 permits RFC3339 precision/offset representations. The metadata
        // clock is canonical nanoseconds; compare instants without rewriting bytes.
        need(
            event.observed_at == time(&m["prepared_at"])?,
            "event observation pin",
        )?;
        event.validate().map_err(|_| invalid("event v1"))?;
        events.push(pos + 52..end);
        pos = end;
    }
    need(pos == bytes.len() - 32, "trailing events")?;
    let id = uuid(&m["receipt_id"])?;
    let info = ReceiptInfo {
        id,
        checksum,
        bytes: bytes.len(),
        prepared_count: events.len(),
    };
    check(ctx)?;
    Ok(StoredReceipt {
        bytes,
        metadata: m,
        original: me..oe,
        events,
        info,
        metadata_end: me,
    })
}
pub(super) fn initial(
    receipt: &StoredReceipt,
    owner: Uuid,
    generation: u64,
) -> Result<Vec<u8>, ReceiptError> {
    let mut prefix = Sha256::new();
    prefix.update(b"SIGPRF01");
    prefix.update(receipt.info.checksum);
    prefix.update(0u32.to_be_bytes());
    let prefix: [u8; 32] = prefix.finalize().into();
    let m = &receipt.metadata;
    let p = serde_json::json!({"schema_version":1,"receipt_id":receipt.info.id.to_string(),"receipt_sha256":hex(&receipt.info.checksum),"binding":m["binding"],"retention":m["retention"],"prepared_count":receipt.info.prepared_count,"owner_id":owner.to_string(),"owner_generation":generation,"revision":0,"previous_sha256":null,"verified_prefix":0,"prefix_sha256":hex(&prefix),"attempt":{"kind":"none","start":0,"count":0,"accepted":0,"response_sha256":null},"custody":{"status":"local_only","witness_id":null,"receipt_sha256":null,"retain_until":null},"ack":{"state":"not_requested","attempt_id":null,"delivery_id":null,"observed_at":null},"retirement":{"state":"active","observed_at":null}});
    let data = canonical(&p, 8 * MIB - 44)?;
    let mut out = b"SIGSCP01".to_vec();
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&data);
    let checksum = Sha256::digest(&out);
    out.extend_from_slice(&checksum);
    Ok(out)
}
pub(super) fn verify_initial(
    data: &[u8],
    r: &StoredReceipt,
    owner: Uuid,
    generation: u64,
) -> Result<(), ReceiptError> {
    need(
        (44..=8 * MIB).contains(&data.len())
            && data[..8] == *b"SIGSCP01"
            && be(&data[8..12])? + 44 == data.len() as u64,
        "control frame",
    )?;
    need(
        data[data.len() - 32..] == Sha256::digest(&data[..data.len() - 32])[..],
        "control checksum",
    )?;
    let p = json(&data[12..data.len() - 32], 8 * MIB - 44, 16, 65536)?;
    if uuid(&p["owner_id"])? != owner || number(&p["owner_generation"], u64::MAX)? != generation {
        return Err(ReceiptError::Owner);
    }
    if number(&p["revision"], u64::MAX)? != 0 || p["retirement"]["state"] != "active" {
        return Err(ReceiptError::UnsupportedProgress);
    }
    need(initial(r, owner, generation)? == data, "control pins")
}
