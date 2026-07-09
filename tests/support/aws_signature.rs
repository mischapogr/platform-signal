//! Independent, test-only SigV4 witness. Production uses Amazon's signer.
//! Recompute HMAC from actual wire method/path/headers/body without AWS crates.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().to_vec()
}
fn encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(*b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
fn decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        out.push(if b == b'%' {
            let hi = char::from(bytes.next()?).to_digit(16)?;
            let lo = char::from(bytes.next()?).to_digit(16)?;
            (hi * 16 + lo) as u8
        } else {
            b
        });
    }
    Some(out)
}
/// Inputs are synthetic request data only; never format credentials or requests
/// in assertion/error output. `service`/`region` are expected trusted scopes.
#[allow(
    clippy::too_many_arguments,
    reason = "test witness keeps actual wire input and trusted expected scope explicit"
)]
pub fn verify(
    method: &str,
    target: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    access: &str,
    secret: &str,
    service: &str,
    region: &str,
) -> bool {
    let Some(auth) = headers
        .get("authorization")
        .and_then(|s| s.strip_prefix("AWS4-HMAC-SHA256 "))
    else {
        return false;
    };
    let fields: BTreeMap<_, _> = auth.split(", ").filter_map(|p| p.split_once('=')).collect();
    let Some(credential) = fields.get("Credential") else {
        return false;
    };
    let parts: Vec<_> = credential.split('/').collect();
    if parts.len() != 5
        || parts[0] != access
        || parts[2] != region
        || parts[3] != service
        || parts[4] != "aws4_request"
    {
        return false;
    }
    let Some(date) = headers
        .get("x-amz-date")
        .filter(|d| d.len() == 16 && d.starts_with(parts[1]))
    else {
        return false;
    };
    let Some(signed) = fields.get("SignedHeaders") else {
        return false;
    };
    let names: Vec<_> = signed.split(';').collect();
    if names.windows(2).any(|pair| pair[0] >= pair[1])
        || !names.contains(&"host")
        || !names.contains(&"x-amz-date")
    {
        return false;
    }
    let mut canonical_headers = String::new();
    for name in names {
        let Some(value) = headers.get(name) else {
            return false;
        };
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&value.split_ascii_whitespace().collect::<Vec<_>>().join(" "));
        canonical_headers.push('\n');
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    // Independently enforce AWS byte encoding rather than generic URL encoding.
    if service == "s3" {
        let canonical_path: Option<Vec<_>> = path
            .split('/')
            .map(|p| decode(p).map(|p| encode(&p)))
            .collect();
        if canonical_path.is_none_or(|parts| parts.join("/") != path) {
            return false;
        }
    }
    let mut pairs = Vec::new();
    if !query.is_empty() {
        for p in query.split('&') {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let (Some(k), Some(v)) = (decode(k), decode(v)) else {
                return false;
            };
            pairs.push((encode(&k), encode(&v)));
        }
    }
    pairs.sort();
    let canonical_query = pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    if service == "s3" && canonical_query != query {
        return false;
    }
    let payload = hex(&Sha256::digest(body));
    if headers
        .get("x-amz-content-sha256")
        .is_some_and(|p| p != &payload)
    {
        return false;
    }
    let canonical =
        format!("{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed}\n{payload}");
    let scope = parts[1..].join("/");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let date_key = hmac(format!("AWS4{secret}").as_bytes(), parts[1].as_bytes());
    let region_key = hmac(&date_key, region.as_bytes());
    let service_key = hmac(&region_key, service.as_bytes());
    let signing_key = hmac(&service_key, b"aws4_request");
    fields
        .get("Signature")
        .is_some_and(|s| **s == hex(&hmac(&signing_key, to_sign.as_bytes())))
}
