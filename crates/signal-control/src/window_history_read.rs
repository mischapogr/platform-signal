//! Source-bound retained metadata, not HTTP authority or canonical payload custody.
use crate::{ControlContext, ControlError, LeaseToken, Scope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCursor {
    schema_version: u16,
    scope: Scope,
    key: String,
    head: Uuid,
    state_sha: String,
    profile_sha: String,
    checkpoint: u64,
    id: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryInput {
    pub schema_version: u16,
    pub key: String,
    pub head: Uuid,
    pub limit: usize,
    pub max_bytes: usize,
    pub cursor: Option<HistoryCursor>,
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl HistoryInput {
    pub fn validate(&self, token: &LeaseToken) -> Result<(), ControlError> {
        token.validate()?;
        if self.schema_version != 1
            || self.head.is_nil()
            || self.key.is_empty()
            || self.key.len() > 256
            || self.key.capacity() > 256
            || self.key.chars().any(char::is_control)
            || !(1..=128).contains(&self.limit)
            || !(4096..=1048576).contains(&self.max_bytes)
        {
            return Err(ControlError::Invalid);
        }
        if let Some(c) = &self.cursor
            && (c.schema_version != 1
                || c.scope.validate().is_err()
                || c.scope != token.scope
                || c.key != self.key
                || c.key.capacity() > 256
                || c.head != self.head
                || c.checkpoint == 0
                || c.checkpoint > i64::MAX as u64
                || !hex(&c.state_sha)
                || !hex(&c.profile_sha)
                || !hex(&c.id))
        {
            return Err(ControlError::Conflict);
        }
        if self.cursor.as_ref().is_some_and(|c| {
            c.state_sha.capacity() > 64 || c.profile_sha.capacity() > 64 || c.id.capacity() > 64
        }) {
            return Err(ControlError::Invalid);
        }
        if serde_json::to_vec(self)
            .map_err(|_| ControlError::Invalid)?
            .len()
            > 8192
        {
            return Err(ControlError::Invalid);
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    id: String,
    checkpoint: u64,
    recorded_at_ms: i64,
    expires_at_ms: i64,
    expired: bool,
    payload: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    schema_version: u16,
    scope: Scope,
    key: String,
    head: Uuid,
    checkpoint: u64,
    state_sha: String,
    profile_sha: String,
    read_at_ms: i64,
    lease_remaining_ms: i64,
    retained_rows: usize,
    retained_bytes: usize,
    records: Vec<WireRecord>,
    truncated: bool,
    cursor: Option<HistoryCursor>,
}
struct Record {
    id: String,
    checkpoint: u64,
    recorded_at_ms: i64,
    expires_at_ms: i64,
    monotonic_expiry: Option<Instant>,
    metadata: Option<serde_json::Value>,
}
/// Private retained bytes can only leave through a bounded, expiry-aware export.
/// This object neither renews a lease nor grants independent read authority.
pub struct HistoryPage {
    scope: Scope,
    key: String,
    head: Uuid,
    checkpoint: u64,
    records: Vec<Record>,
    truncated: bool,
    cursor: Option<HistoryCursor>,
    max_bytes: usize,
    retained_rows: usize,
    retained_bytes: usize,
    context: ControlContext,
}
fn now_ms() -> Result<i64, ControlError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ControlError::Fenced)?
        .as_millis()
        .try_into()
        .map_err(|_| ControlError::Fenced)
}
struct Bounded(Vec<u8>, usize);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.1.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("history export capacity"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl HistoryPage {
    pub fn usage(&self) -> Result<(usize, usize), ControlError> {
        self.context.check()?;
        Ok((self.retained_rows, self.retained_bytes))
    }

    pub fn cursor(&self) -> Result<Option<HistoryCursor>, ControlError> {
        self.context.check()?;
        Ok(self.cursor.clone())
    }
    pub fn export_json(&self) -> Result<Vec<u8>, ControlError> {
        self.context.check()?;
        let now = now_ms()?;
        let monotonic_now = Instant::now();
        #[derive(Serialize)]
        struct Entry<'a> {
            id: &'a str,
            checkpoint: u64,
            recorded_at_ms: i64,
            expires_at_ms: i64,
            expired: bool,
            metadata: Option<&'a serde_json::Value>,
        }
        #[derive(Serialize)]
        struct Export<'a> {
            schema_version: u16,
            scope: &'a Scope,
            key: &'a str,
            head: Uuid,
            checkpoint: u64,
            evidence_kind: &'static str,
            records: &'a [Entry<'a>],
            truncated: bool,
            missing_evidence: bool,
            cursor: &'a Option<HistoryCursor>,
        }
        let records = self
            .records
            .iter()
            .map(|r| {
                let expired = r.metadata.is_none()
                    || r.expires_at_ms <= now
                    || r.monotonic_expiry
                        .is_none_or(|deadline| deadline <= monotonic_now);
                Entry {
                    id: &r.id,
                    checkpoint: r.checkpoint,
                    recorded_at_ms: r.recorded_at_ms,
                    expires_at_ms: r.expires_at_ms,
                    expired,
                    metadata: if expired { None } else { r.metadata.as_ref() },
                }
            })
            .collect::<Vec<_>>();
        let export = Export {
            schema_version: 1,
            scope: &self.scope,
            key: &self.key,
            head: self.head,
            checkpoint: self.checkpoint,
            evidence_kind: "canonical_references",
            records: &records,
            truncated: self.truncated,
            missing_evidence: self.truncated
                || records.is_empty()
                || records.iter().any(|r| r.expired),
            cursor: &self.cursor,
        };
        let mut bytes = Bounded(Vec::new(), self.max_bytes);
        serde_json::to_writer(&mut bytes, &export).map_err(|_| ControlError::Full)?;
        self.context.check()?;
        let delivered = now_ms()?;
        let delivered_monotonic = Instant::now();
        if records.iter().zip(&self.records).any(|(r, original)| {
            r.metadata.is_some()
                && (r.expires_at_ms <= delivered
                    || original
                        .monotonic_expiry
                        .is_none_or(|deadline| deadline <= delivered_monotonic))
        }) {
            return Err(ControlError::SnapshotExpired);
        }
        Ok(bytes.0)
    }
}
fn decode(
    value: serde_json::Value,
    token: &LeaseToken,
    input: &HistoryInput,
    context: &ControlContext,
    anchor: Instant,
) -> Result<HistoryPage, ControlError> {
    if serde_json::to_vec(&value)
        .map_err(|_| ControlError::Corrupt)?
        .len()
        > input.max_bytes
    {
        return Err(ControlError::Full);
    }
    let wire: Wire = serde_json::from_value(value).map_err(|_| ControlError::Corrupt)?;
    if wire.schema_version != 1
        || wire.scope != token.scope
        || wire.key != input.key
        || wire.head != input.head
        || wire.checkpoint == 0
        || wire.checkpoint > i64::MAX as u64
        || !hex(&wire.state_sha)
        || !hex(&wire.profile_sha)
        || wire.retained_rows > 16384
        || wire.retained_bytes > 33554432
        || wire.records.len() > wire.retained_rows
        || (input.cursor.is_none() && !wire.truncated && wire.records.len() != wire.retained_rows)
        || wire.records.len() > input.limit
        || wire.cursor.is_some() != wire.truncated
    {
        return Err(ControlError::Corrupt);
    }
    if let Some(c) = &wire.cursor {
        let mut next = input.clone();
        next.cursor = Some(c.clone());
        next.validate(token).map_err(|_| ControlError::Corrupt)?;
        if c.state_sha != wire.state_sha
            || c.profile_sha != wire.profile_sha
            || wire
                .records
                .last()
                .is_none_or(|r| r.id != c.id || r.checkpoint != c.checkpoint)
        {
            return Err(ControlError::Corrupt);
        }
    }
    let mut records = Vec::with_capacity(wire.records.len());
    let mut before = input.cursor.as_ref().map(|c| (c.checkpoint, c.id.clone()));
    for r in wire.records {
        if !hex(&r.id)
            || r.checkpoint == 0
            || r.checkpoint > wire.checkpoint
            || r.recorded_at_ms >= r.expires_at_ms
            || before
                .as_ref()
                .is_some_and(|p| (r.checkpoint, r.id.as_str()) >= (p.0, p.1.as_str()))
            || r.expired != r.payload.is_none()
        {
            return Err(ControlError::Corrupt);
        }
        let metadata = if let Some(payload) = r.payload {
            if payload.is_empty() || payload.len() > 131072 || !payload.len().is_multiple_of(2) {
                return Err(ControlError::Corrupt);
            }
            let digit = |b: u8| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(ControlError::Corrupt),
            };
            let bytes = payload
                .as_bytes()
                .chunks_exact(2)
                .map(|b| Ok(digit(b[0])? * 16 + digit(b[1])?))
                .collect::<Result<Vec<u8>, ControlError>>()?;
            if Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                != r.id
            {
                return Err(ControlError::Corrupt);
            }
            Some(serde_json::from_slice(&bytes).map_err(|_| ControlError::Corrupt)?)
        } else {
            None
        };
        let monotonic_expiry = if metadata.is_some() {
            let remaining = r
                .expires_at_ms
                .checked_sub(wire.read_at_ms)
                .filter(|n| (1..=31536000000).contains(n))
                .ok_or(ControlError::Corrupt)?;
            Some(anchor + Duration::from_millis(remaining as u64))
        } else {
            None
        };
        before = Some((r.checkpoint, r.id.clone()));
        records.push(Record {
            id: r.id,
            checkpoint: r.checkpoint,
            recorded_at_ms: r.recorded_at_ms,
            expires_at_ms: r.expires_at_ms,
            monotonic_expiry,
            metadata,
        });
    }
    let remaining = wire.lease_remaining_ms;
    if !(1..=60000).contains(&remaining) {
        return Err(ControlError::Fenced);
    }
    let context = context
        .clone()
        .limited_to(anchor + Duration::from_millis(remaining as u64));
    context.check()?;
    Ok(HistoryPage {
        scope: wire.scope,
        key: wire.key,
        head: wire.head,
        checkpoint: wire.checkpoint,
        records,
        truncated: wire.truncated,
        cursor: wire.cursor,
        max_bytes: input.max_bytes,
        retained_rows: wire.retained_rows,
        retained_bytes: wire.retained_bytes,
        context,
    })
}
pub(crate) async fn verify(
    db: &tokio_postgres::Client,
    context: &ControlContext,
) -> Result<(), ControlError> {
    context.check()?;
    if !crate::window_history::verify(db, context).await? {
        return Err(ControlError::Fenced);
    }
    let source = include_str!("../../../schemas/shared-control/013-window-history-read.sql");
    let body = source
        .split_once(" AS $$")
        .and_then(|(_, tail)| tail.split_once("\nEND $$;"))
        .map(|(body, _)| format!("{body}\nEND "))
        .ok_or(ControlError::Corrupt)?;
    let expected: Vec<u8> = Sha256::digest(body.as_bytes()).to_vec();
    let verified:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='signal_window_history_read' AND p.proname='read_page' AND p.pronargs=4 AND p.pronargdefaults=0 AND p.provariadic=0 AND p.prokind='f' AND p.proargtypes[0]='jsonb'::regtype AND p.proargtypes[1]='jsonb'::regtype AND p.proargtypes[2]='bytea'::regtype AND p.proargtypes[3]='bytea'::regtype AND p.prorettype='jsonb'::regtype AND p.prosecdef AND NOT p.proretset AND p.provolatile='v' AND p.proparallel='u' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog, signal_control, pg_temp'] AND p.proowner=n.nspowner AND n.nspowner=(SELECT nspowner FROM pg_namespace WHERE nspname='signal_control') AND (SELECT count(*) FROM pg_proc x WHERE x.pronamespace=n.oid)=1 AND sha256(convert_to(p.prosrc,'UTF8'))=$1)",&[&expected]).await.map_err(crate::client::database_error)?.try_get(0).map_err(|_|ControlError::Corrupt)?;
    if !verified {
        return Err(ControlError::Fenced);
    }
    context.check()
}
pub(crate) async fn run(
    db: &tokio_postgres::Client,
    token: &LeaseToken,
    input: &HistoryInput,
    context: &ControlContext,
    output_context: &ControlContext,
    routines: [u8; 32],
) -> Result<HistoryPage, ControlError> {
    verify(db, context).await?;
    let token_value = serde_json::to_value(token).map_err(|_| ControlError::Invalid)?;
    let request = serde_json::to_value(input).map_err(|_| ControlError::Invalid)?;
    let schema = crate::schema_identity().0;
    let anchor = Instant::now();
    let value = db
        .query_one(
            "SELECT signal_window_history_read.read_page($1,$2,$3,$4)",
            &[&token_value, &request, &&schema[..], &&routines[..]],
        )
        .await
        .map_err(crate::client::database_error)?
        .try_get(0)
        .map_err(|_| ControlError::Corrupt)?;
    context.check()?;
    decode(value, token, input, output_context, anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn token() -> LeaseToken {
        LeaseToken {
            scope: Scope {
                schema_version: 1,
                store_id: Uuid::from_u128(1),
                generation: Uuid::from_u128(2),
                partition_id: Uuid::from_u128(3),
                tenant: "fixture".into(),
                stream: Uuid::from_u128(4),
            },
            owner: Uuid::from_u128(5),
            epoch: 1,
        }
    }
    fn input() -> HistoryInput {
        HistoryInput {
            schema_version: 1,
            key: "window".into(),
            head: Uuid::from_u128(6),
            limit: 2,
            max_bytes: 65536,
            cursor: None,
        }
    }
    fn wire() -> Result<serde_json::Value, ControlError> {
        let now = now_ms()?;
        let payload = br#"{"schema_version":1,"assessment":{"outcome":"indeterminate"}}"#;
        let id = Sha256::digest(payload)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        Ok(
            serde_json::json!({"schema_version":1,"scope":token().scope,"key":"window","head":input().head,
            "checkpoint":2,"state_sha":"11".repeat(32),"profile_sha":"22".repeat(32),"read_at_ms":now,"lease_remaining_ms":60000,"retained_rows":1,"retained_bytes":256+payload.len(),
            "records":[{"id":id,"checkpoint":2,"recorded_at_ms":now,"expires_at_ms":now+60000,
                "expired":false,"payload":payload.iter().map(|b|format!("{b:02x}")).collect::<String>()}],"truncated":false,"cursor":null}),
        )
    }
    fn page() -> Result<HistoryPage, ControlError> {
        decode(
            wire()?,
            &token(),
            &input(),
            &ControlContext::new(Duration::from_secs(5))?,
            Instant::now(),
        )
    }
    #[test]
    fn history_export_withholds_expired_metadata_and_original_cancellation()
    -> Result<(), ControlError> {
        let mut page = page()?;
        let export: serde_json::Value =
            serde_json::from_slice(&page.export_json()?).map_err(|_| ControlError::Corrupt)?;
        assert_eq!(
            export["records"][0]["metadata"]["assessment"]["outcome"],
            "indeterminate"
        );
        assert_eq!(export["missing_evidence"], false);
        page.records[0].expires_at_ms = now_ms()? - 1;
        let export: serde_json::Value =
            serde_json::from_slice(&page.export_json()?).map_err(|_| ControlError::Corrupt)?;
        assert!(export["records"][0]["metadata"].is_null());
        assert_eq!(export["records"][0]["expired"], true);
        assert_eq!(export["missing_evidence"], true);
        page.context.cancel();
        assert!(matches!(page.export_json(), Err(ControlError::Cancelled)));
        assert!(matches!(page.cursor(), Err(ControlError::Cancelled)));
        Ok(())
    }
    #[test]
    fn history_pages_refuse_corrupt_payload_scope_order_and_lease() -> Result<(), ControlError> {
        let context = ControlContext::new(Duration::from_secs(5))?;
        for (path, value) in [
            (
                "/scope/partition_id",
                serde_json::json!(Uuid::from_u128(99)),
            ),
            ("/records/0/id", serde_json::json!("00".repeat(32))),
            ("/records/0/payload", serde_json::json!("gg")),
            ("/records/0/expired", serde_json::json!(true)),
            ("/records/0/checkpoint", serde_json::json!(3)),
            ("/state_sha", serde_json::json!("short")),
            ("/lease_remaining_ms", serde_json::json!(-1)),
        ] {
            let mut value_wire = wire()?;
            *value_wire.pointer_mut(path).ok_or(ControlError::Corrupt)? = value;
            assert!(
                decode(value_wire, &token(), &input(), &context, Instant::now()).is_err(),
                "{path}"
            );
        }
        let mut duplicate = wire()?;
        duplicate["records"] =
            serde_json::json!([duplicate["records"][0], duplicate["records"][0]]);
        assert!(decode(duplicate, &token(), &input(), &context, Instant::now()).is_err());
        let mut empty = wire()?;
        empty["records"] = serde_json::json!([]);
        empty["retained_rows"] = serde_json::json!(0);
        empty["retained_bytes"] = serde_json::json!(0);
        let export = decode(empty, &token(), &input(), &context, Instant::now())?.export_json()?;
        let export: serde_json::Value =
            serde_json::from_slice(&export).map_err(|_| ControlError::Corrupt)?;
        assert_eq!(export["missing_evidence"], true);
        let mut page = page()?;
        page.max_bytes = 1;
        assert!(matches!(page.export_json(), Err(ControlError::Full)));
        Ok(())
    }
    #[test]
    fn history_cursor_scope_revision_position_and_request_bounds() -> Result<(), ControlError> {
        let mut wire = wire()?;
        let cursor = HistoryCursor {
            schema_version: 1,
            scope: token().scope,
            key: "window".into(),
            head: input().head,
            state_sha: "11".repeat(32),
            profile_sha: "22".repeat(32),
            checkpoint: 2,
            id: wire["records"][0]["id"]
                .as_str()
                .ok_or(ControlError::Corrupt)?
                .into(),
        };
        wire["truncated"] = serde_json::json!(true);
        wire["cursor"] = serde_json::to_value(&cursor).map_err(|_| ControlError::Corrupt)?;
        let context = ControlContext::new(Duration::from_secs(5))?;
        let page = decode(wire.clone(), &token(), &input(), &context, Instant::now())?;
        assert!(page.cursor()?.is_some());
        wire["cursor"]["profile_sha"] = serde_json::json!("33".repeat(32));
        assert!(decode(wire, &token(), &input(), &context, Instant::now()).is_err());
        let mut request = input();
        request.cursor = Some(cursor.clone());
        request.validate(&token())?;
        request
            .cursor
            .as_mut()
            .ok_or(ControlError::Corrupt)?
            .scope
            .stream = Uuid::from_u128(99);
        assert!(matches!(
            request.validate(&token()),
            Err(ControlError::Conflict)
        ));
        request = input();
        request.limit = 129;
        assert!(request.validate(&token()).is_err());
        request = input();
        request.max_bytes = 1048577;
        assert!(request.validate(&token()).is_err());
        request = input();
        request.cursor = Some(cursor);
        let value = wire_for_position()?;
        assert!(decode(value, &token(), &request, &context, Instant::now()).is_err());
        Ok(())
    }
    fn wire_for_position() -> Result<serde_json::Value, ControlError> {
        wire()
    }
    #[test]
    fn history_export_and_lease_deadlines_do_not_depend_on_client_clock_agreement()
    -> Result<(), ControlError> {
        let mut page = page()?;
        assert!(page.records[0].expires_at_ms > now_ms()?);
        page.records[0].monotonic_expiry = Some(Instant::now() - Duration::from_secs(1));
        let export: serde_json::Value =
            serde_json::from_slice(&page.export_json()?).map_err(|_| ControlError::Corrupt)?;
        assert!(export["records"][0]["metadata"].is_null());
        assert_eq!(export["missing_evidence"], true);
        let mut response = wire()?;
        response["lease_remaining_ms"] = serde_json::json!(1);
        assert!(matches!(
            decode(
                response,
                &token(),
                &input(),
                &ControlContext::new(Duration::from_secs(5))?,
                Instant::now() - Duration::from_secs(1)
            ),
            Err(ControlError::Timeout)
        ));
        Ok(())
    }
}
