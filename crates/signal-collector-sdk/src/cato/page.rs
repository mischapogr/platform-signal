//! Finite selected capture epoch; trusted host owns atomic custody and publication.
use super::{
    Error, EventsClient, KeyProvider, MAX_BODY_BYTES, MAX_MARKER_BYTES, Position, check, within,
};
use crate::ExtensionContext;
use async_trait::async_trait;
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use signal_event::{IngestEvent, SignalEvent};
use uuid::Uuid;
pub const MAX_PAGES: usize = 16;
pub const MAX_RECORDS: usize = 3000;
pub const MAX_RECORD_BYTES: usize = 65536;
pub const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    name: String,
    id: Uuid,
    initial: Position,
}
impl Epoch {
    /// Explicit private bootstrap authority. Latest starts at recent events;
    /// supplied resume markers are assertions, never historical coverage proof.
    pub fn new(name: &str, id: Uuid, initial: Position) -> Result<Self, Error> {
        if name.is_empty()
            || name.len() > 128
            || name.trim() != name
            || name.chars().any(char::is_control)
            || id.is_nil()
        {
            return Err(Error::Configuration);
        }
        initial.validate_shape()?;
        Ok(Self {
            name: name.into(),
            id,
            initial,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    requested: Position,
    next: String,
    observed_at: DateTime<Utc>,
    original: Vec<u8>,
    prepared: Vec<SignalEvent>,
}
impl Page {
    pub fn original(&self) -> &[u8] {
        &self.original
    }
    pub fn events(&self) -> &[SignalEvent] {
        &self.prepared
    }
    pub fn next_marker(&self) -> &str {
        &self.next
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u16,
    endpoint: String,
    account: String,
    epoch: Epoch,
    pages: Vec<Page>,
}
impl State {
    pub fn revision(&self) -> u64 {
        self.pages.len() as u64
    }
    pub fn pages(&self) -> &[Page] {
        &self.pages
    }
    pub fn events(&self) -> impl Iterator<Item = &SignalEvent> {
        self.pages.iter().flat_map(|p| p.prepared.iter())
    }
    pub fn position(&self) -> Position {
        self.pages.last().map_or_else(
            || self.epoch.initial.clone(),
            |p| Position::Resume {
                marker: p.next.clone(),
                committed_at: p.observed_at,
            },
        )
    }
}
/// Trusted private host: bounded loads, protected original custody, atomic CAS
/// of entire state, disk quotas and physical worker ownership after cancellation.
/// Publication progress is separate; HTTP202 does not retire this outbox.
#[async_trait]
pub trait PageJournal: Send + Sync {
    async fn load(&self, context: &ExtensionContext) -> Result<Option<State>, Error>;
    async fn commit(
        &self,
        expected_revision: u64,
        next: &State,
        context: &ExtensionContext,
    ) -> Result<(), Error>;
}
pub struct Pager<'a, J, K> {
    client: &'a EventsClient,
    journal: &'a J,
    keys: &'a K,
    epoch: Epoch,
}
impl<'a, J: PageJournal, K: KeyProvider> Pager<'a, J, K> {
    pub fn new(client: &'a EventsClient, journal: &'a J, keys: &'a K, epoch: Epoch) -> Self {
        Self {
            client,
            journal,
            keys,
            epoch,
        }
    }
    pub async fn load(&self, context: &ExtensionContext) -> Result<State, Error> {
        let state = within(context, self.journal.load(context))
            .await?
            .unwrap_or_else(|| State {
                schema_version: 1,
                endpoint: self.client.endpoint().into(),
                account: self.client.account().into(),
                epoch: self.epoch.clone(),
                pages: Vec::new(),
            });
        self.validate(&state, context)?;
        Ok(state)
    }
    pub async fn advance(&mut self, context: &ExtensionContext) -> Result<State, Error> {
        // Always reload: a dropped/lost commit reply can conceal durable success.
        let mut state = self.load(context).await?;
        if state.pages.len() >= MAX_PAGES {
            return Err(Error::Limit);
        }
        let revision = state.revision();
        let requested = state.position();
        let original = self
            .client
            .capture(&requested, self.keys, context)
            .await?
            .original_bytes;
        let observed_at = Utc::now();
        let (next, prepared) = prepare(&original, &state, self.client, observed_at, context)?;
        if let Position::Resume { marker, .. } = &requested {
            if next == *marker && !prepared.is_empty() {
                return Err(Error::Conflict);
            }
            if next != *marker
                && (state.pages.iter().any(|p| p.next == next)
                    || matches!(&state.epoch.initial, Position::Resume { marker, .. } if *marker == next))
            {
                return Err(Error::Conflict);
            }
        }
        requested.marker()?;
        state.pages.push(Page {
            requested,
            next,
            observed_at,
            original,
            prepared,
        });
        bounded(&state)?;
        within(context, self.journal.commit(revision, &state, context)).await?;
        Ok(state)
    }
    fn validate(&self, state: &State, context: &ExtensionContext) -> Result<(), Error> {
        if state.schema_version != 1
            || state.endpoint != self.client.endpoint()
            || state.account != self.client.account()
            || state.epoch != self.epoch
            || state.pages.len() > MAX_PAGES
        {
            return Err(Error::Scope);
        }
        bounded(state)?;
        let mut position = state.epoch.initial.clone();
        // Historical retained pages are valid after source retention expires;
        // only the next source request needs a still-live cursor.
        for (i, page) in state.pages.iter().enumerate() {
            check(context)?;
            if page.requested != position {
                return Err(Error::Conflict);
            }
            let (next, events) = prepare(
                &page.original,
                state,
                self.client,
                page.observed_at,
                context,
            )?;
            if next != page.next || events != page.prepared {
                return Err(Error::Conflict);
            }
            if let Position::Resume { marker, .. } = &position {
                if next == *marker && !events.is_empty() {
                    return Err(Error::Conflict);
                }
                if next != *marker
                    && (state.pages[..i].iter().any(|p| p.next == next)
                        || matches!(&state.epoch.initial, Position::Resume { marker, .. } if *marker == next))
                {
                    return Err(Error::Conflict);
                }
            }
            position = Position::Resume {
                marker: next,
                committed_at: page.observed_at,
            };
        }
        Ok(())
    }
}
fn bounded(state: &State) -> Result<(), Error> {
    if state
        .pages
        .iter()
        .any(|p| p.original.len() > MAX_BODY_BYTES || p.prepared.len() > MAX_RECORDS)
    {
        return Err(Error::Limit);
    }
    if serde_json::to_vec(state)
        .map_err(|_| Error::Response)?
        .len()
        > MAX_STATE_BYTES
    {
        return Err(Error::Limit);
    }
    Ok(())
}
fn prepare(
    raw: &[u8],
    state: &State,
    client: &EventsClient,
    observed_at: DateTime<Utc>,
    context: &ExtensionContext,
) -> Result<(String, Vec<SignalEvent>), Error> {
    check(context)?;
    if raw.len() > MAX_BODY_BYTES || !(1..=9999).contains(&observed_at.year()) {
        return Err(Error::Limit);
    }
    let v: Value = serde_json::from_slice(raw).map_err(|_| Error::Response)?;
    // Any GraphQL errors, including partial data, refuse the complete page.
    if v.get("errors")
        .is_some_and(|e| !e.is_null() && e.as_array().is_none_or(|a| !a.is_empty()))
    {
        return Err(Error::Response);
    }
    let feed = v
        .pointer("/data/eventsFeed")
        .and_then(Value::as_object)
        .ok_or(Error::Response)?;
    let next = feed
        .get("marker")
        .and_then(Value::as_str)
        .filter(|s| {
            !s.is_empty() && s.len() <= MAX_MARKER_BYTES && !s.chars().any(char::is_control)
        })
        .ok_or(Error::Response)?
        .to_owned();
    let count = feed
        .get("fetchedCount")
        .and_then(Value::as_u64)
        .filter(|n| *n <= MAX_RECORDS as u64)
        .ok_or(Error::Limit)?;
    let accounts = feed
        .get("accounts")
        .and_then(Value::as_array)
        .filter(|a| a.len() <= 1)
        .ok_or(Error::Scope)?;
    let digest = Sha256::digest(raw);
    let mut events = Vec::new();
    for account in accounts {
        if account.get("id").and_then(Value::as_str) != Some(client.account())
            || account
                .get("errorString")
                .is_some_and(|e| !e.is_null() && e.as_str() != Some(""))
        {
            return Err(Error::Scope);
        }
        let records = account
            .get("records")
            .and_then(Value::as_array)
            .filter(|r| r.len() <= MAX_RECORDS)
            .ok_or(Error::Limit)?;
        for record in records {
            check(context)?;
            if serde_json::to_vec(record)
                .map_err(|_| Error::Response)?
                .len()
                > MAX_RECORD_BYTES
            {
                return Err(Error::Limit);
            }
            let timestamp = record
                .get("time")
                .and_then(Value::as_str)
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&Utc))
                .ok_or(Error::Response)?;
            let fields = record
                .get("fieldsMap")
                .and_then(Value::as_object)
                .filter(|f| f.len() <= 256)
                .ok_or(Error::Limit)?;
            if fields.get("event_type").and_then(Value::as_str) != Some("Security")
                || fields
                    .get("account_id")
                    .is_some_and(|v| v.as_str() != Some(client.account()))
            {
                return Err(Error::Scope);
            }
            let subtype = fields
                .get("event_sub_type")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
                .ok_or(Error::Response)?;
            let ordinal = events.len() as u32;
            let mut hash = Sha256::new();
            for piece in [
                client.endpoint().as_bytes(),
                client.account().as_bytes(),
                state.epoch.name.as_bytes(),
                state.epoch.id.as_bytes(),
                digest.as_slice(),
                &ordinal.to_be_bytes(),
            ] {
                hash.update((piece.len() as u64).to_be_bytes());
                hash.update(piece);
            }
            let bytes = hash.finalize();
            let mut id = [0u8; 16];
            id.copy_from_slice(&bytes[..16]);
            id[6] = (id[6] & 15) | 0x80;
            id[8] = (id[8] & 63) | 0x80;
            let input:IngestEvent=serde_json::from_value(serde_json::json!({"timestamp":timestamp,"source":{"type":"cato.eventsfeed","name":state.epoch.name},"severity":"info","message":format!("Cato security event: {subtype}"),"resource":{"kind":"cato-account","id":client.account(),"account_id":client.account()},"attributes":{"cato":{"fields":fields},"source_receipt":{"epoch":state.epoch.id,"ordinal":ordinal},"normalizer":{"id":"cato-security-eventsfeed","revision":"v1"},"coverage":{"event_type":"Security","filtered":true,"completeness":"not_assessed","marker_validity":"provider_assertion","bootstrap":"explicit_private_selection"}}})).map_err(|_|Error::Response)?;
            let mut event = input.normalize(observed_at).map_err(|_| Error::Response)?;
            event.id = Uuid::from_bytes(id);
            events.push(event);
        }
    }
    if events.len() as u64 != count {
        return Err(Error::Response);
    }
    check(context)?;
    Ok((next, events))
}
