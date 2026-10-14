//! One bounded capture window and trusted application-owned atomic journal.
use super::{ActivityClient, Error, FEED, TokenProvider, check, within};
use crate::ExtensionContext;
use async_trait::async_trait;
use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use signal_event::{IngestEvent, SignalEvent};
use std::collections::BTreeMap;
use uuid::Uuid;
pub const MAX_PAGES: usize = 32;
pub const MAX_CONTENTS: usize = 512;
pub const MAX_EVENTS: usize = 4096;
pub const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Window {
    name: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    publisher: Uuid,
}
impl Window {
    pub fn new(
        name: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        publisher: Uuid,
    ) -> Result<Self, Error> {
        if name.is_empty()
            || name.len() > 128
            || name.trim() != name
            || name.chars().any(char::is_control)
            || !(1..=9999).contains(&start.year())
            || !(1..=9999).contains(&end.year())
            || publisher.is_nil()
            || end <= start
            || end - start > chrono::Duration::hours(24)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            name: name.into(),
            start,
            end,
            publisher,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seen {
    digest: [u8; 32],
    event: SignalEvent,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    id: String,
    bytes: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    request: String,
    actual_request: String,
    next: Option<String>,
    listing: Vec<u8>,
    blobs: Vec<Blob>,
    event_ids: Vec<Uuid>,
}
impl Page {
    pub fn request_uri(&self) -> &str {
        &self.request
    }
    pub fn actual_request_uri(&self) -> &str {
        &self.actual_request
    }
    pub fn original_listing(&self) -> &[u8] {
        &self.listing
    }
    pub fn original_contents(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.blobs
            .iter()
            .map(|b| (b.id.as_str(), b.bytes.as_slice()))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u16,
    root: String,
    tenant: Uuid,
    window: Window,
    cursor: Option<String>,
    pages: Vec<Page>,
    contents: BTreeMap<String, [u8; 32]>,
    events: BTreeMap<Uuid, Seen>,
}
impl State {
    pub fn revision(&self) -> u64 {
        self.pages.len() as u64
    }
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
    pub fn complete(&self) -> bool {
        self.cursor.is_none()
    }
    pub fn pages(&self) -> &[Page] {
        &self.pages
    }
    /// The durable outbox. Publication progress is separately caller-owned;
    /// replay uses these exact canonical values, never current enrichment.
    pub fn events(&self) -> impl Iterator<Item = &SignalEvent> {
        self.events.values().map(|v| &v.event)
    }
    pub fn depth(&self) -> (usize, usize, usize) {
        (self.pages.len(), self.contents.len(), self.events.len())
    }
    pub fn capacity(&self) -> (usize, usize, usize) {
        (MAX_PAGES, MAX_CONTENTS, MAX_EVENTS)
    }
}
/// Trusted extension seam, not a disk-sync proof. Commit must atomically own
/// ALL originals/prepared bytes and cursor with compare-and-swap revision.
/// A returned error/cancellation can be uncertain: reload before retry. The
/// implementation owns finite disk quotas and physical worker retention.
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
struct Size(usize);
impl std::io::Write for Size {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_STATE_BYTES)
            .ok_or_else(|| std::io::Error::other("state limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn first(client: &ActivityClient, window: &Window) -> Result<String, Error> {
    let mut url = reqwest::Url::parse(&format!("{}subscriptions/content", client.root()))
        .map_err(|_| Error::Configuration)?;
    url.query_pairs_mut()
        .append_pair("contentType", FEED)
        .append_pair("startTime", &window.start.to_rfc3339())
        .append_pair("endTime", &window.end.to_rfc3339())
        .append_pair("PublisherIdentifier", &window.publisher.to_string());
    Ok(url.into())
}
fn listing_uri(client: &ActivityClient, window: &Window, uri: &str) -> Result<(), Error> {
    let url = client.validate_uri(uri)?;
    if !client.is_listing_uri(&url) {
        return Err(Error::Scope);
    }
    let mut pairs = BTreeMap::new();
    for (k, v) in url.query_pairs() {
        if !matches!(
            k.as_ref(),
            "contentType" | "startTime" | "endTime" | "PublisherIdentifier" | "nextPage"
        ) || pairs.insert(k.into_owned(), v.into_owned()).is_some()
        {
            return Err(Error::Scope);
        }
    }
    if pairs.get("contentType").map(String::as_str) != Some(FEED) {
        return Err(Error::Scope);
    }
    for (key, expected) in [("startTime", window.start), ("endTime", window.end)] {
        let value = pairs.get(key).ok_or(Error::Scope)?;
        let instant = time(value).or_else(|_| {
            chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .map(|t| t.and_utc())
                .ok_or(Error::Scope)
        })?;
        if instant != expected {
            return Err(Error::Scope);
        }
    }
    if let Some(publisher) = pairs.get("PublisherIdentifier")
        && Uuid::parse_str(publisher).map_err(|_| Error::Scope)? != window.publisher
    {
        return Err(Error::Scope);
    }
    if pairs
        .get("nextPage")
        .is_some_and(|v| v.is_empty() || v.len() > 1024 || v.chars().any(char::is_control))
    {
        return Err(Error::Scope);
    }
    Ok(())
}
fn request_uri(client: &ActivityClient, window: &Window, raw: &str) -> Result<String, Error> {
    listing_uri(client, window, raw)?;
    let mut url = client.validate_uri(raw)?;
    if !url
        .query_pairs()
        .any(|(key, _)| key == "PublisherIdentifier")
    {
        url.query_pairs_mut()
            .append_pair("PublisherIdentifier", &window.publisher.to_string());
    }
    Ok(url.into())
}
fn json(bytes: &[u8]) -> Result<Value, Error> {
    crate::cloudtrail::decode_json(bytes, super::MAX_BODY_BYTES, 32, 65536)
        .map_err(|_| Error::Response)
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 4096)
        .ok_or(Error::Response)
}
fn time(value: &str) -> Result<DateTime<Utc>, Error> {
    if let Ok(t) = DateTime::parse_from_rfc3339(value) {
        return Ok(t.with_timezone(&Utc));
    }
    // The native common schema documents UTC values, including zone-less samples.
    NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
        .map(|t| t.and_utc())
        .map_err(|_| Error::Response)
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn event_id(client: &ActivityClient, window: &Window, id: Uuid) -> Uuid {
    let mut h = Sha256::new();
    h.update(b"PLATFORM::SIGNAL/m365-activity/v1\0");
    for part in [
        client.root(),
        window.name.as_str(),
        FEED,
        &window.start.to_rfc3339(),
        &window.end.to_rfc3339(),
        &window.publisher.to_string(),
    ] {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part.as_bytes());
    }
    h.update(id.as_bytes());
    let d = h.finalize();
    let mut b = [0; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 15) | 0x80;
    b[8] = (b[8] & 63) | 0x80;
    Uuid::from_bytes(b)
}
fn normalize(
    client: &ActivityClient,
    window: &Window,
    native: &Value,
    observed: DateTime<Utc>,
    context: &ExtensionContext,
) -> Result<(Uuid, Seen), Error> {
    let id = Uuid::parse_str(text(native, "Id")?).map_err(|_| Error::Response)?;
    if id.is_nil()
        || Uuid::parse_str(text(native, "OrganizationId")?).map_err(|_| Error::Scope)?
            != client.tenant()
    {
        return Err(Error::Scope);
    }
    if text(native, "Workload")? != "AzureActiveDirectory"
        || native.get("RecordType").and_then(Value::as_u64).is_none()
        || native.get("UserType").and_then(Value::as_u64).is_none()
    {
        return Err(Error::Response);
    }
    for key in ["Operation", "UserId", "UserKey"] {
        text(native, key)?;
    }
    let timestamp = time(text(native, "CreationTime")?)?;
    let input:IngestEvent=serde_json::from_value(serde_json::json!({"timestamp":timestamp,
        "source":{"type":"m365.activity","name":window.name},"severity":"info","message":"Microsoft 365 audit activity",
        "resource":{"kind":"m365-tenant","id":client.tenant(),"account_id":client.tenant().to_string()},
        "attributes":{"m365":native,"normalizer":{"id":"m365-activity-aad","revision":"v1"},
            "coverage":{"feed":FEED,"completeness":"not_assessed","graph_sign_ins":"not_assessed"}}
    })).map_err(|_|Error::Response)?;
    let mut event = input.normalize(observed).map_err(|_| Error::Response)?;
    event.id = event_id(client, window, id);
    crate::validate_event(&event, crate::EventLimits::default(), context)
        .map_err(|_| check(context).err().unwrap_or(Error::Limit))?;
    let bytes = serde_json::to_vec(native).map_err(|_| Error::Response)?;
    Ok((
        id,
        Seen {
            digest: digest(&bytes),
            event,
        },
    ))
}
impl ActivityClient {
    /// One page per invocation; no detached poll loop, implicit subscription start,
    /// checkpoint-only write or publication. Resume by loading the atomic journal.
    pub async fn advance(
        &mut self,
        window: &Window,
        tokens: &impl TokenProvider,
        journal: &impl PageJournal,
        context: &ExtensionContext,
    ) -> Result<State, Error> {
        check(context)?;
        Window::new(&window.name, window.start, window.end, window.publisher)?;
        let mut state = within(context, journal.load(context))
            .await?
            .unwrap_or(State {
                schema_version: 1,
                root: self.root().into(),
                tenant: self.tenant(),
                window: window.clone(),
                cursor: Some(first(self, window)?),
                pages: Vec::new(),
                contents: BTreeMap::new(),
                events: BTreeMap::new(),
            });
        self.validate_state(window, &state, context)?;
        let Some(uri) = state.cursor.clone() else {
            return Ok(state);
        };
        if state.pages.len() >= MAX_PAGES {
            return Err(Error::Limit);
        }
        let expected = state.revision();
        let actual_request = request_uri(self, window, &uri)?;
        let listing = self.capture(&actual_request, tokens, context).await?;
        if let Some(next) = &listing.next_page_uri {
            listing_uri(self, window, next)?;
            if next == &uri || state.pages.iter().any(|p| &p.request == next) {
                return Err(Error::Conflict);
            }
        }
        let rows = json(&listing.original_bytes)?;
        let rows = rows
            .as_array()
            .filter(|a| a.len() <= 64)
            .ok_or(Error::Limit)?;
        let mut page = Page {
            request: uri,
            actual_request,
            next: listing.next_page_uri,
            listing: listing.original_bytes,
            blobs: Vec::new(),
            event_ids: Vec::new(),
        };
        for metadata in rows {
            check(context)?;
            if text(metadata, "contentType")? != FEED {
                return Err(Error::Scope);
            }
            let id = text(metadata, "contentId")?.to_owned();
            let content_uri = text(metadata, "contentUri")?;
            let url = self.validate_uri(content_uri)?;
            if !url
                .path()
                .strip_prefix(
                    reqwest::Url::parse(self.root())
                        .map_err(|_| Error::Configuration)?
                        .path(),
                )
                .is_some_and(|tail| tail.starts_with("audit/"))
            {
                return Err(Error::Scope);
            }
            let created = time(text(metadata, "contentCreated")?)?;
            let expiration = time(text(metadata, "contentExpiration")?)?;
            if created < window.start || created >= window.end {
                return Err(Error::Scope);
            }
            if expiration <= Utc::now() {
                return Err(Error::Expired);
            }
            if expiration <= created {
                return Err(Error::Response);
            }
            let capture = self.capture(content_uri, tokens, context).await?;
            if capture.next_page_uri.is_some() {
                return Err(Error::Response);
            }
            let hash = digest(&capture.original_bytes);
            if state.contents.get(&id).is_some_and(|old| old != &hash) {
                return Err(Error::Conflict);
            }
            state.contents.insert(id.clone(), hash);
            if state.contents.len() > MAX_CONTENTS {
                return Err(Error::Limit);
            }
            let native = json(&capture.original_bytes)?;
            let native = native
                .as_array()
                .filter(|v| v.len() <= 1024)
                .ok_or(Error::Limit)?;
            let observed = Utc::now();
            for row in native {
                check(context)?;
                let (key, seen) = normalize(self, window, row, observed, context)?;
                if let Some(old) = state.events.get(&key) {
                    if old.digest != seen.digest {
                        return Err(Error::Conflict);
                    }
                } else {
                    state.events.insert(key, seen);
                    page.event_ids.push(key);
                }
                if state.events.len() > MAX_EVENTS {
                    return Err(Error::Limit);
                }
            }
            page.blobs.push(Blob {
                id,
                bytes: capture.original_bytes,
            });
            // Validate finite memory/state size before proceeding to another blob.
            let mut budget = Size(0);
            serde_json::to_writer(&mut budget, &state).map_err(|_| Error::Limit)?;
            serde_json::to_writer(&mut budget, &page).map_err(|_| Error::Limit)?;
        }
        state.cursor = page.next.clone();
        state.pages.push(page);
        self.validate_state(window, &state, context)?;
        within(context, journal.commit(expected, &state, context)).await?;
        Ok(state)
    }
    fn validate_state(
        &self,
        window: &Window,
        state: &State,
        context: &ExtensionContext,
    ) -> Result<(), Error> {
        check(context)?;
        if state.schema_version != 1
            || state.root != self.root()
            || state.tenant != self.tenant()
            || &state.window != window
        {
            return Err(Error::Scope);
        }
        if state.pages.len() > MAX_PAGES
            || state.contents.len() > MAX_CONTENTS
            || state.events.len() > MAX_EVENTS
        {
            return Err(Error::Limit);
        }
        serde_json::to_writer(&mut Size(0), state).map_err(|_| Error::Limit)?;
        let mut cursor = Some(first(self, window)?);
        let mut seen_requests = std::collections::BTreeSet::new();
        let mut content_hashes = BTreeMap::new();
        let mut event_hashes = BTreeMap::new();
        for page in &state.pages {
            check(context)?;
            listing_uri(self, window, &page.request)?;
            if page.actual_request != request_uri(self, window, &page.request)? {
                return Err(Error::Conflict);
            }
            if cursor.as_ref() != Some(&page.request)
                || !seen_requests.insert(&page.request)
                || page.blobs.len() > 64
            {
                return Err(Error::Conflict);
            }
            let metadata = json(&page.listing)?;
            let metadata = metadata
                .as_array()
                .filter(|v| v.len() == page.blobs.len())
                .ok_or(Error::Conflict)?;
            let mut first_ids = Vec::new();
            for (meta, blob) in metadata.iter().zip(&page.blobs) {
                if text(meta, "contentType")? != FEED || text(meta, "contentId")? != blob.id {
                    return Err(Error::Scope);
                }
                let uri = self.validate_uri(text(meta, "contentUri")?)?;
                if !uri
                    .path()
                    .strip_prefix(
                        reqwest::Url::parse(self.root())
                            .map_err(|_| Error::Configuration)?
                            .path(),
                    )
                    .is_some_and(|s| s.starts_with("audit/"))
                {
                    return Err(Error::Scope);
                }
                let created = time(text(meta, "contentCreated")?)?;
                if created < window.start
                    || created >= window.end
                    || time(text(meta, "contentExpiration")?)? <= created
                {
                    return Err(Error::Scope);
                }
                if blob.bytes.len() > super::MAX_BODY_BYTES {
                    return Err(Error::Limit);
                }
                let hash = digest(&blob.bytes);
                if state.contents.get(&blob.id) != Some(&hash)
                    || content_hashes
                        .insert(blob.id.clone(), hash)
                        .is_some_and(|old| old != hash)
                {
                    return Err(Error::Conflict);
                }
                let native = json(&blob.bytes)?;
                let native = native
                    .as_array()
                    .filter(|v| v.len() <= 1024)
                    .ok_or(Error::Limit)?;
                for row in native {
                    check(context)?;
                    let id = Uuid::parse_str(text(row, "Id")?).map_err(|_| Error::Response)?;
                    let saved = state.events.get(&id).ok_or(Error::Conflict)?;
                    let (id, expected) =
                        normalize(self, window, row, saved.event.observed_at, context)?;
                    if expected.digest != saved.digest || expected.event != saved.event {
                        return Err(Error::Conflict);
                    }
                    if let Some(old) = event_hashes.insert(id, expected.digest) {
                        if old != expected.digest {
                            return Err(Error::Conflict);
                        }
                    } else {
                        first_ids.push(id);
                    }
                }
            }
            if first_ids != page.event_ids {
                return Err(Error::Conflict);
            }
            cursor = page.next.clone();
            if let Some(uri) = &cursor {
                listing_uri(self, window, uri)?;
                if seen_requests.contains(uri) {
                    return Err(Error::Conflict);
                }
            }
        }
        if cursor != state.cursor
            || content_hashes != state.contents
            || event_hashes.len() != state.events.len()
        {
            return Err(Error::Conflict);
        }
        check(context)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn prepared_delivery_identity_binds_window_and_publisher() {
        let client =
            ActivityClient::local_fixture("http://127.0.0.1:9", Uuid::from_u128(1)).unwrap();
        let start: DateTime<Utc> = "2026-10-14T00:00:00Z"
            .parse()
            .unwrap_or_else(|_| unreachable!("literal timestamp"));
        let first = Window::new(
            "fixture",
            start,
            start + chrono::Duration::hours(1),
            Uuid::from_u128(2),
        )
        .unwrap_or_else(|_| unreachable!("valid fixture window"));
        let second = Window::new(
            "fixture",
            start + chrono::Duration::hours(1),
            start + chrono::Duration::hours(2),
            Uuid::from_u128(2),
        )
        .unwrap_or_else(|_| unreachable!("valid fixture window"));
        let publisher = Window::new(
            "fixture",
            start,
            start + chrono::Duration::hours(1),
            Uuid::from_u128(3),
        )
        .unwrap_or_else(|_| unreachable!("valid fixture window"));
        let id = Uuid::from_u128(100);
        assert_eq!(event_id(&client, &first, id), event_id(&client, &first, id));
        assert_ne!(
            event_id(&client, &first, id),
            event_id(&client, &second, id)
        );
        assert_ne!(
            event_id(&client, &first, id),
            event_id(&client, &publisher, id)
        );
    }
}
