//! Pure bounded Kubernetes list/watch reconciliation. The application owns
//! authenticated transport, original stream sequencing, custody and persistence.
pub mod client;
mod projection;
use chrono::{DateTime, Datelike, TimeDelta, Utc};
pub use projection::MetadataObject;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Kind {
    Pod,
    Node,
    Namespace,
    Role,
    ClusterRole,
    RoleBinding,
    ClusterRoleBinding,
}
impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Pod => "Pod",
            Self::Node => "Node",
            Self::Namespace => "Namespace",
            Self::Role => "Role",
            Self::ClusterRole => "ClusterRole",
            Self::RoleBinding => "RoleBinding",
            Self::ClusterRoleBinding => "ClusterRoleBinding",
        }
    }
    pub fn api_version(self) -> &'static str {
        match self {
            Self::Pod | Self::Node | Self::Namespace => "v1",
            _ => "rbac.authorization.k8s.io/v1",
        }
    }
    pub fn namespaced(self) -> bool {
        matches!(self, Self::Pod | Self::Role | Self::RoleBinding)
    }
}
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum Error {
    #[error("invalid Kubernetes context configuration")]
    Configuration,
    #[error("invalid or conflicting Kubernetes metadata record")]
    Record,
    #[error("Kubernetes context scope mismatch")]
    Scope,
    #[error("Kubernetes context capacity exceeded")]
    Limit,
    #[error("Kubernetes context stream/list continuity lost")]
    Continuity,
    #[error("Kubernetes context is stale or clock regressed")]
    Stale,
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_objects: usize,
    pub max_inventory_bytes: usize,
    pub max_object_bytes: usize,
    pub max_page_bytes: usize,
    pub max_pages: usize,
    pub max_watch_frames: u64,
    pub max_watch_bytes: usize,
    pub max_age_seconds: i64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_objects: 1024,
            max_inventory_bytes: 4 * 1024 * 1024,
            max_object_bytes: 64 * 1024,
            max_page_bytes: 1024 * 1024,
            max_pages: 64,
            max_watch_frames: 4096,
            max_watch_bytes: 8 * 1024 * 1024,
            max_age_seconds: 300,
        }
    }
}
#[derive(Clone)]
pub struct Profile {
    cluster: String,
    kind: Kind,
    namespace: Option<String>,
    node: Option<String>,
    limits: Limits,
    binding: String,
}
impl Profile {
    /// None namespace explicitly selects all namespaces for namespaced kinds.
    /// Node selectors apply only to Pods. No trust is inferred from record fields.
    pub fn new(
        cluster: &str,
        kind: Kind,
        namespace: Option<&str>,
        node: Option<&str>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if !text(cluster)
            || namespace.is_some_and(|s| !text(s))
            || node.is_some_and(|s| !text(s))
            || !kind.namespaced() && namespace.is_some()
            || node.is_some() && kind != Kind::Pod
            || !(1..=4096).contains(&limits.max_objects)
            || !(1024..=16 * 1024 * 1024).contains(&limits.max_inventory_bytes)
            || !(256..=256 * 1024).contains(&limits.max_object_bytes)
            || limits.max_object_bytes > limits.max_inventory_bytes
            || !(256..=2 * 1024 * 1024).contains(&limits.max_page_bytes)
            || !(1..=128).contains(&limits.max_pages)
            || !(1..=65_536).contains(&limits.max_watch_frames)
            || !(256..=64 * 1024 * 1024).contains(&limits.max_watch_bytes)
            || !(1..=3600).contains(&limits.max_age_seconds)
        {
            return Err(Error::Configuration);
        }
        let wire = serde_json::to_vec(&(
            1,
            cluster,
            kind,
            namespace,
            node,
            limits.max_objects,
            limits.max_inventory_bytes,
            limits.max_object_bytes,
            limits.max_page_bytes,
            limits.max_pages,
            limits.max_watch_frames,
            limits.max_watch_bytes,
            limits.max_age_seconds,
        ))
        .map_err(|_| Error::Configuration)?;
        let binding = Sha256::digest(wire)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(Self {
            cluster: cluster.into(),
            kind,
            namespace: namespace.map(str::to_owned),
            node: node.map(str::to_owned),
            limits,
            binding,
        })
    }
    pub fn binding(&self) -> &str {
        &self.binding
    }
}
fn text(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.trim() == s && !s.chars().any(char::is_control)
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str, Error> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| text(s))
        .ok_or(Error::Record)
}
fn time_ok(time: DateTime<Utc>) -> bool {
    (1..=9999).contains(&time.year()) && time.timestamp_subsec_nanos() < 1_000_000_000
}
fn decode(raw: &[u8], limit: usize) -> Result<Value, Error> {
    crate::cloudtrail::decode_json(raw, limit, 32, 65_536).map_err(|error| match error {
        crate::cloudtrail::NormalizeError::RecordBytesExceeded
        | crate::cloudtrail::NormalizeError::JsonDepthExceeded
        | crate::cloudtrail::NormalizeError::JsonNodesExceeded => Error::Limit,
        _ => Error::Record,
    })
}
fn size(value: &impl Serialize, limit: usize) -> Result<usize, Error> {
    struct Counter {
        used: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit - self.used {
                return Err(std::io::Error::other("bounded metadata"));
            }
            self.used += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { used: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|_| Error::Limit)?;
    Ok(counter.used)
}
#[derive(Default)]
struct Inventory {
    objects: BTreeMap<String, MetadataObject>,
    bytes: usize,
}
struct Listing {
    epoch: u64,
    started: DateTime<Utc>,
    revision: Option<String>,
    next: Option<String>,
    tokens: Vec<String>,
    pages: usize,
    inventory: Inventory,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Metrics {
    pub retained_objects: usize,
    pub staged_objects: usize,
    pub retained_bytes: usize,
    pub staged_bytes: usize,
    pub object_capacity: usize,
    pub inventory_capacity_bytes: usize,
    pub watch_frames: u64,
    pub watch_bytes: usize,
    pub watch_frame_capacity: u64,
    pub watch_byte_capacity: usize,
    pub rejections: u64,
    pub invalidations: u64,
}
#[derive(Serialize)]
pub struct Snapshot<'a> {
    pub schema_version: u16,
    pub profile_binding: &'a str,
    pub cluster: &'a str,
    pub kind: Kind,
    pub namespace: Option<&'a str>,
    pub node: Option<&'a str>,
    pub generation: u64,
    pub resource_version: Option<&'a str>,
    pub observed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub authoritative: bool,
    pub objects: Vec<&'a MetadataObject>,
}
/// One complete retained inventory plus one finite staged inventory; no history
/// queue, clock reads, I/O or background worker. Views are not source-health proof.
pub struct Reconciler {
    profile: Profile,
    retained: Inventory,
    listing: Option<Listing>,
    revision: Option<String>,
    observed: Option<DateTime<Utc>>,
    epoch: u64,
    retained_epoch: u64,
    sequence: u64,
    last_frame: Option<[u8; 32]>,
    watch_bytes: usize,
    valid: bool,
    last_time: Option<DateTime<Utc>>,
    rejections: u64,
    invalidations: u64,
}
impl Reconciler {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            retained: Inventory::default(),
            listing: None,
            revision: None,
            observed: None,
            epoch: 0,
            retained_epoch: 0,
            sequence: 0,
            last_frame: None,
            watch_bytes: 0,
            valid: false,
            last_time: None,
            rejections: 0,
            invalidations: 0,
        }
    }
    pub fn invalidate(&mut self) {
        self.valid = false;
        self.listing = None;
        self.invalidations = self.invalidations.saturating_add(1);
    }
    fn failed<T>(&mut self, error: Error) -> Result<T, Error> {
        self.rejections = self.rejections.saturating_add(1);
        self.invalidate();
        Err(error)
    }
    fn advance_clock(&mut self, now: DateTime<Utc>) -> Result<(), Error> {
        if !time_ok(now) || self.last_time.is_some_and(|previous| now < previous) {
            return self.failed(Error::Stale);
        }
        self.last_time = Some(now);
        Ok(())
    }
    pub fn begin_list(&mut self, now: DateTime<Utc>) -> Result<u64, Error> {
        self.advance_clock(now)?;
        self.invalidate();
        self.epoch = self.epoch.checked_add(1).ok_or(Error::Limit)?;
        self.sequence = 0;
        self.last_frame = None;
        self.watch_bytes = 0;
        self.listing = Some(Listing {
            epoch: self.epoch,
            started: now,
            revision: None,
            next: None,
            tokens: vec![],
            pages: 0,
            inventory: Inventory::default(),
        });
        Ok(self.epoch)
    }
    /// Token must be exactly the token returned by the preceding page; None is
    /// accepted only for the first page. True means the list committed atomically.
    pub fn list_page(
        &mut self,
        epoch: u64,
        token: Option<&str>,
        raw: &[u8],
        now: DateTime<Utc>,
    ) -> Result<bool, Error> {
        self.advance_clock(now)?;
        let result = self.stage_page(epoch, token, raw, now);
        match result {
            Ok(done) => Ok(done),
            Err(error) => self.failed(error),
        }
    }
    fn stage_page(
        &mut self,
        epoch: u64,
        token: Option<&str>,
        raw: &[u8],
        now: DateTime<Utc>,
    ) -> Result<bool, Error> {
        let list = self.listing.as_mut().ok_or(Error::Continuity)?;
        if epoch != list.epoch
            || token != list.next.as_deref()
            || list.pages >= self.profile.limits.max_pages
            || now >= list.started + TimeDelta::seconds(self.profile.limits.max_age_seconds)
        {
            return Err(Error::Continuity);
        }
        let page = decode(raw, self.profile.limits.max_page_bytes)?;
        if string(&page, "apiVersion")? != self.profile.kind.api_version()
            || string(&page, "kind")? != format!("{}List", self.profile.kind.name())
        {
            return Err(Error::Record);
        }
        let metadata = &page["metadata"];
        let revision = string(metadata, "resourceVersion")?;
        if list.revision.as_ref().is_some_and(|r| r != revision) {
            return Err(Error::Continuity);
        }
        let next = match metadata.get("continue") {
            None => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) if text(s) => Some(s.clone()),
            _ => return Err(Error::Record),
        };
        if next.as_ref().is_some_and(|n| list.tokens.contains(n)) {
            return Err(Error::Continuity);
        }
        let objects = page
            .get("items")
            .and_then(Value::as_array)
            .ok_or(Error::Record)?;
        for object in objects {
            let projected = projection::project(object, &self.profile, list.started, true)?;
            let bytes = size(&projected, self.profile.limits.max_object_bytes)?;
            if list.inventory.objects.len() >= self.profile.limits.max_objects
                || bytes > self.profile.limits.max_inventory_bytes - list.inventory.bytes
            {
                return Err(Error::Limit);
            }
            if list.inventory.objects.contains_key(projected.uid())
                || list
                    .inventory
                    .objects
                    .values()
                    .any(|v| v.name_key() == projected.name_key())
            {
                return Err(Error::Record);
            }
            list.inventory.bytes += bytes;
            list.inventory
                .objects
                .insert(projected.uid().into(), projected);
        }
        list.revision = Some(revision.into());
        list.pages += 1;
        if let Some(next) = next {
            list.tokens.push(next.clone());
            list.next = Some(next);
            return Ok(false);
        }
        let list = self.listing.take().ok_or(Error::Continuity)?;
        self.retained_epoch = list.epoch;
        self.retained = list.inventory;
        self.revision = list.revision;
        self.observed = Some(list.started);
        self.valid = true;
        Ok(true)
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn resource_version(&self) -> Option<&str> {
        self.revision.as_deref()
    }
    fn fresh(&self, now: DateTime<Utc>) -> bool {
        self.valid
            && time_ok(now)
            && self.last_time.is_none_or(|last| now >= last)
            && self.observed.is_some_and(|seen| {
                now >= seen && now < seen + TimeDelta::seconds(self.profile.limits.max_age_seconds)
            })
    }
    pub fn authoritative(&mut self, now: DateTime<Utc>) -> bool {
        if self.advance_clock(now).is_err() {
            return false;
        }
        let fresh = self.fresh(now);
        if self.valid && !fresh {
            self.invalidate();
        }
        fresh
    }
    pub fn lookup(&mut self, uid: &str, now: DateTime<Utc>) -> Option<&MetadataObject> {
        if !self.authoritative(now) {
            return None;
        }
        self.retained.objects.get(uid)
    }
    pub fn snapshot(&mut self, now: DateTime<Utc>) -> Snapshot<'_> {
        let authoritative = self.authoritative(now);
        Snapshot {
            schema_version: 1,
            profile_binding: &self.profile.binding,
            cluster: &self.profile.cluster,
            kind: self.profile.kind,
            namespace: self.profile.namespace.as_deref(),
            node: self.profile.node.as_deref(),
            generation: self.retained_epoch,
            resource_version: self.resource_version(),
            observed_at: self.observed,
            expires_at: self
                .observed
                .map(|t| t + TimeDelta::seconds(self.profile.limits.max_age_seconds)),
            authoritative,
            objects: self.retained.objects.values().collect(),
        }
    }
    /// The caller assigns sequence numbers to complete frames on one authenticated
    /// ordered stream. Reusing another stream epoch never establishes continuity.
    pub fn watch_frame(
        &mut self,
        epoch: u64,
        sequence: u64,
        raw: &[u8],
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        self.advance_clock(now)?;
        if epoch != self.epoch || !self.fresh(now) || self.listing.is_some() {
            return self.failed(Error::Stale);
        }
        if raw.len() > self.profile.limits.max_page_bytes {
            return self.failed(Error::Limit);
        }
        let hash: [u8; 32] = Sha256::digest(raw).into();
        if sequence == self.sequence && self.last_frame == Some(hash) {
            return Ok(());
        }
        if sequence != self.sequence.checked_add(1).ok_or(Error::Limit)? {
            return self.failed(Error::Continuity);
        }
        if sequence > self.profile.limits.max_watch_frames
            || raw.len() > self.profile.limits.max_page_bytes
            || raw.len() > self.profile.limits.max_watch_bytes - self.watch_bytes
        {
            return self.failed(Error::Limit);
        }
        let result = self.apply_watch(raw, now);
        match result {
            Ok(revision) => {
                self.revision = Some(revision);
                self.sequence = sequence;
                self.last_frame = Some(hash);
                self.watch_bytes += raw.len();
                Ok(())
            }
            Err(error) => self.failed(error),
        }
    }
    fn apply_watch(&mut self, raw: &[u8], now: DateTime<Utc>) -> Result<String, Error> {
        let frame = decode(raw, self.profile.limits.max_page_bytes)?;
        let action = string(&frame, "type")?;
        let native = frame.get("object").ok_or(Error::Record)?;
        if action == "BOOKMARK" {
            if native
                .get("kind")
                .is_some_and(|v| v != self.profile.kind.name())
                || native
                    .get("apiVersion")
                    .is_some_and(|v| v != self.profile.kind.api_version())
            {
                return Err(Error::Scope);
            }
            return Ok(string(&native["metadata"], "resourceVersion")?.into());
        }
        if !["ADDED", "MODIFIED", "DELETED"].contains(&action) {
            return Err(Error::Continuity);
        }
        let object = projection::project(native, &self.profile, now, false)?;
        let revision = object.resource_version().to_owned();
        let existing = self.retained.objects.get(object.uid());
        if let Some(existing) = existing {
            if existing.name_key() != object.name_key() {
                return Err(Error::Record);
            }
            if existing.resource_version() == object.resource_version()
                && !existing.same_content(&object)
            {
                return Err(Error::Record);
            }
        }
        if action == "DELETED" {
            let removed_bytes = existing
                .map(|old| size(old, self.profile.limits.max_object_bytes))
                .transpose()?
                .unwrap_or(0);
            self.retained.objects.remove(object.uid());
            self.retained.bytes -= removed_bytes;
            return Ok(revision);
        }
        if action == "MODIFIED" && existing.is_none() {
            return Err(Error::Continuity);
        }
        if existing.is_some_and(|old| old.same_content(&object)) {
            return Ok(revision);
        }
        if action == "ADDED" && existing.is_some() {
            return Err(Error::Continuity);
        }
        if self
            .retained
            .objects
            .values()
            .any(|old| old.uid() != object.uid() && old.name_key() == object.name_key())
        {
            return Err(Error::Continuity);
        }
        let old_bytes = existing
            .map(|old| size(old, self.profile.limits.max_object_bytes))
            .transpose()?
            .unwrap_or(0);
        let bytes = size(&object, self.profile.limits.max_object_bytes)?;
        if existing.is_none() && self.retained.objects.len() >= self.profile.limits.max_objects
            || bytes > self.profile.limits.max_inventory_bytes - (self.retained.bytes - old_bytes)
        {
            return Err(Error::Limit);
        }
        self.retained.bytes = self.retained.bytes - old_bytes + bytes;
        self.retained.objects.insert(object.uid().into(), object);
        Ok(revision)
    }
    pub fn metrics(&self) -> Metrics {
        Metrics {
            retained_objects: self.retained.objects.len(),
            staged_objects: self
                .listing
                .as_ref()
                .map_or(0, |s| s.inventory.objects.len()),
            retained_bytes: self.retained.bytes,
            staged_bytes: self.listing.as_ref().map_or(0, |s| s.inventory.bytes),
            object_capacity: self.profile.limits.max_objects,
            inventory_capacity_bytes: self.profile.limits.max_inventory_bytes,
            watch_frames: self.sequence,
            watch_bytes: self.watch_bytes,
            watch_frame_capacity: self.profile.limits.max_watch_frames,
            watch_byte_capacity: self.profile.limits.max_watch_bytes,
            rejections: self.rejections,
            invalidations: self.invalidations,
        }
    }
}
#[cfg(test)]
mod tests;
