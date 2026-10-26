//! Versioned, bounded case workflow. Host testimony is not authentication.
mod store;
use crate::{FindingContext, disposition::FindingReference};
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub use store::{CaseConfig, CaseMetrics, CaseStore};
use thiserror::Error;
use uuid::Uuid;

pub const CASE_SCHEMA_VERSION: u16 = 1;
pub const MAX_CASE_REFERENCES: usize = 32;
pub const MAX_CASE_RECORD_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaseChange {
    Create {
        title: String,
        references: Vec<FindingReference>,
    },
    Assign {
        assignee: Option<String>,
    },
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRequest {
    pub schema_version: u16,
    pub operation_id: Uuid,
    pub case_id: Uuid,
    pub expected_revision: u64,
    pub change: CaseChange,
    pub note: Option<String>,
}
fn identity(s: &String) -> bool {
    !s.trim().is_empty()
        && s.len() <= 256
        && s.capacity() <= 256
        && !s.chars().any(char::is_control)
}
fn references_valid(references: &[FindingReference]) -> bool {
    !references.is_empty()
        && references.len() <= MAX_CASE_REFERENCES
        && references.iter().all(|r| r.validate().is_ok())
        && references
            .windows(2)
            .all(|r| (r[0].stream_id, r[0].finding_id) < (r[1].stream_id, r[1].finding_id))
}
impl CaseRequest {
    pub fn validate(&self) -> Result<(), CaseError> {
        if self.schema_version != CASE_SCHEMA_VERSION
            || self.operation_id.is_nil()
            || self.case_id.is_nil()
            || self.expected_revision >= 1_000_000
            || self
                .note
                .as_ref()
                .is_some_and(|n| n.len() > 2048 || n.capacity() > 2048)
        {
            return Err(CaseError::Invalid);
        }
        match &self.change {
            CaseChange::Create { title, references }
                if self.expected_revision == 0
                    && !title.trim().is_empty()
                    && title.len() <= 1024
                    && title.capacity() <= 1024
                    && !title.chars().any(char::is_control)
                    && references_valid(references)
                    && references.capacity() <= MAX_CASE_REFERENCES =>
            {
                Ok(())
            }
            CaseChange::Assign { assignee }
                if self.expected_revision > 0 && assignee.as_ref().is_none_or(identity) =>
            {
                Ok(())
            }
            _ => Err(CaseError::Invalid),
        }
    }
    fn digest(&self) -> Result<[u8; 32], CaseError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| CaseError::Invalid)?;
        Ok(Sha256::digest(bytes).into())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseHead {
    pub schema_version: u16,
    pub case_id: Uuid,
    pub revision: u64,
    pub title: String,
    pub references: Vec<FindingReference>,
    pub assignee: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRecord {
    pub schema_version: u16,
    pub request: CaseRequest,
    pub actor: String,
    pub recorded_at: DateTime<Utc>,
    pub head: CaseHead,
}
impl CaseRecord {
    fn prepare(
        request: CaseRequest,
        actor: String,
        previous: Option<&CaseHead>,
    ) -> Result<Self, CaseError> {
        request.validate()?;
        if !identity(&actor) {
            return Err(CaseError::Invalid);
        }
        let head = Self::next(&request, previous)?;
        Ok(Self {
            schema_version: CASE_SCHEMA_VERSION,
            request,
            actor,
            recorded_at: Utc::now(),
            head,
        })
    }
    fn next(request: &CaseRequest, previous: Option<&CaseHead>) -> Result<CaseHead, CaseError> {
        request.validate()?;
        match (&request.change, previous) {
            (CaseChange::Create { title, references }, None) => Ok(CaseHead {
                schema_version: CASE_SCHEMA_VERSION,
                case_id: request.case_id,
                revision: 1,
                title: title.clone(),
                references: references.clone(),
                assignee: None,
            }),
            (CaseChange::Assign { assignee }, Some(old))
                if old.case_id == request.case_id && old.revision == request.expected_revision =>
            {
                let mut head = old.clone();
                head.revision += 1;
                head.assignee = assignee.clone();
                Ok(head)
            }
            _ => Err(CaseError::Conflict),
        }
    }
    fn validate_after(&self, previous: Option<&CaseHead>) -> Result<(), CaseError> {
        if self.schema_version != CASE_SCHEMA_VERSION
            || !identity(&self.actor)
            || !(0..=9999).contains(&self.recorded_at.year())
            || Self::next(&self.request, previous)? != self.head
        {
            return Err(CaseError::Corrupt);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct CaseReceipt {
    pub schema_version: u16,
    pub record: CaseRecord,
    pub replayed: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct CaseHistory {
    pub schema_version: u16,
    pub records: Vec<CaseRecord>,
    pub has_more: bool,
    pub next_revision: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CasePermission {
    Read,
    Write,
}

/// Nonserialized host testimony. The host authenticates actor, verifies every
/// finding and all its scopes, and independently authorizes the assignee.
/// This constructor checks only shape. Never construct this from HTTP claims.
#[derive(Clone)]
pub struct CaseAuthority {
    namespace: Uuid,
    case_id: Uuid,
    actor: String,
    references: Vec<FindingReference>,
    request: Option<[u8; 32]>,
    context: FindingContext,
    utc_window: Option<CaseUtcWindow>,
}
impl CaseAuthority {
    /// Bridge an independently verified UTC lease; this still does not authenticate.
    pub fn for_write_bounded(
        namespace: Uuid,
        actor: String,
        references: Vec<FindingReference>,
        request: &CaseRequest,
        context: FindingContext,
        window: CaseUtcWindow,
    ) -> Result<Self, CaseError> {
        let mut proof =
            Self::for_write(namespace, actor, references, request, window.cap(context)?)?;
        proof.utc_window = Some(window);
        proof.check()?;
        Ok(proof)
    }
    pub fn for_read_bounded(
        namespace: Uuid,
        case_id: Uuid,
        actor: String,
        references: Vec<FindingReference>,
        context: FindingContext,
        window: CaseUtcWindow,
    ) -> Result<Self, CaseError> {
        let mut proof =
            Self::for_read(namespace, case_id, actor, references, window.cap(context)?)?;
        proof.utc_window = Some(window);
        proof.check()?;
        Ok(proof)
    }
    pub fn for_write(
        namespace: Uuid,
        actor: String,
        references: Vec<FindingReference>,
        request: &CaseRequest,
        context: FindingContext,
    ) -> Result<Self, CaseError> {
        let proof = Self {
            namespace,
            case_id: request.case_id,
            actor,
            references,
            request: Some(request.digest()?),
            context,
            utc_window: None,
        };
        proof.check()?;
        Ok(proof)
    }
    pub fn for_read(
        namespace: Uuid,
        case_id: Uuid,
        actor: String,
        references: Vec<FindingReference>,
        context: FindingContext,
    ) -> Result<Self, CaseError> {
        let proof = Self {
            namespace,
            case_id,
            actor,
            references,
            request: None,
            context,
            utc_window: None,
        };
        proof.check()?;
        Ok(proof)
    }
    fn check(&self) -> Result<(), CaseError> {
        if self.namespace.is_nil()
            || self.case_id.is_nil()
            || !identity(&self.actor)
            || !references_valid(&self.references)
            || self.references.capacity() > MAX_CASE_REFERENCES
        {
            return Err(CaseError::Invalid);
        }
        check(&self.context)?;
        if let Some(window) = self.utc_window {
            window.check()?;
        }
        Ok(())
    }
    fn authorize(
        &self,
        namespace: Uuid,
        case_id: Uuid,
        references: &[FindingReference],
        request: Option<&CaseRequest>,
    ) -> Result<(), CaseError> {
        self.check()?;
        if namespace != self.namespace
            || case_id != self.case_id
            || references != self.references
            || match request {
                Some(r) => self.request != Some(r.digest()?),
                None => self.request.is_some(),
            }
        {
            return Err(CaseError::Forbidden);
        }
        Ok(())
    }
}
fn check(context: &FindingContext) -> Result<(), CaseError> {
    if context.cancellation.is_cancelled() {
        Err(CaseError::Cancelled)
    } else if tokio::time::Instant::now() >= context.deadline {
        Err(CaseError::Timeout)
    } else {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CaseError {
    #[error("invalid case input or configuration")]
    Invalid,
    #[error("case authority denied")]
    Forbidden,
    #[error("case not available")]
    NotFound,
    #[error("case revision or operation conflict")]
    Conflict,
    #[error("case capacity exhausted")]
    Capacity,
    #[error("case journal corrupt or unsafe")]
    Corrupt,
    #[error("case journal unavailable")]
    Unavailable,
    #[error("case root already owned")]
    Locked,
    #[error("case operation timed out")]
    Timeout,
    #[error("case operation cancelled")]
    Cancelled,
}

/// Host-only catalogue testimony, not client authorization. Authenticate and
/// admit the host request before construction; authorize every discovered
/// reference before exposing any metadata or constructing CaseAuthority.
#[derive(Clone)]
pub struct CaseInventoryAuthority {
    namespace: Uuid,
    actor: String,
    context: FindingContext,
    utc_window: Option<CaseUtcWindow>,
}
impl CaseInventoryAuthority {
    pub fn new_bounded(
        namespace: Uuid,
        actor: String,
        context: FindingContext,
        window: CaseUtcWindow,
    ) -> Result<Self, CaseError> {
        let mut proof = Self::new(namespace, actor, window.cap(context)?)?;
        proof.utc_window = Some(window);
        proof.check()?;
        Ok(proof)
    }
    pub fn new(namespace: Uuid, actor: String, context: FindingContext) -> Result<Self, CaseError> {
        let authority = Self {
            namespace,
            actor,
            context,
            utc_window: None,
        };
        authority.check()?;
        Ok(authority)
    }
    fn check(&self) -> Result<(), CaseError> {
        if self.namespace.is_nil() || !identity(&self.actor) {
            return Err(CaseError::Invalid);
        }
        check(&self.context)?;
        if let Some(window) = self.utc_window {
            window.check()?;
        }
        Ok(())
    }
    fn authorize(&self, namespace: Uuid) -> Result<(), CaseError> {
        self.check()?;
        if namespace != self.namespace {
            Err(CaseError::Forbidden)
        } else {
            Ok(())
        }
    }
}
/// Private discovery data, deliberately not Serialize/Deserialize. This does
/// not authorize a user to read the case, its references or original evidence.
#[derive(Clone)]
pub struct CaseInventoryEntry {
    namespace: Uuid,
    case_id: Uuid,
    revision: u64,
    references: Vec<FindingReference>,
}
impl CaseInventoryEntry {
    pub fn namespace(&self) -> Uuid {
        self.namespace
    }
    pub fn case_id(&self) -> Uuid {
        self.case_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn references(&self) -> &[FindingReference] {
        &self.references
    }
    fn wire(&self) -> InventoryWire<'_> {
        InventoryWire {
            namespace: self.namespace,
            case_id: self.case_id,
            revision: self.revision,
            references: &self.references,
        }
    }
    /// Size of the internal metadata encoding, not a client wire response.
    pub fn encoded_len(&self) -> Result<usize, CaseError> {
        self.count_bytes(usize::MAX)
    }
    fn check_bytes(&self, limit: usize) -> Result<(), CaseError> {
        self.count_bytes(limit).map(|_| ())
    }
    fn count_bytes(&self, limit: usize) -> Result<usize, CaseError> {
        let mut counter = crate::BoundedWriter {
            bytes: 0,
            limit,
            data: None,
        };
        serde_json::to_writer(&mut counter, &self.wire()).map_err(|_| CaseError::Capacity)?;
        Ok(counter.bytes)
    }
}
#[derive(Serialize)]
struct InventoryWire<'a> {
    namespace: Uuid,
    case_id: Uuid,
    revision: u64,
    references: &'a [FindingReference],
}
/// Bounded internal UUID traversal. Its cursor must never be a public response;
/// an authenticated adapter needs its own actor/enrollment-bound continuation.
pub struct CaseInventoryPage {
    namespace: Uuid,
    entries: Vec<CaseInventoryEntry>,
    next_case_id: Option<Uuid>,
    has_more: bool,
    commit_binding: [u8; 32],
}
impl CaseInventoryPage {
    pub fn namespace(&self) -> Uuid {
        self.namespace
    }
    pub fn entries(&self) -> &[CaseInventoryEntry] {
        &self.entries
    }
    pub fn next_case_id(&self) -> Option<Uuid> {
        self.next_case_id
    }
    pub fn has_more(&self) -> bool {
        self.has_more
    }
    pub fn commit_binding(&self) -> [u8; 32] {
        self.commit_binding
    }
    /// Size of the internal metadata encoding, not a client wire response.
    pub fn encoded_len(&self) -> Result<usize, CaseError> {
        self.count_bytes(usize::MAX)
    }
    fn check_bytes(&self, limit: usize) -> Result<(), CaseError> {
        self.count_bytes(limit).map(|_| ())
    }
    fn count_bytes(&self, limit: usize) -> Result<usize, CaseError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            schema_version: u16,
            namespace: Uuid,
            entries: Vec<InventoryWire<'a>>,
            next_case_id: Option<Uuid>,
            has_more: bool,
            commit_binding: [u8; 32],
        }
        let wire = Wire {
            schema_version: 1,
            namespace: self.namespace,
            entries: self.entries.iter().map(CaseInventoryEntry::wire).collect(),
            next_case_id: self.next_case_id,
            has_more: self.has_more,
            commit_binding: self.commit_binding,
        };
        let mut counter = crate::BoundedWriter {
            bytes: 0,
            limit,
            data: None,
        };
        serde_json::to_writer(&mut counter, &wire).map_err(|_| CaseError::Capacity)?;
        Ok(counter.bytes)
    }
}

/// Independent absolute UTC lease, paired with an original monotonic context.
/// Shape/freshness checks only: callers must authenticate and verify all grants.
/// No serialization path can turn stored timestamps into current authority.
#[derive(Clone, Copy)]
pub struct CaseUtcWindow {
    not_before: u64,
    expires_at: u64,
}
impl CaseUtcWindow {
    pub fn new(not_before: u64, expires_at: u64) -> Result<Self, CaseError> {
        if not_before >= expires_at || expires_at > 253_402_300_799 {
            return Err(CaseError::Invalid);
        }
        let window = Self {
            not_before,
            expires_at,
        };
        window.check()?;
        Ok(window)
    }
    fn check(&self) -> Result<(), CaseError> {
        let now = u64::try_from(Utc::now().timestamp()).map_err(|_| CaseError::Timeout)?;
        if now < self.not_before || now >= self.expires_at {
            Err(CaseError::Timeout)
        } else {
            Ok(())
        }
    }
    fn cap(self, mut context: FindingContext) -> Result<FindingContext, CaseError> {
        self.check()?;
        check(&context)?;
        let until =
            DateTime::<Utc>::from_timestamp(self.expires_at as i64, 0).ok_or(CaseError::Invalid)?;
        let remaining = until
            .signed_duration_since(Utc::now())
            .to_std()
            .map_err(|_| CaseError::Timeout)?;
        let now = tokio::time::Instant::now();
        context.deadline = now
            .checked_add(remaining.min(context.deadline.saturating_duration_since(now)))
            .ok_or(CaseError::Invalid)?;
        check(&context)?;
        Ok(context)
    }
}
