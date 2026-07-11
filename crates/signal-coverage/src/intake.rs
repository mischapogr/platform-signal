//! Trusted application grants and bounded requests; no credential authentication.
use crate::{
    AdmissionMetadata, CoverageError as Error, Receipt,
    format::{self, HistoryBinding, ProfileDefinition, Timestamp},
};
use uuid::Uuid;

/// An application's current, exact authorization decision for one observer/binding.
/// Construct only after authenticating the observer and authorizing the full binding.
/// Reissue for each operation; record names, tokens and proof URIs do not grant access.
#[derive(Clone, Debug)]
pub struct AuthorizedBinding {
    pub(crate) binding: HistoryBinding,
    pub(crate) revision: String,
    pub(crate) lease: Option<AuthorizationLease>,
}
impl AuthorizedBinding {
    pub fn new(
        authenticated_observer: &str,
        binding: HistoryBinding,
        authority_revision: String,
    ) -> Result<Self, Error> {
        if authenticated_observer != binding.observer_id() {
            return Err(Error::NotAuthorized);
        }
        if authority_revision.trim().is_empty()
            || authority_revision.len() > 1024
            || authority_revision.chars().any(char::is_control)
        {
            return Err(Error::Invalid("authority revision"));
        }
        Ok(Self {
            binding,
            revision: authority_revision.into_boxed_str().into_string(),
            lease: None,
        })
    }
}

/// Finite, request-local authorization validity supplied by an authenticated host.
/// Not serialized or persisted. Wall-clock and monotonic bounds both apply.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthorizationLease {
    issued_at: u64,
    expires_at: u64,
    deadline: tokio::time::Instant,
}
impl AuthorizationLease {
    fn new(issued_at: u64, expires_at: u64) -> Result<Self, Error> {
        let origin = tokio::time::Instant::now();
        let now = chrono::Utc::now();
        let at = u64::try_from(now.timestamp()).map_err(|_| Error::NotAuthorized)?;
        if issued_at > at
            || issued_at >= expires_at
            || at >= expires_at
            || expires_at > 253_402_300_799
        {
            return Err(Error::NotAuthorized);
        }
        let remaining = std::time::Duration::from_secs(expires_at - at)
            .checked_sub(std::time::Duration::from_nanos(u64::from(
                now.timestamp_subsec_nanos(),
            )))
            .ok_or(Error::NotAuthorized)?;
        let deadline = origin.checked_add(remaining).ok_or(Error::NotAuthorized)?;
        Ok(Self {
            issued_at,
            expires_at,
            deadline,
        })
    }
    pub(crate) fn check(self) -> Result<(), Error> {
        let at = u64::try_from(chrono::Utc::now().timestamp()).map_err(|_| Error::NotAuthorized)?;
        if at < self.issued_at
            || at >= self.expires_at
            || tokio::time::Instant::now() >= self.deadline
        {
            Err(Error::NotAuthorized)
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.deadline = tokio::time::Instant::now();
    }
    pub(crate) fn deadline(self) -> tokio::time::Instant {
        self.deadline
    }
}
impl AuthorizedBinding {
    /// Attach exactly the backend grant's issue/expiry bounds after authorizing
    /// this whole binding. Timestamps alone do not authenticate any caller.
    pub fn with_lease(mut self, issued_at: u64, expires_at: u64) -> Result<Self, Error> {
        self.lease = Some(AuthorizationLease::new(issued_at, expires_at)?);
        Ok(self)
    }
    /// The ingress can bound body acquisition/response work without changing the
    /// retained physical worker's separate original operation watchdog budget.
    pub fn lease_deadline(&self) -> Option<tokio::time::Instant> {
        self.lease.map(AuthorizationLease::deadline)
    }
}

/// Finite trusted application policy. These are seconds, not deployment defaults.
#[derive(Clone, Copy, Debug)]
pub struct IntakePolicy {
    pub(crate) max_report_age_seconds: u32,
    pub(crate) max_clock_skew_seconds: u32,
    payload_retention_seconds: u32,
    identity_retention_seconds: u32,
}
impl IntakePolicy {
    pub fn new(
        max_report_age_seconds: u32,
        max_clock_skew_seconds: u32,
        payload_retention_seconds: u32,
        identity_retention_seconds: u32,
    ) -> Result<Self, Error> {
        if max_report_age_seconds == 0
            || max_clock_skew_seconds > 300
            || u64::from(payload_retention_seconds)
                <= u64::from(max_report_age_seconds) + u64::from(max_clock_skew_seconds)
            || identity_retention_seconds < payload_retention_seconds
        {
            return Err(Error::Config("intake age/skew/retention bounds"));
        }
        Ok(Self {
            max_report_age_seconds,
            max_clock_skew_seconds,
            payload_retention_seconds,
            identity_retention_seconds,
        })
    }
    pub(crate) fn admission(
        &self,
        at: Timestamp,
        revision: String,
    ) -> Result<AdmissionMetadata, Error> {
        fn deadline(at: Timestamp, seconds: u32) -> Result<Timestamp, Error> {
            let next = at
                .datetime()?
                .checked_add_signed(chrono::TimeDelta::seconds(i64::from(seconds)))
                .ok_or(Error::Invalid("retention time overflow"))?;
            Timestamp::parse(&next.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
                .map_err(|_| Error::Invalid("retention time range"))
        }
        Ok(AdmissionMetadata {
            authority_revision: revision,
            accepted_at: at,
            replay_until: deadline(at, self.payload_retention_seconds)?,
            identity_until: deadline(at, self.identity_retention_seconds)?,
        })
    }
}

/// Receiver time and new-write profile/policy from the trusted application.
/// `None` permits replay of a retained pin but forbids new admission.
#[derive(Clone, Debug)]
pub struct IntakeContext {
    pub(crate) authority: AuthorizedBinding,
    pub(crate) received_at: Timestamp,
    pub(crate) profile: Option<ProfileDefinition>,
    pub(crate) policy: IntakePolicy,
}
impl IntakeContext {
    pub fn new(
        authority: AuthorizedBinding,
        received_at: Timestamp,
        current_profile: Option<ProfileDefinition>,
        policy: IntakePolicy,
    ) -> Self {
        Self {
            authority,
            received_at,
            profile: current_profile,
            policy,
        }
    }
}

/// Original immutable producer submission. Bounds are checked before copying bytes.
#[derive(Clone, Debug)]
pub struct CoverageSubmission {
    pub(crate) record_id: Uuid,
    pub(crate) raw: Vec<u8>,
    pub(crate) correction_of: Option<Uuid>,
}
impl CoverageSubmission {
    pub fn new(record_id: Uuid, raw: &[u8], correction_of: Option<Uuid>) -> Result<Self, Error> {
        format::non_nil(record_id)?;
        if let Some(id) = correction_of {
            format::non_nil(id)?;
        }
        if raw.is_empty() || raw.len() > format::MAX_RAW_BYTES {
            return Err(Error::Invalid("submission byte bound"));
        }
        Ok(Self {
            record_id,
            raw: raw.to_vec(),
            correction_of,
        })
    }
}

/// Both variants contain the immutable durable receipt; replay performs no mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntakeOutcome {
    Accepted(Receipt),
    Replayed(Receipt),
}
