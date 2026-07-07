//! Bounded SourceCoverage v1 validation and assessment. No I/O or retained state.
//!
//! Profiles and consumer context must come from trusted configuration. Parsing
//! names and proof references does not authenticate observers or verify proofs.

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;

#[cfg(feature = "aws-source")]
pub mod cloudtrail;
pub mod observer;

pub const MAX_RECORD_BYTES: usize = 65_536;
pub const MAX_STRING_BYTES: usize = 1_024;
const MAX_GAPS: usize = 128;
const MAX_PROOFS: usize = 32;
const MAX_ATTRIBUTES: usize = 16;
const MAX_GAP_TOTAL: u64 = (1_u64 << 53) - 1;

/// Static errors never include source content, proof references or credentials.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CoverageError {
    #[error("record_bytes_exceeded")]
    RecordBytesExceeded,
    #[error("invalid_structure")]
    InvalidStructure,
    #[error("string_bytes_exceeded")]
    StringBytesExceeded,
    #[error("invalid_timestamp")]
    InvalidTimestamp,
    #[error("invalid_record_id")]
    InvalidRecordId,
    #[error("nil_record_id")]
    NilRecordId,
    #[error("invalid_profile")]
    InvalidProfile,
    #[error("profile_unavailable")]
    ProfileUnavailable,
    #[error("invalid_interval")]
    InvalidInterval,
    #[error("interval_budget_exceeded")]
    IntervalBudgetExceeded,
    #[error("verification_before_end")]
    VerificationBeforeEnd,
    #[error("data_observation_after_report")]
    DataObservationAfterReport,
    #[error("verification_after_observation")]
    VerificationAfterObservation,
    #[error("invalid_expiry")]
    InvalidExpiry,
    #[error("expiry_budget_exceeded")]
    ExpiryBudgetExceeded,
    #[error("gap_outside_interval")]
    GapOutsideInterval,
    #[error("gap_scope_mismatch")]
    GapScopeMismatch,
    #[error("duplicate_gap_id")]
    DuplicateGapId,
    #[error("unrecovered_gap_verified")]
    UnrecoveredGapVerified,
    #[error("recovered_gap_missing_proof")]
    RecoveredGapMissingProof,
    #[error("gap_summary_mismatch")]
    GapSummaryMismatch,
    #[error("summary_mismatch")]
    SummaryMismatch,
    #[error("missing_proof_reference")]
    MissingProofReference,
    #[error("missing_checkpoint")]
    MissingCheckpoint,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Verified,
    Partial,
    Unknown,
    Failed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageReason {
    ProfileUnavailable,
    InvalidRecord,
    BindingMismatch,
    ObserverMismatch,
    VerificationInFuture,
    ObservationInFuture,
    ObserverUnhealthy,
    ObserverUnknown,
    Expired,
    IntervalUncovered,
    IntervalPartial,
    ComponentFailed,
    ComponentUnknown,
    ComponentUnsupported,
    GapDetailsTruncated,
    ComponentPartial,
}

/// Versioned assessment with zero or one primary reason. Constructed by assessment.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct CoverageAssessment {
    schema_version: u32,
    status: CoverageStatus,
    #[serde(rename = "reason_codes", serialize_with = "serialize_reason")]
    reason: Option<CoverageReason>,
}

impl CoverageAssessment {
    pub fn status(&self) -> CoverageStatus {
        self.status
    }

    pub fn reason_codes(&self) -> &[CoverageReason] {
        self.reason.as_slice()
    }

    fn new(status: CoverageStatus, reason: Option<CoverageReason>) -> Self {
        Self {
            schema_version: 1,
            status,
            reason,
        }
    }

    fn unknown(reason: CoverageReason) -> Self {
        Self::new(CoverageStatus::Unknown, Some(reason))
    }
}

fn serialize_reason<S: Serializer>(
    reason: &Option<CoverageReason>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    reason.as_slice().serialize(serializer)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Component {
    Configuration,
    Scope,
    Continuity,
    SourceIntegrity,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileWire {
    schema_version: u32,
    id: String,
    revision: String,
    required_components: Vec<Component>,
    requires_checkpoint: bool,
    max_interval_seconds: u32,
    max_verification_age_seconds: u32,
    max_clock_skew_seconds: u32,
}

/// Immutable validated profile. Resolution and trust remain the caller's job.
#[derive(Clone, Debug)]
pub struct CoverageProfile(ProfileWire);

impl CoverageProfile {
    pub fn parse(bytes: &[u8]) -> Result<Self, CoverageError> {
        let wire: ProfileWire = decode(bytes)?;
        text(&wire.id)?;
        text(&wire.revision)?;
        if wire.schema_version != 1
            || !(3..=4).contains(&wire.required_components.len())
            || !unique(&wire.required_components)
            || ![
                Component::Configuration,
                Component::Scope,
                Component::Continuity,
            ]
            .iter()
            .all(|c| wire.required_components.contains(c))
            || !(1..=86_400).contains(&wire.max_interval_seconds)
            || !(1..=86_400).contains(&wire.max_verification_age_seconds)
            || wire.max_clock_skew_seconds > 300
        {
            return Err(CoverageError::InvalidProfile);
        }
        Ok(Self(wire))
    }

    pub fn id(&self) -> &str {
        &self.0.id
    }
    pub fn revision(&self) -> &str {
        &self.0.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Scope {
    kind: String,
    id: String,
    #[serde(default, deserialize_with = "scope_attributes")]
    attributes: BTreeMap<String, String>,
}

impl Scope {
    fn validate(&self) -> Result<(), CoverageError> {
        text(&self.kind)?;
        text(&self.id)?;
        if self.attributes.len() > MAX_ATTRIBUTES {
            return Err(CoverageError::InvalidStructure);
        }
        for (key, value) in &self.attributes {
            text(key)?;
            text(value)?;
        }
        Ok(())
    }
}

// Derived struct deserializers reject duplicate known fields. Scope attributes
// are the only open map; reject duplicates here too, including escaped-key aliases.
fn scope_attributes<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Attributes;
    impl<'de> de::Visitor<'de> for Attributes {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded unique scope attributes")
        }
        fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if result.len() >= MAX_ATTRIBUTES || result.contains_key(&key) {
                    return Err(de::Error::custom("invalid scope attributes"));
                }
                let value: String = map.next_value()?;
                result.insert(key, value);
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Attributes)
}

// deserialize_with makes missing fields errors while accepting explicit null.
fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProfileRef {
    id: String,
    revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Binding {
    source_id: String,
    collector_id: String,
    resource_scope: Scope,
    expected_stream: String,
    coverage_profile: ProfileRef,
    collection_config_revision: String,
}

impl Binding {
    fn validate(&self) -> Result<(), CoverageError> {
        for s in [
            &self.source_id,
            &self.collector_id,
            &self.expected_stream,
            &self.coverage_profile.id,
            &self.coverage_profile.revision,
            &self.collection_config_revision,
        ] {
            text(s)?;
        }
        self.resource_scope.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Milestone {
    Capture,
    DurableReceipt,
    ProcessedInput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    schema_version: u32,
    kind: String,
    milestone: Milestone,
    value: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Recoverability {
    Pending,
    Recovered,
    Irrecoverable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Gap {
    id: String,
    start: String,
    #[serde(deserialize_with = "nullable")]
    end: Option<String>,
    resource_scope: Scope,
    reason_code: String,
    recoverability: Recoverability,
    #[serde(deserialize_with = "nullable")]
    proof_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct GapSummary {
    #[serde(deserialize_with = "nullable")]
    total: Option<u64>,
    truncated: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Validation {
    configuration: CoverageStatus,
    scope: CoverageStatus,
    continuity: CoverageStatus,
    source_integrity: CoverageStatus,
}

impl Validation {
    fn component(&self, component: Component) -> CoverageStatus {
        match component {
            Component::Configuration => self.configuration,
            Component::Scope => self.scope,
            Component::Continuity => self.continuity,
            Component::SourceIntegrity => self.source_integrity,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    observer_id: String,
    method: String,
    proof_refs: Vec<String>,
    observed_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    schema_version: u32,
    record_id: String,
    source_id: String,
    collector_id: String,
    resource_scope: Scope,
    expected_stream: String,
    coverage_profile: ProfileRef,
    collection_config_revision: String,
    coverage_start: String,
    coverage_end: String,
    #[serde(deserialize_with = "nullable")]
    last_observed_at: Option<String>,
    last_verified_at: String,
    valid_until: String,
    #[serde(deserialize_with = "nullable")]
    checkpoint: Option<Checkpoint>,
    validation_status: CoverageStatus,
    validation: Validation,
    gaps: Vec<Gap>,
    gap_summary: GapSummary,
    provenance: Provenance,
}

impl RecordWire {
    fn matches(&self, binding: &Binding) -> bool {
        self.source_id == binding.source_id
            && self.collector_id == binding.collector_id
            && self.resource_scope == binding.resource_scope
            && self.expected_stream == binding.expected_stream
            && self.coverage_profile == binding.coverage_profile
            && self.collection_config_revision == binding.collection_config_revision
    }

    fn validate_structure(&self) -> Result<(), CoverageError> {
        if self.schema_version != 1
            || self.gaps.len() > MAX_GAPS
            || self.provenance.proof_refs.len() > MAX_PROOFS
            || !unique(&self.provenance.proof_refs)
            || self.gap_summary.total.is_some_and(|n| n > MAX_GAP_TOTAL)
        {
            return Err(CoverageError::InvalidStructure);
        }
        record_id(&self.record_id)?;
        for s in [
            &self.source_id,
            &self.collector_id,
            &self.expected_stream,
            &self.coverage_profile.id,
            &self.coverage_profile.revision,
            &self.collection_config_revision,
            &self.provenance.observer_id,
            &self.provenance.method,
        ] {
            text(s)?;
        }
        self.resource_scope.validate()?;
        for s in &self.provenance.proof_refs {
            text(s)?;
        }
        if let Some(checkpoint) = &self.checkpoint {
            if checkpoint.schema_version != 1 {
                return Err(CoverageError::InvalidStructure);
            }
            text(&checkpoint.kind)?;
            text(&checkpoint.value)?;
            // Typed enum validation applies without interpreting opaque positions.
            let _ = checkpoint.milestone;
        }
        for gap in &self.gaps {
            text(&gap.id)?;
            text(&gap.reason_code)?;
            gap.resource_scope.validate()?;
            if let Some(s) = &gap.proof_ref {
                text(s)?;
            }
        }
        Ok(())
    }
}

/// Validated immutable assertion. No methods mutate verification or expiry.
#[derive(Clone, Debug)]
pub struct ValidatedCoverage {
    wire: RecordWire,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    verified: DateTime<Utc>,
    expires: DateTime<Utc>,
    observed: DateTime<Utc>,
    clock_skew_seconds: u32,
    base_reason: Option<CoverageReason>,
}

impl ValidatedCoverage {
    /// Admit bounded raw UTF-8 JSON and an already validated trusted profile.
    /// A missing or different profile revision fails closed.
    pub fn parse(bytes: &[u8], profile: Option<&CoverageProfile>) -> Result<Self, CoverageError> {
        let wire: RecordWire = decode(bytes)?;
        wire.validate_structure()?;
        let start = timestamp(&wire.coverage_start)?;
        let end = timestamp(&wire.coverage_end)?;
        let verified = timestamp(&wire.last_verified_at)?;
        let expires = timestamp(&wire.valid_until)?;
        let observed = timestamp(&wire.provenance.observed_at)?;
        let arrival = wire
            .last_observed_at
            .as_deref()
            .map(timestamp)
            .transpose()?;
        let gap_times: Vec<_> = wire
            .gaps
            .iter()
            .map(|gap| {
                Ok((
                    timestamp(&gap.start)?,
                    gap.end.as_deref().map(timestamp).transpose()?,
                ))
            })
            .collect::<Result<_, CoverageError>>()?;
        let profile = profile
            .filter(|p| {
                p.id() == wire.coverage_profile.id && p.revision() == wire.coverage_profile.revision
            })
            .ok_or(CoverageError::ProfileUnavailable)?;
        if start >= end {
            return Err(CoverageError::InvalidInterval);
        }
        if end.signed_duration_since(start) > seconds(profile.0.max_interval_seconds) {
            return Err(CoverageError::IntervalBudgetExceeded);
        }
        if end > verified {
            return Err(CoverageError::VerificationBeforeEnd);
        }
        if arrival.is_some_and(|a| a > observed) {
            return Err(CoverageError::DataObservationAfterReport);
        }
        if verified > observed {
            return Err(CoverageError::VerificationAfterObservation);
        }
        if expires <= verified {
            return Err(CoverageError::InvalidExpiry);
        }
        if expires.signed_duration_since(verified) > seconds(profile.0.max_verification_age_seconds)
        {
            return Err(CoverageError::ExpiryBudgetExceeded);
        }
        for (index, (gap, (gap_start, gap_end))) in wire.gaps.iter().zip(&gap_times).enumerate() {
            if gap.resource_scope != wire.resource_scope {
                return Err(CoverageError::GapScopeMismatch);
            }
            if *gap_start < start
                || *gap_start >= end
                || gap_end.is_some_and(|e| e <= *gap_start || e > end)
            {
                return Err(CoverageError::GapOutsideInterval);
            }
            if wire.gaps[..index]
                .iter()
                .any(|earlier| earlier.id == gap.id)
            {
                return Err(CoverageError::DuplicateGapId);
            }
            if gap.recoverability == Recoverability::Recovered {
                if gap.proof_ref.is_none() {
                    return Err(CoverageError::RecoveredGapMissingProof);
                }
            } else if wire.validation.continuity == CoverageStatus::Verified {
                return Err(CoverageError::UnrecoveredGapVerified);
            }
        }
        let count = wire.gaps.len() as u64; // At most MAX_GAPS after structural validation.
        if (!wire.gap_summary.truncated && wire.gap_summary.total != Some(count))
            || (wire.gap_summary.truncated && wire.gap_summary.total.is_some_and(|n| n <= count))
        {
            return Err(CoverageError::GapSummaryMismatch);
        }
        let (summary, base_reason) = reduce(
            &wire.validation,
            &profile.0.required_components,
            wire.gap_summary.truncated,
        );
        if summary != wire.validation_status {
            return Err(CoverageError::SummaryMismatch);
        }
        if summary == CoverageStatus::Verified {
            if wire.provenance.proof_refs.is_empty() {
                return Err(CoverageError::MissingProofReference);
            }
            if profile.0.requires_checkpoint && wire.checkpoint.is_none() {
                return Err(CoverageError::MissingCheckpoint);
            }
        }
        Ok(Self {
            wire,
            start,
            end,
            verified,
            expires,
            observed,
            clock_skew_seconds: profile.0.max_clock_skew_seconds,
            base_reason,
        })
    }

    pub fn record_id(&self) -> &str {
        &self.wire.record_id
    }
    pub fn status(&self) -> CoverageStatus {
        self.wire.validation_status
    }

    pub fn assess(&self, context: &CoverageContext) -> CoverageAssessment {
        use CoverageReason as R;
        if !self.wire.matches(&context.wire.binding) {
            return CoverageAssessment::unknown(R::BindingMismatch);
        }
        if self.wire.provenance.observer_id != context.wire.observer_id {
            return CoverageAssessment::unknown(R::ObserverMismatch);
        }
        // Difference comparison preserves nanoseconds and avoids year-boundary addition overflow.
        let skew = seconds(self.clock_skew_seconds);
        if self.verified.signed_duration_since(context.at) > skew {
            return CoverageAssessment::unknown(R::VerificationInFuture);
        }
        if self.observed.signed_duration_since(context.at) > skew {
            return CoverageAssessment::unknown(R::ObservationInFuture);
        }
        if context.wire.mode == AssessmentMode::Current {
            match context.wire.observer_status {
                ObserverStatus::Unhealthy => {
                    return CoverageAssessment::unknown(R::ObserverUnhealthy);
                }
                ObserverStatus::Unknown => return CoverageAssessment::unknown(R::ObserverUnknown),
                ObserverStatus::Healthy => {}
            }
            if context.at >= self.expires {
                return CoverageAssessment::unknown(R::Expired);
            }
        }
        if context.end <= self.start || context.start >= self.end {
            return CoverageAssessment::unknown(R::IntervalUncovered);
        }
        if (context.start < self.start || context.end > self.end)
            && self.status() == CoverageStatus::Verified
        {
            return CoverageAssessment::new(CoverageStatus::Partial, Some(R::IntervalPartial));
        }
        CoverageAssessment::new(self.status(), self.base_reason)
    }
}

/// Assess raw candidates, giving missing trusted profiles the first guard.
/// Use `ValidatedCoverage::parse` separately when retaining a rejection error.
pub fn assess_coverage(
    bytes: &[u8],
    profile: Option<&CoverageProfile>,
    context: &CoverageContext,
) -> CoverageAssessment {
    if profile.is_none() {
        return CoverageAssessment::unknown(CoverageReason::ProfileUnavailable);
    }
    match ValidatedCoverage::parse(bytes, profile) {
        Ok(record) => record.assess(context),
        Err(CoverageError::ProfileUnavailable) => {
            CoverageAssessment::unknown(CoverageReason::ProfileUnavailable)
        }
        Err(_) => CoverageAssessment::unknown(CoverageReason::InvalidRecord),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AssessmentMode {
    Current,
    Historical,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ObserverStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Interval {
    start: String,
    end: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextWire {
    at: String,
    mode: AssessmentMode,
    observer_status: ObserverStatus,
    observer_id: String,
    binding: Binding,
    interval: Interval,
}

/// Local trusted consumer input, not a public HTTP or serialized storage contract.
#[derive(Clone, Debug)]
pub struct CoverageContext {
    wire: ContextWire,
    at: DateTime<Utc>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

impl CoverageContext {
    pub fn parse(bytes: &[u8]) -> Result<Self, CoverageError> {
        let wire: ContextWire = decode(bytes)?;
        wire.binding.validate()?;
        text(&wire.observer_id)?;
        let at = timestamp(&wire.at)?;
        let start = timestamp(&wire.interval.start)?;
        let end = timestamp(&wire.interval.end)?;
        if start >= end {
            return Err(CoverageError::InvalidInterval);
        }
        Ok(Self {
            wire,
            at,
            start,
            end,
        })
    }
}

fn reduce(
    validation: &Validation,
    required: &[Component],
    truncated: bool,
) -> (CoverageStatus, Option<CoverageReason>) {
    use CoverageReason as R;
    use CoverageStatus as S;
    if [
        validation.configuration,
        validation.scope,
        validation.continuity,
        validation.source_integrity,
    ]
    .contains(&S::Failed)
    {
        return (S::Failed, Some(R::ComponentFailed));
    }
    for (status, reason) in [
        (S::Unknown, R::ComponentUnknown),
        (S::Unsupported, R::ComponentUnsupported),
    ] {
        if required.iter().any(|c| validation.component(*c) == status) {
            return (status, Some(reason));
        }
    }
    if truncated {
        return (S::Partial, Some(R::GapDetailsTruncated));
    }
    if required
        .iter()
        .any(|c| validation.component(*c) == S::Partial)
    {
        return (S::Partial, Some(R::ComponentPartial));
    }
    (S::Verified, None)
}

fn decode<T: de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CoverageError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CoverageError::RecordBytesExceeded);
    }
    // from_str rejects invalid UTF-8 even in whitespace; derived closed objects
    // and the map visitor reject duplicate keys before any last-value-wins conversion.
    let input = std::str::from_utf8(bytes).map_err(|_| CoverageError::InvalidStructure)?;
    serde_json::from_str(input).map_err(|_| CoverageError::InvalidStructure)
}

fn text(value: &str) -> Result<(), CoverageError> {
    if value.is_empty() {
        return Err(CoverageError::InvalidStructure);
    }
    if value.len() > MAX_STRING_BYTES {
        return Err(CoverageError::StringBytesExceeded);
    }
    Ok(())
}

fn unique<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

fn record_id(value: &str) -> Result<(), CoverageError> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
    {
        return Err(CoverageError::InvalidRecordId);
    }
    if value == "00000000-0000-0000-0000-000000000000" {
        return Err(CoverageError::NilRecordId);
    }
    Ok(())
}

fn timestamp(value: &str) -> Result<DateTime<Utc>, CoverageError> {
    let b = value.as_bytes();
    if !(20..=30).contains(&b.len())
        || b[19..].last() != Some(&b'Z')
        || !b[..19].iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        })
        || (b.len() > 20
            && (b[19] != b'.'
                || b.len() < 22
                || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit)))
        || &b[..4] == b"0000"
        || &b[17..19] > b"59".as_slice()
    {
        return Err(CoverageError::InvalidTimestamp);
    }
    DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| CoverageError::InvalidTimestamp)
}

fn seconds(value: u32) -> TimeDelta {
    // Validated profile budgets are <= 86,400, safely inside Chrono's range.
    TimeDelta::seconds(i64::from(value))
}
