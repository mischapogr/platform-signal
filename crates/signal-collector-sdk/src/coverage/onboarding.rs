//! Current onboarding snapshots, not activation permits or source authentication.
//!
//! The trusted host supplies live connection checks, configured requirements and
//! actual loaded-rule state. Never populate these from collector claims or HTTP
//! parameters. Coverage uses the same trusted profile/context as normal assessment.
//! Recompute at use time; a serialized report grants no authority to enable rules.

use super::{
    CoverageAssessment, CoverageContext, CoverageProfile, CoverageStatus, assess_coverage,
};
use serde::Serialize;
use std::collections::BTreeSet;
use thiserror::Error;

pub const MAX_DETECTIONS: usize = 64;
pub const MAX_REQUIREMENTS: usize = 32;
pub const MAX_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequirementStatus {
    Met,
    Missing,
    Unknown,
}

/// Trusted host evidence for a configured prerequisite. Unknown blocks readiness.
#[derive(Clone, Debug)]
pub struct Requirement {
    pub id: String,
    pub status: RequirementStatus,
}

/// One rule's host-checked preconditions for the exact assessed source scope.
/// Empty lists mean no requirement in that category, not an unknown inventory.
#[derive(Clone, Debug)]
pub struct Detection {
    pub id: String,
    pub supported: bool,
    pub loaded: bool,
    pub permissions: Vec<Requirement>,
    pub categories: Vec<Requirement>,
    pub state: Vec<Requirement>,
}

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Disconnected,
    Connected,
    CoverageVerified,
    DetectionsActive,
}

#[derive(Clone, Copy, Debug, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BlockerCode {
    Disconnected,
    HistoricalContext,
    CoverageNotVerified,
    UnsupportedDetection,
    RuleNotLoaded,
    MissingPermission,
    UnknownPermission,
    MissingCategory,
    UnknownCategory,
    MissingState,
    UnknownState,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct Blocker {
    pub code: BlockerCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirement: Option<String>,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct DetectionReport {
    pub id: String,
    pub active: bool,
    pub blockers: Vec<Blocker>,
}

/// Read-only v1 snapshot. `detections_active` means at least one listed rule is
/// eligible and loaded; blocked rules remain explicit and never become active.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct OnboardingReport {
    pub schema_version: u32,
    pub stage: Stage,
    pub coverage: CoverageAssessment,
    pub detections: Vec<DetectionReport>,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OnboardingError {
    #[error("onboarding_budget_exceeded")]
    BudgetExceeded,
    #[error("invalid_onboarding_id")]
    InvalidId,
    #[error("duplicate_onboarding_id")]
    DuplicateId,
}

fn validate_ids<'a>(ids: impl Iterator<Item = &'a str>) -> Result<(), OnboardingError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        if id.is_empty()
            || id.len() > MAX_ID_BYTES
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        {
            return Err(OnboardingError::InvalidId);
        }
        if !seen.insert(id) {
            return Err(OnboardingError::DuplicateId);
        }
    }
    Ok(())
}

fn prerequisite_blockers(
    blockers: &mut Vec<Blocker>,
    requirements: &[Requirement],
    missing: BlockerCode,
    unknown: BlockerCode,
) {
    for requirement in requirements {
        let code = match requirement.status {
            RequirementStatus::Met => continue,
            RequirementStatus::Missing => missing,
            RequirementStatus::Unknown => unknown,
        };
        blockers.push(Blocker {
            code,
            requirement: Some(requirement.id.clone()),
        });
    }
}

/// Assess bounded trusted inputs. No I/O, queue, retained state or rule mutation.
/// `connected` must come from a live host check, never token entry or event receipt.
pub fn assess_onboarding(
    connected: bool,
    record: &[u8],
    profile: Option<&CoverageProfile>,
    context: &CoverageContext,
    detections: &[Detection],
) -> Result<OnboardingReport, OnboardingError> {
    if detections.len() > MAX_DETECTIONS {
        return Err(OnboardingError::BudgetExceeded);
    }
    validate_ids(detections.iter().map(|d| d.id.as_str()))?;
    for detection in detections {
        for requirements in [
            &detection.permissions,
            &detection.categories,
            &detection.state,
        ] {
            if requirements.len() > MAX_REQUIREMENTS {
                return Err(OnboardingError::BudgetExceeded);
            }
            validate_ids(requirements.iter().map(|r| r.id.as_str()))?;
        }
    }
    let coverage = assess_coverage(record, profile, context);
    let verified = context.is_current() && coverage.status() == CoverageStatus::Verified;
    let reports: Vec<_> = detections
        .iter()
        .map(|detection| {
            let mut blockers = Vec::new();
            for (blocked, code) in [
                (!connected, BlockerCode::Disconnected),
                (!context.is_current(), BlockerCode::HistoricalContext),
                (!verified, BlockerCode::CoverageNotVerified),
                (!detection.supported, BlockerCode::UnsupportedDetection),
                (!detection.loaded, BlockerCode::RuleNotLoaded),
            ] {
                if blocked {
                    blockers.push(Blocker {
                        code,
                        requirement: None,
                    });
                }
            }
            prerequisite_blockers(
                &mut blockers,
                &detection.permissions,
                BlockerCode::MissingPermission,
                BlockerCode::UnknownPermission,
            );
            prerequisite_blockers(
                &mut blockers,
                &detection.categories,
                BlockerCode::MissingCategory,
                BlockerCode::UnknownCategory,
            );
            prerequisite_blockers(
                &mut blockers,
                &detection.state,
                BlockerCode::MissingState,
                BlockerCode::UnknownState,
            );
            DetectionReport {
                id: detection.id.clone(),
                active: blockers.is_empty(),
                blockers,
            }
        })
        .collect();
    let stage = if !connected {
        Stage::Disconnected
    } else if !verified {
        Stage::Connected
    } else if reports.iter().any(|report| report.active) {
        Stage::DetectionsActive
    } else {
        Stage::CoverageVerified
    };
    Ok(OnboardingReport {
        schema_version: 1,
        stage,
        coverage,
        detections: reports,
    })
}
