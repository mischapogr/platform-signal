//! Loading seams for trusted external metadata and detection providers.

use crate::{Enricher, ExtensionContext, ExtensionError, bounded};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// External overlay location selected explicitly or through `SIGNAL_OVERLAY_PATH`.
/// Selection does not read files or introduce a compiled-in default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayPath(PathBuf);

impl OverlayPath {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, ExtensionError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(ExtensionError::MissingOverlayPath);
        }
        Ok(Self(path))
    }

    pub fn from_env() -> Result<Self, ExtensionError> {
        let path =
            std::env::var_os("SIGNAL_OVERLAY_PATH").ok_or(ExtensionError::MissingOverlayPath)?;
        Self::new(PathBuf::from(path))
    }

    /// An explicit path takes precedence over the environment.
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self, ExtensionError> {
        match explicit {
            Some(path) => Self::new(path),
            None => Self::from_env(),
        }
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Provider-owned configuration must be validated before returning an enricher.
/// Implementations own their overlay path and must bound all reads and allocations.
#[async_trait]
pub trait EnrichmentProvider: Send + Sync {
    async fn load(&self, context: ExtensionContext) -> Result<Arc<dyn Enricher>, ExtensionError>;
}

/// A versioned transport envelope containing YAML for the consumer's rule parser.
/// Version 1 does not change the YAML rule schema; the consumer must compile it
/// using its rule engine before readiness or processing events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDocument {
    pub schema_version: u16,
    pub yaml: String,
}

/// Providers return bounded source documents; validation of YAML predicates and
/// duplicate rule IDs belongs to the consuming rule engine.
#[async_trait]
pub trait RuleProvider: Send + Sync {
    async fn load(&self, context: ExtensionContext) -> Result<Vec<RuleDocument>, ExtensionError>;
}

#[derive(Clone, Copy, Debug)]
pub struct RuleDocumentLimits {
    pub max_documents: usize,
    pub max_document_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for RuleDocumentLimits {
    fn default() -> Self {
        Self {
            max_documents: 64,
            max_document_bytes: 64 * 1024,
            max_total_bytes: 1024 * 1024,
        }
    }
}

impl RuleDocumentLimits {
    pub fn validate(&self) -> Result<(), ExtensionError> {
        if self.max_documents == 0
            || self.max_documents > 1024
            || self.max_document_bytes == 0
            || self.max_document_bytes > 2 * 1024 * 1024
            || self.max_total_bytes == 0
            || self.max_total_bytes > 16 * 1024 * 1024
        {
            return Err(ExtensionError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Load without spawning workers. Providers must cooperate with cancellation,
/// yield, and validate their own metadata schema before returning.
pub async fn load_enricher(
    provider: &dyn EnrichmentProvider,
    context: ExtensionContext,
) -> Result<Arc<dyn Enricher>, ExtensionError> {
    bounded(&context, provider.load(context.clone())).await
}

/// Enforce version and finite output budgets before consumer schema compilation.
/// This bounds returned documents, not allocations inside trusted provider code.
pub async fn load_rules(
    provider: &dyn RuleProvider,
    context: ExtensionContext,
    limits: RuleDocumentLimits,
) -> Result<Vec<RuleDocument>, ExtensionError> {
    context.check()?;
    limits.validate()?;
    let documents = bounded(&context, provider.load(context.clone())).await?;
    if documents.len() > limits.max_documents {
        return Err(ExtensionError::RulesTooLarge);
    }
    let mut remaining = limits.max_total_bytes;
    for document in &documents {
        context.check()?;
        if document.yaml.len() > limits.max_document_bytes {
            return Err(ExtensionError::RulesTooLarge);
        }
        remaining = remaining
            .checked_sub(document.yaml.len())
            .ok_or(ExtensionError::RulesTooLarge)?;
        if document.schema_version != 1 || document.yaml.trim().is_empty() {
            return Err(ExtensionError::InvalidRuleDocument);
        }
    }
    context.check()?;
    Ok(documents)
}
