//! Durable file positions shared by input and spool workers.

use serde::{Deserialize, Serialize};

/// A locally durable source position. The enclosing spool format is versioned.
/// `anchor` contains at most the 64 bytes immediately preceding `offset`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCheckpoint {
    pub input: u16,
    pub device: u64,
    pub inode: u64,
    pub offset: u64,
    pub anchor: Vec<u8>,
    /// Optional v1 profile binding; absent in legacy unbound file modes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_binding: Option<String>,
    /// Present only in the separately bound node spool profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identity: Option<NodeSourceIdentity>,
}

/// Durable node-file identity, independent of the slot currently assigned to it.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSourceIdentity {
    pub schema_version: u16,
    pub source: signal_collector_sdk::kubernetes_log::LogIdentity,
    pub file_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<NodeTermination>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeTermination {
    Drained,
    MissingGeneration,
    CompressedGeneration,
    UncertainRotation,
}
impl NodeSourceIdentity {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.source.validate().map_err(|_| "node source identity")?;
        let (name, _) = crate::node_root::log_name(&self.file_name).ok_or("node file name")?;
        if self.schema_version != 1 || name != format!("{}.log", self.source.restart_count) {
            return Err("node source contract");
        }
        Ok(())
    }
}
