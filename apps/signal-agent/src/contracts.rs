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
}
