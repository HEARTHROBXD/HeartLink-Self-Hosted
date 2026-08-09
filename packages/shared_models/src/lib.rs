//! Plaintext-free models shared by clients and the synchronization service.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Kinds are visible metadata; record contents remain opaque ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// Server address and presentation record.
    ServerProfile,
    /// Encrypted credential record.
    Credential,
    /// Encrypted private-key record.
    PrivateKey,
    /// Server group.
    ServerGroup,
    /// Tag.
    Tag,
    /// Command snippet.
    CommandSnippet,
    /// User preference or theme record.
    Preference,
}

/// An opaque record accepted by the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherRecord {
    /// Stable client-generated identifier.
    pub id: Uuid,
    /// Visible routing metadata.
    pub kind: RecordKind,
    /// Versioned AEAD envelope encoded by the client.
    pub ciphertext: String,
    /// Client record format version.
    pub data_version: u32,
    /// Revision the client last observed; zero creates a record.
    pub base_revision: i64,
    /// Tombstone marker.
    pub deleted: bool,
    /// Device which authored this version.
    pub device_id: Uuid,
}

/// Server-assigned synchronized revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionedRecord {
    /// Opaque client record.
    #[serde(flatten)]
    pub record: CipherRecord,
    /// Monotonic revision cursor.
    pub revision: i64,
    /// Unix timestamp in seconds assigned by the service.
    pub updated_at: i64,
}
