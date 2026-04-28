//! `Content` — the JSON payload that gets age-encrypted, one copy
//! per recipient, and dropped on disk under
//! `<store>/<entry-hash>/<recipient-fingerprint>.age`.
//!
//! The path is stored *inside* the payload so a recipient who
//! decrypts can recover the human-readable name without consulting
//! anyone else's index. The salt is a 32-byte random value mixed
//! into the encrypted blob so two encryptions of the same secret
//! to the same recipient produce different ciphertexts — git's
//! commit history therefore can't trivially detect "nothing
//! changed".

use crate::metadata::Metadata;
use crate::types::{EntryPath, Salt};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Content {
    pub path: EntryPath,
    pub salt: Salt,
    /// Plaintext payload. The whole `Content` JSON is what gets
    /// fed to age — `payload` is therefore a string the user
    /// chose, not anything age-encoded.
    pub payload: String,
    pub metadata: Metadata,
}
