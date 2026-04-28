//! Pure data types shared across the DSL, the data model, and the
//! commands. None of these has effects — they're all values that
//! flow through `R<A>` either as inputs or outputs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Human-readable entry path, e.g. `"database/prod/password"`.
///
/// Slashes are conventional for hierarchical organisation but the
/// store treats the whole string as opaque — it's hashed before
/// hitting disk so the layout never leaks the namespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryPath(pub String);

impl EntryPath {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// SHA-256 of the path bytes, hex-encoded. Used as the on-disk
    /// directory name for the entry — `store/<hash>/`.
    pub fn hash(&self) -> EntryHash {
        let digest = Sha256::digest(self.0.as_bytes());
        EntryHash(hex::encode(digest))
    }
}

impl fmt::Display for EntryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Hex-encoded SHA-256 of an [`EntryPath`]. The on-disk directory
/// name for an entry, deliberately opaque so the store layout
/// doesn't leak organisational structure.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryHash(pub String);

impl EntryHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntryHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An age recipient string — what gets stored in `config.json` as
/// `whoami` and what `allow` accepts on the command line. Wrapping
/// the string keeps the DSL effects honest about whether they're
/// taking a key spec or random text, but the spec is never parsed
/// at the data-model layer; that lives in the Live interpreter.
///
/// Recognised forms (decided by [`age`]):
///   * `age1...`              — native X25519
///   * `ssh-ed25519 AAAA...`  — OpenSSH Ed25519
///   * `ssh-rsa AAAA...`      — OpenSSH RSA
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecipientSpec(pub String);

impl RecipientSpec {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into().trim().to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Stable per-recipient identifier used as a filename inside an
    /// entry's directory. SHA-256 of the canonical recipient string,
    /// truncated to 16 hex chars (8 bytes / 64 bits) — collisions
    /// are catastrophic for sharing semantics, so we want plenty of
    /// bits but not the full 64-char tax on every filename.
    pub fn fingerprint(&self) -> RecipientFingerprint {
        let digest = Sha256::digest(self.0.as_bytes());
        RecipientFingerprint(hex::encode(&digest[..8]))
    }
}

impl fmt::Display for RecipientSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Short hex digest of a [`RecipientSpec`]. File names inside an
/// entry's directory are `<RecipientFingerprint>.age`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecipientFingerprint(pub String);

impl RecipientFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecipientFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Random salt mixed into [`crate::content::Content`] so the same
/// payload encrypted twice produces visibly different plaintext
/// (defeats trivial equality oracles on the backing git history).
///
/// 32 bytes hex-encoded → 64 chars.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Salt(pub String);

impl Salt {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(bytes))
    }
}

/// Result of a [`crate::Vault::shell`] invocation. Mirrors orim's
/// `ProcessOut` shape so future renderers can reuse machinery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOut {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl ProcessOut {
    pub fn success(&self) -> bool {
        self.status == 0
    }

    pub fn stdout_str(&self) -> &str {
        std::str::from_utf8(&self.stdout).unwrap_or("<non-utf8>")
    }

    pub fn stderr_str(&self) -> &str {
        std::str::from_utf8(&self.stderr).unwrap_or("<non-utf8>")
    }
}
