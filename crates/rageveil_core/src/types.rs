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
    /// entry's directory: `<RecipientFingerprint>.age`. SHA-256 of
    /// the **canonical key** ([`Self::canonical_key`]) — *not* the
    /// verbatim spec — truncated to 16 hex chars (8 bytes / 64 bits).
    ///
    /// Hashing the canonical key rather than the raw string is what
    /// lets the sharer and the recipient agree on the filename. They
    /// derive their recipient strings *independently* — the sharer
    /// from the address book / command line, the recipient from
    /// their own `whoami` (the first line of their `.pub`). An
    /// OpenSSH key carries a free-form trailing comment that age
    /// ignores when encrypting; if it differs between the two sides
    /// (the everyday case: the address book holds the key without
    /// its comment, the recipient's `.pub` still has one), hashing
    /// the verbatim string would yield two different fingerprints
    /// for the *same key*. The share would then be written at a path
    /// the recipient's `sync` never looks for, and the entry would
    /// silently never appear in their `list`. Collisions are
    /// catastrophic for sharing semantics, so we keep 64 bits.
    pub fn fingerprint(&self) -> RecipientFingerprint {
        let digest = Sha256::digest(self.canonical_key().as_bytes());
        RecipientFingerprint(hex::encode(&digest[..8]))
    }

    /// The cosmetic-free key identity — what actually decides whether
    /// two specs denote the same recipient.
    ///
    /// An OpenSSH public key is `<type> <base64> [comment]`; only the
    /// first two fields are the key (age ignores the comment), so the
    /// comment and any extra spacing must not influence identity. age
    /// `age1…` recipients are already a single canonical token and
    /// pass through untouched. This is pure string surgery — no key
    /// parsing — so it stays at the data-model layer, consistent with
    /// this type's contract that recipient parsing belongs to the
    /// interpreter, not here.
    pub fn canonical_key(&self) -> String {
        let t = self.0.trim();
        if t.starts_with("ssh-") {
            let mut fields = t.split_whitespace();
            match (fields.next(), fields.next()) {
                (Some(kind), Some(body)) => format!("{kind} {body}"),
                // Malformed (no base64 body) — fall back to the
                // trimmed string rather than inventing an identity.
                _ => t.to_owned(),
            }
        } else {
            t.to_owned()
        }
    }

    /// The pre-canonicalisation fingerprint: SHA-256 of the *verbatim*
    /// recipient string. This is what stores written before the
    /// canonical-key fix named their files with. Readers fall back to
    /// it (via [`crate::store::StoreLayout::entry_file_candidates`]) so
    /// upgrading the binary never loses access to entries shared
    /// earlier; `deny` also removes it so revocation is complete on a
    /// legacy store. **Writers never use this** — new files always go
    /// under the canonical [`Self::fingerprint`]. Identical to
    /// `fingerprint()` for every `age1…` recipient and any ssh key
    /// that already lacked a comment, so on those stores there is
    /// nothing to fall back to and nothing changes.
    pub fn legacy_fingerprint(&self) -> RecipientFingerprint {
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

#[cfg(test)]
mod tests {
    use super::*;

    // The headline invariant: an OpenSSH recipient's fingerprint —
    // the per-recipient `.age` filename, computed independently by
    // sharer and recipient — must not depend on the cosmetic comment
    // age ignores. Otherwise a share lands at a name the recipient
    // never looks for and silently vanishes from their `list`.
    #[test]
    fn fingerprint_ignores_ssh_comment() {
        let base = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexamplekeymaterial0000";
        let with = RecipientSpec::new(format!("{base} pa@laptop"));
        let other = RecipientSpec::new(format!("{base} pa@desktop"));
        let none = RecipientSpec::new(base.to_string());
        assert_eq!(with.fingerprint(), none.fingerprint());
        assert_eq!(with.fingerprint(), other.fingerprint());
    }

    #[test]
    fn fingerprint_collapses_internal_whitespace_for_ssh() {
        let tidy = RecipientSpec::new("ssh-ed25519 AAAAkeybody comment-a");
        // Constructed via the bare tuple (no `new` trim) with ragged
        // spacing and a different comment — still the same key.
        let ragged = RecipientSpec("  ssh-ed25519   AAAAkeybody   comment-b ".to_string());
        assert_eq!(tidy.fingerprint(), ragged.fingerprint());
    }

    #[test]
    fn distinct_ssh_keys_still_differ() {
        let a = RecipientSpec::new("ssh-ed25519 AAAAkeyONE shared-comment");
        let b = RecipientSpec::new("ssh-ed25519 AAAAkeyTWO shared-comment");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn age_recipient_passes_through_canonicalisation() {
        // age recipients are a single canonical token already; the
        // canonicalisation must be a no-op (don't mangle them).
        let age = RecipientSpec::new("age1exampleexampleexampleexampleexampleexampleexm");
        assert_eq!(age.canonical_key(), age.as_str());
    }

    #[test]
    fn legacy_fingerprint_is_the_old_verbatim_hash() {
        // For a commented ssh key the legacy (verbatim) fingerprint
        // must differ from the canonical one — that gap is exactly
        // the pre-fix store layout the reader falls back to.
        let k = RecipientSpec::new("ssh-ed25519 AAAAkeybody owner@host");
        assert_ne!(k.legacy_fingerprint(), k.fingerprint());
    }

    #[test]
    fn legacy_equals_canonical_when_nothing_to_canonicalise() {
        // No comment / age key ⇒ verbatim == canonical ⇒ no fallback
        // path exists, nothing to migrate.
        let ssh = RecipientSpec::new("ssh-ed25519 AAAAkeybody");
        assert_eq!(ssh.legacy_fingerprint(), ssh.fingerprint());
        let age = RecipientSpec::new("age1exampleexampleexampleexampleexampleexampleexm");
        assert_eq!(age.legacy_fingerprint(), age.fingerprint());
    }
}
