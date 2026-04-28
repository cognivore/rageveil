//! Pure path-arithmetic for the on-disk store layout.
//!
//! ```text
//! <root>/
//!   config.json                     ← Config { whoami, identity_path }
//!   index.json                      ← local-only plaintext cache
//!   store/                          ← git working tree (the *shared* part)
//!     .git/
//!     <entry-hash>/                 ← one dir per entry
//!       <recipient-fingerprint>.age ← one file per recipient
//! ```
//!
//! Nothing in this module touches the filesystem; it just composes
//! `PathBuf`s. The Vault DSL takes care of actually reading and
//! writing.

use crate::types::{EntryHash, RecipientFingerprint};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct StoreLayout {
    pub root: PathBuf,
}

impl StoreLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    /// Working tree of the git repository — the directory whose
    /// contents *are* the shared store.
    pub fn store_dir(&self) -> PathBuf {
        self.root.join("store")
    }

    pub fn entry_dir(&self, hash: &EntryHash) -> PathBuf {
        self.store_dir().join(hash.as_str())
    }

    pub fn entry_file(
        &self,
        hash: &EntryHash,
        fp: &RecipientFingerprint,
    ) -> PathBuf {
        self.entry_dir(hash).join(format!("{}.age", fp.as_str()))
    }

    /// Filename → recipient fingerprint, if it parses as one of
    /// our `<fp>.age` shaped names.
    pub fn fingerprint_from_filename(p: &Path) -> Option<RecipientFingerprint> {
        let name = p.file_name()?.to_str()?;
        let stem = name.strip_suffix(".age")?;
        // Sanity-check the shape so foreign files in the entry
        // dir don't pollute the recipient list.
        if stem.is_empty() || !stem.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(RecipientFingerprint(stem.to_owned()))
    }
}
