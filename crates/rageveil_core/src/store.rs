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

use crate::types::{EntryHash, RecipientFingerprint, RecipientSpec};
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

    /// The shared address book, `<store>/addressbook.json`. Unlike
    /// [`Self::index_path`] this lives *inside* the git working tree
    /// ([`Self::store_dir`]), so it is committed and synced — the
    /// name→key table is the same for everyone who pulls the store.
    pub fn addressbook_path(&self) -> PathBuf {
        self.store_dir().join(crate::addressbook::ADDRESSBOOK_FILE)
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

    /// Per-recipient entry-file candidates, newest scheme first: the
    /// canonical-fingerprint name, then — only when it differs — the
    /// legacy (verbatim-string) name used by stores written before the
    /// canonical-key fix.
    ///
    /// Readers (`show`, `sync`'s index rebuild, `allow`/`deny`'s
    /// self-decrypt) take the *first that exists* via
    /// [`crate::sugar::first_existing`], so upgrading the binary never
    /// drops access to an entry shared earlier. Writers always use the
    /// canonical name (`entry_file(hash, &spec.fingerprint())`); the
    /// legacy copy, if any, is left in place so a collaborator still on
    /// the old binary keeps reading it. For `age1…` recipients and
    /// already-comment-free ssh keys the two coincide and only one
    /// path comes back.
    pub fn entry_file_candidates(
        &self,
        hash: &EntryHash,
        spec: &RecipientSpec,
    ) -> Vec<PathBuf> {
        let canonical = spec.fingerprint();
        let legacy = spec.legacy_fingerprint();
        let mut out = vec![self.entry_file(hash, &canonical)];
        if legacy != canonical {
            out.push(self.entry_file(hash, &legacy));
        }
        out
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
