//! `store/addressbook.json` — the shared name → recipient mapping.
//!
//! Unlike [`crate::index`] (`index.json`: local, plaintext,
//! per-operator, never committed) this file lives **inside** the git
//! working tree, so the whole team shares one name→key table. Public
//! keys aren't secret — committing them is fine, and it means once
//! you `rageveil address add pa <key>` everyone who `sync`s can write
//! `rageveil allow <secret> pa` instead of pasting the raw recipient.
//!
//! The map is `name → RecipientSpec`. Names are short handles
//! (`pa`, `alice`); the value is exactly what `allow`/`deny` would
//! otherwise take on the command line (`age1…`, `ssh-ed25519 …`,
//! `ssh-rsa …`).

use crate::types::RecipientSpec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Filename of the address book inside the git working tree
/// (`<store>/addressbook.json`). Exposed as a `const` so the `sync`
/// store-walk can skip it by name the same way it skips `.gitkeep` —
/// it sits next to the `<entry-hash>/` directories but is not one.
pub const ADDRESSBOOK_FILE: &str = "addressbook.json";

/// The shared address book. `#[serde(transparent)]` so the on-disk
/// JSON is just the map (`{"pa":"age1…","alice":"ssh-ed25519 …"}`) —
/// same trick [`crate::index::Index`] uses.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AddressBook {
    /// name → recipient. `BTreeMap` keeps the serialised output
    /// stable (deterministic git diffs) and makes `address list`
    /// sorted for free.
    pub people: BTreeMap<String, RecipientSpec>,
}

impl AddressBook {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&RecipientSpec> {
        self.people.get(name)
    }
}

/// Heuristic: does this token already look like a raw recipient key
/// rather than an address-book name? `age1…` is native X25519;
/// `ssh-…` covers `ssh-ed25519` / `ssh-rsa`. Names that would collide
/// with these prefixes are rejected at `address add` time, so the
/// classification stays unambiguous when `allow`/`deny` resolve their
/// arguments.
pub fn looks_like_key(token: &str) -> bool {
    let t = token.trim();
    t.starts_with("age1") || t.starts_with("ssh-")
}
