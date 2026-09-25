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
use std::collections::{BTreeMap, BTreeSet};

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

// ─── personas ────────────────────────────────────────────────────────────

/// Filename of the persona groups inside the git working tree
/// (`<store>/personas.json`), beside the address book and signed
/// the same way.
pub const PERSONAS_FILE: &str = "personas.json";

/// Persona groups: one person, several address-book names.
///
/// `lucia` carries a laptop key and a work phone; both are
/// registered in the address book under their own names, and this
/// file says they are the same person: `{"lucia":
/// ["lucia-work-phone"]}`. The canonical name is the group's key;
/// it is a member too whenever it has an address-book entry of its
/// own. `allow` resolves any name in a group to every key in it, so
/// a secret shared to one device reaches all of them. Revocation
/// reaches no further than what is named: `deny`/`revoke` on the
/// canonical name take every device, on a member name only that one.
///
/// Whoever can rewrite this file can put their own name inside
/// someone else's group and be handed every later share, so it is
/// signed and verified exactly like the address book.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Personas {
    /// canonical name → the other names that are the same person.
    pub groups: BTreeMap<String, BTreeSet<String>>,
}

impl Personas {
    pub fn empty() -> Self {
        Self::default()
    }

    /// The canonical name of the group `name` belongs to, whether
    /// as its key or as a member.
    pub fn canonical_of(&self, name: &str) -> Option<&str> {
        if let Some((canonical, _)) = self.groups.get_key_value(name) {
            return Some(canonical.as_str());
        }
        self.groups
            .iter()
            .find(|(_, members)| members.contains(name))
            .map(|(canonical, _)| canonical.as_str())
    }

    /// Every name that is the same person as `name`, canonical
    /// first. A name in no group is its own group of one.
    pub fn expand(&self, name: &str) -> Vec<String> {
        match self.canonical_of(name) {
            None => vec![name.to_owned()],
            Some(canonical) => {
                let mut out = vec![canonical.to_owned()];
                if let Some(members) = self.groups.get(canonical) {
                    out.extend(members.iter().cloned());
                }
                out
            }
        }
    }
}
