//! Human-only entries whose current value a plain key once held.
//!
//! AI-generated module: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! Making an automation-tolerant entry human-only takes the copies away
//! from plain keys, but the store's git history still has them: any plain
//! key that held one can read the old value back with `git show`. Only a
//! new value makes the entry as safe as its tier says. Until then the
//! entry is *exposed*, and `list` and `info` say so.
//!
//! The record is the file `<store>/exposed.txt`, one entry hash per line,
//! sorted, so concurrent changes from two people merge line by line.
//! It lives outside the encrypted entries on purpose: marking an entry
//! must not need the finger that opening it needs, and every collaborator
//! sees the same warning. Who can push to the store can edit the file,
//! which hides or adds a warning and changes nothing else.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::dsl::Vault;
use crate::store::StoreLayout;
use crate::types::{EntryHash, EntryPath};
use crate::vault_do;

/// Named with a dot: clients released before this file existed skip
/// every name in the store with a dot in it, and would take any other
/// name for an entry directory.
pub const EXPOSED_FILE: &str = "exposed.txt";

/// Hashes of the exposed entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exposed {
    pub hashes: BTreeSet<String>,
}

impl Exposed {
    /// Lines that are not a 64-digit hex hash are ignored rather than
    /// refused: a damaged line must not stop anyone opening the store.
    pub fn parse(text: &str) -> Self {
        let hashes = text
            .lines()
            .map(str::trim)
            .filter(|l| l.len() == 64 && l.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(str::to_ascii_lowercase)
            .collect();
        Self { hashes }
    }

    pub fn render(&self) -> String {
        self.hashes.iter().map(|h| format!("{h}\n")).collect()
    }

    pub fn holds(&self, hash: &EntryHash) -> bool {
        self.hashes.contains(hash.as_str())
    }
}

pub fn exposed_path(layout: &StoreLayout) -> PathBuf {
    layout.store_dir().join(EXPOSED_FILE)
}

pub fn load_exposed_or_empty<S>(s: S, layout: &StoreLayout) -> S::R<Exposed>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let path = exposed_path(layout);
    let s2 = s.clone();
    vault_do! { s ;
        let there = s.exists(path.clone()) ;
        match there {
            false => s2.pure(Exposed::default()),
            true => {
                let s3 = s2.clone();
                vault_do! { s2 ;
                    let bytes = s2.read_file(path) ;
                    s3.pure(Exposed::parse(&String::from_utf8_lossy(&bytes)))
                }
            }
        }
    }
}

/// Record whether the entry is exposed. Writes only when that changes,
/// and removes the file once nothing is exposed. The caller stages and
/// commits it with the entry.
pub fn mark<S>(s: S, layout: StoreLayout, hash: EntryHash, exposed: bool) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let path = exposed_path(&layout);
    let s2 = s.clone();
    vault_do! { s ;
        let mut current = load_exposed_or_empty(s.clone(), &layout) ;
        {
            let changed = if exposed {
                current.hashes.insert(hash.0.clone())
            } else {
                current.hashes.remove(hash.as_str())
            };
            match (changed, current.hashes.is_empty()) {
                (false, _) => s2.pure(()),
                (true, true) => s2.remove_file(path),
                (true, false) => s2.write_file(path, current.render().into_bytes()),
            }
        }
    }
}

/// The service an entry belongs to: its path up to the first `/`.
pub fn service_of(path: &EntryPath) -> &str {
    path.0.split('/').next().unwrap_or(&path.0)
}

/// A Kagi search for how to change the password at the entry's service.
/// Only the service goes into the query, never the account name.
pub fn rotation_search_url(path: &EntryPath) -> String {
    let query = format!("{} change password", service_of(path));
    let mut encoded = String::with_capacity(query.len() * 3);
    for b in query.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{b:02X}")),
        }
    }
    format!("https://kagi.com/search?q={encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_search_names_the_service_alone() {
        let path = EntryPath::new("accounts.google.com/jane@example.com/recovery");
        assert_eq!(service_of(&path), "accounts.google.com");
        assert_eq!(
            rotation_search_url(&path),
            "https://kagi.com/search?q=accounts.google.com+change+password"
        );
        assert_eq!(
            rotation_search_url(&EntryPath::new("a&b")),
            "https://kagi.com/search?q=a%26b+change+password"
        );
    }

    #[test]
    fn the_file_round_trips_and_ignores_damage() {
        let h = "a".repeat(64);
        let text = format!("{h}\nnot a hash\n\n{}\n", "B".repeat(64));
        let parsed = Exposed::parse(&text);
        assert_eq!(parsed.hashes.len(), 2);
        assert!(parsed.holds(&EntryHash(h.clone())));
        assert_eq!(Exposed::parse(&parsed.render()), parsed);
    }
}
