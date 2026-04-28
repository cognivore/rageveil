//! `index.json` — local plaintext cache of `EntryPath -> Cached`.
//!
//! Lives at `<store>/index.json`, **never** committed to git (the
//! whole point is that it's plaintext and per-operator). It exists
//! so `list` / `search` / `info` don't have to decrypt every
//! entry to surface human-readable names.

use crate::metadata::Metadata;
use crate::types::{EntryHash, EntryPath};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cached {
    pub hash: EntryHash,
    pub metadata: Metadata,
    /// Last time this operator's local index saw the entry change.
    /// Not authoritative for ordering — just useful for `info`.
    pub seen: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Index {
    pub entries: BTreeMap<EntryPath, Cached>,
}

impl Index {
    pub fn empty() -> Self {
        Self::default()
    }
}

/// What changed between two index snapshots — exactly the four
/// states passveil reports during sync. Used by `commands::sync`
/// to render colored `-/+/*/!` lines per affected entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexMod {
    /// Entry-file vanished from the store (someone deleted, or
    /// `deny` revoked our last copy). Painted red `-`.
    Removed(EntryPath),
    /// Entry appeared (someone shared with us, or we just
    /// inserted). Painted green `+`.
    Inserted(EntryPath),
    /// Content / hash changed but the metadata's `updated` stamp
    /// didn't move — typical case: a `deny` operation that didn't
    /// touch the value, or a `delete`+re-`insert` that landed on
    /// the same path. Painted yellow `*`.
    Modified(EntryPath),
    /// Metadata's `updated` stamp changed — the canonical "this
    /// secret was edited or shared" signal. Painted magenta `!`.
    Updated(EntryPath),
}

impl IndexMod {
    pub fn path(&self) -> &EntryPath {
        match self {
            IndexMod::Removed(p)
            | IndexMod::Inserted(p)
            | IndexMod::Modified(p)
            | IndexMod::Updated(p) => p,
        }
    }
}

/// Diff `before` against `after`, producing one [`IndexMod`] per
/// entry that changed. Order is by path so output is deterministic.
///
/// Classification rules — matching passveil:
///   * present in `before`, missing in `after`  → `Removed`
///   * missing in `before`, present in `after`  → `Inserted`
///   * present in both, `metadata.updated` differs → `Updated`
///   * present in both, anything else differs (hash, log entries,
///     `seen`)                                  → `Modified`
///   * present in both, fully equal             → no mod emitted
pub fn diff(before: &Index, after: &Index) -> Vec<IndexMod> {
    let mut mods = Vec::new();
    let mut seen_paths: std::collections::BTreeSet<&EntryPath> = before.entries.keys().collect();
    seen_paths.extend(after.entries.keys());

    for path in seen_paths {
        match (before.entries.get(path), after.entries.get(path)) {
            (Some(_), None) => mods.push(IndexMod::Removed(path.clone())),
            (None, Some(_)) => mods.push(IndexMod::Inserted(path.clone())),
            (Some(b), Some(a)) => {
                let stamps_differ = match (&b.metadata.updated, &a.metadata.updated) {
                    (None, None) => false,
                    (Some(x), Some(y)) => x.at != y.at || x.by != y.by,
                    _ => true,
                };
                if stamps_differ {
                    mods.push(IndexMod::Updated(path.clone()));
                } else if b.hash != a.hash
                    || b.metadata.log.len() != a.metadata.log.len()
                {
                    mods.push(IndexMod::Modified(path.clone()));
                }
                // Fully equal → no mod.
            }
            (None, None) => unreachable!(),
        }
    }
    mods
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::Stamp;
    use crate::types::RecipientSpec;
    use chrono::TimeZone;

    fn stamp_at(year: i32, day: u32) -> Stamp {
        Stamp {
            at: Utc.with_ymd_and_hms(year, 1, day, 0, 0, 0).single().expect("stamp"),
            by: RecipientSpec::new("age1stub"),
        }
    }

    fn cached_with(updated: Option<Stamp>, log_len: usize, hash: &str) -> Cached {
        Cached {
            hash: EntryHash(hash.to_string()),
            metadata: Metadata {
                created: stamp_at(2026, 1),
                updated,
                log: (0..log_len)
                    .map(|_| crate::metadata::LogEntry::Allow {
                        subject: RecipientSpec::new("age1x"),
                        stamp: stamp_at(2026, 1),
                    })
                    .collect(),
            },
            seen: stamp_at(2026, 1).at,
        }
    }

    fn idx(entries: &[(&str, Cached)]) -> Index {
        Index {
            entries: entries
                .iter()
                .map(|(p, c)| (EntryPath::new(*p), c.clone()))
                .collect(),
        }
    }

    #[test]
    fn diff_inserted() {
        let before = idx(&[]);
        let after = idx(&[("foo", cached_with(None, 1, "h"))]);
        assert_eq!(diff(&before, &after), vec![IndexMod::Inserted(EntryPath::new("foo"))]);
    }

    #[test]
    fn diff_removed() {
        let before = idx(&[("foo", cached_with(None, 1, "h"))]);
        let after = idx(&[]);
        assert_eq!(diff(&before, &after), vec![IndexMod::Removed(EntryPath::new("foo"))]);
    }

    #[test]
    fn diff_updated_via_metadata_stamp() {
        let before = idx(&[("foo", cached_with(None, 1, "h"))]);
        let after = idx(&[("foo", cached_with(Some(stamp_at(2026, 5)), 1, "h"))]);
        assert_eq!(diff(&before, &after), vec![IndexMod::Updated(EntryPath::new("foo"))]);
    }

    #[test]
    fn diff_modified_via_log_change() {
        let before = idx(&[("foo", cached_with(None, 1, "h"))]);
        let after = idx(&[("foo", cached_with(None, 2, "h"))]);
        assert_eq!(diff(&before, &after), vec![IndexMod::Modified(EntryPath::new("foo"))]);
    }

    #[test]
    fn diff_no_change_when_equal() {
        let c = cached_with(Some(stamp_at(2026, 2)), 3, "h");
        let before = idx(&[("foo", c.clone())]);
        let after = idx(&[("foo", c)]);
        assert!(diff(&before, &after).is_empty());
    }
}
