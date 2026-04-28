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
