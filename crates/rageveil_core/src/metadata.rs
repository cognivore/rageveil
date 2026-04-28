//! Per-entry metadata: who created it, who updated it, the trust
//! log of `allow` / `deny` events.
//!
//! The same shape as passveil's `Metadata` / `Log` / `Trust` — the
//! original is straightforward enough that there's nothing to gain
//! by reorganising. What differs:
//!
//!   * Issuers are age recipient strings instead of GPG fingerprints.
//!   * No signing log; age has no signature primitive in 0.11 and
//!     adding one would require a separate scheme. `info`-style
//!     verification is therefore best-effort and we don't pretend
//!     otherwise. (The user explicitly de-prioritised `info` parity.)

use crate::types::RecipientSpec;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// "When and by whom." Stamps every metadata transition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stamp {
    pub at: DateTime<Utc>,
    pub by: RecipientSpec,
}

/// One entry in the trust log.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum LogEntry {
    /// Recipient `subject` was added by `stamp.by` at `stamp.at`.
    Allow { subject: RecipientSpec, stamp: Stamp },
    /// Recipient `subject` was removed by `stamp.by` at `stamp.at`.
    Deny { subject: RecipientSpec, stamp: Stamp },
}

impl LogEntry {
    pub fn subject(&self) -> &RecipientSpec {
        match self {
            LogEntry::Allow { subject, .. } | LogEntry::Deny { subject, .. } => subject,
        }
    }
}

/// Metadata travels inside the encrypted payload (so the trust log
/// is itself confidential — the on-disk filenames already disclose
/// recipient fingerprints, but exposing the human-readable issuer
/// strings would be worse) and also caches into the local plaintext
/// `index.json` after decryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub created: Stamp,
    #[serde(default)]
    pub updated: Option<Stamp>,
    pub log: Vec<LogEntry>,
}

impl Metadata {
    pub fn new(by: RecipientSpec, at: DateTime<Utc>) -> Self {
        Self {
            created: Stamp { at, by: by.clone() },
            updated: None,
            log: vec![LogEntry::Allow {
                subject: by.clone(),
                stamp: Stamp { at, by },
            }],
        }
    }

    /// The set of recipients currently trusted to decrypt this
    /// entry — replay the log keeping the last write per subject.
    pub fn trusted(&self) -> Vec<RecipientSpec> {
        let mut state: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
        let mut canonical: std::collections::BTreeMap<String, RecipientSpec> =
            std::collections::BTreeMap::new();
        for entry in &self.log {
            let key = entry.subject().0.clone();
            canonical.insert(key.clone(), entry.subject().clone());
            state.insert(
                key,
                matches!(entry, LogEntry::Allow { .. }),
            );
        }
        state
            .into_iter()
            .filter_map(|(k, allowed)| if allowed { canonical.remove(&k) } else { None })
            .collect()
    }
}
