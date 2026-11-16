//! Who may open an entry without a person present.
//!
//! An entry is either **automation-tolerant** or **human-only**.
//!
//! * Automation-tolerant (the default): every trusted recipient gets a
//!   copy. That includes a laptop's plain SSH key, which anything
//!   running as that user can read, an AI agent included. Use it for
//!   what such an agent is meant to use: API keys, a low-limit card,
//!   service passwords.
//! * Human-only: only **gated** recipients get a copy — keys that are
//!   released by a person, not by a file. A gated key is a Secure
//!   Enclave key (`age1se1…`, opened with Touch ID), or a key the store
//!   lists in `gated.json`: a phone's or a Visageveil app's device key,
//!   kept behind the device's biometrics. Plain keys stay trusted, so
//!   setting the entry back to automation-tolerant reaches them again,
//!   but they hold no copy while it is human-only.
//!
//! The tier lives inside the encrypted entry, in its metadata. Older
//! readers ignore the field; an older *writer* would drop it and reshare
//! to everyone, which is why the store should be written only by this
//! version once a human-only entry exists.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::dsl::Vault;
use crate::metadata::Metadata;
use crate::store::StoreLayout;
use crate::sugar::read_json;
use crate::types::{EntryHash, RecipientSpec};
use crate::vault_do;

/// The file, beside the address book, that lists gated device keys.
pub const GATED_FILE: &str = "gated.json";

/// How an entry may be opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// Every trusted recipient holds a copy.
    #[default]
    Automation,
    /// Only gated recipients hold a copy.
    Human,
}

impl Tier {
    pub fn is_automation(&self) -> bool {
        *self == Tier::Automation
    }

    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "automation" | "automation-tolerant" => Some(Tier::Automation),
            "human" | "human-only" => Some(Tier::Human),
            _ => None,
        }
    }

    pub fn word(&self) -> &'static str {
        match self {
            Tier::Automation => "automation-tolerant",
            Tier::Human => "human-only",
        }
    }

    /// The command that sets this tier, which also names it in the history.
    pub fn verb(&self) -> &'static str {
        match self {
            Tier::Automation => "auto",
            Tier::Human => "noauto",
        }
    }
}

/// Device keys that a person's biometrics guard, by canonical key.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Gated {
    pub keys: BTreeSet<String>,
}

impl Gated {
    /// A Secure Enclave recipient is gated by what it is; any other key
    /// only when the store lists it.
    pub fn holds(&self, r: &RecipientSpec) -> bool {
        crate::se::is_se_recipient(r.as_str()) || self.keys.contains(&r.canonical_key())
    }
}

/// The trusted recipients that hold a copy at this tier, and those that do not.
pub fn split(
    trusted: Vec<RecipientSpec>,
    tier: Tier,
    gated: &Gated,
) -> (Vec<RecipientSpec>, Vec<RecipientSpec>) {
    match tier {
        Tier::Automation => (trusted, Vec::new()),
        Tier::Human => trusted.into_iter().partition(|r| gated.holds(r)),
    }
}

pub fn gated_path(layout: &StoreLayout) -> PathBuf {
    layout.store_dir().join(GATED_FILE)
}

pub fn load_gated_or_empty<S>(s: S, path: PathBuf) -> S::R<Gated>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    vault_do! { s ;
        let exists = s.exists(path.clone()) ;
        match exists {
            true => read_json::<S, Gated>(s2.clone(), path),
            false => s2.pure(Gated::default()),
        }
    }
}

/// Write an entry's copies for the recipients its tier serves, and take
/// away any copy a withheld recipient still has. Every command that
/// writes an entry goes through here, so no path can forget the tier.
pub(crate) fn write_entry<S>(
    s: S,
    layout: StoreLayout,
    hash: EntryHash,
    plaintext: Vec<u8>,
    metadata: Metadata,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    let gated_at = gated_path(&layout);
    vault_do! { s ;
        let gated = load_gated_or_empty(s.clone(), gated_at) ;
        write_split(s2.clone(), layout, hash, plaintext, metadata, gated)
    }
}

fn write_split<S>(
    s: S,
    layout: StoreLayout,
    hash: EntryHash,
    plaintext: Vec<u8>,
    metadata: Metadata,
    gated: Gated,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let (served, withheld) = split(metadata.trusted(), metadata.tier, &gated);
    if served.is_empty() {
        return s.fail(format!(
            "this entry would be {} with nobody able to open it: none of its {} trusted \
             recipients is a gated key. Add a Touch ID key or a phone first.",
            metadata.tier.word(),
            metadata.trusted().len()
        ));
    }
    let stale: Vec<PathBuf> = withheld
        .iter()
        .flat_map(|r| layout.entry_file_candidates(&hash, r))
        .collect();
    let s2 = s.clone();
    vault_do! { s ;
        let _ = remove_existing(s2.clone(), stale) ;
        crate::commands::allow::write_per_recipient(s2.clone(), layout, hash, plaintext, served)
    }
}

fn remove_existing<S>(s: S, paths: Vec<PathBuf>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let mut iter = paths.into_iter();
    match iter.next() {
        None => s.pure(()),
        Some(p) => {
            let s2 = s.clone();
            let rest: Vec<PathBuf> = iter.collect();
            vault_do! { s ;
                let there = s.exists(p.clone()) ;
                let _ = if there { s.remove_file(p) } else { s.pure(()) } ;
                remove_existing(s2, rest)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_only_reaches_gated_keys_alone() {
        let laptop = RecipientSpec::new("ssh-ed25519 AAAAlaptop jane@laptop");
        let touch = RecipientSpec::new("age1se1qd63u86e3hqd7efs9l5yexpw0yfjmgr8mptgl0fhxf68n4n2mwpl7tuhx9k");
        let phone = RecipientSpec::new("ssh-ed25519 AAAAphone");
        let mut gated = Gated::default();
        gated.keys.insert(phone.canonical_key());
        let all = vec![laptop.clone(), touch.clone(), phone.clone()];

        let (served, withheld) = split(all.clone(), Tier::Automation, &gated);
        assert_eq!((served.len(), withheld.len()), (3, 0));

        let (served, withheld) = split(all, Tier::Human, &gated);
        assert_eq!(served, vec![touch, phone]);
        assert_eq!(withheld, vec![laptop]);
    }

    #[test]
    fn tier_words_round_trip_and_default_is_automation() {
        assert_eq!(Tier::default(), Tier::Automation);
        for tier in [Tier::Automation, Tier::Human] {
            assert_eq!(Tier::parse(tier.word()), Some(tier));
        }
        assert_eq!(Tier::parse("human"), Some(Tier::Human));
        assert_eq!(Tier::parse("everyone"), None);
    }
}
