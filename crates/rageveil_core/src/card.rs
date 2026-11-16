//! Name cards: what a plain key may know about a human-only entry.
//!
//! AI-generated module: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! An entry's name and its sharing record live inside its encrypted
//! copies, beside the secret. A human-only entry gives plain keys no copy,
//! so a laptop could not even list it until a person opened it with Touch
//! ID. Human-only is meant to guard the secret, not the fact that it exists.
//!
//! So every plain key that a human-only entry trusts gets a card instead
//! of a copy: `<entry>/<fingerprint>.card`, age-encrypted to that key
//! alone, holding the entry's path and metadata and no secret. `sync`
//! indexes the entry from it, and `list` marks the entry `noauto`.
//!
//! The suffix is `.card`, not `.age`: clients released before cards
//! existed take a recipient only from a `<hex>.age` name and skip every
//! other file, so a card is invisible to them.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::dsl::Vault;
use crate::metadata::Metadata;
use crate::store::StoreLayout;
use crate::types::{EntryHash, EntryPath, RecipientFingerprint, RecipientSpec};
use crate::vault_do;

pub const CARD_SUFFIX: &str = ".card";

/// The card's contents. `v` leaves room for a later shape.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NameCard {
    pub v: u32,
    pub path: EntryPath,
    pub metadata: Metadata,
}

impl NameCard {
    pub fn new(path: EntryPath, metadata: Metadata) -> Self {
        Self { v: 1, path, metadata }
    }
}

pub fn card_file(layout: &StoreLayout, hash: &EntryHash, fp: &RecipientFingerprint) -> PathBuf {
    layout.entry_dir(hash).join(format!("{}{CARD_SUFFIX}", fp.as_str()))
}

/// Where a key's card may be: under its canonical fingerprint, or the
/// legacy one, as for copies.
pub fn card_candidates(layout: &StoreLayout, hash: &EntryHash, spec: &RecipientSpec) -> Vec<PathBuf> {
    let canonical = spec.fingerprint();
    let legacy = spec.legacy_fingerprint();
    let mut out = vec![card_file(layout, hash, &canonical)];
    if legacy != canonical {
        out.push(card_file(layout, hash, &legacy));
    }
    out
}

/// The fingerprint a card file belongs to, if the name is a card's.
pub fn fingerprint_of_card(p: &std::path::Path) -> Option<RecipientFingerprint> {
    let stem = p.file_name()?.to_str()?.strip_suffix(CARD_SUFFIX)?;
    (!stem.is_empty() && stem.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| RecipientFingerprint(stem.to_owned()))
}

/// Write a card for each of `keys`, and remove every other card in the
/// entry: a key that holds the secret, or is no longer trusted, keeps none.
pub(crate) fn write_cards<S>(
    s: S,
    layout: StoreLayout,
    hash: EntryHash,
    card: NameCard,
    keys: Vec<RecipientSpec>,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let keep: std::collections::BTreeSet<String> =
        keys.iter().map(|k| k.fingerprint().as_str().to_owned()).collect();
    let dir = layout.entry_dir(&hash);
    let s2 = s.clone();
    vault_do! { s ;
        let there = s.exists(dir.clone()) ;
        let files = match there {
            true => s.list_dir(dir),
            false => s.pure(Vec::new()),
        } ;
        let _ = remove_each(
            s.clone(),
            files
                .into_iter()
                .filter(|f| fingerprint_of_card(f).is_some_and(|fp| !keep.contains(fp.as_str())))
                .collect(),
        ) ;
        let body = s.encode_json(card) ;
        write_each(s2.clone(), layout, hash, body, keys)
    }
}

fn write_each<S>(s: S, layout: StoreLayout, hash: EntryHash, body: Vec<u8>, mut keys: Vec<RecipientSpec>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    match keys.pop() {
        None => s.pure(()),
        Some(key) => {
            let file = card_file(&layout, &hash, &key.fingerprint());
            let s2 = s.clone();
            vault_do! { s ;
                let cipher = s.encrypt(body.clone(), vec![key]) ;
                let _ = s.write_file(file, cipher) ;
                write_each(s2.clone(), layout, hash, body, keys)
            }
        }
    }
}

fn remove_each<S>(s: S, mut files: Vec<PathBuf>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    match files.pop() {
        None => s.pure(()),
        Some(f) => {
            let s2 = s.clone();
            vault_do! { s ;
                let _ = s.remove_file(f) ;
                remove_each(s2.clone(), files)
            }
        }
    }
}

/// Read this key's card for an entry, if there is one.
pub(crate) fn read_card<S>(s: S, file: PathBuf, identity: PathBuf) -> S::R<NameCard>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    vault_do! { s ;
        let cipher = s.read_file(file) ;
        let plain = s.decrypt(cipher, vec![identity]) ;
        s.decode_json::<NameCard>(plain)
    }
}
