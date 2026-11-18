//! `rageveil cards` — give existing human-only entries their name cards.
//!
//! AI-generated module: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! Every write of a human-only entry leaves a name card for each plain key
//! it trusts (see [`crate::card`]). Entries made human-only before cards
//! existed have none, so laptops cannot list them. This command finds the
//! entries this laptop's Touch ID key holds while its plain key has neither
//! a copy nor a card, opens each once (one touch each), and rewrites it,
//! which writes the cards for every plain key it trusts. It indexes them
//! on the way, and commits once; `sync` publishes.
//!
//! AI-assisted update (the operator's devices, 2026-11-18): model Claude
//! Opus 5.5 (`claude-opus-5-5`); reasoning effort unavailable (not exposed
//! by the harness).
//!
//! An entry the operator's group holds is rewritten to every device of
//! that group, the set `insert` gives a new secret (see
//! [`super::persona::own_devices`]): gated devices get a copy, plain keys
//! a card. Before, an entry made on the phone trusted only the phone and
//! the Touch ID key, so `cards` opened it and then left it as it was: the
//! laptop never learned its name and a new device never got it. Nobody
//! outside the operator's own group is added.

use super::persona::own_devices;
use crate::card::card_candidates;
use crate::config::{Config, TouchIdentity};
use crate::content::Content;
use crate::dsl::Vault;
use crate::metadata::{LogEntry, Metadata, Stamp};
use crate::store::StoreLayout;
use crate::sugar::{first_existing, read_json};
use crate::tier::{write_entry, Tier};
use crate::types::{CommitOutcome, EntryHash, RecipientSpec};
use crate::{git, vault_do};

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct CardsArgs {
    pub root: PathBuf,
}

pub fn cards<S>(s: S, args: CardsArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root);
    let s2 = s.clone();
    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), layout.config_path()) ;
        let dirs = s.list_dir(layout.store_dir()) ;
        let devices = own_devices(s.clone(), layout.clone(), cfg.whoami.clone()) ;
        match cfg.touch.clone() {
            None => s2.log("no Touch ID key is configured here, so there is nothing to open".into()),
            Some(touch) => {
                let hashes: Vec<EntryHash> = dirs
                    .iter()
                    .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
                    .filter(|n| super::sync::is_entry_dir_name(n))
                    .map(|n| EntryHash(n.to_owned()))
                    .collect();
                let s3 = s2.clone();
                let devices: Vec<RecipientSpec> = devices.into_iter().map(|(_, k)| k).collect();
                vault_do! { s2 ;
                    let done = each(s2.clone(), layout.clone(), cfg.clone(), devices, touch, hashes, 0) ;
                    finish(s3.clone(), layout.store_dir(), done)
                }
            }
        }
    }
}

fn each<S>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    devices: Vec<RecipientSpec>,
    touch: TouchIdentity,
    mut hashes: Vec<EntryHash>,
    done: usize,
) -> S::R<usize>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let Some(hash) = hashes.pop() else {
        return s.pure(done);
    };
    let own = layout.entry_file_candidates(&hash, &cfg.whoami);
    let own_card = card_candidates(&layout, &hash, &cfg.whoami);
    let behind_touch = layout.entry_file_candidates(&hash, &touch.whoami);
    let s2 = s.clone();
    let (layout_in, cfg_in, devices_in, hash_in, identity) = (
        layout.clone(),
        cfg.clone(),
        devices.clone(),
        hash.clone(),
        touch.identity_path.clone(),
    );
    vault_do! { s ;
        let copy = first_existing(s.clone(), own) ;
        let card = first_existing(s.clone(), own_card) ;
        let touch_copy = first_existing(s.clone(), behind_touch) ;
        let n = match (copy, card, touch_copy) {
            (None, None, Some(file)) => {
                let s3 = s2.clone();
                vault_do! { s2 ;
                    let opened = s2.handle(open(s2.clone(), file, identity)) ;
                    match opened {
                        Ok(content) => rewrite(s3.clone(), layout_in, cfg_in, devices_in, hash_in, content),
                        Err(e) => {
                            let s4 = s3.clone();
                            vault_do! { s3 ;
                                let _ = s3.log(format!("cards: skipping {} ({e})", &hash_in.as_str()[..12])) ;
                                s4.pure(0)
                            }
                        }
                    }
                }
            }
            _ => s2.pure(0),
        } ;
        each(s2.clone(), layout.clone(), cfg.clone(), devices.clone(), touch.clone(), hashes, done + n)
    }
}

fn open<S>(s: S, file: PathBuf, identity: PathBuf) -> S::R<Content>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    vault_do! { s ;
        let cipher = s.read_file(file) ;
        let plain = s.decrypt(cipher, vec![identity]) ;
        s.decode_json::<Content>(plain)
    }
}

/// Rewrite a human-only entry that the operator's group holds, trusting
/// every device of the group, which writes copies for its gated keys and
/// cards for its plain ones, and index it. Anything else is left as it is.
fn rewrite<S>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    devices: Vec<RecipientSpec>,
    hash: EntryHash,
    content: Content,
) -> S::R<usize>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let mine: Vec<RecipientSpec> = std::iter::once(cfg.whoami.clone()).chain(devices).collect();
    if content.metadata.tier != Tier::Human || !holds_any(&content.metadata, &mine) {
        return s.pure(0);
    }
    let path = content.path.clone();
    let by = cfg.whoami.clone();
    let s2 = s.clone();
    vault_do! { s ;
        let now = s.now() ;
        let metadata = s.pure(widen(content.metadata.clone(), &mine, &by, now)) ;
        let plaintext = s.encode_json(Content { metadata: metadata.clone(), ..content }) ;
        let _ = write_entry(s.clone(), layout.clone(), hash.clone(), plaintext, metadata.clone()) ;
        let _ = crate::commands::allow::update_index(s.clone(), layout, path.clone(), hash, metadata, now) ;
        let _ = s.log(format!("cards: {path}")) ;
        s2.pure(1)
    }
}

/// Whether `metadata` trusts any of `keys`, compared canonically.
fn holds_any(metadata: &Metadata, keys: &[RecipientSpec]) -> bool {
    let trusted: Vec<String> = metadata.trusted().iter().map(RecipientSpec::canonical_key).collect();
    keys.iter().any(|k| trusted.contains(&k.canonical_key()))
}

/// `metadata` with an allow, stamped by `by` at `now`, for each of `keys`
/// it does not trust yet: what `allow` records for them.
fn widen(
    mut metadata: Metadata,
    keys: &[RecipientSpec],
    by: &RecipientSpec,
    now: chrono::DateTime<chrono::Utc>,
) -> Metadata {
    for key in keys {
        if !holds_any(&metadata, std::slice::from_ref(key)) {
            metadata.log.push(LogEntry::Allow {
                subject: key.clone(),
                stamp: Stamp { at: now, by: by.clone() },
            });
        }
    }
    metadata
}

fn finish<S>(s: S, store_dir: PathBuf, done: usize) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    if done == 0 {
        return s.log("cards: every human-only entry this laptop can open already has its cards".into());
    }
    let s2 = s.clone();
    vault_do! { s ;
        let _ = git::add_all(&s, store_dir.clone()) ;
        let out = git::commit(&s, store_dir, format!("cards: name cards for {done} human-only entries")) ;
        match out {
            CommitOutcome::Committed | CommitOutcome::NothingToCommit => s2.log(format!(
                "cards: {done} human-only entries now have name cards; `rageveil sync` publishes them"
            )),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn widening_adds_each_missing_device_once() {
        let now = chrono::Utc::now();
        let phone = RecipientSpec::new("ssh-ed25519 AAAAphone visageveil@iPhone");
        let laptop = RecipientSpec::new("ssh-ed25519 AAAAlaptop me@mac");
        let app = RecipientSpec::new("ssh-ed25519 AAAAapp visageveil@mac");
        let made_on_phone = Metadata::new(phone.clone(), now);
        assert!(holds_any(&made_on_phone, &[laptop.clone(), phone.clone()]));
        assert!(!holds_any(&made_on_phone, &[laptop.clone(), app.clone()]));
        let mine = [laptop.clone(), RecipientSpec::new("ssh-ed25519 AAAAphone other-comment"), app.clone()];
        let wide = widen(made_on_phone, &mine, &laptop, now);
        let trusted: Vec<String> = wide.trusted().iter().map(RecipientSpec::canonical_key).collect();
        assert_eq!(trusted.len(), 3, "{trusted:?}");
        for k in [&phone, &laptop, &app] {
            assert!(trusted.contains(&k.canonical_key()));
        }
        let again = widen(wide.clone(), &mine, &laptop, now);
        assert_eq!(again.log.len(), wide.log.len());
    }
}
