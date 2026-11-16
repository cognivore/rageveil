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

use crate::card::card_candidates;
use crate::config::{Config, TouchIdentity};
use crate::content::Content;
use crate::dsl::Vault;
use crate::store::StoreLayout;
use crate::sugar::{first_existing, read_json};
use crate::tier::{write_entry, Tier};
use crate::types::{CommitOutcome, EntryHash};
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
                vault_do! { s2 ;
                    let done = each(s2.clone(), layout.clone(), cfg.clone(), touch, hashes, 0) ;
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
    let (layout_in, cfg_in, hash_in, identity) =
        (layout.clone(), cfg.clone(), hash.clone(), touch.identity_path.clone());
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
                        Ok(content) => rewrite(s3.clone(), layout_in, cfg_in, hash_in, content),
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
        each(s2.clone(), layout.clone(), cfg.clone(), touch.clone(), hashes, done + n)
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

/// Rewrite a human-only entry that trusts this laptop's plain key, which
/// writes its cards, and index it. Anything else is left as it is.
fn rewrite<S>(s: S, layout: StoreLayout, cfg: Config, hash: EntryHash, content: Content) -> S::R<usize>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let me = cfg.whoami.canonical_key();
    let trusts_me = content.metadata.trusted().iter().any(|r| r.canonical_key() == me);
    if content.metadata.tier != Tier::Human || !trusts_me {
        return s.pure(0);
    }
    let path = content.path.clone();
    let metadata = content.metadata.clone();
    let s2 = s.clone();
    vault_do! { s ;
        let plaintext = s.encode_json(content) ;
        let _ = write_entry(s.clone(), layout.clone(), hash.clone(), plaintext, metadata.clone()) ;
        let now = s.now() ;
        let _ = crate::commands::allow::update_index(s.clone(), layout, path.clone(), hash, metadata, now) ;
        let _ = s.log(format!("cards: {path}")) ;
        s2.pure(1)
    }
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
