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
//! AI-assisted update (the operator's devices, 2026-11-19): model Claude
//! Opus 5.5 (`claude-opus-5-5`); reasoning effort unavailable (not exposed
//! by the harness).
//!
//! A human-only entry the operator's group holds reaches every device of
//! that group the entry's log has never named, the set `insert` gives a new
//! secret (see [`super::persona::own_devices`]): gated devices get a copy,
//! plain keys a card. A key the log names already keeps its place: a
//! `deny` stays a deny, and nobody outside the operator's group is added.
//!
//! A touch is spent only where it changes something. What is known of an
//! entry without one, its index record or this laptop's card, decides
//! whether it needs opening; an entry known nowhere is opened once and
//! indexed, so it is never opened again for nothing. A failure on one entry
//! is logged and the rest still run, and whatever was rewritten is
//! committed even when a later entry fails or an earlier run was cut short.

use super::persona::own_devices;
use crate::card::{card_candidates, read_card};
use crate::config::{Config, TouchIdentity};
use crate::content::Content;
use crate::dsl::Vault;
use crate::index::Index;
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

/// What one run did, for its last line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Tally {
    /// Rewritten to the operator's devices: one touch each.
    rewritten: usize,
    /// Opened once and indexed, with nothing to rewrite.
    indexed: usize,
    /// Could not be opened or rewritten; logged one by one.
    failed: usize,
}

/// Everything one entry needs, decided before any touch.
#[derive(Clone)]
struct Job {
    layout: StoreLayout,
    cfg: Config,
    /// The operator's own key, then every other device of their group.
    mine: Vec<RecipientSpec>,
    touch: TouchIdentity,
    index: Index,
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
        let index = super::deny::read_index_or_empty(s.clone(), layout.index_path()) ;
        match cfg.touch.clone() {
            None => s2.log("no Touch ID key is configured here, so there is nothing to open".into()),
            Some(touch) => {
                let mut hashes: Vec<EntryHash> = dirs
                    .iter()
                    .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
                    .filter(|n| super::sync::is_entry_dir_name(n))
                    .map(|n| EntryHash(n.to_owned()))
                    .collect();
                hashes.sort();
                hashes.reverse();
                let mine: Vec<RecipientSpec> = std::iter::once(cfg.whoami.clone())
                    .chain(devices.into_iter().map(|(_, k)| k))
                    .collect();
                let job = Job { layout: layout.clone(), cfg: cfg.clone(), mine, touch, index };
                let s3 = s2.clone();
                vault_do! { s2 ;
                    let tally = each(s2.clone(), job, hashes, Tally::default()) ;
                    finish(s3.clone(), layout.store_dir(), tally)
                }
            }
        }
    }
}

fn each<S>(s: S, job: Job, mut hashes: Vec<EntryHash>, tally: Tally) -> S::R<Tally>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let Some(hash) = hashes.pop() else {
        return s.pure(tally);
    };
    let s2 = s.clone();
    let job2 = job.clone();
    vault_do! { s ;
        let out = s.handle(one(s.clone(), job.clone(), hash.clone())) ;
        let tally = match out {
            Ok(Outcome::Rewritten) => s2.pure(Tally { rewritten: tally.rewritten + 1, ..tally }),
            Ok(Outcome::Indexed) => s2.pure(Tally { indexed: tally.indexed + 1, ..tally }),
            Ok(Outcome::Untouched) => s2.pure(tally),
            Err(e) => {
                let s3 = s2.clone();
                vault_do! { s2 ;
                    let _ = s2.log(format!("cards: skipping {} ({e})", short(&hash))) ;
                    s3.pure(Tally { failed: tally.failed + 1, ..tally })
                }
            }
        } ;
        each(s2.clone(), job2.clone(), hashes, tally)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Rewritten,
    Indexed,
    Untouched,
}

/// One entry: skipped when this laptop reads it plainly or the Touch ID
/// key holds no copy; decided from its index record or this laptop's
/// card when there is one; opened once otherwise.
fn one<S>(s: S, job: Job, hash: EntryHash) -> S::R<Outcome>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let own = job.layout.entry_file_candidates(&hash, &job.cfg.whoami);
    let own_card = card_candidates(&job.layout, &hash, &job.cfg.whoami);
    let behind_touch = job.layout.entry_file_candidates(&hash, &job.touch.whoami);
    let remembered = job
        .index
        .entries
        .values()
        .find(|c| c.hash == hash)
        .map(|c| c.metadata.clone());
    let s2 = s.clone();
    vault_do! { s ;
        let copy = first_existing(s.clone(), own) ;
        let card = first_existing(s.clone(), own_card) ;
        let touch_copy = first_existing(s.clone(), behind_touch) ;
        match (copy, touch_copy) {
            (Some(_), _) | (None, None) => s2.pure(Outcome::Untouched),
            (None, Some(file)) => {
                let s3 = s2.clone();
                let (job3, hash3) = (job.clone(), hash.clone());
                vault_do! { s2 ;
                    let known = known_metadata(s2.clone(), job.cfg.identity_path.clone(), remembered.clone(), card) ;
                    let held = held_by(s2.clone(), job.layout.clone(), hash.clone(), job.mine.clone(), Vec::new()) ;
                    match known {
                        Some(metadata) if !needs_rewrite(&metadata, &job3.mine, &held) => s3.pure(Outcome::Untouched),
                        _ => open_and_settle(s3.clone(), job3.clone(), hash3.clone(), file, held),
                    }
                }
            }
        }
    }
}

/// The entry's metadata as known without a touch: its index record, else
/// this laptop's card (read with the plain key), else nothing.
fn known_metadata<S>(
    s: S,
    identity: PathBuf,
    remembered: Option<Metadata>,
    card: Option<PathBuf>,
) -> S::R<Option<Metadata>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    match (remembered, card) {
        (Some(m), _) => s.pure(Some(m)),
        (None, None) => s.pure(None),
        (None, Some(file)) => {
            let s2 = s.clone();
            vault_do! { s ;
                let read = s.handle(read_card(s.clone(), file, identity)) ;
                s2.pure(read.ok().map(|c| c.metadata))
            }
        }
    }
}

/// Open the entry with the Touch ID key (one touch), then rewrite it if it
/// needs it, and index it either way. The opened metadata decides, not
/// what was known before: the store may have moved since.
fn open_and_settle<S>(s: S, job: Job, hash: EntryHash, file: PathBuf, held: Vec<String>) -> S::R<Outcome>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    vault_do! { s ;
        let content = open(s.clone(), file, job.touch.identity_path.clone()) ;
        match needs_rewrite(&content.metadata, &job.mine, &held) {
            true => rewrite(s2.clone(), job.clone(), hash.clone(), content),
            false => {
                let s3 = s2.clone();
                let (path, metadata) = (content.path.clone(), content.metadata.clone());
                vault_do! { s2 ;
                    let now = s2.now() ;
                    let _ = crate::commands::allow::update_index(s2.clone(), job.layout.clone(), path, hash.clone(), metadata, now) ;
                    s3.pure(Outcome::Indexed)
                }
            }
        }
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

/// Which of `keys` have a file in the entry's directory, a copy or a card,
/// as canonical keys. No touch: it only looks at file names.
fn held_by<S>(
    s: S,
    layout: StoreLayout,
    hash: EntryHash,
    mut keys: Vec<RecipientSpec>,
    held: Vec<String>,
) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let Some(key) = keys.pop() else {
        return s.pure(held);
    };
    let mut files = layout.entry_file_candidates(&hash, &key);
    files.extend(card_candidates(&layout, &hash, &key));
    let s2 = s.clone();
    vault_do! { s ;
        let found = first_existing(s.clone(), files) ;
        {
            let mut held = held.clone();
            if found.is_some() {
                held.push(key.canonical_key());
            }
            held_by(s2.clone(), layout.clone(), hash.clone(), keys.clone(), held)
        }
    }
}

/// Whether a human-only entry the operator's group holds is missing one of
/// the group's devices: a device its log has never named, or one it trusts
/// whose copy or card is not in the store (`held` lists the devices that
/// have a file). Anything else is left as it is.
fn needs_rewrite(metadata: &Metadata, mine: &[RecipientSpec], held: &[String]) -> bool {
    let trusted: Vec<String> = metadata.trusted().iter().map(RecipientSpec::canonical_key).collect();
    metadata.tier == Tier::Human
        && holds_any(metadata, mine)
        && mine.iter().any(|k| {
            let k_c = k.canonical_key();
            !named(metadata, k) || (trusted.contains(&k_c) && !held.contains(&k_c))
        })
}

/// Rewrite the entry to every device of the operator's group its log has
/// never named, which writes copies for its gated keys and cards for its
/// plain ones, and index it.
fn rewrite<S>(s: S, job: Job, hash: EntryHash, content: Content) -> S::R<Outcome>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let path = content.path.clone();
    let by = job.cfg.whoami.clone();
    let s2 = s.clone();
    vault_do! { s ;
        let now = s.now() ;
        let metadata = s.pure(widen(content.metadata.clone(), &job.mine, &by, now)) ;
        let plaintext = s.encode_json(Content { metadata: metadata.clone(), ..content }) ;
        let _ = write_entry(s.clone(), job.layout.clone(), hash.clone(), plaintext, metadata.clone()) ;
        let _ = crate::commands::allow::update_index(s.clone(), job.layout.clone(), path.clone(), hash, metadata, now) ;
        let _ = s.log(format!("cards: {path}")) ;
        s2.pure(Outcome::Rewritten)
    }
}

/// Whether `metadata` trusts any of `keys` now, compared canonically.
fn holds_any(metadata: &Metadata, keys: &[RecipientSpec]) -> bool {
    let trusted: Vec<String> = metadata.trusted().iter().map(RecipientSpec::canonical_key).collect();
    keys.iter().any(|k| trusted.contains(&k.canonical_key()))
}

/// Whether the log names `key` at all, allowed or denied.
fn named(metadata: &Metadata, key: &RecipientSpec) -> bool {
    let k = key.canonical_key();
    metadata.log.iter().any(|e| e.subject().canonical_key() == k)
}

/// `metadata` with an allow, stamped by `by` at `now`, for each of `keys`
/// its log has never named: what `allow` records for them. A key the log
/// names, allowed or denied, keeps the place the log gives it.
fn widen(
    mut metadata: Metadata,
    keys: &[RecipientSpec],
    by: &RecipientSpec,
    now: chrono::DateTime<chrono::Utc>,
) -> Metadata {
    for key in keys {
        if !named(&metadata, key) {
            metadata.log.push(LogEntry::Allow {
                subject: key.clone(),
                stamp: Stamp { at: now, by: by.clone() },
            });
        }
    }
    metadata
}

fn short(hash: &EntryHash) -> &str {
    &hash.as_str()[..12.min(hash.as_str().len())]
}

/// Commit whatever is rewritten in the store, this run's or a cut-short
/// earlier run's, and say what happened.
fn finish<S>(s: S, store_dir: PathBuf, tally: Tally) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    let Tally { rewritten, indexed, failed } = tally;
    let s3 = s.clone();
    vault_do! { s ;
        let _ = git::add_all(&s, store_dir.clone()) ;
        let changed = s.git_has_changes(store_dir.clone()) ;
        let out = match changed {
            true => git::commit(&s3, store_dir, format!("cards: {rewritten} human-only entries reach every device of their owner")),
            false => s3.pure(CommitOutcome::NothingToCommit),
        } ;
        let _ = match out {
            CommitOutcome::Committed => s2.log(format!(
                "cards: {rewritten} human-only entries now reach every device of yours, with name cards for your laptops; `rageveil sync` publishes them"
            )),
            CommitOutcome::NothingToCommit => s2.log("cards: no human-only entry of yours is missing a device".into()),
        } ;
        let _ = match indexed {
            0 => s2.pure(()),
            n => s2.log(format!("cards: {n} other entries opened once and listed here from now on")),
        } ;
        match failed {
            0 => s2.pure(()),
            n => s2.log(format!("cards: {n} entries could not be opened or rewritten; see above, and run `cards` again")),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn all_held(keys: &[RecipientSpec]) -> Vec<String> {
        keys.iter().map(RecipientSpec::canonical_key).collect()
    }

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

    #[test]
    fn a_denied_device_is_not_given_the_entry_again() {
        let now = chrono::Utc::now();
        let phone = RecipientSpec::new("ssh-ed25519 AAAAphone visageveil@iPhone");
        let ipad = RecipientSpec::new("ssh-ed25519 AAAAipad visageveil@iPad");
        let laptop = RecipientSpec::new("ssh-ed25519 AAAAlaptop me@mac");
        let mut m = Metadata::new(phone.clone(), now);
        m.log.push(LogEntry::Allow { subject: ipad.clone(), stamp: Stamp { at: now, by: phone.clone() } });
        m.log.push(LogEntry::Deny { subject: ipad.clone(), stamp: Stamp { at: now, by: phone.clone() } });
        m.tier = Tier::Human;
        let mine = [laptop.clone(), phone.clone(), ipad.clone()];
        assert!(needs_rewrite(&m, &mine, &[]), "the laptop was never named");
        let wide = widen(m, &mine, &laptop, now);
        let trusted: Vec<String> = wide.trusted().iter().map(RecipientSpec::canonical_key).collect();
        assert!(!trusted.contains(&ipad.canonical_key()), "a deny was undone");
        assert!(trusted.contains(&laptop.canonical_key()));
        assert!(!needs_rewrite(&wide, &mine, &all_held(&mine)), "nothing left to do, so no touch next time");
        // A trusted device whose file is gone is work to do again.
        let without_laptop: Vec<String> = all_held(&mine).into_iter().filter(|k| *k != laptop.canonical_key()).collect();
        assert!(needs_rewrite(&wide, &mine, &without_laptop));
    }

    #[test]
    fn only_a_human_only_entry_of_the_group_is_rewritten() {
        let now = chrono::Utc::now();
        let phone = RecipientSpec::new("ssh-ed25519 AAAAphone visageveil@iPhone");
        let laptop = RecipientSpec::new("ssh-ed25519 AAAAlaptop me@mac");
        let stranger = RecipientSpec::new("ssh-ed25519 AAAAstranger s@x");
        let mut auto = Metadata::new(phone.clone(), now);
        assert!(!needs_rewrite(&auto, &[laptop.clone(), phone.clone()], &[]), "automation-tolerant");
        auto.tier = Tier::Human;
        assert!(needs_rewrite(&auto, &[laptop.clone(), phone.clone()], &[]));
        let theirs = Metadata { tier: Tier::Human, ..Metadata::new(stranger, now) };
        assert!(!needs_rewrite(&theirs, &[laptop, phone], &[]), "not held by the group");
    }
}
