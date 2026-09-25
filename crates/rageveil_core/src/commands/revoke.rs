//! `rageveil revoke NAME…` — take a device, or a whole person, out
//! of the vault in one go.
//!
//! `deny` works one entry at a time and `address remove` / `persona
//! remove` only forget names, leaving every share in place. Revoking
//! someone therefore meant a `deny` per entry and remembering to
//! clean up the names afterwards. This command does all of it:
//!
//!   * **A device name** (an address-book name that is not a
//!     persona's canonical name): its key comes off every entry that
//!     trusts it, it leaves the persona group it was in, and its name
//!     leaves the address book. Every other key keeps exactly the
//!     access it had — a member name is *not* widened to its group,
//!     which is how a lost phone is cut off without touching the
//!     laptop.
//!   * **A persona's canonical name**: the same for every device of
//!     that person, and the group itself is dropped.
//!   * **A raw key** (`age1…`, `ssh-…`): that key, and any
//!     address-book name bound to it.
//!
//! Refused before anything is written: anything that would take the
//! operator's own key, and any entry that would be left unreadable by
//! the operator. Each rewritten entry records a `Deny` in its trust
//! log, exactly as `deny` does, so `rageveil info` shows the
//! revocation.
//!
//! Like `deny`, the result is one local commit; `rageveil sync`
//! publishes it. Only entries in the local index — the ones this
//! operator can decrypt, as of the last sync — can be rewritten; any
//! other entry that still holds a copy for a revoked key is reported
//! by its store directory so someone who can read it can finish the
//! job.

use super::address::{load_or_empty, load_personas_or_empty, stage_signed};
use super::deny::{deny_entry, read_index_or_empty};
use super::sync::is_entry_dir_name;
use crate::addressbook::{AddressBook, Personas, looks_like_key};
use crate::config::Config;
use crate::dsl::Vault;
use crate::index::Index;
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::{CommitOutcome, EntryPath, RecipientFingerprint, RecipientSpec};
use crate::{git, vault_do};

use chrono::{DateTime, Utc};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct RevokeArgs {
    pub root: PathBuf,
    /// Address-book names, persona canonical names, or raw keys.
    pub names: Vec<String>,
}

pub fn revoke<S>(s: S, args: RevokeArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let names: Vec<String> = args.names.iter().map(|n| n.trim().to_owned()).collect();
    if names.is_empty() {
        return s.fail("revoke: name at least one device, persona or key".into());
    }
    let s2 = s.clone();
    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), layout.config_path()) ;
        let book = load_or_empty(s.clone(), layout.addressbook_path()) ;
        let personas = load_personas_or_empty(s.clone(), layout.personas_path()) ;
        let index = read_index_or_empty(s.clone(), layout.index_path()) ;
        let now = s.now() ;
        carry_out(s2.clone(), layout, cfg, book, personas, index, names, now)
    }
}

// ─── what to revoke (pure) ───────────────────────────────────────────────

/// Everything the command will do, worked out before any write.
#[derive(Clone, Debug)]
struct Revocation {
    /// One line per NAME as typed, for the log.
    described: Vec<String>,
    /// The keys coming off every entry, one per canonical key.
    keys: Vec<RecipientSpec>,
    /// canonical key → the address-book name it was known by, for
    /// readable per-entry log lines.
    shown_as: BTreeMap<String, String>,
    /// Address-book names bound to a revoked key.
    dropped_names: Vec<String>,
    book: AddressBook,
    book_changed: bool,
    personas: Personas,
    personas_changed: bool,
}

fn plan_revocation(
    book: &AddressBook,
    personas: &Personas,
    names: &[String],
    whoami: &RecipientSpec,
) -> Result<Revocation, String> {
    let me = whoami.canonical_key();
    let mut keys: Vec<RecipientSpec> = Vec::new();
    let mut shown_as: BTreeMap<String, String> = BTreeMap::new();
    let mut described: Vec<String> = Vec::new();
    let mut drop_groups: BTreeSet<String> = BTreeSet::new();
    let refuse_self = |what: String| {
        format!(
            "refusing to revoke {what}: that is this store's own key ({}), and revoking \
             it would leave you unable to decrypt your own vault",
            whoami.as_str()
        )
    };
    let mut add_key = |key: &RecipientSpec, shown: &str| {
        let ck = key.canonical_key();
        if !keys.iter().any(|k| k.canonical_key() == ck) {
            keys.push(key.clone());
        }
        shown_as.entry(ck).or_insert_with(|| shown.to_owned());
    };

    for t in names {
        if t.is_empty() {
            return Err("revoke: empty name".into());
        }
        if looks_like_key(t) {
            let key = RecipientSpec::new(t.as_str());
            if key.canonical_key() == me {
                return Err(refuse_self(format!("{t:?}")));
            }
            let known: Vec<&str> = book
                .people
                .iter()
                .filter(|(_, k)| k.canonical_key() == key.canonical_key())
                .map(|(n, _)| n.as_str())
                .collect();
            add_key(&key, known.first().copied().unwrap_or(t.as_str()));
            described.push(match known.is_empty() {
                true => format!("{t} — key, in no address-book name"),
                false => format!("{t} — key, known as {}", known.join(", ")),
            });
        } else if personas.groups.contains_key(t) {
            let devices: Vec<(String, RecipientSpec)> = personas
                .expand(t)
                .into_iter()
                .filter_map(|n| book.get(&n).cloned().map(|k| (n, k)))
                .collect();
            for (device, key) in &devices {
                if key.canonical_key() == me {
                    return Err(refuse_self(format!(
                        "persona {t:?} (its device {device:?})"
                    )));
                }
            }
            for (device, key) in &devices {
                add_key(key, device);
            }
            drop_groups.insert(t.clone());
            let listed: Vec<&str> = devices.iter().map(|(n, _)| n.as_str()).collect();
            described.push(match listed.is_empty() {
                true => format!("{t} — persona with no registered device"),
                false => format!("{t} — persona, every device: {}", listed.join(", ")),
            });
        } else if let Some(key) = book.get(t) {
            if key.canonical_key() == me {
                return Err(refuse_self(format!("{t:?}")));
            }
            add_key(key, t);
            described.push(match personas.canonical_of(t) {
                None => format!("{t} — device"),
                Some(group) => {
                    let siblings: Vec<String> = personas
                        .expand(group)
                        .into_iter()
                        .filter(|n| n != t && book.get(n).is_some())
                        .collect();
                    match siblings.is_empty() {
                        true => format!("{t} — device of persona {group}"),
                        false => format!(
                            "{t} — device of persona {group}; {} keep their access",
                            siblings.join(", ")
                        ),
                    }
                }
            });
        } else {
            return Err(format!(
                "no address-book name or persona called {t:?} (see `rageveil address list` \
                 and `rageveil persona list`)"
            ));
        }
    }

    let revoked: BTreeSet<String> = keys.iter().map(RecipientSpec::canonical_key).collect();
    let dropped_names: Vec<String> = book
        .people
        .iter()
        .filter(|(_, k)| revoked.contains(&k.canonical_key()))
        .map(|(n, _)| n.clone())
        .collect();

    let mut next_book = book.clone();
    for n in &dropped_names {
        next_book.people.remove(n);
    }
    let mut next_personas = personas.clone();
    for g in &drop_groups {
        next_personas.groups.remove(g);
    }
    for members in next_personas.groups.values_mut() {
        for n in &dropped_names {
            members.remove(n);
        }
    }
    next_personas
        .groups
        .retain(|_, members| !members.is_empty());

    Ok(Revocation {
        described,
        keys,
        shown_as,
        book_changed: next_book.people != book.people,
        book: next_book,
        personas_changed: next_personas.groups != personas.groups,
        personas: next_personas,
        dropped_names,
    })
}

/// Entries in the index that trust any revoked key, with the log's
/// own spelling of each such key.
fn entries_trusting(index: &Index, keys: &[RecipientSpec]) -> Vec<(EntryPath, Vec<RecipientSpec>)> {
    let revoked: BTreeSet<String> = keys.iter().map(RecipientSpec::canonical_key).collect();
    index
        .entries
        .iter()
        .filter_map(|(path, cached)| {
            let hits: Vec<RecipientSpec> = cached
                .metadata
                .trusted()
                .into_iter()
                .filter(|t| revoked.contains(&t.canonical_key()))
                .collect();
            (!hits.is_empty()).then(|| (path.clone(), hits))
        })
        .collect()
}

/// Entries the operator would no longer be able to read afterwards.
/// The operator's key is never among the revoked ones, so this only
/// trips on an index that no longer matches the store — and then
/// nothing is written.
fn unreadable_after(
    index: &Index,
    todo: &[(EntryPath, Vec<RecipientSpec>)],
    whoami: &RecipientSpec,
) -> Vec<EntryPath> {
    let me = whoami.canonical_key();
    todo.iter()
        .filter(|(path, hits)| {
            let revoked: BTreeSet<String> = hits.iter().map(RecipientSpec::canonical_key).collect();
            let left: Vec<String> = index
                .entries
                .get(path)
                .map(|c| c.metadata.trusted())
                .unwrap_or_default()
                .iter()
                .map(RecipientSpec::canonical_key)
                .filter(|k| !revoked.contains(k))
                .collect();
            !left.contains(&me)
        })
        .map(|(path, _)| path.clone())
        .collect()
}

// ─── doing it ────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn carry_out<S>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    book: AddressBook,
    personas: Personas,
    index: Index,
    names: Vec<String>,
    now: DateTime<Utc>,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let rev = match plan_revocation(&book, &personas, &names, &cfg.whoami) {
        Ok(rev) => rev,
        Err(msg) => return s.fail(msg),
    };
    let todo = entries_trusting(&index, &rev.keys);
    let stuck = unreadable_after(&index, &todo, &cfg.whoami);
    if !stuck.is_empty() {
        let shown: Vec<String> = stuck.iter().map(ToString::to_string).collect();
        return s.fail(format!(
            "refusing to revoke: you would no longer be able to read {} afterwards. \
             Nothing was written. Run `rageveil sync` and try again.",
            shown.join(", ")
        ));
    }

    let intro: Vec<String> = rev
        .described
        .iter()
        .map(|d| format!("revoke: {d}"))
        .collect();
    let s2 = s.clone();
    let s3 = s.clone();
    vault_do! { s ;
        let _ = log_lines(s.clone(), intro) ;
        let outcome = rewrite_each(
            s2.clone(),
            layout.clone(),
            cfg.clone(),
            rev.clone(),
            todo,
            now,
            Outcome::default(),
        ) ;
        finish(s3.clone(), layout, rev, names, outcome)
    }
}

#[derive(Clone, Debug, Default)]
struct Outcome {
    done: Vec<EntryPath>,
    failed: Vec<(EntryPath, String)>,
}

/// Take the revoked keys off each entry in turn. A failure on one
/// entry is recorded and the rest still run; [`finish`] decides what
/// that means for the names.
fn rewrite_each<S>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    rev: Revocation,
    todo: Vec<(EntryPath, Vec<RecipientSpec>)>,
    now: DateTime<Utc>,
    acc: Outcome,
) -> S::R<Outcome>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let mut iter = todo.into_iter();
    let Some((path, hits)) = iter.next() else {
        return s.pure(acc);
    };
    let rest: Vec<(EntryPath, Vec<RecipientSpec>)> = iter.collect();
    let whoami = cfg.whoami.clone();
    let s2 = s.clone();
    let s3 = s.clone();
    vault_do! { s ;
        let out = s.handle(deny_entry(
            s2.clone(),
            layout.clone(),
            cfg.clone(),
            path.clone(),
            hits,
            now,
            Some(whoami),
        )) ;
        {
            let mut acc = acc;
            let line = match out {
                Ok(removed) => {
                    let who: Vec<String> = removed
                        .iter()
                        .map(|k| {
                            rev.shown_as
                                .get(&k.canonical_key())
                                .cloned()
                                .unwrap_or_else(|| k.as_str().to_owned())
                        })
                        .collect();
                    acc.done.push(path.clone());
                    format!("revoked from {path}: {}", who.join(", "))
                }
                Err(e) => {
                    let line = format!("could not rewrite {path}: {e}");
                    acc.failed.push((path.clone(), e));
                    line
                }
            };
            let s4 = s3.clone();
            vault_do! { s3 ;
                let _ = s3.log(line) ;
                rewrite_each(s4, layout, cfg, rev, rest, now, acc)
            }
        }
    }
}

/// Commit. When every entry was rewritten, the names go too: out of
/// the address book and the persona groups, in the same commit. When
/// any entry could not be rewritten, the names stay, so the same
/// `revoke` can be run again once the cause is fixed — and the
/// command fails.
fn finish<S>(
    s: S,
    layout: StoreLayout,
    rev: Revocation,
    names: Vec<String>,
    outcome: Outcome,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let store_dir = layout.store_dir();
    let n = outcome.done.len();
    let entries = match n {
        1 => "1 entry".to_owned(),
        n => format!("{n} entries"),
    };
    let keys = match rev.keys.len() {
        1 => "1 key".to_owned(),
        k => format!("{k} keys"),
    };

    if !outcome.failed.is_empty() {
        let failed: Vec<String> = outcome.failed.iter().map(|(p, _)| p.to_string()).collect();
        let msg = format!(
            "revoke {}: took {keys} off {entries}, but could not rewrite {}. The \
             address book and persona groups were left as they were, so the same \
             `rageveil revoke` can be run again once that is fixed.",
            names.join(" "),
            failed.join(", ")
        );
        let s2 = s.clone();
        return vault_do! { s ;
            let _ = git::add_all(&s, store_dir.clone()) ;
            let _ = commit(s.clone(), store_dir, format!("revoke {} (incomplete)", names.join(" "))) ;
            s2.fail(msg)
        };
    }

    let fps = fingerprints(&rev.keys);
    let dropped = rev.dropped_names.clone();
    let summary = format!(
        "revoked {keys} from {entries}{}{}. Committed locally — `rageveil sync` publishes it.",
        match dropped.is_empty() {
            true => String::new(),
            false => format!("; removed {} from the address book", dropped.join(", ")),
        },
        match rev.personas_changed {
            true => " and the persona groups",
            false => "",
        },
    );
    let keys_shown: Vec<String> = rev.keys.iter().map(|k| k.as_str().to_owned()).collect();
    let s2 = s.clone();
    let s3 = s.clone();
    vault_do! { s ;
        let _ = save_names(s2.clone(), layout.clone(), rev) ;
        let _ = git::add_all(&s, store_dir.clone()) ;
        let _ = commit(s.clone(), store_dir.clone(), format!("revoke {}", names.join(" "))) ;
        let leftover = holding_dirs(s2.clone(), store_dir, fps) ;
        let _ = warn_leftover(s3.clone(), leftover, keys_shown) ;
        s3.log(summary)
    }
}

/// Write and stage the address book and persona file, signed on a
/// signed store, if the revocation changed them.
fn save_names<S>(s: S, layout: StoreLayout, rev: Revocation) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let store_dir = layout.store_dir();
    let book_path = layout.addressbook_path();
    let personas_path = layout.personas_path();
    let s2 = s.clone();
    let s3 = s.clone();
    let sd2 = store_dir.clone();
    vault_do! { s ;
        let _ = match rev.book_changed {
            true => vault_do! { s2 ;
                let _ = write_json(s2.clone(), book_path.clone(), rev.book.clone()) ;
                stage_signed(s2.clone(), store_dir.clone(), book_path.clone(), crate::signing::ADDRESSBOOK_NAMESPACE)
            },
            false => s2.pure(()),
        } ;
        match rev.personas_changed {
            true => vault_do! { s3 ;
                let _ = write_json(s3.clone(), personas_path.clone(), rev.personas.clone()) ;
                stage_signed(s3.clone(), sd2.clone(), personas_path.clone(), crate::signing::PERSONAS_NAMESPACE)
            },
            false => s3.pure(()),
        }
    }
}

fn commit<S>(s: S, store_dir: PathBuf, msg: String) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    vault_do! { s ;
        let out = git::commit(&s, store_dir, msg) ;
        match out {
            CommitOutcome::Committed | CommitOutcome::NothingToCommit => s.pure(()),
        }
    }
}

// ─── what is left behind ─────────────────────────────────────────────────

/// Every file name a copy for these keys could have: the canonical
/// fingerprint and, where it differs, the pre-fix verbatim one.
fn fingerprints(keys: &[RecipientSpec]) -> BTreeSet<String> {
    keys.iter()
        .flat_map(|k| [k.fingerprint(), k.legacy_fingerprint()])
        .map(|fp: RecipientFingerprint| fp.as_str().to_owned())
        .collect()
}

/// Entry directories that still hold a copy for any of `fps` — after
/// the rewrite, those are entries this operator cannot read.
fn holding_dirs<S>(s: S, store_dir: PathBuf, fps: BTreeSet<String>) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    vault_do! { s ;
        let children = s.list_dir(store_dir) ;
        {
            let dirs: Vec<PathBuf> = children
                .into_iter()
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(is_entry_dir_name)
                })
                .collect();
            scan_dirs(s2.clone(), dirs, fps, Vec::new())
        }
    }
}

fn scan_dirs<S>(
    s: S,
    dirs: Vec<PathBuf>,
    fps: BTreeSet<String>,
    mut acc: Vec<String>,
) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let mut iter = dirs.into_iter();
    let Some(dir) = iter.next() else {
        return s.pure(acc);
    };
    let rest: Vec<PathBuf> = iter.collect();
    let s2 = s.clone();
    vault_do! { s ;
        let files = s.list_dir(dir.clone()) ;
        {
            let holds = files.iter().any(|f| {
                StoreLayout::fingerprint_from_filename(f)
                    .is_some_and(|fp| fps.contains(fp.as_str()))
            });
            if holds {
                acc.push(
                    dir.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                        .to_owned(),
                );
            }
            scan_dirs(s2.clone(), rest, fps, acc)
        }
    }
}

fn warn_leftover<S>(s: S, dirs: Vec<String>, keys: Vec<String>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    if dirs.is_empty() {
        return s.pure(());
    }
    let short: Vec<String> = dirs.iter().map(|d| d.chars().take(12).collect()).collect();
    s.log(format!(
        "WARNING: {} entr{} you cannot decrypt still hold a copy for the revoked key(s) \
         (store dirs {}). Someone who can read them must run `rageveil deny <path> <key>` \
         with the raw key: {}",
        dirs.len(),
        if dirs.len() == 1 { "y" } else { "ies" },
        short.join(", "),
        keys.join(" | ")
    ))
}

fn log_lines<S>(s: S, lines: Vec<String>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let mut iter = lines.into_iter();
    let Some(line) = iter.next() else {
        return s.pure(());
    };
    let rest: Vec<String> = iter.collect();
    let s2 = s.clone();
    vault_do! { s ;
        let _ = s.log(line) ;
        log_lines(s2.clone(), rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(k: &str) -> RecipientSpec {
        RecipientSpec::new(k)
    }

    fn fixture() -> (AddressBook, Personas) {
        let mut book = AddressBook::empty();
        book.people.insert("jonn".into(), key("age1jonn"));
        book.people.insert("octoprophet".into(), key("age1octo"));
        book.people.insert("phone".into(), key("age1phone"));
        book.people.insert("bob".into(), key("age1bob"));
        let mut personas = Personas::empty();
        personas.groups.insert(
            "jonn".into(),
            ["octoprophet".to_owned(), "phone".to_owned()]
                .into_iter()
                .collect(),
        );
        (book, personas)
    }

    #[test]
    fn a_member_name_is_one_device() -> Result<(), String> {
        let (book, personas) = fixture();
        let rev = plan_revocation(&book, &personas, &["octoprophet".into()], &key("age1bob"))?;
        assert_eq!(rev.keys, vec![key("age1octo")]);
        assert_eq!(rev.dropped_names, vec!["octoprophet".to_owned()]);
        let group = rev.personas.groups.get("jonn").ok_or("group stays")?;
        assert!(group.contains("phone") && !group.contains("octoprophet"));
        assert!(rev.book.get("jonn").is_some() && rev.book.get("phone").is_some());
        Ok(())
    }

    #[test]
    fn a_canonical_name_is_the_whole_person() -> Result<(), String> {
        let (book, personas) = fixture();
        let rev = plan_revocation(&book, &personas, &["jonn".into()], &key("age1bob"))?;
        assert_eq!(rev.keys.len(), 3);
        assert!(rev.personas.groups.is_empty());
        assert_eq!(rev.book.people.keys().collect::<Vec<_>>(), vec!["bob"]);
        Ok(())
    }

    #[test]
    fn the_operator_is_refused() {
        let (book, personas) = fixture();
        let me = key("age1phone");
        for name in ["jonn", "phone", "age1phone"] {
            let out = plan_revocation(&book, &personas, &[name.into()], &me);
            assert!(
                matches!(&out, Err(e) if e.contains("own key")),
                "{name}: {out:?}"
            );
        }
        // Another device of the operator's own persona is fine.
        assert!(plan_revocation(&book, &personas, &["octoprophet".into()], &me).is_ok());
    }

    #[test]
    fn an_unknown_name_is_refused() {
        let (book, personas) = fixture();
        let out = plan_revocation(&book, &personas, &["nobody".into()], &key("age1bob"));
        assert!(matches!(&out, Err(e) if e.contains("nobody")), "{out:?}");
    }
}
