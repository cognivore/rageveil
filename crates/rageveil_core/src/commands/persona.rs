//! `rageveil persona …` — one person, several devices.
//!
//! The address book maps names to keys, one key per name. A person
//! with a laptop and a phone therefore has two names, and without
//! this file `allow db/prod lucia` reaches the laptop and not the
//! phone. `personas.json` groups names under a canonical one, and
//! `allow`/`deny` resolve any name in a group to every key in it
//! (see [`super::address::resolve_recipients`]).
//!
//! Three subcommands plus one library entry point:
//!   * [`persona_add`]    — put names under a canonical one, then
//!     share every entry any of them already holds to the rest
//!   * [`persona_remove`] — take names out of a group, or drop it
//!   * [`persona_list`]   — enumerate `(canonical, members)` pairs
//!   * [`own_devices`]    — the operator's other keys, which
//!     `insert` encrypts a new entry to from the start
//!
//! Membership therefore works in both directions: a device joining
//! a group is handed what the group holds, and a secret made on
//! any device of the group is made for all of them.
//!
//! The file is signed and verified like the address book, because
//! it carries the same power: a member added to someone else's
//! group receives that person's next share.

use super::address::{commit_personas, load_or_empty, load_personas_or_empty, validate_name};
use super::allow::{AllowArgs, allow};
use crate::addressbook::{AddressBook, Personas};
use crate::dsl::Vault;
use crate::index::Index;
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::{EntryPath, RecipientSpec};
use crate::vault_do;

use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct PersonaAddArgs {
    pub root: PathBuf,
    /// The name the group is known by. Needs no address-book entry
    /// of its own: `jonn` may be nothing but `phone`.
    pub canonical: String,
    /// Address-book names that are the same person.
    pub members: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PersonaRemoveArgs {
    pub root: PathBuf,
    pub canonical: String,
    /// Names to take out of the group. Empty drops the whole group.
    pub members: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PersonaListArgs {
    pub root: PathBuf,
}

// ─── add ─────────────────────────────────────────────────────────────────

/// Group `members` under `canonical`, commit, and then backfill:
/// every entry this operator can see that any of the group already
/// holds is shared to the rest of the group, so joining a group is
/// not a promise about future shares only.
///
/// Only entries this operator can decrypt are backfilled, because
/// only someone who can decrypt may share. Anything else is
/// reported so another holder can run `allow` for it.
pub fn persona_add<S>(s: S, args: PersonaAddArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let canonical = args.canonical.trim().to_owned();
    let members: Vec<String> = args.members.iter().map(|m| m.trim().to_owned()).collect();

    if let Err(msg) = validate_name(&canonical) {
        return s.fail(msg);
    }
    for m in &members {
        if let Err(msg) = validate_name(m) {
            return s.fail(msg);
        }
    }
    if members.is_empty() {
        return s.fail(format!("persona add {canonical}: name at least one member"));
    }

    let root = args.root;
    let s2 = s.clone();
    let s3 = s.clone();
    let s4 = s.clone();
    let layout2 = layout.clone();
    vault_do! { s ;
        let book = load_or_empty(s2.clone(), layout.addressbook_path()) ;
        let personas = load_personas_or_empty(s3.clone(), layout.personas_path()) ;
        let grouped = join_group(s4.clone(), book.clone(), personas, canonical.clone(), members.clone()) ;
        let _ = write_json(s4.clone(), layout2.personas_path(), grouped.clone()) ;
        let _ = commit_personas(
            s4.clone(),
            layout2.store_dir(),
            layout2.personas_path(),
            format!("persona add {canonical}: {}", members.join(", ")),
        ) ;
        backfill(s4.clone(), root, layout2, book, grouped, canonical)
    }
}

/// Check the group is well-formed and return the updated file.
fn join_group<S: Vault>(
    s: S,
    book: AddressBook,
    mut personas: Personas,
    canonical: String,
    members: Vec<String>,
) -> S::R<Personas> {
    if let Some(other) = personas
        .canonical_of(&canonical)
        .filter(|o| *o != canonical)
    {
        return s.fail(format!(
            "{canonical:?} is already a member of {other:?}; one person, one group"
        ));
    }
    for m in &members {
        if *m == canonical {
            return s.fail(format!(
                "{canonical:?} is the group itself, not a member of it"
            ));
        }
        if book.get(m).is_none() {
            return s.fail(format!(
                "{m:?} is not in the address book; register it first with \
                 `rageveil address add {m} <key>` (or `rageveil invite {m}`)"
            ));
        }
        match personas.canonical_of(m) {
            Some(other) if other != canonical => {
                return s.fail(format!(
                    "{m:?} is already a member of {other:?}; remove it from there first"
                ));
            }
            _ => {}
        }
    }
    personas
        .groups
        .entry(canonical)
        .or_default()
        .extend(members);
    s.pure(personas)
}

/// The keys a group resolves to: every member's address-book key,
/// plus the canonical name's own if it has one.
fn group_keys(book: &AddressBook, personas: &Personas, canonical: &str) -> Vec<RecipientSpec> {
    personas
        .expand(canonical)
        .iter()
        .filter_map(|n| book.get(n).cloned())
        .collect()
}

/// The operator's other devices: every address-book name whose key
/// is `whoami`, expanded through the persona file, minus `whoami`
/// itself. `insert` encrypts a new entry to these as well as to
/// the operator, so a secret made on the laptop is on the phone
/// at the next sync without a separate `allow`.
///
/// Empty when the operator is not in the address book or is in no
/// group, which leaves `insert` doing what it always did. Pairs
/// of name and key, so the caller can say who was reached.
///
/// The book and the personas are loaded through the signed path:
/// a persona file someone slipped a stranger into must not decide
/// who receives the operator's next secret.
pub fn own_devices<S>(
    s: S,
    layout: StoreLayout,
    whoami: RecipientSpec,
) -> S::R<Vec<(String, RecipientSpec)>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    let s3 = s.clone();
    vault_do! { s ;
        let book = load_or_empty(s2.clone(), layout.addressbook_path()) ;
        let personas = load_personas_or_empty(s3.clone(), layout.personas_path()) ;
        s3.pure(other_devices(&book, &personas, &whoami))
    }
}

/// Pure half of [`own_devices`]. Keys are compared canonically, so
/// an SSH comment that differs between `whoami` and the book does
/// not make the operator a stranger to their own group.
fn other_devices(
    book: &AddressBook,
    personas: &Personas,
    whoami: &RecipientSpec,
) -> Vec<(String, RecipientSpec)> {
    let me = whoami.canonical_key();
    let mut out: Vec<(String, RecipientSpec)> = Vec::new();
    let my_names = book
        .people
        .iter()
        .filter(|(_, key)| key.canonical_key() == me)
        .map(|(name, _)| name.as_str());
    for name in my_names {
        for other in personas.expand(name) {
            let Some(key) = book.get(&other) else { continue };
            let ck = key.canonical_key();
            if ck == me || out.iter().any(|(_, k)| k.canonical_key() == ck) {
                continue;
            }
            out.push((other, key.clone()));
        }
    }
    out
}

/// Which entries need a share, judged from the local index: it
/// lists exactly the entries this operator could decrypt at the
/// last sync, with their trusted sets.
fn backfill<S>(
    s: S,
    root: PathBuf,
    layout: StoreLayout,
    book: AddressBook,
    personas: Personas,
    canonical: String,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let keys = group_keys(&book, &personas, &canonical);
    let index_path = layout.index_path();
    let s2 = s.clone();
    let s3 = s.clone();
    vault_do! { s ;
        let exists = s.exists(index_path.clone()) ;
        let index = match exists {
            true => read_json::<S, Index>(s2.clone(), index_path),
            false => s2.pure(Index::empty()),
        } ;
        {
            let todo = entries_missing_a_key(&index, &keys);
            let n = todo.len();
            let s4 = s3.clone();
            vault_do! { s3 ;
                let _ = s3.log(match n {
                    0 => format!("persona {canonical}: nothing to backfill"),
                    1 => format!("persona {canonical}: backfilling 1 entry"),
                    n => format!("persona {canonical}: backfilling {n} entries"),
                }) ;
                share_each(s4, root, keys, todo)
            }
        }
    }
}

/// Entries where the group holds some keys but not all of them.
/// Compared by canonical key: the operator's own key is stamped
/// into an entry from `config.json` and looked up in the book,
/// and the two may carry different SSH comments.
fn entries_missing_a_key(index: &Index, keys: &[RecipientSpec]) -> Vec<EntryPath> {
    index
        .entries
        .iter()
        .filter(|(_, cached)| {
            let trusted: BTreeSet<String> = cached
                .metadata
                .trusted()
                .iter()
                .map(RecipientSpec::canonical_key)
                .collect();
            let held = keys
                .iter()
                .filter(|k| trusted.contains(&k.canonical_key()))
                .count();
            held > 0 && held < keys.len()
        })
        .map(|(path, _)| path.clone())
        .collect()
}

/// `allow` each entry to the whole group, one after another. A
/// failure on one entry (the index is stale and we no longer hold
/// it, say) is logged and the rest still run.
fn share_each<S>(s: S, root: PathBuf, keys: Vec<RecipientSpec>, todo: Vec<EntryPath>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let mut iter = todo.into_iter();
    match iter.next() {
        None => s.pure(()),
        Some(path) => {
            let rest: Vec<EntryPath> = iter.collect();
            let s2 = s.clone();
            let s3 = s.clone();
            let keys2 = keys.clone();
            let root2 = root.clone();
            let shown = path.to_string();
            vault_do! { s ;
                let out = s.handle(allow(
                    s2.clone(),
                    AllowArgs { root: root.clone(), path, recipients: keys },
                )) ;
                let _ = match out {
                    Ok(()) => s3.pure(()),
                    Err(e) => s3.log(format!("persona: could not backfill {shown}: {e}")),
                } ;
                share_each(s3.clone(), root2, keys2, rest)
            }
        }
    }
}

// ─── remove ──────────────────────────────────────────────────────────────

/// Take `members` out of `canonical`'s group, or drop the group when
/// no members are named. Shares already made stay made: leaving a
/// group changes who future `allow`s reach, and `deny` is the tool
/// for taking access away.
pub fn persona_remove<S>(s: S, args: PersonaRemoveArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let canonical = args.canonical.trim().to_owned();
    let members: Vec<String> = args.members.iter().map(|m| m.trim().to_owned()).collect();
    let s2 = s.clone();
    let s3 = s.clone();
    let layout2 = layout.clone();
    vault_do! { s ;
        let personas = load_personas_or_empty(s2.clone(), layout.personas_path()) ;
        let shrunk = leave_group(s3.clone(), personas, canonical.clone(), members.clone()) ;
        let _ = write_json(s3.clone(), layout2.personas_path(), shrunk) ;
        commit_personas(
            s3.clone(),
            layout2.store_dir(),
            layout2.personas_path(),
            match members.is_empty() {
                true => format!("persona remove {canonical}"),
                false => format!("persona remove {canonical}: {}", members.join(", ")),
            },
        )
    }
}

fn leave_group<S: Vault>(
    s: S,
    mut personas: Personas,
    canonical: String,
    members: Vec<String>,
) -> S::R<Personas> {
    let Some(group) = personas.groups.get_mut(&canonical) else {
        return s.fail(format!("no persona named {canonical:?}"));
    };
    if members.is_empty() {
        personas.groups.remove(&canonical);
        return s.pure(personas);
    }
    for m in &members {
        if !group.remove(m) {
            return s.fail(format!("{m:?} is not a member of {canonical:?}"));
        }
    }
    if group.is_empty() {
        personas.groups.remove(&canonical);
    }
    s.pure(personas)
}

// ─── list ────────────────────────────────────────────────────────────────

/// Every `(canonical, members)` pair, sorted by canonical name.
pub fn persona_list<S>(s: S, args: PersonaListArgs) -> S::R<Vec<(String, Vec<String>)>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root);
    let s2 = s.clone();
    vault_do! { s ;
        let personas = load_personas_or_empty(s2.clone(), layout.personas_path()) ;
        s2.pure(
            personas
                .groups
                .into_iter()
                .map(|(c, m)| (c, m.into_iter().collect()))
                .collect(),
        )
    }
}
