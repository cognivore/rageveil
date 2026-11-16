//! `rageveil address rename`, `rageveil persona rename` and
//! `rageveil persona tree`: names for people and their keys.
//!
//! AI-generated module: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! A person is a group in `personas.json`, and its members are the names
//! of their keys in the address book. The names spell out a tree:
//!
//! ```text
//! jons                     the natural person: the group's canonical name
//!   jons-macbook-touch     a device (macbook) and a key on it (touch)
//!   jons-macbook-ssh       the same device's plain, automation key
//!   jons-iphone            a device with one key of its own
//!   jons-yubikey           a key outside any device
//! ```
//!
//! Nothing else in the store holds a name: entries, `gated.json` and
//! `exposed.txt` refer to keys and hashes, and the index to paths. So a
//! rename rewrites the address book and the persona groups, together, in
//! one signed commit, and pushes it like any address-book change. On the
//! dedicated host the server lets only an administrator push that; on a
//! signed store this client refuses first when its key is not an admin's.
//! Nobody gains or loses a secret.

use super::address::{
    classify_remote, guard_remote, load_or_empty, load_personas_or_empty, propagate,
    stage_signed, validate_name,
};
use crate::addressbook::{AddressBook, Personas};
use crate::commands::invite::INVITE_ENTRY_PREFIX;
use crate::config::Config;
use crate::dsl::Vault;
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::{CommitOutcome, RecipientSpec};
use crate::{git, vault_do};

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The kinds of key a device carries, as the last part of its name.
pub const KEY_KINDS: [&str; 3] = ["touch", "ssh", "humanssh"];

#[derive(Clone, Debug)]
pub struct RenameArgs {
    pub root: PathBuf,
    pub from: String,
    pub to: String,
    /// Waive the dedicated-host check, as `address add --force` does.
    pub force: bool,
}

/// The book and groups after a rename, and what was renamed, for the
/// commit message and the log.
#[derive(Clone, Debug)]
pub struct Renamed {
    pub book: AddressBook,
    pub personas: Personas,
    /// Address-book names, old and new.
    pub names: Vec<(String, String)>,
    /// Members of a renamed person whose names do not begin with the
    /// person's name, left as they were.
    pub left: Vec<String>,
}

fn taken(book: &AddressBook, personas: &Personas, name: &str) -> bool {
    book.people.contains_key(name)
        || personas.canonical_of(name).is_some()
        || book.people.contains_key(&format!("{INVITE_ENTRY_PREFIX}{name}"))
}

fn check_new(book: &AddressBook, personas: &Personas, name: &str) -> Result<(), String> {
    validate_name(name)?;
    if name.starts_with(INVITE_ENTRY_PREFIX) {
        return Err(format!("{name:?} is how a pending invitation is named; pick another"));
    }
    if taken(book, personas, name) {
        return Err(format!("{name:?} is already a name in this store"));
    }
    Ok(())
}

fn check_no_invite(book: &AddressBook, name: &str) -> Result<(), String> {
    match book.people.contains_key(&format!("{INVITE_ENTRY_PREFIX}{name}")) {
        true => Err(format!(
            "an invitation for {name:?} is pending; accept or revoke it before renaming"
        )),
        false => Ok(()),
    }
}

/// Rename one key's name. Its place in a group follows it. When the key
/// is the one a group is named after (a person whose own name was their
/// first key), the group keeps the person's name and the key joins it as
/// a member under its new name.
pub fn rename_address(
    book: &AddressBook,
    personas: &Personas,
    from: &str,
    to: &str,
) -> Result<Renamed, String> {
    let key = book
        .people
        .get(from)
        .filter(|_| !from.starts_with(INVITE_ENTRY_PREFIX))
        .cloned()
        .ok_or_else(|| format!("no address-book entry named {from:?}"))?;
    check_no_invite(book, from)?;
    check_new(book, personas, to)?;

    let mut book = book.clone();
    let mut personas = personas.clone();
    book.people.remove(from);
    book.people.insert(to.to_owned(), key);
    for (canonical, members) in personas.groups.iter_mut() {
        if members.remove(from) || canonical == from {
            members.insert(to.to_owned());
        }
    }
    Ok(Renamed { book, personas, names: vec![(from.into(), to.into())], left: Vec::new() })
}

/// Rename a person: their group, the key named after them if there is
/// one, and every member whose name begins with `FROM-`, which becomes
/// `TO-` with the rest unchanged. Members named otherwise stay as they
/// are and are reported, for `address rename`.
pub fn rename_person(
    book: &AddressBook,
    personas: &Personas,
    from: &str,
    to: &str,
) -> Result<Renamed, String> {
    let members = personas.groups.get(from).cloned().ok_or_else(|| {
        match personas.canonical_of(from) {
            Some(group) => format!("{from:?} is a key of {group:?}, not a person; use `address rename`"),
            None => format!("no person named {from:?}; `persona list` shows who there is"),
        }
    })?;
    check_new(book, personas, to)?;
    check_no_invite(book, from)?;

    let prefix = format!("{from}-");
    let mut names: Vec<(String, String)> = Vec::new();
    let mut left: Vec<String> = Vec::new();
    for m in &members {
        match m.strip_prefix(&prefix) {
            Some(rest) => names.push((m.clone(), format!("{to}-{rest}"))),
            None => left.push(m.clone()),
        }
    }
    if book.people.contains_key(from) {
        names.push((from.to_owned(), to.to_owned()));
    }

    let mut new_book = book.clone();
    for (old, new) in &names {
        check_no_invite(book, old)?;
        if old != from {
            validate_name(new)?;
            if taken(book, personas, new) {
                return Err(format!("{old:?} would become {new:?}, which is already a name"));
            }
        }
        let key = new_book.people.remove(old).ok_or_else(|| {
            format!("{old:?} is in {from:?}'s group but not in the address book")
        })?;
        new_book.people.insert(new.clone(), key);
    }

    let renamed: BTreeSet<String> = members
        .iter()
        .map(|m| {
            names
                .iter()
                .find(|(old, _)| old == m)
                .map(|(_, new)| new.clone())
                .unwrap_or_else(|| m.clone())
        })
        .collect();
    let mut new_personas = personas.clone();
    new_personas.groups.remove(from);
    new_personas.groups.insert(to.to_owned(), renamed);
    Ok(Renamed { book: new_book, personas: new_personas, names, left })
}

/// One line per person, device and key, indented, for `persona tree`.
/// A name that does not begin with its person's name is listed as is.
pub fn tree(book: &AddressBook, personas: &Personas) -> Vec<String> {
    let key_of = |name: &str| -> String {
        book.people
            .get(name)
            .map(short)
            .unwrap_or_else(|| "(not in the address book)".into())
    };
    let mut out = Vec::new();
    let grouped: BTreeSet<&str> = personas
        .groups
        .iter()
        .flat_map(|(c, ms)| std::iter::once(c.as_str()).chain(ms.iter().map(String::as_str)))
        .collect();
    for (person, members) in &personas.groups {
        out.push(person.clone());
        if book.people.contains_key(person) {
            out.push(format!("  {person}  {}", key_of(person)));
        }
        let prefix = format!("{person}-");
        let mut devices: std::collections::BTreeMap<String, Vec<(String, String)>> =
            Default::default();
        let mut other: Vec<String> = Vec::new();
        for m in members {
            match m.strip_prefix(&prefix) {
                None => other.push(m.clone()),
                Some(rest) => {
                    let (device, kind) = match rest.rsplit_once('-') {
                        Some((d, k)) if KEY_KINDS.contains(&k) => (d.to_owned(), k.to_owned()),
                        _ => (rest.to_owned(), String::new()),
                    };
                    devices.entry(device).or_default().push((kind, m.clone()));
                }
            }
        }
        for (device, keys) in devices {
            match keys.as_slice() {
                [(kind, name)] if kind.is_empty() => {
                    out.push(format!("  {device}  {name}  {}", key_of(name)))
                }
                _ => {
                    out.push(format!("  {device}"));
                    for (kind, name) in keys {
                        let kind = if kind.is_empty() { "key".to_owned() } else { kind };
                        out.push(format!("    {kind}  {name}  {}", key_of(&name)));
                    }
                }
            }
        }
        for name in other {
            out.push(format!("  {name}  {}", key_of(&name)));
        }
    }
    let loose: Vec<&String> = book
        .people
        .keys()
        .filter(|n| !grouped.contains(n.as_str()) && !n.starts_with(INVITE_ENTRY_PREFIX))
        .collect();
    if !loose.is_empty() {
        out.push("(in no group)".into());
        for name in loose {
            out.push(format!("  {name}  {}", key_of(name)));
        }
    }
    out
}

fn short(key: &RecipientSpec) -> String {
    let k = key.canonical_key();
    let shown: String = k.chars().take(28).collect();
    if k.chars().count() > 28 { format!("{shown}…") } else { shown }
}

/// `address rename`.
pub fn address_rename<S>(s: S, args: RenameArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    apply(s, args, "address rename", rename_address)
}

/// `persona rename`.
pub fn persona_rename<S>(s: S, args: RenameArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    apply(s, args, "persona rename", rename_person)
}

/// `persona tree`.
pub fn persona_tree<S>(s: S, root: PathBuf) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(root);
    let s2 = s.clone();
    vault_do! { s ;
        let book = load_or_empty(s.clone(), layout.addressbook_path()) ;
        let personas = load_personas_or_empty(s.clone(), layout.personas_path()) ;
        s2.pure(tree(&book, &personas))
    }
}

fn apply<S>(
    s: S,
    args: RenameArgs,
    verb: &'static str,
    plan: fn(&AddressBook, &Personas, &str, &str) -> Result<Renamed, String>,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let store_dir = layout.store_dir();
    let (from, to) = (args.from.trim().to_owned(), args.to.trim().to_owned());
    let s2 = s.clone();
    vault_do! { s ;
        let _ = refuse_unless_admin(s.clone(), layout.clone()) ;
        let kind = classify_remote(s.clone(), store_dir.clone()) ;
        let _ = guard_remote(s.clone(), kind.clone(), args.force) ;
        let book = load_or_empty(s.clone(), layout.addressbook_path()) ;
        let personas = load_personas_or_empty(s.clone(), layout.personas_path()) ;
        let renamed = crate::sugar::lift_result(&s, plan(&book, &personas, &from, &to)) ;
        let head = git::head(&s, store_dir.clone()) ;
        let _ = write_json(s.clone(), layout.addressbook_path(), renamed.book.clone()) ;
        let _ = write_json(s.clone(), layout.personas_path(), renamed.personas.clone()) ;
        let _ = stage_signed(s.clone(), store_dir.clone(), layout.addressbook_path(),
                             crate::signing::ADDRESSBOOK_NAMESPACE) ;
        let _ = stage_signed(s.clone(), store_dir.clone(), layout.personas_path(),
                             crate::signing::PERSONAS_NAMESPACE) ;
        let message = s.pure(format!(
            "{verb} {from} {to}: {}",
            renamed.names.iter().map(|(a, b)| format!("{a} → {b}")).collect::<Vec<_>>().join(", ")
        )) ;
        let out = git::commit(&s, store_dir.clone(), message.clone()) ;
        let _ = match out {
            CommitOutcome::Committed => s.log(message),
            CommitOutcome::NothingToCommit => s.log("nothing changed".into()),
        } ;
        let _ = match renamed.left.is_empty() {
            true => s.pure(()),
            false => s.log(format!(
                "kept as they were, since they do not begin with {from:?}: {}; \
                 rename them with `rageveil address rename`",
                renamed.left.join(", ")
            )),
        } ;
        propagate(s2.clone(), store_dir, kind, format!("{from} → {to}"), head)
    }
}

/// On a signed store, only an administrator's key signs the book that
/// everyone verifies, so refuse before writing anything. The server
/// refuses the push of anyone else as well.
fn refuse_unless_admin<S>(s: S, layout: StoreLayout) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let root = layout.root.clone();
    let admins = crate::signing::admins_path(&root);
    let s2 = s.clone();
    vault_do! { s ;
        let signed = s.exists(admins.clone()) ;
        match signed {
            false => s2.pure(()),
            true => {
                let s3 = s2.clone();
                vault_do! { s2 ;
                    let cfg = read_json::<S, Config>(s2.clone(), layout.config_path()) ;
                    let list = read_json::<S, Vec<String>>(s2.clone(), admins) ;
                    {
                        let me = cfg.whoami.canonical_key();
                        match list.iter().any(|a| RecipientSpec::new(a.clone()).canonical_key() == me) {
                            true => s3.pure(()),
                            false => s3.fail(
                                "only an administrator of this store renames people and keys".into(),
                            ),
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (AddressBook, Personas) {
        let mut book = AddressBook::empty();
        for (n, k) in [
            ("jonn-ssh", "ssh-ed25519 AAAAmac"),
            ("jonn-touch", "age1se1qmac"),
            ("octoprophet", "ssh-ed25519 AAAAlinux"),
            ("phone", "ssh-ed25519 AAAAphone"),
            ("lucia", "ssh-ed25519 AAAAlucia"),
            ("lucia-work-phone", "ssh-ed25519 AAAAlphone"),
            ("brian", "ssh-ed25519 AAAAbrian"),
        ] {
            book.people.insert(n.into(), RecipientSpec::new(k));
        }
        let mut personas = Personas::empty();
        personas.groups.insert(
            "jonn".into(),
            ["jonn-ssh", "jonn-touch", "octoprophet", "phone"].map(String::from).into(),
        );
        personas.groups.insert("lucia".into(), ["lucia-work-phone".to_owned()].into());
        (book, personas)
    }

    #[test]
    fn a_person_and_their_prefixed_keys_are_renamed_together() {
        let (book, personas) = store();
        let r = rename_person(&book, &personas, "jonn", "jons").expect("renames");
        assert!(r.personas.groups.get("jonn").is_none());
        let members = &r.personas.groups["jons"];
        for m in ["jons-ssh", "jons-touch", "octoprophet", "phone"] {
            assert!(members.contains(m), "{m} missing: {members:?}");
        }
        assert_eq!(r.book.people["jons-ssh"], book.people["jonn-ssh"]);
        assert!(!r.book.people.contains_key("jonn-ssh"));
        assert_eq!(r.left, vec!["octoprophet".to_owned(), "phone".to_owned()]);
        assert_eq!(r.book.people.len(), book.people.len(), "no key gained or lost");
    }

    #[test]
    fn a_person_named_by_their_own_key_keeps_it() {
        let (book, personas) = store();
        let r = rename_person(&book, &personas, "lucia", "lu").expect("renames");
        assert_eq!(r.book.people["lu"], book.people["lucia"]);
        assert!(r.personas.groups["lu"].contains("lu-work-phone"));
    }

    #[test]
    fn a_key_keeps_its_group_and_a_group_named_key_joins_as_member() {
        let (book, personas) = store();
        let r = rename_address(&book, &personas, "octoprophet", "jonn-linux-ssh").expect("renames");
        assert!(r.personas.groups["jonn"].contains("jonn-linux-ssh"));
        assert!(!r.personas.groups["jonn"].contains("octoprophet"));

        let r = rename_address(&book, &personas, "lucia", "lucia-macbook-ssh").expect("renames");
        assert!(r.personas.groups.contains_key("lucia"));
        assert!(r.personas.groups["lucia"].contains("lucia-macbook-ssh"));
        assert!(!r.book.people.contains_key("lucia"));
    }

    #[test]
    fn taken_names_unknown_names_and_pending_invitations_are_refused() {
        let (mut book, personas) = store();
        assert!(rename_address(&book, &personas, "phone", "brian").is_err());
        assert!(rename_address(&book, &personas, "phone", "jonn").is_err(), "a person's name");
        assert!(rename_address(&book, &personas, "nobody", "x").is_err());
        assert!(rename_person(&book, &personas, "jonn-ssh", "x").is_err(), "a key, not a person");
        assert!(rename_person(&book, &personas, "jonn", "brian").is_err());
        book.people.insert("invite:phone".into(), RecipientSpec::new("age1transport"));
        assert!(rename_address(&book, &personas, "phone", "jonn-iphone").is_err());
        assert!(rename_address(&book, &personas, "brian", "phone").is_err(), "pending name");
    }

    #[test]
    fn the_tree_groups_keys_by_device() {
        let (book, personas) = store();
        let r = rename_person(&book, &personas, "jonn", "jons").expect("renames");
        let r = rename_address(&r.book, &r.personas, "jons-ssh", "jons-macbook-ssh").expect("ok");
        let r = rename_address(&r.book, &r.personas, "jons-touch", "jons-macbook-touch").expect("ok");
        let r = rename_address(&r.book, &r.personas, "phone", "jons-iphone").expect("ok");
        let lines = tree(&r.book, &r.personas);
        let at = |s: &str| lines.iter().position(|l| l.starts_with(s)).unwrap_or(usize::MAX);
        assert!(at("jons") < at("  macbook"), "{lines:#?}");
        assert_eq!(at("  macbook") + 1, at("    ssh  jons-macbook-ssh"), "{lines:#?}");
        assert!(at("    touch  jons-macbook-touch") < usize::MAX, "{lines:#?}");
        assert!(at("  iphone  jons-iphone") < usize::MAX, "{lines:#?}");
        assert!(at("  octoprophet") < usize::MAX, "{lines:#?}");
        assert!(at("(in no group)") < at("  brian"), "{lines:#?}");
    }
}
