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
///
/// `tpm` (draft) is a Linux laptop's TPM key behind a PIN, the
/// counterpart of a Mac's `touch`. A TPM key without a PIN is not a
/// kind of its own: nothing releases it but the laptop, so it is no
/// better than `ssh`, and `rageveil tpm` refuses one.
///
/// `touchssh` (draft) is an SSH key the device's keychain releases
/// only to a finger or a face: a Visageveil app's key on a Mac, which
/// sits beside that Mac's `touch` key under the same device.
pub const KEY_KINDS: [&str; 5] = ["touch", "touchssh", "tpm", "ssh", "humanssh"];

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

// AI-assisted addition (the structured tree, key-name composition and
// admin standing below, 2026-11-16): model Claude Opus 5.5
// (`claude-opus-5-5`); reasoning effort unavailable (not exposed by the
// harness).

/// What each key kind is, in a phrase, for a screen that offers them.
pub fn key_kind_summary(kind: &str) -> Option<&'static str> {
    match kind {
        "touch" => Some("Secure Enclave key, opened with a finger or a face"),
        "touchssh" => Some("SSH key in the keychain, opened with a finger or a face"),
        "tpm" => Some("TPM key, opened with its PIN"),
        "ssh" => Some("plain SSH key: opens with no one present, for automation"),
        "humanssh" => Some("SSH key behind a passphrase"),
        _ => None,
    }
}

/// The device and kind that a key's name gives under `person`:
/// `jons-macbook-touch` is (`macbook`, `touch`), `jons-iphone` is
/// (`iphone`, none), and so is a key outside any device, `jons-yubikey`.
/// `None` when the name does not begin with `person-`.
pub fn split_key_name<'a>(person: &str, name: &'a str) -> Option<(&'a str, Option<&'a str>)> {
    let rest = name.strip_prefix(person)?.strip_prefix('-')?;
    Some(match rest.rsplit_once('-') {
        Some((device, kind)) if KEY_KINDS.contains(&kind) => (device, Some(kind)),
        _ => (rest, None),
    })
}

/// The name that person, device and kind spell, as typed, for showing
/// while they are typed: `jons-macbook-touch`. [`compose_key_name`]
/// says whether it is a good one.
pub fn join_key_name(person: &str, device: &str, kind: Option<&str>) -> String {
    [person.trim(), device.trim(), kind.unwrap_or("").trim()]
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Spell a key's name from its parts, refusing parts that would not
/// read back as the same parts: [`split_key_name`] of the result under
/// `person` is `(device, kind)`. `device` is the device's name, or the
/// key's own for a key outside any device. Whether the name is free in
/// a store is [`check_new_name`]'s question.
pub fn compose_key_name(person: &str, device: &str, kind: Option<&str>) -> Result<String, String> {
    let (person, device) = (person.trim(), device.trim());
    let kind = kind.map(str::trim).filter(|k| !k.is_empty());
    if person.is_empty() {
        return Err("name the person whose key this is".into());
    }
    if device.is_empty() {
        return Err("name the device, or the key itself if it is on no device".into());
    }
    for (what, part) in [("person", person), ("device", device)] {
        if part.chars().any(char::is_whitespace) {
            return Err(format!("the {what} is one word, with no spaces: {part:?}"));
        }
        if part.starts_with('-') || part.ends_with('-') {
            return Err(format!(
                "the {what} cannot begin or end with a dash, which joins the parts: {part:?}"
            ));
        }
    }
    if let Some(k) = kind.filter(|k| !KEY_KINDS.contains(k)) {
        return Err(format!("{k:?} is not a key kind; one of {}", KEY_KINDS.join(", ")));
    }
    if let (None, Some((_, k))) = (kind, device.rsplit_once('-'))
        && KEY_KINDS.contains(&k)
    {
        return Err(format!(
            "{device:?} ends in -{k}, which reads as the key's kind; choose kind {k} instead"
        ));
    }
    let name = join_key_name(person, device, kind);
    validate_name(&name)?;
    if name.starts_with(INVITE_ENTRY_PREFIX) {
        return Err(format!("{name:?} is how a pending invitation is named; pick another"));
    }
    Ok(name)
}

/// Why `name` cannot be a new name in this store, if it cannot: a bad
/// name, a pending invitation's, or one a key or person already has.
pub fn check_new_name(book: &AddressBook, personas: &Personas, name: &str) -> Result<(), String> {
    check_new(book, personas, name)
}

/// One key in the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyNode {
    /// Its address-book name: `jons-macbook-touch`.
    pub name: String,
    /// The kind its name ends in, one of [`KEY_KINDS`]; `None` for a
    /// device's one key, a key outside any device, and a name that
    /// does not follow the person's.
    pub kind: Option<String>,
    /// `None` when a group names a key the address book does not hold.
    pub key: Option<RecipientSpec>,
}

/// A device and its keys, or a key outside any device (one key, no
/// kind): `macbook`, `iphone`, `yubikey`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceNode {
    pub device: String,
    /// In order of name.
    pub keys: Vec<KeyNode>,
}

/// A natural person: a group in `personas.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersonNode {
    /// The group's canonical name, which each key's name begins with.
    pub person: String,
    /// The key named exactly as the person, if the address book has one.
    pub own: Option<KeyNode>,
    /// In order of device name.
    pub devices: Vec<DeviceNode>,
    /// Members whose names do not begin with `person-`, as they are.
    pub other: Vec<KeyNode>,
}

/// The people in a store, their devices and each device's keys, and the
/// names in no group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeopleTree {
    /// In order of name.
    pub people: Vec<PersonNode>,
    /// Address-book names in no group, pending invitations left out.
    pub loose: Vec<KeyNode>,
}

/// The tree that the names spell. One reading of the names, for
/// `persona tree` and for the apps: see [`tree`].
pub fn people_tree(book: &AddressBook, personas: &Personas) -> PeopleTree {
    let node = |name: &str, kind: Option<&str>| KeyNode {
        name: name.to_owned(),
        kind: kind.map(str::to_owned),
        key: book.people.get(name).cloned(),
    };
    let grouped: BTreeSet<&str> = personas
        .groups
        .iter()
        .flat_map(|(c, ms)| std::iter::once(c.as_str()).chain(ms.iter().map(String::as_str)))
        .collect();
    let people = personas
        .groups
        .iter()
        .map(|(person, members)| {
            let mut devices: std::collections::BTreeMap<&str, Vec<KeyNode>> = Default::default();
            let mut other = Vec::new();
            for m in members {
                match split_key_name(person, m) {
                    None => other.push(node(m, None)),
                    Some((device, kind)) => devices.entry(device).or_default().push(node(m, kind)),
                }
            }
            PersonNode {
                person: person.clone(),
                own: book.people.contains_key(person).then(|| node(person, None)),
                devices: devices
                    .into_iter()
                    .map(|(device, keys)| DeviceNode { device: device.to_owned(), keys })
                    .collect(),
                other,
            }
        })
        .collect();
    let loose = book
        .people
        .keys()
        .filter(|n| !grouped.contains(n.as_str()) && !n.starts_with(INVITE_ENTRY_PREFIX))
        .map(|n| node(n, None))
        .collect();
    PeopleTree { people, loose }
}

/// One line per person, device and key, indented, for `persona tree`,
/// each key shortened. A name that does not begin with its person's
/// name is listed as is.
pub fn tree(book: &AddressBook, personas: &Personas) -> Vec<String> {
    render_tree(book, personas, short)
}

/// The same tree for `address list`: with every key in full, so a key
/// can be copied from it, or with no keys at all (`--no-descriptors`).
pub fn tree_full(book: &AddressBook, personas: &Personas, keys: bool) -> Vec<String> {
    if keys {
        render_tree(book, personas, |k| k.canonical_key().to_owned())
    } else {
        render_tree(book, personas, |_| String::new())
            .into_iter()
            .map(|l| l.trim_end().to_owned())
            .collect()
    }
}

fn render_tree(
    book: &AddressBook,
    personas: &Personas,
    shown: fn(&RecipientSpec) -> String,
) -> Vec<String> {
    let key_of = |k: &KeyNode| -> String {
        k.key.as_ref().map(shown).unwrap_or_else(|| "(not in the address book)".into())
    };
    let people = people_tree(book, personas);
    let mut out = Vec::new();
    for p in &people.people {
        out.push(p.person.clone());
        if let Some(own) = &p.own {
            out.push(format!("  {}  {}", own.name, key_of(own)));
        }
        for d in &p.devices {
            match d.keys.as_slice() {
                [k] if k.kind.is_none() => {
                    out.push(format!("  {}  {}  {}", d.device, k.name, key_of(k)))
                }
                keys => {
                    out.push(format!("  {}", d.device));
                    for k in keys {
                        let kind = k.kind.as_deref().unwrap_or("key");
                        out.push(format!("    {kind}  {}  {}", k.name, key_of(k)));
                    }
                }
            }
        }
        for k in &p.other {
            out.push(format!("  {}  {}", k.name, key_of(k)));
        }
    }
    if !people.loose.is_empty() {
        out.push("(in no group)".into());
        for k in &people.loose {
            out.push(format!("  {}  {}", k.name, key_of(k)));
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

/// `address list`: the tree, with every key in full when `keys`.
pub fn address_tree<S>(s: S, root: PathBuf, keys: bool) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(root);
    let s2 = s.clone();
    vault_do! { s ;
        let book = load_or_empty(s.clone(), layout.addressbook_path()) ;
        let personas = load_personas_or_empty(s.clone(), layout.personas_path()) ;
        s2.pure(tree_full(&book, &personas, keys))
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

/// Whether this store's operator may rename, as the client sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminStanding {
    /// The store records no administrators (no `admins.json`), so
    /// nothing here refuses; on the dedicated host the server decides.
    Unsigned,
    /// The operator's key is one of the recorded administrators'.
    Admin,
    /// Administrators are recorded and the operator is not one.
    NotAdmin,
}

/// Whether `whoami` is among the administrator keys `admins` lists.
pub fn is_admin(admins: &[String], whoami: &RecipientSpec) -> bool {
    let me = whoami.canonical_key();
    admins.iter().any(|a| RecipientSpec::new(a.clone()).canonical_key() == me)
}

/// Read the store's administrators and the operator's key. Local: no
/// key is unlocked and nothing is fetched.
pub fn admin_standing<S>(s: S, root: PathBuf) -> S::R<AdminStanding>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(root);
    let admins = crate::signing::admins_path(&layout.root);
    let s2 = s.clone();
    vault_do! { s ;
        let signed = s.exists(admins.clone()) ;
        match signed {
            false => s2.pure(AdminStanding::Unsigned),
            true => {
                let s3 = s2.clone();
                vault_do! { s2 ;
                    let cfg = read_json::<S, Config>(s2.clone(), layout.config_path()) ;
                    let list = read_json::<S, Vec<String>>(s2.clone(), admins) ;
                    s3.pure(match is_admin(&list, &cfg.whoami) {
                        true => AdminStanding::Admin,
                        false => AdminStanding::NotAdmin,
                    })
                }
            }
        }
    }
}

/// On a signed store, only an administrator's key signs the book that
/// everyone verifies, so refuse before writing anything. The server
/// refuses the push of anyone else as well.
fn refuse_unless_admin<S>(s: S, layout: StoreLayout) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    vault_do! { s ;
        let standing = admin_standing(s.clone(), layout.root.clone()) ;
        match standing {
            AdminStanding::Unsigned | AdminStanding::Admin => s2.pure(()),
            AdminStanding::NotAdmin => s2.fail(
                "only an administrator of this store renames people and keys".into(),
            ),
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
    fn a_keychain_key_behind_a_finger_sits_under_its_device() {
        let (book, personas) = store();
        let r = rename_address(&book, &personas, "jonn-touch", "jonn-macbook-touch").expect("ok");
        let mut book = r.book;
        book.people.insert("jonn-macbook-touchssh".into(), RecipientSpec::new("ssh-ed25519 AAAAapp"));
        let mut personas = r.personas;
        personas.groups.get_mut("jonn").expect("jonn").insert("jonn-macbook-touchssh".into());
        assert_eq!(split_key_name("jonn", "jonn-macbook-touchssh"), Some(("macbook", Some("touchssh"))));
        let t = people_tree(&book, &personas);
        let macbook = t.people[0].devices.iter().find(|d| d.device == "macbook").expect("macbook");
        let kinds: Vec<Option<&str>> = macbook.keys.iter().map(|k| k.kind.as_deref()).collect();
        assert_eq!(kinds, [Some("touch"), Some("touchssh")]);
    }

    #[test]
    fn address_list_shows_full_keys_or_none() {
        let (book, personas) = store();
        let full = tree_full(&book, &personas, true);
        assert!(full.iter().any(|l| l.ends_with("ssh-ed25519 AAAAlucia")), "{full:#?}");
        let bare = tree_full(&book, &personas, false);
        assert!(bare.iter().all(|l| !l.contains("AAAA") && l == l.trim_end()), "{bare:#?}");
        assert_eq!(full.len(), bare.len());
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

    #[test]
    fn the_structured_tree_holds_person_device_and_kind() {
        let (book, personas) = store();
        let r = rename_address(&book, &personas, "jonn-ssh", "jonn-macbook-ssh").expect("ok");
        let r = rename_address(&r.book, &r.personas, "jonn-touch", "jonn-macbook-touch").expect("ok");
        let r = rename_address(&r.book, &r.personas, "phone", "jonn-iphone").expect("ok");
        let t = people_tree(&r.book, &r.personas);
        let names: Vec<&str> = t.people.iter().map(|p| p.person.as_str()).collect();
        assert_eq!(names, ["jonn", "lucia"]);
        let jonn = &t.people[0];
        assert_eq!(jonn.own, None);
        let devices: Vec<&str> = jonn.devices.iter().map(|d| d.device.as_str()).collect();
        assert_eq!(devices, ["iphone", "macbook"]);
        let macbook: Vec<(&str, Option<&str>)> = jonn.devices[1]
            .keys
            .iter()
            .map(|k| (k.name.as_str(), k.kind.as_deref()))
            .collect();
        assert_eq!(macbook, [("jonn-macbook-ssh", Some("ssh")), ("jonn-macbook-touch", Some("touch"))]);
        assert_eq!(jonn.devices[1].keys[1].key, Some(RecipientSpec::new("age1se1qmac")));
        assert_eq!(jonn.devices[0].keys[0].kind, None);
        assert_eq!(jonn.other.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(), ["octoprophet"]);
        let lucia = &t.people[1];
        assert_eq!(lucia.own.as_ref().map(|k| k.name.as_str()), Some("lucia"));
        assert_eq!(lucia.devices[0].device, "work-phone");
        assert_eq!(t.loose.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(), ["brian"]);
    }

    #[test]
    fn a_group_member_missing_from_the_book_has_no_key() {
        let (book, mut personas) = store();
        personas.groups.get_mut("lucia").expect("lucia").insert("lucia-ghost".into());
        let t = people_tree(&book, &personas);
        let ghost = &t.people[1].devices.iter().find(|d| d.device == "ghost").expect("ghost").keys[0];
        assert_eq!(ghost.key, None);
        assert!(tree(&book, &personas).iter().any(|l| l.contains("(not in the address book)")));
    }

    #[test]
    fn composed_names_read_back_as_their_parts() {
        let cases: [(&str, &str, Option<&str>); 7] = [
            ("jons", "macbook", Some("touch")),
            ("jons", "macbook", Some("ssh")),
            ("jons", "macbook", Some("humanssh")),
            ("jons", "framework", Some("tpm")),
            ("jons", "iphone", None),
            ("emi", "iphone16", None),
            ("lucia", "work-phone", Some("ssh")),
        ];
        for (person, device, kind) in cases {
            let name = compose_key_name(person, device, kind).expect("composes");
            assert_eq!(split_key_name(person, &name), Some((device, kind)), "{name}");
        }
        assert_eq!(compose_key_name(" jons ", " macbook ", Some("touch")).as_deref(), Ok("jons-macbook-touch"));
        assert_eq!(join_key_name("jons", "", Some("touch")), "jons-touch");
        assert_eq!(join_key_name("jons", "mac", None), "jons-mac");
    }

    #[test]
    fn parts_that_would_not_read_back_are_refused() {
        assert!(compose_key_name("", "macbook", None).is_err());
        assert!(compose_key_name("jons", "", Some("touch")).is_err());
        assert!(compose_key_name("jo ns", "macbook", None).is_err());
        assert!(compose_key_name("jons", "mac-", None).is_err());
        assert!(compose_key_name("jons-", "mac", None).is_err());
        assert!(compose_key_name("jons", "macbook", Some("yubi")).is_err());
        let e = compose_key_name("jons", "macbook-ssh", None).expect_err("reads as a kind");
        assert!(e.contains("choose kind ssh"), "{e}");
        assert!(compose_key_name("invite:jons", "x", None).is_err());
        assert!(compose_key_name("ssh-ed25519", "x", None).is_err(), "looks like a key");
        for k in KEY_KINDS {
            assert!(key_kind_summary(k).is_some(), "{k} has no summary");
        }
    }

    #[test]
    fn a_new_name_must_be_free() {
        let (book, personas) = store();
        assert!(check_new_name(&book, &personas, "brian").is_err());
        assert!(check_new_name(&book, &personas, "jonn").is_err(), "a person's name");
        assert!(check_new_name(&book, &personas, "jonn-ssh").is_err());
        assert!(check_new_name(&book, &personas, "jonn-macbook-ssh").is_ok());
    }

    #[test]
    fn an_admin_is_recognised_by_key_whatever_its_comment() {
        let me = RecipientSpec::new("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMe me@laptop");
        let listed = vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMe".to_owned()];
        assert!(is_admin(&listed, &me));
        assert!(!is_admin(&["age1other".to_owned()], &me));
        assert!(!is_admin(&[], &me));
    }
}
