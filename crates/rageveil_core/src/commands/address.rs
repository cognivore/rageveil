//! `rageveil address …` — manage the shared name → key book, plus
//! the recipient resolution that `allow` / `deny` run their
//! command-line arguments through.
//!
//! The book lives at `<store>/addressbook.json` (see
//! [`crate::addressbook`]) — inside the git working tree, so adding a
//! name commits, and a subsequent `sync` pushes it to every
//! collaborator. Once `pa` is registered you can write
//! `rageveil allow db/prod pa` instead of pasting the raw key.
//!
//! Three subcommands plus one library entry point:
//!   * [`address_add`]    — register/update `name → key`
//!   * [`address_remove`] — drop a name
//!   * [`address_list`]   — enumerate `(name, key)` pairs
//!   * [`resolve_recipients`] — used by `allow`/`deny` to turn CLI
//!     tokens (names *or* raw keys) into concrete [`RecipientSpec`]s.

use crate::addressbook::{AddressBook, looks_like_key};
use crate::dsl::Vault;
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::RecipientSpec;
use crate::{git, vault_do};

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct AddressAddArgs {
    pub root: PathBuf,
    pub name: String,
    /// The recipient key as typed on the command line (CLI tokens
    /// already joined with spaces, so an unquoted `ssh-ed25519 AAAA…`
    /// survives). `None` when reading from `key_file` instead.
    pub key: Option<String>,
    /// Read the public key from this file (e.g. `~/.ssh/id_ed25519.pub`)
    /// rather than the command line. Mutually exclusive with `key`.
    pub key_file: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct AddressRemoveArgs {
    pub root: PathBuf,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct AddressListArgs {
    pub root: PathBuf,
}

// ─── add ─────────────────────────────────────────────────────────────────

/// Register (or overwrite) a `name → key` mapping, then commit the
/// book. The new entry is pushed to the remote on the next `sync`.
pub fn address_add<S>(s: S, args: AddressAddArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let name = args.name.trim().to_owned();

    // Reject ambiguous / malformed names *before* touching disk: a
    // name that looks like a key would be indistinguishable from a
    // raw recipient at resolve time, and a whitespace-bearing name is
    // a paste accident.
    if let Err(msg) = validate_name(&name) {
        return s.fail(msg);
    }

    let key_source = resolve_key_source(s.clone(), args.key, args.key_file);
    write_entry(s, layout, name, key_source)
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("address-book name is empty".into());
    }
    if name.chars().any(char::is_whitespace) {
        return Err(format!(
            "invalid address-book name {name:?}: must be a single word with no whitespace"
        ));
    }
    if looks_like_key(name) {
        return Err(format!(
            "invalid address-book name {name:?}: looks like a raw key (age1…/ssh-…); \
             pick a plain handle such as `pa`"
        ));
    }
    Ok(())
}

/// Produce the key string as an effect: inline value, file contents,
/// or a `fail` for the ambiguous / empty cases.
fn resolve_key_source<S>(s: S, key: Option<String>, key_file: Option<PathBuf>) -> S::R<String>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    match (key, key_file) {
        (Some(k), None) => s.pure(k.trim().to_owned()),
        (None, Some(f)) => {
            let s2 = s.clone();
            vault_do! { s ;
                let bytes = s.read_file(f) ;
                first_key_line(s2.clone(), bytes)
            }
        }
        (Some(_), Some(_)) => s.fail("pass a key OR --file, not both".into()),
        (None, None) => {
            s.fail("no key given: pass a recipient (age1…/ssh-ed25519 …) or --file PATH".into())
        }
    }
}

/// First non-empty line of a (public-key) file. A `.pub` file is a
/// single `ssh-ed25519 AAAA… comment` line; an age recipients file is
/// one `age1…` per line — either way the first content line is what
/// we want.
fn first_key_line<S: Vault>(s: S, bytes: Vec<u8>) -> S::R<String> {
    match String::from_utf8(bytes) {
        Ok(text) => match text.lines().map(str::trim).find(|l| !l.is_empty()) {
            Some(line) => s.pure(line.to_owned()),
            None => s.fail("key file is empty".into()),
        },
        Err(_) => s.fail("key file is not valid UTF-8".into()),
    }
}

fn validate_key<S: Vault>(s: S, key: String) -> S::R<RecipientSpec> {
    let trimmed = key.trim().to_owned();
    if !looks_like_key(&trimmed) {
        return s.fail(format!(
            "{trimmed:?} doesn't look like an age (age1…) or OpenSSH \
             (ssh-ed25519/ssh-rsa …) public key"
        ));
    }
    s.pure(RecipientSpec::new(trimmed))
}

fn write_entry<S>(s: S, layout: StoreLayout, name: String, key_source: S::R<String>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let ab_path = layout.addressbook_path();
    let store_dir = layout.store_dir();
    let s2 = s.clone();
    vault_do! { s ;
        let key_str = key_source ;
        let key = validate_key(s2.clone(), key_str) ;
        let book = load_or_empty(s2.clone(), ab_path.clone()) ;
        let _ = insert_and_write(s2.clone(), ab_path.clone(), book, name.clone(), key) ;
        commit_book(s2.clone(), store_dir.clone(), format!("address add {name}"))
    }
}

fn insert_and_write<S>(
    s: S,
    ab_path: PathBuf,
    mut book: AddressBook,
    name: String,
    key: RecipientSpec,
) -> S::R<()>
where
    S: Vault + Clone + Send + 'static,
{
    book.people.insert(name, key);
    write_json(s, ab_path, book)
}

// ─── remove ──────────────────────────────────────────────────────────────

/// Remove a name from the book and commit. Fails loudly if the name
/// isn't present (rather than silently committing a no-op).
pub fn address_remove<S>(s: S, args: AddressRemoveArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let ab_path = layout.addressbook_path();
    let store_dir = layout.store_dir();
    let name = args.name.trim().to_owned();
    let s2 = s.clone();
    vault_do! { s ;
        let exists = s.exists(ab_path.clone()) ;
        match exists {
            false => s.fail("address book is empty (nothing to remove)".into()),
            true => remove_entry(s2.clone(), ab_path, store_dir, name),
        }
    }
}

fn remove_entry<S>(s: S, ab_path: PathBuf, store_dir: PathBuf, name: String) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    vault_do! { s ;
        let book = read_json::<S, AddressBook>(s2.clone(), ab_path.clone()) ;
        finish_remove(s2.clone(), ab_path, store_dir, book, name)
    }
}

fn finish_remove<S>(
    s: S,
    ab_path: PathBuf,
    store_dir: PathBuf,
    mut book: AddressBook,
    name: String,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    match book.people.remove(&name) {
        None => s.fail(format!("no address-book entry named {name:?}")),
        Some(_) => {
            let s2 = s.clone();
            vault_do! { s ;
                let _ = write_json(s2.clone(), ab_path, book) ;
                commit_book(s2.clone(), store_dir, format!("address remove {name}"))
            }
        }
    }
}

// ─── list ────────────────────────────────────────────────────────────────

/// Every `(name, key)` pair, sorted by name (the `BTreeMap` ordering).
pub fn address_list<S>(s: S, args: AddressListArgs) -> S::R<Vec<(String, RecipientSpec)>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let ab_path = layout.addressbook_path();
    let s2 = s.clone();
    vault_do! { s ;
        let book = load_or_empty(s2.clone(), ab_path) ;
        s2.pure(book.people.into_iter().collect())
    }
}

// ─── resolution (used by allow / deny) ──────────────────────────────────

/// Resolve a list of `allow`/`deny` command-line tokens to concrete
/// recipients. A token that already looks like a key (`age1…`,
/// `ssh-…`) is taken verbatim; anything else is looked up in the
/// shared address book. Unknown names fail loudly with a hint, so a
/// typo never silently drops a recipient.
pub fn resolve_recipients<S>(
    s: S,
    ab_path: PathBuf,
    tokens: Vec<String>,
) -> S::R<Vec<RecipientSpec>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    vault_do! { s ;
        let book = load_or_empty(s2.clone(), ab_path) ;
        resolve_with(s2.clone(), book, tokens)
    }
}

fn resolve_with<S: Vault>(
    s: S,
    book: AddressBook,
    tokens: Vec<String>,
) -> S::R<Vec<RecipientSpec>> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut unknown = Vec::new();
    for token in tokens {
        let t = token.trim();
        if looks_like_key(t) {
            out.push(RecipientSpec::new(t));
        } else if let Some(r) = book.get(t) {
            out.push(r.clone());
        } else {
            unknown.push(t.to_owned());
        }
    }
    if !unknown.is_empty() {
        return s.fail(format!(
            "unknown recipient(s): {}. Pass a raw key (age1…/ssh-…) or register a name \
             first with `rageveil address add <name> <key>`",
            unknown.join(", ")
        ));
    }
    s.pure(out)
}

// ─── shared helpers ──────────────────────────────────────────────────────

/// Load the book if present, else an empty one. Mirrors the
/// `read_index_or_empty` idiom used across the commands.
pub fn load_or_empty<S>(s: S, ab_path: PathBuf) -> S::R<AddressBook>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    vault_do! { s ;
        let exists = s.exists(ab_path.clone()) ;
        match exists {
            true => read_json::<S, AddressBook>(s2.clone(), ab_path),
            false => s2.pure(AddressBook::empty()),
        }
    }
}

fn commit_book<S>(s: S, store_dir: PathBuf, msg: String) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    vault_do! { s ;
        let out_add = git::add_all(&s, store_dir.clone()) ;
        match out_add.success() {
            false => s.fail(format!("git add failed: {}", out_add.stderr_str())),
            true => do_commit(s2.clone(), store_dir, msg),
        }
    }
}

fn do_commit<S>(s: S, store_dir: PathBuf, msg: String) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    vault_do! { s ;
        let out = git::commit(&s, store_dir, msg) ;
        match out.success() {
            true => s.pure(()),
            false if out.stderr_str().contains("nothing to commit") => s.pure(()),
            false => s.fail(format!("git commit failed: {}", out.stderr_str())),
        }
    }
}
