//! `rageveil info PATH` — audit an entry's trust history.
//!
//! Answers "what was given to whom, and what was revoked from whom".
//! Reads the **local index** (the same plaintext cache `list` /
//! `search` use — never decrypts the payload) for the entry's
//! [`Metadata`], plus the shared address book so recipient keys are
//! rendered as their registered names instead of raw `age1…`/`ssh-…`
//! blobs, and the operator's own `whoami` so their actions read as
//! `you`.
//!
//! Faithful to `passveil info` (created / updated / trusted /
//! insiders / chronological allow-deny log), minus its `issued`
//! GPG-signature verification — age 0.11 has no signature primitive,
//! so rageveil records no signing log (see [`crate::metadata`]).

use crate::addressbook::AddressBook;
use crate::config::Config;
use crate::dsl::Vault;
use crate::index::Index;
use crate::metadata::{LogEntry, Metadata};
use crate::store::StoreLayout;
use crate::sugar::read_json;
use crate::types::{EntryPath, RecipientSpec};
use crate::{commands::address, vault_do};

use std::collections::BTreeMap;
use std::path::PathBuf;

// ANSI palette, matching `sync`'s operator-facing trace.
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

#[derive(Clone, Debug)]
pub struct InfoArgs {
    pub root: PathBuf,
    pub path: EntryPath,
}

/// Render the audit as a list of lines (with ANSI colour, like
/// `sync`). The binary emits them through `stdout`.
pub fn info<S>(s: S, args: InfoArgs) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let index_path = layout.index_path();
    let path = args.path;
    let s2 = s.clone();

    vault_do! { s ;
        let exists = s.exists(index_path.clone()) ;
        match exists {
            false => s.fail(
                "no local index yet — run `rageveil sync` first".into(),
            ),
            true => gather(s2.clone(), layout, index_path, path),
        }
    }
}

fn gather<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    index_path: PathBuf,
    path: EntryPath,
) -> S::R<Vec<String>> {
    let ab_path = layout.addressbook_path();
    let cfg_path = layout.config_path();
    let s2 = s.clone();
    vault_do! { s ;
        let idx = read_json::<S, Index>(s.clone(), index_path) ;
        let book = address::load_or_empty(s.clone(), ab_path) ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        finish(s2.clone(), idx, book, cfg, path)
    }
}

fn finish<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    idx: Index,
    book: AddressBook,
    cfg: Config,
    path: EntryPath,
) -> S::R<Vec<String>> {
    match idx.entries.get(&path) {
        None => s.fail(format!(
            "no entry {path} in the local index (only entries you can decrypt show up; try `rageveil sync`)"
        )),
        Some(cached) => s.pure(render(&path, &cached.metadata, &book, &cfg.whoami)),
    }
}

// ─── pure rendering ───────────────────────────────────────────────────────

/// Map each address-book recipient to its name, keyed by *canonical*
/// key so a comment-bearing log subject still resolves.
fn name_index(book: &AddressBook) -> BTreeMap<String, String> {
    book.people
        .iter()
        .map(|(name, key)| (key.canonical_key(), name.clone()))
        .collect()
}

/// How a recipient is shown: `you`, an address-book name, or a
/// truncated key tagged with its fingerprint (so an unknown key can
/// still be matched against `address list` / the filenames on disk).
fn display(spec: &RecipientSpec, names: &BTreeMap<String, String>, you: &str) -> String {
    let ck = spec.canonical_key();
    let named = names.get(&ck);
    if ck == you {
        return match named {
            Some(n) => format!("you ({n})"),
            None => "you".to_string(),
        };
    }
    match named {
        Some(n) => n.clone(),
        None => {
            let prefix: String = ck.chars().take(24).collect();
            let ellipsis = if ck.chars().count() > 24 { "…" } else { "" };
            format!("{prefix}{ellipsis} {DIM}[{}]{RESET}", spec.fingerprint())
        }
    }
}

fn fmt_time(at: chrono::DateTime<chrono::Utc>) -> String {
    at.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn render(
    path: &EntryPath,
    m: &Metadata,
    book: &AddressBook,
    whoami: &RecipientSpec,
) -> Vec<String> {
    let names = name_index(book);
    let you = whoami.canonical_key();
    let disp = |r: &RecipientSpec| display(r, &names, &you);

    let mut out = Vec::new();
    out.push(format!("entry: {path}"));
    out.push(format!(
        "created  {CYAN}{}{RESET}  by {}",
        fmt_time(m.created.at),
        disp(&m.created.by)
    ));
    if let Some(u) = &m.updated {
        out.push(format!(
            "updated  {CYAN}{}{RESET}  by {}",
            fmt_time(u.at),
            disp(&u.by)
        ));
    }

    let trusted = m.trusted();
    out.push(String::new());
    out.push(format!("trusted now ({}):", trusted.len()));
    for r in &trusted {
        out.push(format!("  {GREEN}•{RESET} {}", disp(r)));
    }

    let insiders = m.insiders();
    out.push(String::new());
    out.push(format!("insiders ever ({}):", insiders.len()));
    for r in &insiders {
        // Mark insiders who are no longer trusted — revoked access,
        // but they have seen the secret. That's the audit's point.
        let revoked = !trusted.iter().any(|t| t.canonical_key() == r.canonical_key());
        let tag = if revoked {
            format!(" {RED}(revoked){RESET}")
        } else {
            String::new()
        };
        out.push(format!("  {}{tag}", disp(r)));
    }

    out.push(String::new());
    out.push("log:".to_string());
    for entry in &m.log {
        let (sym, color, subject, stamp) = match entry {
            LogEntry::Allow { subject, stamp } => ("+", GREEN, subject, stamp),
            LogEntry::Deny { subject, stamp } => ("-", RED, subject, stamp),
        };
        out.push(format!(
            "  {CYAN}{}{RESET}  {}  {color}{sym}{RESET} {}",
            fmt_time(stamp.at),
            disp(&stamp.by),
            disp(subject),
        ));
    }

    out
}
