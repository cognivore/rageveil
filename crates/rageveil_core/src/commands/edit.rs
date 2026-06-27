//! `rageveil edit PATH` — change an entry's secret value while
//! preserving its trust history.
//!
//! The crucial difference from `insert`: re-running `insert` on an
//! existing path rebuilds the entry from scratch — `Metadata::new`,
//! re-keyed to the operator alone — which *resets* the allow/deny
//! log and the "insiders ever" audit set, and silently drops every
//! other recipient. `edit` instead decrypts the existing entry,
//! swaps in the new payload (with a fresh salt, so the ciphertext
//! genuinely rotates), keeps the metadata log **verbatim**, stamps
//! `updated`, and re-encrypts one copy per *currently trusted*
//! recipient — exactly the set [`super::allow`] / [`super::deny`]
//! maintain. Nobody gains or loses access; only the value changes.
//!
//! Backwards compatible by construction: the on-disk shape is
//! byte-for-byte what `insert`/`allow` already write (`Content`
//! JSON → per-recipient `.age`, plus the `index.json` cache). No
//! new metadata variant, no schema change — an older rageveil reads
//! an edited entry without noticing the verb ever existed.

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::index::{Cached, Index};
use crate::metadata::{Metadata, Stamp};
use crate::store::StoreLayout;
use crate::sugar::{first_existing, read_json, write_json};
use crate::types::{EntryHash, EntryPath, RecipientSpec, Salt};
use crate::{git, vault_do};

use chrono::{DateTime, Utc};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct EditArgs {
    pub root: PathBuf,
    pub path: EntryPath,
    /// The new secret, supplied directly (`--payload`) or read from
    /// stdin when `payload_from_stdin` is set. The interactive
    /// editor form resolves to `payload` at the binding layer (the
    /// editor is seeded with the *current* secret there, since it
    /// needs a TTY the DSL deliberately doesn't surface).
    pub payload: Option<String>,
    pub payload_from_stdin: bool,
}

pub fn edit<S>(s: S, args: EditArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let cfg_path = layout.config_path();
    let path = args.path.clone();
    let payload_supplied = args.payload.clone();
    let payload_from_stdin = args.payload_from_stdin;

    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let content = decrypt_self(s.clone(), layout.clone(), cfg.clone(), path.clone()) ;
        let payload = resolve_payload(s.clone(), payload_supplied, payload_from_stdin) ;
        let salt_bytes = s.random_bytes(32) ;
        let now = s.now() ;
        let _ = apply_edit(
            s.clone(),
            layout.clone(),
            with_new_value(content, payload, Salt::from_bytes(&salt_bytes), cfg.whoami.clone(), now),
            now,
        ) ;
        let out_add = git::add_all(&s, layout.store_dir()) ;
        match out_add.success() {
            true => commit_edit(s.clone(), layout.store_dir(), path),
            false => s.fail(format!("git add failed: {}", out_add.stderr_str())),
        }
    }
}

/// Decrypt the operator's own copy of the entry. Identical to the
/// helper in [`super::allow`] / [`super::deny`] — canonical name
/// first, legacy (pre-canonical-key-fix) name as a fallback so a
/// store written by an older rageveil still opens.
fn decrypt_self<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    path: EntryPath,
) -> S::R<Content> {
    let identity_path = cfg.identity_path.clone();
    let hash = path.hash();
    let candidates = layout.entry_file_candidates(&hash, &cfg.whoami);
    let where_msg = candidates
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" or ");
    let path_for_msg = path.clone();
    let whoami_for_msg = cfg.whoami.clone();
    let s2 = s.clone();
    vault_do! { s ;
        let found = first_existing(s.clone(), candidates) ;
        let file = match found {
            Some(f) => s2.pure(f),
            None => s2.fail(format!(
                "no entry for {} as {} (looked at {})",
                path_for_msg, whoami_for_msg, where_msg
            )),
        } ;
        let cipher = s.read_file(file) ;
        let plain = s.decrypt(cipher, vec![identity_path]) ;
        s.decode_json::<Content>(plain)
    }
}

/// Resolve the new payload from `--payload` or stdin (`--batch`).
/// Same shape as `insert`'s resolver — the editor form has already
/// collapsed to `Some(..)` by the time we run.
fn resolve_payload<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    supplied: Option<String>,
    from_stdin: bool,
) -> S::R<String> {
    match (supplied, from_stdin) {
        (Some(p), _) => s.pure(p),
        (None, true) => {
            vault_do! { s ;
                let bytes = s.read_stdin() ;
                match String::from_utf8(bytes) {
                    Ok(s2) => s.pure(s2.trim_end_matches('\n').to_owned()),
                    Err(e) => s.fail(format!("stdin not utf-8: {e}")),
                }
            }
        }
        (None, false) => s.fail(
            "no new value supplied; pass --payload or --batch (and pipe one in), \
             or omit both to edit in $EDITOR"
                .into(),
        ),
    }
}

/// Build the post-edit [`Content`]: keep the path and the entire
/// metadata log, stamp `updated`, and swap in the fresh salt and the
/// new payload. Pure — the whole point of `edit` vs `insert` is that
/// the trust *model* is carried through untouched; only the value
/// (and the salt that freshens its ciphertext) changes.
fn with_new_value(
    mut content: Content,
    payload: String,
    salt: Salt,
    whoami: RecipientSpec,
    now: DateTime<Utc>,
) -> Content {
    content.metadata.updated = Some(Stamp { at: now, by: whoami });
    content.salt = salt;
    content.payload = payload;
    content
}

/// Write the edited entry: one fresh ciphertext per *currently
/// trusted* recipient (membership is unchanged, so this overwrites
/// each existing per-recipient file in place), then refresh the
/// index cache. `now` stamps the index's `seen`.
fn apply_edit<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    content: Content,
    now: DateTime<Utc>,
) -> S::R<()> {
    let metadata = content.metadata.clone();
    let trusted = content.metadata.trusted();
    let path = content.path.clone();
    let hash = path.hash();
    let entry_dir = layout.entry_dir(&hash);
    let s2 = s.clone();
    let layout2 = layout.clone();
    let path2 = path.clone();
    vault_do! { s ;
        let plaintext = s.encode_json(content) ;
        // mkdir once: the per-recipient writes all land in the same
        // entry-dir, no need to repeat the syscall in the loop.
        let _ = s.mkdir_p(entry_dir) ;
        let _ = write_per_recipient(s2.clone(), layout2.clone(), hash.clone(), plaintext, trusted) ;
        let _ = update_index(s2.clone(), layout2.clone(), path2, hash, metadata, now) ;
        log_edited(s2.clone(), path)
    }
}

/// Re-encrypt the new plaintext, one fresh `.age` per trusted
/// recipient, overwriting the existing per-recipient file in place.
/// Identical to the helper in [`super::allow`].
fn write_per_recipient<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    hash: EntryHash,
    plaintext: Vec<u8>,
    trusted: Vec<RecipientSpec>,
) -> S::R<()> {
    fn go<S: Vault + Clone + Send + Sync + 'static>(
        s: S,
        layout: StoreLayout,
        hash: EntryHash,
        plaintext: Vec<u8>,
        rest: Vec<RecipientSpec>,
    ) -> S::R<()> {
        let mut iter = rest.into_iter();
        match iter.next() {
            None => s.pure(()),
            Some(r) => {
                let s2 = s.clone();
                let layout2 = layout.clone();
                let hash2 = hash.clone();
                let plaintext2 = plaintext.clone();
                let entry_file = layout.entry_file(&hash, &r.fingerprint());
                let remaining: Vec<RecipientSpec> = iter.collect();
                vault_do! { s ;
                    let cipher = s.encrypt(plaintext2, vec![r]) ;
                    let _ = s.write_file(entry_file, cipher) ;
                    go(s2, layout2, hash2, plaintext, remaining)
                }
            }
        }
    }
    let s2 = s.clone();
    go(s2, layout, hash, plaintext, trusted)
}

fn update_index<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    path: EntryPath,
    hash: EntryHash,
    metadata: Metadata,
    now: DateTime<Utc>,
) -> S::R<()> {
    let s2 = s.clone();
    let index_path = layout.index_path();
    vault_do! { s ;
        let mut idx = read_index_or_empty(s2.clone(), index_path.clone()) ;
        {
            idx.entries.insert(path.clone(), Cached { hash, metadata, seen: now });
            write_json(s2.clone(), index_path, idx)
        }
    }
}

fn read_index_or_empty<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    path: PathBuf,
) -> S::R<Index> {
    let s2 = s.clone();
    vault_do! { s ;
        let exists = s.exists(path.clone()) ;
        match exists {
            true  => read_json::<S, Index>(s2.clone(), path),
            false => s.pure(Index::empty()),
        }
    }
}

fn log_edited<S: Vault + Clone + Send + Sync + 'static>(s: S, path: EntryPath) -> S::R<()> {
    s.log(format!("edited {}", path))
}

fn commit_edit<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    path: EntryPath,
) -> S::R<()> {
    vault_do! { s ;
        let out = git::commit(&s, store_dir, format!("edit {}", path)) ;
        match out.success() {
            true => s.pure(()),
            // A fresh salt means an edit is never bytewise identical
            // to what was on disk, so "nothing to commit" shouldn't
            // arise — but swallow it for parity with insert/allow if
            // a future change makes edits idempotent.
            false if out.stderr_str().contains("nothing to commit") => s.pure(()),
            false => s.fail(format!("git commit failed: {}", out.stderr_str())),
        }
    }
}
