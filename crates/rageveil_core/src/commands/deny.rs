//! `rageveil deny PATH RECIPIENT...` — revoke share, mirror of
//! [`super::allow`].
//!
//! Decrypts with the operator's identity, appends `Deny` log
//! entries for each recipient, then **deletes** the per-recipient
//! file for anyone no longer in the trusted set and **rewrites**
//! the per-recipient files for everyone still trusted (so the
//! ciphertexts are bit-fresh, which matters for git history
//! observability — the alternative is signalling "denied" by
//! deletion only and trusting older cipher copies, which is fine
//! cryptographically but messy in audit trails).

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::index::{Cached, Index};
use crate::metadata::{LogEntry, Metadata, Stamp};
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::{CommitOutcome, EntryHash, EntryPath, RecipientSpec};
use crate::{git, vault_do};

use chrono::{DateTime, Utc};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct DenyArgs {
    pub root: PathBuf,
    pub path: EntryPath,
    pub recipients: Vec<RecipientSpec>,
}

pub fn deny<S>(s: S, args: DenyArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let cfg_path = layout.config_path();
    let path = args.path.clone();
    let denied = args.recipients.clone();

    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let now = s.now() ;
        let removed = deny_entry(s.clone(), layout.clone(), cfg, path.clone(), denied, now, None) ;
        let _ = log_removed(s.clone(), removed) ;
        let _ = git::add_all(&s, layout.store_dir()) ;
        commit_deny(s.clone(), layout.store_dir(), path)
    }
}

/// Take `denied` off one entry without committing: decrypt as the
/// operator, append a `Deny` per recipient that is trusted now, then
/// delete their copies and re-encrypt for everyone left. Returns the
/// subjects actually denied (as the entry's log spells them).
///
/// Shared by `deny` (one entry, one commit) and `revoke` (every
/// entry, one commit). Recipients are matched by canonical key, so
/// an SSH comment that differs between the address book and the
/// entry's log does not turn a revocation into a silent no-op.
///
/// Refuses, before writing anything, to leave the entry with no
/// recipient at all, and — when `keep` is given — to leave it
/// without `keep` (the operator, for `revoke`).
pub(crate) fn deny_entry<S>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    path: EntryPath,
    denied: Vec<RecipientSpec>,
    now: DateTime<Utc>,
    keep: Option<RecipientSpec>,
) -> S::R<Vec<RecipientSpec>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let s2 = s.clone();
    vault_do! { s ;
        let content = decrypt_self(s.clone(), layout.clone(), cfg.clone(), path.clone()) ;
        revoke(s2.clone(), layout.clone(), cfg.clone(), path.clone(), content, denied.clone(), now, keep.clone())
    }
}

/// The operator's copy: the plain key's, or the Touch ID key's for a human-only entry.
use crate::own::decrypt_own as decrypt_self;

#[allow(clippy::too_many_arguments)]
fn revoke<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    path: EntryPath,
    content: Content,
    denied: Vec<RecipientSpec>,
    now: DateTime<Utc>,
    keep: Option<RecipientSpec>,
) -> S::R<Vec<RecipientSpec>> {
    let trusted_now = content.metadata.trusted();
    let trusted_before: std::collections::BTreeSet<String> =
        trusted_now.iter().map(|r| r.0.clone()).collect();

    let mut metadata = content.metadata.clone();
    let mut removed: Vec<RecipientSpec> = Vec::new();
    for r in denied {
        // The log's own spelling of this key, so the replay in
        // `trusted()` sees the Deny cancel the Allow it answers.
        let ck = r.canonical_key();
        let Some(subject) = trusted_now.iter().find(|t| t.canonical_key() == ck) else {
            continue;
        };
        if removed.contains(subject) {
            continue;
        }
        removed.push(subject.clone());
        metadata.log.push(LogEntry::Deny {
            subject: subject.clone(),
            stamp: Stamp { at: now, by: cfg.whoami.clone() },
        });
    }
    metadata.updated = Some(Stamp { at: now, by: cfg.whoami.clone() });

    let trusted_after = metadata.trusted();
    if trusted_after.is_empty() {
        return s.fail(format!(
            "refusing to deny {path}: nobody would be left able to decrypt it \
             (use `rageveil delete {path}` to drop the entry)"
        ));
    }
    if let Some(k) = keep
        && !trusted_after.iter().any(|t| t.canonical_key() == k.canonical_key())
    {
        return s.fail(format!(
            "refusing to rewrite {path}: {} would lose access to it",
            k.as_str()
        ));
    }
    let trusted_after_set: std::collections::BTreeSet<String> =
        trusted_after.iter().map(|r| r.0.clone()).collect();

    let updated_content = Content {
        path: path.clone(),
        salt: content.salt,
        payload: content.payload,
        metadata: metadata.clone(),
    };

    let to_remove: Vec<RecipientSpec> = trusted_before
        .iter()
        .filter(|r| !trusted_after_set.contains(*r))
        .map(|spec| RecipientSpec(spec.clone()))
        .collect();

    let hash = path.hash();
    let entry_dir = layout.entry_dir(&hash);
    let s2 = s.clone();
    let layout2 = layout.clone();
    let path2 = path.clone();
    let metadata_for_index = metadata.clone();
    vault_do! { s ;
        let plaintext = s.encode_json(updated_content) ;
        // mkdir once for the entry-dir; the per-recipient writes
        // below all land here.
        let _ = s.mkdir_p(entry_dir) ;
        let _ = remove_per_recipient(s2.clone(), layout2.clone(), hash.clone(), to_remove) ;
        let _ = crate::tier::write_entry(s2.clone(), layout2.clone(), hash.clone(), plaintext, metadata_for_index.clone()) ;
        let _ = update_index(s2.clone(), layout2, path2, hash, metadata_for_index, now) ;
        s2.pure(removed)
    }
}

fn remove_per_recipient<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    hash: EntryHash,
    revoked: Vec<RecipientSpec>,
) -> S::R<()> {
    fn go<S: Vault + Clone + Send + Sync + 'static>(
        s: S,
        layout: StoreLayout,
        hash: EntryHash,
        rest: Vec<RecipientSpec>,
    ) -> S::R<()> {
        let mut iter = rest.into_iter();
        match iter.next() {
            None => s.pure(()),
            Some(r) => {
                let s2 = s.clone();
                let layout2 = layout.clone();
                let hash2 = hash.clone();
                // Delete BOTH the canonical and the legacy name —
                // revocation must remove a pre-fix copy too, or the
                // denied recipient could still decrypt it.
                let to_delete = layout.entry_file_candidates(&hash, &r);
                let remaining: Vec<RecipientSpec> = iter.collect();
                vault_do! { s ;
                    let _ = remove_each(s.clone(), to_delete) ;
                    go(s2, layout2, hash2, remaining)
                }
            }
        }
    }
    let s2 = s.clone();
    go(s2, layout, hash, revoked)
}

/// Remove every path in `paths`, ignoring absent ones (`remove_file`
/// is idempotent on `NotFound`).
fn remove_each<S: Vault + Clone + Send + 'static>(s: S, paths: Vec<PathBuf>) -> S::R<()> {
    fn go<S: Vault + Clone + Send + 'static>(
        s: S,
        mut iter: std::vec::IntoIter<PathBuf>,
    ) -> S::R<()> {
        match iter.next() {
            None => s.pure(()),
            Some(p) => {
                let s2 = s.clone();
                vault_do! { s ;
                    let _ = s.remove_file(p) ;
                    go(s2, iter)
                }
            }
        }
    }
    let s2 = s.clone();
    go(s2, paths.into_iter())
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

pub(crate) fn read_index_or_empty<S: Vault + Clone + Send + Sync + 'static>(
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

fn log_removed<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    removed: Vec<RecipientSpec>,
) -> S::R<()> {
    if removed.is_empty() {
        return s.log("deny: nothing to do (no listed recipients are trusted)".into());
    }
    let names: Vec<String> = removed.iter().map(|r| r.0.clone()).collect();
    s.log(format!("denied: {}", names.join(", ")))
}

fn commit_deny<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    path: EntryPath,
) -> S::R<()> {
    vault_do! { s ;
        let out = git::commit(&s, store_dir, format!("deny {}", path)) ;
        match out {
            CommitOutcome::Committed | CommitOutcome::NothingToCommit => s.pure(()),
        }
    }
}
