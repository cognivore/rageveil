//! `rageveil sync` — pull from + push to the configured remote,
//! then rebuild the local index by walking the store and decrypting
//! whatever the operator can decrypt.
//!
//! `--offline` skips the network steps (still rebuilds the index).
//! Idempotent: running `sync` twice in a row is a no-op the second
//! time.

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::index::{Cached, Index};
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::{EntryHash, EntryPath, RecipientFingerprint};
use crate::{git, vault_do};

use chrono::{DateTime, Utc};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct SyncArgs {
    pub root: PathBuf,
    pub offline: bool,
}

pub fn sync<S>(s: S, args: SyncArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let cfg_path = layout.config_path();
    let offline = args.offline;
    let store_dir = layout.store_dir();

    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let _ = network_round_trip(s.clone(), store_dir.clone(), offline) ;
        let now = s.now() ;
        rebuild_index(s.clone(), layout.clone(), cfg, now)
    }
}

fn network_round_trip<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    offline: bool,
) -> S::R<()> {
    if offline {
        return s.pure(());
    }
    let store_dir2 = store_dir.clone();
    vault_do! { s ;
        let remote = git::has_remote(&s, store_dir.clone()) ;
        // Empty remote list → no upstream configured → skip
        // network without complaint. This is the "init without
        // a remote" path.
        match remote.success() && !remote.stdout_str().trim().is_empty() {
            false => s.pure(()),
            true  => do_pull_then_push(s.clone(), store_dir2),
        }
    }
}

fn do_pull_then_push<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
) -> S::R<()> {
    let cwd_pull = store_dir.clone();
    let cwd_push = store_dir;
    vault_do! { s ;
        let pull = git::pull(&s, cwd_pull) ;
        let _ = match pull.success() {
            true => s.pure(()),
            false => s.fail(format!(
                "git pull failed: {}",
                pull.stderr_str()
            )),
        } ;
        let push = git::push(&s, cwd_push) ;
        match push.success() {
            true => s.pure(()),
            // A brand-new branch has no upstream; let the user
            // run `git push -u origin main` themselves rather
            // than guessing the remote name.
            false if push.stderr_str().contains("upstream") => {
                s.log("sync: push skipped (no upstream); set with `git push -u`".into())
            }
            false => s.fail(format!(
                "git push failed: {}",
                push.stderr_str()
            )),
        }
    }
}

fn rebuild_index<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    now: DateTime<Utc>,
) -> S::R<()> {
    let s2 = s.clone();
    let layout2 = layout.clone();
    // Whoami's fingerprint is invariant across the walk — compute
    // once here rather than re-fingerprinting per candidate.
    let whoami_fp = cfg.whoami.fingerprint();
    vault_do! { s ;
        let store_entries = s.list_dir(layout.store_dir()) ;
        let idx = walk_entries(s2.clone(), layout2.clone(), cfg.clone(), whoami_fp, store_entries, now) ;
        write_json(s2.clone(), layout2.index_path(), idx)
    }
}

/// Walk every `<store>/<entry-hash>/<whoami-fp>.age` we can
/// decrypt, collecting `Cached` records into an [`Index`].
/// Entries we can't decrypt (newly shared but not to us yet, or
/// that are foreign noise) are silently skipped.
fn walk_entries<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    whoami_fp: RecipientFingerprint,
    candidates: Vec<PathBuf>,
    now: DateTime<Utc>,
) -> S::R<Index> {
    fn go<S: Vault + Clone + Send + Sync + 'static>(
        s: S,
        layout: StoreLayout,
        cfg: Config,
        whoami_fp: RecipientFingerprint,
        rest: Vec<PathBuf>,
        idx: Index,
        now: DateTime<Utc>,
    ) -> S::R<Index> {
        let mut iter = rest.into_iter();
        match iter.next() {
            None => s.pure(idx),
            Some(p) => {
                let s2 = s.clone();
                let layout2 = layout.clone();
                let cfg2 = cfg.clone();
                let whoami_fp2 = whoami_fp.clone();
                let remaining: Vec<PathBuf> = iter.collect();
                vault_do! { s ;
                    let next_idx = absorb_one(s2.clone(), layout2.clone(), cfg2.clone(), whoami_fp2.clone(), p, idx, now) ;
                    go(s2, layout2, cfg2, whoami_fp2, remaining, next_idx, now)
                }
            }
        }
    }
    go(s.clone(), layout, cfg, whoami_fp, candidates, Index::empty(), now)
}

fn absorb_one<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    whoami_fp: RecipientFingerprint,
    candidate: PathBuf,
    idx: Index,
    now: DateTime<Utc>,
) -> S::R<Index> {
    // Skip non-directories (notably `.gitkeep`) and the `.git`
    // directory itself.
    let name = candidate
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_owned();
    if name.is_empty() || name == ".git" || name == ".gitkeep" {
        return s.pure(idx);
    }

    let hash_candidate = EntryHash(name);
    let entry_file = layout.entry_file(&hash_candidate, &whoami_fp);

    vault_do! { s ;
        let exists = s.exists(entry_file.clone()) ;
        match exists {
            false => s.pure(idx),
            true  => decrypt_and_record(s.clone(), cfg.clone(), entry_file, hash_candidate, idx, now),
        }
    }
}

fn decrypt_and_record<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    cfg: Config,
    entry_file: PathBuf,
    hash: EntryHash,
    idx: Index,
    now: DateTime<Utc>,
) -> S::R<Index> {
    let s2 = s.clone();
    vault_do! { s ;
        let cipher = s.read_file(entry_file) ;
        let plain = s.decrypt(cipher, vec![cfg.identity_path.clone()]) ;
        // `handle` lifts any upstream `fail` (corrupt entry, decode
        // error) into the value channel so a single bad file
        // doesn't sink the whole rebuild — log and skip.
        let decoded = s.handle(s.decode_json::<Content>(plain)) ;
        match decoded {
            Ok(content) => {
                let mut idx2 = idx;
                let path: EntryPath = content.path.clone();
                idx2.entries.insert(
                    path,
                    Cached { hash, metadata: content.metadata, seen: now },
                );
                s2.pure(idx2)
            }
            Err(e) => {
                let s3 = s2.clone();
                vault_do! { s2 ;
                    let _ = s2.log(format!("sync: skipping entry: {e}")) ;
                    s3.pure(idx)
                }
            }
        }
    }
}
