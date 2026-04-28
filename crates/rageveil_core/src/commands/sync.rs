//! `rageveil sync` — synchronise with the configured remote and
//! refresh the local index.
//!
//! Faithful port of `passveil sync` (modulo darcs → git):
//!
//!   1. (unless `--offline`) `git fetch origin`, narrate the
//!      ahead/behind counts.
//!   2. Pull: prefer fast-forward (`git merge --ff-only @{u}`); if
//!      the local branch has its own commits, fall back to
//!      `git pull --rebase` so we never produce a merge commit.
//!      Merge commits over .age files are unsafe — age ciphertexts
//!      aren't bytewise mergeable, so any auto-merge produces a
//!      file that decrypts to garbage. Rebasing keeps history
//!      linear and surfaces conflicts loudly.
//!   3. Scan every `.age` file in the working tree for git
//!      conflict markers; flag any hit as **CORRUPT** (a real
//!      problem the user must resolve manually before the entry
//!      decrypts again).
//!   4. Push: `git push`. Skip on missing upstream.
//!   5. Refresh the index: walk the store, decrypt every
//!      `<hash>/<whoami-fp>.age` we can decrypt, build a new
//!      index, diff against the old one, print colored mod lines.
//!   6. `--reindex` empties the in-memory old index before the
//!      diff so the entire store gets reported as `Inserted` —
//!      mirrors `passveil sync --reindex`.

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::index::{self, Cached, Index, IndexMod};
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
    /// Drop the local index before the refresh so every entry the
    /// operator can decrypt is reported as a fresh insert. Useful
    /// after manually fiddling with the store directory.
    pub reindex: bool,
}

pub fn sync<S>(s: S, args: SyncArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let cfg_path = layout.config_path();
    let SyncArgs { offline, reindex, .. } = args;
    let store_dir = layout.store_dir();

    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let _ = network_round_trip(s.clone(), store_dir.clone(), offline) ;
        let _ = scan_for_age_conflicts(s.clone(), store_dir) ;
        let now = s.now() ;
        rebuild_index_with_diff(s.clone(), layout.clone(), cfg, now, reindex)
    }
}

// ─── Step 1+2: network round-trip with narration ─────────────────────────

fn network_round_trip<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    offline: bool,
) -> S::R<()> {
    if offline {
        return s.log("sync: --offline, skipping network".into());
    }
    let s2 = s.clone();
    let dir = store_dir.clone();
    vault_do! { s ;
        let remote = git::has_remote(&s, store_dir.clone()) ;
        match remote.success() && !remote.stdout_str().trim().is_empty() {
            false => s.log("sync: no upstream configured, skipping network".into()),
            true  => network_with_remote(s2.clone(), dir),
        }
    }
}

fn network_with_remote<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
) -> S::R<()> {
    let s2 = s.clone();
    let dir2 = store_dir.clone();
    vault_do! { s ;
        let _ = s.log("sync: fetching from origin…".into()) ;
        let fetch = git::fetch(&s, store_dir.clone()) ;
        let _ = match fetch.success() {
            true => s.pure(()),
            false => s.fail(format!(
                "git fetch failed: {}",
                fetch.stderr_str().trim()
            )),
        } ;
        // After fetch, narrate ahead/behind so the operator sees
        // exactly what's about to happen — same diagnostic darcs
        // gives during `darcs pull`.
        let counts = git::ahead_behind(&s, store_dir.clone()) ;
        let _ = log_ahead_behind(s.clone(), counts) ;
        let _ = pull_strategy(s.clone(), store_dir) ;
        push_or_warn(s2.clone(), dir2)
    }
}

fn log_ahead_behind<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    counts: crate::types::ProcessOut,
) -> S::R<()> {
    if !counts.success() {
        return s.log(format!(
            "sync: couldn't compute ahead/behind ({}), continuing optimistically",
            counts.stderr_str().trim()
        ));
    }
    // `git rev-list --count --left-right HEAD...@{u}` prints "A\tB"
    // where A is local-ahead and B is local-behind upstream.
    let line = counts.stdout_str().trim();
    let (ahead, behind) = parse_ahead_behind(line);
    s.log(format!("sync: local is {ahead} ahead, {behind} behind origin"))
}

fn parse_ahead_behind(line: &str) -> (u64, u64) {
    let mut parts = line.split_whitespace();
    let a = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let b = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (a, b)
}

/// Try fast-forward first; fall back to rebase. Never produce a
/// merge commit — auto-merging .age files is the silent-corruption
/// failure mode this whole flow is designed around.
fn pull_strategy<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
) -> S::R<()> {
    let dir_for_rebase = store_dir.clone();
    vault_do! { s ;
        let _ = s.log("sync: attempting fast-forward (git merge --ff-only)…".into()) ;
        let ff = git::merge_ff_only(&s, store_dir) ;
        match ff.success() {
            true => s.log("sync: fast-forwarded cleanly".into()),
            false => {
                // ff failed — either nothing to pull (already up-to-date)
                // or local has diverging commits. Distinguish by the
                // stderr message and react accordingly.
                let stderr = ff.stderr_str().to_string();
                if stderr.contains("Already up to date")
                    || stderr.contains("Already up-to-date")
                    || stderr.is_empty()
                {
                    s.log("sync: nothing to pull (already up-to-date)".into())
                } else if stderr.contains("Not possible to fast-forward")
                    || stderr.contains("not a fast-forward")
                    || stderr.contains("not possible to fast-forward")
                    || stderr.contains("non-fast-forward")
                {
                    rebase_fallback(s.clone(), dir_for_rebase, stderr)
                } else {
                    // Some other ff failure (no upstream ref, etc.) — surface it.
                    s.fail(format!("git merge --ff-only failed: {}", stderr.trim()))
                }
            }
        }
    }
}

fn rebase_fallback<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    ff_stderr: String,
) -> S::R<()> {
    vault_do! { s ;
        let _ = s.log(format!(
            "sync: ff refused ({}), falling back to git pull --rebase",
            ff_stderr.trim()
        )) ;
        let rebase = git::pull(&s, store_dir.clone()) ;
        match rebase.success() {
            true => s.log("sync: rebased local commits onto origin cleanly".into()),
            false => {
                // Rebase conflict — leave the working tree as-is so the
                // user can `git rebase --continue` / `--abort` themselves.
                // Surface the conflict loudly.
                s.fail(format!(
                    "git pull --rebase failed: {}\n\n  → resolve manually with `git -C {} rebase --continue` (or `--abort`); \n  → no rageveil state was modified.",
                    rebase.stderr_str().trim(),
                    store_dir.display(),
                ))
            }
        }
    }
}

fn push_or_warn<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
) -> S::R<()> {
    vault_do! { s ;
        let _ = s.log("sync: pushing to origin…".into()) ;
        let push = git::push(&s, store_dir) ;
        match push.success() {
            true => s.log("sync: push complete".into()),
            // Brand-new branch with no upstream — same edge case
            // passveil's "set-default" sidesteps. Don't fail; let
            // the operator wire it up.
            false if push.stderr_str().contains("upstream") =>
                s.log(format!(
                    "sync: push skipped (no upstream tracking); set with `git -C {} push -u origin main`",
                    "<store-dir>",
                )),
            false => s.fail(format!(
                "git push failed: {}",
                push.stderr_str().trim()
            )),
        }
    }
}

// ─── Step 3: post-pull integrity scan ────────────────────────────────────

/// Walk the store dir, look at every `<hash>/<fp>.age` file, and
/// flag any that contains git conflict markers (`<<<<<<<`,
/// `=======`, `>>>>>>>`) — meaning git tried to auto-merge an
/// encrypted blob, which produces silent corruption.
///
/// Detection here is post-mortem: rebase normally aborts on
/// conflicts before reaching this point, but `merge --ff-only`
/// can succeed *and* leave a file with conflict markers if the
/// user previously resolved a conflict by hand and committed the
/// markers (e.g. via `git mergetool` gone wrong). Cheap to scan;
/// catches the catastrophic case the user explicitly asked about.
fn scan_for_age_conflicts<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
) -> S::R<()> {
    let s2 = s.clone();
    vault_do! { s ;
        let entries = s.list_dir(store_dir.clone()) ;
        scan_each(s2.clone(), entries)
    }
}

fn scan_each<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    entries: Vec<PathBuf>,
) -> S::R<()> {
    fn go<S: Vault + Clone + Send + Sync + 'static>(
        s: S,
        rest: Vec<PathBuf>,
    ) -> S::R<()> {
        let mut iter = rest.into_iter();
        match iter.next() {
            None => s.pure(()),
            Some(p) => {
                let s2 = s.clone();
                let remaining: Vec<PathBuf> = iter.collect();
                let p_for_scan = p.clone();
                vault_do! { s ;
                    let _ = scan_one_entry_dir(s.clone(), p_for_scan) ;
                    go(s2, remaining)
                }
            }
        }
    }
    go(s, entries)
}

fn scan_one_entry_dir<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    entry_dir: PathBuf,
) -> S::R<()> {
    // Skip non-directories (`.gitkeep`) and `.git` itself.
    let name = entry_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_owned();
    if name.is_empty() || name == ".git" || name == ".gitkeep" {
        return s.pure(());
    }
    let s2 = s.clone();
    vault_do! { s ;
        let files = s.list_dir(entry_dir.clone()) ;
        scan_age_files(s2.clone(), files)
    }
}

fn scan_age_files<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    files: Vec<PathBuf>,
) -> S::R<()> {
    fn go<S: Vault + Clone + Send + Sync + 'static>(
        s: S,
        rest: Vec<PathBuf>,
    ) -> S::R<()> {
        let mut iter = rest.into_iter();
        match iter.next() {
            None => s.pure(()),
            Some(p) => {
                let s2 = s.clone();
                let remaining: Vec<PathBuf> = iter.collect();
                let extension_age = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e == "age")
                    .unwrap_or(false);
                if !extension_age {
                    return go(s2, remaining);
                }
                let p_for_read = p.clone();
                let p_for_msg = p.clone();
                vault_do! { s ;
                    let bytes = s.read_file(p_for_read) ;
                    let _ = check_for_markers(s.clone(), p_for_msg, bytes) ;
                    go(s2, remaining)
                }
            }
        }
    }
    go(s, files)
}

fn check_for_markers<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    path: PathBuf,
    bytes: Vec<u8>,
) -> S::R<()> {
    if has_conflict_markers(&bytes) {
        s.fail(format!(
            "CORRUPT .age file: {} contains git conflict markers (<<<<<<< / =======/ >>>>>>>). \
             Age ciphertexts cannot be auto-merged. Resolve manually: pick one side's bytes, \
             or restore from a remote that has a clean copy.",
            path.display()
        ))
    } else {
        s.pure(())
    }
}

/// True if `bytes` contains git's standard conflict-marker triple.
/// We only flag when *all three* markers appear, to avoid false
/// positives on age headers (which contain `-----` but never the
/// `<<<<<<<` / `>>>>>>>` lines).
fn has_conflict_markers(bytes: &[u8]) -> bool {
    bytes.windows(7).any(|w| w == b"<<<<<<<")
        && bytes.windows(7).any(|w| w == b"=======")
        && bytes.windows(7).any(|w| w == b">>>>>>>")
}

// ─── Step 5+6: rebuild index, diff, narrate ──────────────────────────────

fn rebuild_index_with_diff<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    now: DateTime<Utc>,
    reindex: bool,
) -> S::R<()> {
    let s2 = s.clone();
    let layout2 = layout.clone();
    let layout3 = layout.clone();
    let whoami_fp = cfg.whoami.fingerprint();
    vault_do! { s ;
        // Old snapshot: either the on-disk index (normal sync) or
        // an empty index (--reindex).
        let old = if reindex {
            s.pure(Index::empty())
        } else {
            read_index_or_empty(s.clone(), layout.index_path())
        } ;
        let _ = s.log("sync: refreshing index…".into()) ;
        let store_entries = s.list_dir(layout.store_dir()) ;
        let new_idx = walk_entries(
            s2.clone(),
            layout2.clone(),
            cfg.clone(),
            whoami_fp,
            store_entries,
            now,
        ) ;
        let _ = write_json(s2.clone(), layout3.index_path(), new_idx.clone()) ;
        report_mods(s2.clone(), &old, &new_idx, reindex)
    }
}

fn read_index_or_empty<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    path: PathBuf,
) -> S::R<Index> {
    let s2 = s.clone();
    let path_for_read = path.clone();
    vault_do! { s ;
        let exists = s.exists(path.clone()) ;
        match exists {
            false => s.pure(Index::empty()),
            true  => read_json::<S, Index>(s2.clone(), path_for_read),
        }
    }
}

/// Walk every `<store>/<entry-hash>/<whoami-fp>.age` we can
/// decrypt, collecting `Cached` records into an [`Index`].
/// Entries we can't decrypt are silently skipped (newly shared but
/// not to us yet, foreign noise).
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
    let path_for_msg = entry_file.clone();
    vault_do! { s ;
        let cipher = s.read_file(entry_file) ;
        let plain = s.decrypt(cipher, vec![cfg.identity_path.clone()]) ;
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
                let p = path_for_msg;
                vault_do! { s2 ;
                    let _ = s2.log(format!(
                        "sync: skipping {} ({})",
                        p.display(), e
                    )) ;
                    s3.pure(idx)
                }
            }
        }
    }
}

fn report_mods<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    old: &Index,
    new: &Index,
    reindex: bool,
) -> S::R<()> {
    let mods = index::diff(old, new);
    if mods.is_empty() {
        let msg = if reindex {
            "sync: --reindex on an empty store; nothing to report"
        } else {
            "sync: no index changes"
        };
        return s.log(msg.into());
    }
    emit_mods_chain(s, mods)
}

fn emit_mods_chain<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    mods: Vec<IndexMod>,
) -> S::R<()> {
    fn go<S: Vault + Clone + Send + Sync + 'static>(
        s: S,
        mut iter: std::vec::IntoIter<IndexMod>,
    ) -> S::R<()> {
        match iter.next() {
            None => s.pure(()),
            Some(m) => {
                let line = render_mod_line(&m);
                let s2 = s.clone();
                vault_do! { s ;
                    let _ = s.stdout(line.into_bytes()) ;
                    go(s2, iter)
                }
            }
        }
    }
    go(s, mods.into_iter())
}

/// Same colour grammar passveil ships with: red `-` for removals,
/// green `+` for inserts, yellow `*` for content/log changes,
/// magenta `!` for explicit metadata updates. ANSI escapes go
/// through unconditionally — the trace is operator-facing, not a
/// stable machine format.
fn render_mod_line(m: &IndexMod) -> String {
    let (ansi, prefix, path) = match m {
        IndexMod::Removed(p) => ("\x1b[31m", "-", p),
        IndexMod::Inserted(p) => ("\x1b[32m", "+", p),
        IndexMod::Modified(p) => ("\x1b[33m", "*", p),
        IndexMod::Updated(p) => ("\x1b[35m", "!", p),
    };
    let reset = "\x1b[0m";
    format!("{ansi}{prefix}{reset} {}\n", path)
}
