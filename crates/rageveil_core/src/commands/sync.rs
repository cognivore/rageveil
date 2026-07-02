//! `rageveil sync` — synchronise with the configured remote and
//! refresh the local index.
//!
//! Faithful port of `passveil sync` (modulo darcs → git):
//!
//!   1. (unless `--offline`) `git fetch origin`, narrate the
//!      ahead/behind counts.
//!   2. Pull: decide from those counts — behind-only fast-forwards
//!      (`git merge --ff-only @{u}`), diverged rebases
//!      (`git pull --rebase`) so we never produce a merge commit.
//!      Merge commits over .age files are unsafe — age ciphertexts
//!      aren't bytewise mergeable, so any auto-merge produces a
//!      file that decrypts to garbage. Rebasing keeps history
//!      linear, and a conflicting rebase stops and surfaces loudly
//!      rather than letting git pick a side.
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
use crate::types::{EntryHash, EntryPath};
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
        // gives during `darcs pull`. The same counts pick the pull
        // strategy below.
        let counts = git::ahead_behind(&s, store_dir.clone()) ;
        let _ = narrate_and_pull(s.clone(), store_dir, counts) ;
        push_or_warn(s2.clone(), dir2)
    }
}

/// What the pull step should do, decided from the ahead/behind
/// counts rather than by attempting a merge and sniffing its
/// stderr. Counts are computed anyway for narration; using them
/// for control flow means no doomed `merge --ff-only` run on a
/// diverged store (whose hint-laden failure text we'd re-print)
/// and no dependence on the wording of git's error messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PullPlan {
    /// ahead == 0, behind == 0 — nothing to do.
    UpToDate,
    /// ahead > 0, behind == 0 — nothing to pull; push will send.
    PushOnly,
    /// ahead == 0, behind > 0 — strict fast-forward is safe.
    FastForward,
    /// ahead > 0, behind > 0 — diverged; rebase local commits.
    Rebase,
}

fn choose_pull(ahead: u64, behind: u64) -> PullPlan {
    match (ahead > 0, behind > 0) {
        (false, false) => PullPlan::UpToDate,
        (true, false) => PullPlan::PushOnly,
        (false, true) => PullPlan::FastForward,
        (true, true) => PullPlan::Rebase,
    }
}

/// Parse `git rev-list --count --left-right HEAD...@{u}` output
/// ("A\tB": local-ahead, local-behind). `None` when the command
/// failed (no upstream tracking ref) or printed something
/// unrecognisable — callers must treat that as "don't pull",
/// never as "up to date".
fn parse_ahead_behind(counts: &crate::types::ProcessOut) -> Option<(u64, u64)> {
    if !counts.success() {
        return None;
    }
    let mut parts = counts.stdout_str().split_whitespace();
    let ahead = parts.next()?.parse().ok()?;
    let behind = parts.next()?.parse().ok()?;
    Some((ahead, behind))
}

fn narrate_and_pull<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    counts: crate::types::ProcessOut,
) -> S::R<()> {
    match parse_ahead_behind(&counts) {
        // No upstream tracking ref: pulling is meaningless. Skip it
        // and let the push step print the `push -u` hint.
        None => {
            let why = counts.stderr_str().trim().to_owned();
            s.log(if why.is_empty() {
                "sync: no upstream tracking ref; skipping pull".into()
            } else {
                format!("sync: no upstream tracking ref ({why}); skipping pull")
            })
        }
        Some((ahead, behind)) => {
            let s2 = s.clone();
            vault_do! { s ;
                let _ = s.log(format!(
                    "sync: local is {ahead} ahead, {behind} behind origin"
                )) ;
                execute_pull(s2.clone(), store_dir, choose_pull(ahead, behind))
            }
        }
    }
}

fn execute_pull<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    plan: PullPlan,
) -> S::R<()> {
    match plan {
        PullPlan::UpToDate => s.log("sync: nothing to pull (already up-to-date)".into()),
        PullPlan::PushOnly => s.log("sync: nothing to pull; local commits will be pushed".into()),
        PullPlan::FastForward => fast_forward(s, store_dir),
        PullPlan::Rebase => rebase_diverged(s, store_dir),
    }
}

fn fast_forward<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
) -> S::R<()> {
    vault_do! { s ;
        let _ = s.log("sync: fast-forwarding to origin…".into()) ;
        let ff = git::merge_ff_only(&s, store_dir) ;
        match ff.success() {
            true => s.log("sync: fast-forwarded cleanly".into()),
            // Behind-only should always fast-forward; a refusal
            // means something real (working-tree changes overlapping
            // the pulled paths, unborn HEAD). Surface it verbatim.
            false => s.fail(format!(
                "git merge --ff-only failed: {}",
                ff.stderr_str().trim()
            )),
        }
    }
}

fn rebase_diverged<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
) -> S::R<()> {
    let dir = store_dir.display().to_string();
    vault_do! { s ;
        let _ = s.log(
            "sync: diverged from origin; rebasing local commits (git pull --rebase)…".into()
        ) ;
        let rebase = git::pull(&s, store_dir.clone()) ;
        match rebase.success() {
            true => s.log("sync: rebased local commits onto origin cleanly".into()),
            // Conflict: the rebase has stopped mid-flight, on purpose
            // — git must never auto-pick a side of an .age file. Tell
            // the operator how to pick one themselves. During a
            // rebase `--ours` is origin's version and `--theirs` is
            // the local commit being replayed.
            false => {
                let detail = [rebase.stdout_str().trim(), rebase.stderr_str().trim()]
                    .iter()
                    .filter(|part| !part.is_empty())
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
                s.fail(format!(
                    "git pull --rebase stopped: {detail}\n\n  Both sides changed the same file — likely a secret rotated in two places.\n  Do NOT hand-merge .age files; pick a side per file:\n    keep origin's copy:  git -C {dir} checkout --ours <file>\n    keep your copy:      git -C {dir} checkout --theirs <file>\n  then `git -C {dir} add <file>` and `git -C {dir} rebase --continue`,\n  or `git -C {dir} rebase --abort` to undo the pull and keep local state.\n  The rageveil index was not modified."
                ))
            }
        }
    }
}

fn push_or_warn<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
) -> S::R<()> {
    let dir = store_dir.display().to_string();
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
                    "sync: push skipped (no upstream tracking); set with `git -C {dir} push -u origin main`"
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
    // Skip non-directories (`.gitkeep`, `addressbook.json`) and
    // `.git` itself — `list_dir` on a regular file would error.
    let name = entry_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_owned();
    if name.is_empty()
        || name == ".git"
        || name == ".gitkeep"
        || name == crate::addressbook::ADDRESSBOOK_FILE
    {
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

/// Walk every `<store>/<entry-hash>/` and, for each, index the copy
/// we can decrypt — read under the canonical per-recipient name, or
/// the legacy name for entries shared before the canonical-key fix
/// (see [`StoreLayout::entry_file_candidates`]). Entries we can't
/// decrypt are silently skipped (newly shared but not to us yet,
/// foreign noise).
fn walk_entries<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    candidates: Vec<PathBuf>,
    now: DateTime<Utc>,
) -> S::R<Index> {
    fn go<S: Vault + Clone + Send + Sync + 'static>(
        s: S,
        layout: StoreLayout,
        cfg: Config,
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
                let remaining: Vec<PathBuf> = iter.collect();
                vault_do! { s ;
                    let next_idx = absorb_one(s2.clone(), layout2.clone(), cfg2.clone(), p, idx, now) ;
                    go(s2, layout2, cfg2, remaining, next_idx, now)
                }
            }
        }
    }
    go(s.clone(), layout, cfg, candidates, Index::empty(), now)
}

fn absorb_one<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    candidate: PathBuf,
    idx: Index,
    now: DateTime<Utc>,
) -> S::R<Index> {
    let name = candidate
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_owned();
    if name.is_empty()
        || name == ".git"
        || name == ".gitkeep"
        || name == crate::addressbook::ADDRESSBOOK_FILE
    {
        return s.pure(idx);
    }

    let hash_candidate = EntryHash(name);
    // Canonical name first, legacy name as fallback — so a freshly
    // upgraded binary still finds entries written under the old
    // verbatim-string fingerprint.
    let entry_candidates = layout.entry_file_candidates(&hash_candidate, &cfg.whoami);
    let s2 = s.clone();

    vault_do! { s ;
        let found = crate::sugar::first_existing(s.clone(), entry_candidates) ;
        match found {
            None => s2.pure(idx),
            Some(entry_file) =>
                decrypt_and_record(s2.clone(), cfg.clone(), entry_file, hash_candidate, idx, now),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProcessOut;

    fn out(status: i32, stdout: &str, stderr: &str) -> ProcessOut {
        ProcessOut {
            status,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    // The pull decision is driven by counts, never by sniffing
    // git's (localised, version-drifting) error text. Pin all four
    // quadrants.
    #[test]
    fn pull_plan_quadrants() {
        assert_eq!(choose_pull(0, 0), PullPlan::UpToDate);
        assert_eq!(choose_pull(2, 0), PullPlan::PushOnly);
        assert_eq!(choose_pull(0, 3), PullPlan::FastForward);
        assert_eq!(choose_pull(1, 3), PullPlan::Rebase);
    }

    #[test]
    fn counts_parse_left_right_output() {
        assert_eq!(parse_ahead_behind(&out(0, "1\t3\n", "")), Some((1, 3)));
        assert_eq!(parse_ahead_behind(&out(0, "0\t0\n", "")), Some((0, 0)));
    }

    // A failed rev-list (no upstream ref) or garbage output must map
    // to "don't pull", not to (0, 0) = "up to date" — the previous
    // parser's unwrap_or(0) conflated exactly those two.
    #[test]
    fn counts_failure_or_garbage_is_none() {
        assert_eq!(
            parse_ahead_behind(&out(
                128,
                "",
                "fatal: no upstream configured for branch 'main'"
            )),
            None
        );
        assert_eq!(parse_ahead_behind(&out(0, "garbage", "")), None);
        assert_eq!(parse_ahead_behind(&out(0, "", "")), None);
    }
}
