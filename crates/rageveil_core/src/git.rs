//! Git wrappers over [`Vault::shell`]. Returns
//! `S::R<ProcessOut>` so callers can chain through `vault_do!`
//! without dropping into ad-hoc futures.
//!
//! The wrappers exist so the rest of the codebase composes git
//! invocations through the DSL — no `std::process::Command` or
//! `git2` calls slip in past the trait. That keeps Plan honest:
//! a future renderer that wants to *describe* a sync without
//! running it can intercept `Vault::shell`.

use crate::dsl::Vault;
use crate::types::ProcessOut;
use std::path::PathBuf;

fn git<S: Vault>(s: &S, cwd: PathBuf, args: Vec<&str>) -> S::R<ProcessOut> {
    s.shell(
        "git".into(),
        args.into_iter().map(String::from).collect(),
        Some(cwd),
        // Pin git's message language: sync's push step matches an
        // English substring ("upstream") to tell a missing tracking
        // ref apart from a real push failure. Under a translated
        // locale that benign case would become a hard error.
        vec![("LC_ALL".into(), "C".into())],
    )
}

pub fn init<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(s, cwd, vec!["init", "--quiet", "--initial-branch", "main"])
}

pub fn clone<S: Vault>(s: &S, parent: PathBuf, remote: String, target: String) -> S::R<ProcessOut> {
    s.shell(
        "git".into(),
        vec!["clone".into(), "--quiet".into(), remote, target],
        Some(parent),
        Vec::new(),
    )
}

pub fn add_all<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(s, cwd, vec!["add", "-A"])
}

/// `git add -- <path>` — stage a single path. Used by `address` so a
/// book commit never sweeps in unrelated working-tree changes; that
/// keeps the rollback after a rejected push (see [`reset_hard`])
/// surgical.
pub fn add_path<S: Vault>(s: &S, cwd: PathBuf, path: PathBuf) -> S::R<ProcessOut> {
    s.shell(
        "git".into(),
        vec![
            "add".into(),
            "--".into(),
            path.to_string_lossy().into_owned(),
        ],
        Some(cwd),
        Vec::new(),
    )
}

/// `git rev-parse HEAD` — current commit, captured before a mutation so
/// it can be restored if a subsequent push is rejected.
pub fn rev_parse_head<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(s, cwd, vec!["rev-parse", "HEAD"])
}

/// `git reset --hard <refspec>` — restore the working tree and HEAD to
/// `refspec`. Used to undo a local address-book commit the server
/// rejected, so a non-admin's attempt doesn't poison local history.
pub fn reset_hard<S: Vault>(s: &S, cwd: PathBuf, refspec: String) -> S::R<ProcessOut> {
    s.shell(
        "git".into(),
        vec!["reset".into(), "--hard".into(), "--quiet".into(), refspec],
        Some(cwd),
        Vec::new(),
    )
}

pub fn commit<S: Vault>(s: &S, cwd: PathBuf, msg: String) -> S::R<ProcessOut> {
    s.shell(
        "git".into(),
        vec![
            "-c".into(),
            "user.name=rageveil".into(),
            "-c".into(),
            "user.email=rageveil@localhost".into(),
            "-c".into(),
            "commit.gpgsign=false".into(),
            "commit".into(),
            "--quiet".into(),
            "--allow-empty".into(),
            "-m".into(),
            msg,
        ],
        Some(cwd),
        Vec::new(),
    )
}

/// `git pull --rebase`, deliberately with **no** merge strategy
/// options: a conflict stops the rebase and fails the pull. Any
/// `-X ours`/`-X theirs` would let git pick a side of a conflicted
/// `.age` file silently — and during a rebase "theirs" is the
/// *local* commit being replayed, so `-X theirs` would quietly
/// overwrite freshly-pulled remote rotations, leave no conflict
/// markers for the post-pull scan to catch, and the subsequent
/// push would publish the loss.
pub fn pull<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(s, cwd, vec!["pull", "--quiet", "--rebase"])
}

/// `git fetch --quiet --tags origin` — bring remote refs up to date
/// without touching the working tree.
pub fn fetch<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(s, cwd, vec!["fetch", "--quiet", "--tags", "origin"])
}

/// `git merge --ff-only @{u}` — refuse anything but a strict
/// fast-forward. Auto-merging .age files would silently corrupt
/// ciphertext, so we never let `git merge` try.
pub fn merge_ff_only<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(s, cwd, vec!["merge", "--ff-only", "--quiet", "@{u}"])
}

/// `git rev-list --count --left-right HEAD...@{u}` — prints "A\tB"
/// where A is local-ahead, B is local-behind upstream. Used by
/// sync to narrate state before pulling.
pub fn ahead_behind<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(
        s,
        cwd,
        vec!["rev-list", "--count", "--left-right", "HEAD...@{u}"],
    )
}

pub fn push<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(s, cwd, vec!["push", "--quiet"])
}

pub fn status_porcelain<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(s, cwd, vec!["status", "--porcelain"])
}

pub fn has_remote<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(s, cwd, vec!["remote"])
}

/// `git remote get-url <name>` — print the configured URL for a
/// remote on stdout, or exit non-zero if the remote doesn't exist.
/// `address add` reads this to enforce the dedicated-`git@`-host
/// convention before a name change can grant repository access.
pub fn remote_get_url<S: Vault>(s: &S, cwd: PathBuf, name: String) -> S::R<ProcessOut> {
    s.shell(
        "git".into(),
        vec!["remote".into(), "get-url".into(), name],
        Some(cwd),
        Vec::new(),
    )
}

/// `git remote add <name> <url>`. Used by `init --dumb-remote` to
/// wire the freshly-bootstrapped bare repo into the local store
/// after `git init`.
pub fn remote_add<S: Vault>(
    s: &S,
    cwd: PathBuf,
    name: String,
    url: String,
) -> S::R<ProcessOut> {
    s.shell(
        "git".into(),
        vec!["remote".into(), "add".into(), name, url],
        Some(cwd),
        Vec::new(),
    )
}

/// `git push -u <remote> <branch>`. Establishes upstream tracking
/// so subsequent `git push` / `git pull` know where to go.
pub fn push_set_upstream<S: Vault>(
    s: &S,
    cwd: PathBuf,
    remote: String,
    branch: String,
) -> S::R<ProcessOut> {
    s.shell(
        "git".into(),
        vec!["push".into(), "--quiet".into(), "-u".into(), remote, branch],
        Some(cwd),
        Vec::new(),
    )
}
