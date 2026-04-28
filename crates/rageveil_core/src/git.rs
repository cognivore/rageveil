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
        Vec::new(),
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

pub fn pull<S: Vault>(s: &S, cwd: PathBuf) -> S::R<ProcessOut> {
    git(
        s,
        cwd,
        vec![
            "pull",
            "--quiet",
            "--rebase",
            "--no-edit",
            "--strategy=recursive",
            "--strategy-option=theirs",
        ],
    )
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
