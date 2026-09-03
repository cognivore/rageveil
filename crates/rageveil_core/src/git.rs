//! Ergonomic wrappers over the typed `Vault::git_*` effects.
//!
//! Call sites keep reading `git::fetch(&s, dir)`; what each call
//! *means* is pinned by the typed op / outcome vocabulary in
//! [`crate::types`], and how it is realised is the interpreter's
//! business (subprocess `git` under [`crate::Live`], libgit2 under
//! a mobile interpreter). No `std::process::Command`, no `git2`
//! call, and no exit-code or stderr sniffing exists outside the
//! interpreters.

use crate::dsl::Vault;
use crate::types::{
    AheadBehindOutcome, CommitId, CommitOutcome, GitUnitOp, PushOutcome, RebaseOutcome,
};
use std::path::PathBuf;

pub fn init<S: Vault>(s: &S, cwd: PathBuf) -> S::R<()> {
    s.git_unit(cwd, GitUnitOp::Init)
}

/// Clone `remote` as `<parent>/<target>`.
pub fn clone<S: Vault>(s: &S, parent: PathBuf, remote: String, target: String) -> S::R<()> {
    s.git_unit(parent, GitUnitOp::Clone { remote, target })
}

pub fn add_all<S: Vault>(s: &S, cwd: PathBuf) -> S::R<()> {
    s.git_unit(cwd, GitUnitOp::AddAll)
}

/// Stage a single path. Used by `address` so a book commit never
/// sweeps in unrelated working-tree changes; that keeps the
/// rollback after a rejected push (see [`reset_hard`]) surgical.
pub fn add_path<S: Vault>(s: &S, cwd: PathBuf, path: PathBuf) -> S::R<()> {
    s.git_unit(cwd, GitUnitOp::AddPath { path })
}

/// Current commit, captured before a mutation so it can be restored
/// if a subsequent push is rejected. `None` on an unborn branch.
pub fn head<S: Vault>(s: &S, cwd: PathBuf) -> S::R<Option<CommitId>> {
    s.git_head(cwd)
}

/// Restore the working tree and HEAD to `refspec`. Used to undo a
/// local address-book commit the server rejected, so a non-admin's
/// attempt doesn't poison local history.
pub fn reset_hard<S: Vault>(s: &S, cwd: PathBuf, refspec: String) -> S::R<()> {
    s.git_unit(cwd, GitUnitOp::ResetHard { refspec })
}

pub fn commit<S: Vault>(s: &S, cwd: PathBuf, msg: String) -> S::R<CommitOutcome> {
    s.git_commit(cwd, msg)
}

/// `git rebase @{u}` semantics — onto the upstream a preceding
/// [`fetch`] already brought in, so no second network trip — and
/// deliberately with **no** merge strategy options: a conflict
/// stops the rebase and surfaces as [`RebaseOutcome::Stopped`]. Any
/// `-X ours`/`-X theirs` would let git pick a side of a conflicted
/// `.age` file silently — and during a rebase "theirs" is the
/// *local* commit being replayed, so `-X theirs` would quietly
/// overwrite freshly-pulled remote rotations, leave no conflict
/// markers for the post-pull scan to catch, and the subsequent push
/// would publish the loss.
pub fn rebase_onto_upstream<S: Vault>(s: &S, cwd: PathBuf) -> S::R<RebaseOutcome> {
    s.git_rebase_onto_upstream(cwd)
}

/// Bring remote refs up to date without touching the working tree.
pub fn fetch<S: Vault>(s: &S, cwd: PathBuf) -> S::R<()> {
    s.git_unit(cwd, GitUnitOp::Fetch)
}

/// Refuse anything but a strict fast-forward. Auto-merging .age
/// files would silently corrupt ciphertext, so we never let a merge
/// try.
pub fn merge_ff_only<S: Vault>(s: &S, cwd: PathBuf) -> S::R<()> {
    s.git_unit(cwd, GitUnitOp::MergeFfOnly)
}

/// Local-ahead / local-behind counts against upstream. Used by sync
/// to narrate state before pulling and to pick the pull strategy.
pub fn ahead_behind<S: Vault>(s: &S, cwd: PathBuf) -> S::R<AheadBehindOutcome> {
    s.git_ahead_behind(cwd)
}

pub fn push<S: Vault>(s: &S, cwd: PathBuf) -> S::R<PushOutcome> {
    s.git_push(cwd)
}

pub fn has_remote<S: Vault>(s: &S, cwd: PathBuf) -> S::R<bool> {
    s.git_has_remote(cwd)
}

/// The configured URL for a remote, or `None` if the remote doesn't
/// exist. `address add` reads this to enforce the dedicated-`git@`-
/// host convention before a name change can grant repository access.
pub fn remote_get_url<S: Vault>(s: &S, cwd: PathBuf, name: String) -> S::R<Option<String>> {
    s.git_remote_url(cwd, name)
}

/// `git remote add <name> <url>`. Used by `init --lightweight-node`
/// to wire the freshly-bootstrapped bare repo into the local store
/// after `git init`.
pub fn remote_add<S: Vault>(s: &S, cwd: PathBuf, name: String, url: String) -> S::R<()> {
    s.git_unit(cwd, GitUnitOp::RemoteAdd { name, url })
}

/// `git push -u <remote> <branch>`. Establishes upstream tracking
/// so subsequent `git push` / `git pull` know where to go.
pub fn push_set_upstream<S: Vault>(
    s: &S,
    cwd: PathBuf,
    remote: String,
    branch: String,
) -> S::R<()> {
    s.git_unit(cwd, GitUnitOp::PushSetUpstream { remote, branch })
}
