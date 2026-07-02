//! Real-git sync tests for the **diverged** store paths — the two
//! `sync` outcomes `git_sync.rs` never reaches:
//!
//!   * local and remote each have commits touching *different*
//!     files → `sync` must rebase cleanly, push, and leave linear
//!     history (no merge commit — auto-merging .age files is the
//!     silent-corruption failure mode the flow is designed around);
//!   * local and remote both rewrote the *same* .age file → `sync`
//!     must stop loudly at the rebase conflict. It must NOT let git
//!     auto-pick a side: during a rebase "theirs" is the local
//!     commit, so the old `-X theirs` pull silently overwrote the
//!     freshly-pulled remote rotation and then pushed the loss.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::types::EntryPath;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// Bare repo at `<dir>/origin.git`, same shape as git_sync.rs.
fn make_bare_remote(dir: &Path) -> anyhow::Result<PathBuf> {
    let bare = dir.join("origin.git");
    std::fs::create_dir_all(&bare)?;
    let out = Command::new("git")
        .args(["init", "--bare", "--initial-branch", "main", "--quiet"])
        .arg(&bare)
        .output()?;
    anyhow::ensure!(
        out.status.success(),
        "git init --bare failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(bare)
}

fn git_in(store: &Path, args: &[&str]) -> anyhow::Result<std::process::Output> {
    Ok(Command::new("git").arg("-C").arg(store).args(args).output()?)
}

fn git_stdout(store: &Path, args: &[&str]) -> anyhow::Result<String> {
    let out = git_in(store, args)?;
    anyhow::ensure!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn init_actor(actor: &Actor, remote_url: &str) -> anyhow::Result<()> {
    let s = live_for(actor);
    run_blocking({
        let store = actor.store_root.clone();
        let identity = actor.identity_path.clone();
        let url = remote_url.to_string();
        async move {
            commands::init(
                s,
                commands::init::InitArgs {
                    root: store,
                    identity_path: identity,
                    remote: commands::init::InitRemote::Clone(url),
                },
            )
            .await
        }
    })
}

fn insert(actor: &Actor, path: &str, payload: &str) -> anyhow::Result<()> {
    let s = live_for(actor);
    run_blocking({
        let store = actor.store_root.clone();
        let path = EntryPath::new(path);
        let payload = payload.to_string();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root: store,
                    path,
                    payload: Some(payload),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })
}

fn edit(actor: &Actor, path: &str, payload: &str) -> anyhow::Result<()> {
    let s = live_for(actor);
    run_blocking({
        let store = actor.store_root.clone();
        let path = EntryPath::new(path);
        let payload = payload.to_string();
        async move {
            commands::edit(
                s,
                commands::edit::EditArgs {
                    root: store,
                    path,
                    payload: Some(payload),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })
}

fn sync(actor: &Actor) -> anyhow::Result<()> {
    let s = live_for(actor);
    run_blocking({
        let store = actor.store_root.clone();
        async move {
            commands::sync(
                s,
                commands::sync::SyncArgs { root: store, offline: false, reindex: false },
            )
            .await
        }
    })
}

fn show(actor: &Actor, path: &str) -> anyhow::Result<String> {
    let s = live_for(actor);
    let out = run_blocking({
        let store = actor.store_root.clone();
        let path = EntryPath::new(path);
        async move {
            commands::show(s, commands::show::ShowArgs { root: store, path }).await
        }
    })?;
    Ok(out.content.payload)
}

/// First push needs `-u` so later pushes/pulls know their upstream
/// (cloning an *empty* bare repo leaves the branch untracked).
fn push_upstream(actor: &Actor) -> anyhow::Result<()> {
    let out = git_in(
        &actor.store_root.join("store"),
        &["push", "-u", "origin", "main", "--quiet"],
    )?;
    anyhow::ensure!(
        out.status.success(),
        "push -u failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

// ─── Diverged, disjoint files: rebase cleanly, keep history linear ───────

#[test]
fn diverged_stores_rebase_cleanly_without_merge_commits() -> anyhow::Result<()> {
    let scratch = TempDir::new()?;
    let bare = make_bare_remote(scratch.path())?;
    let remote_url = format!("file://{}", bare.display());

    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");

    println!("[step 1] alice init + seed the remote");
    init_actor(&alice, &remote_url)?;
    insert(&alice, "deploy/token", "seed")?;
    push_upstream(&alice)?;

    println!("[step 2] bob clones the seeded remote");
    init_actor(&bob, &remote_url)?;

    println!("[step 3] alice inserts alpha/one and pushes");
    insert(&alice, "alpha/one", "alice-only")?;
    sync(&alice)?;

    println!("[step 4] bob inserts beta/two locally — now 1 ahead, 1 behind");
    insert(&bob, "beta/two", "bob-only")?;

    println!("[step 5] bob sync — must take the rebase path and push");
    sync(&bob)?;

    let bob_store = bob.store_root.join("store");
    // Linear history: the whole point of rebasing is that no merge
    // commit ever exists over .age files.
    let merges = git_stdout(&bob_store, &["rev-list", "--merges", "HEAD"])?;
    assert!(merges.is_empty(), "sync must never create a merge commit, got: {merges}");

    // Bob's replayed commit reached the remote.
    let head = git_stdout(&bob_store, &["rev-parse", "HEAD"])?;
    let remote_head = git_stdout(&bob_store, &["rev-parse", "origin/main"])?;
    assert_eq!(head, remote_head, "bob's rebased commit should be pushed");

    // Both divergent commits survived, in one linear line.
    let subjects = git_stdout(&bob_store, &["log", "--format=%s"])?;
    assert!(subjects.contains("insert beta/two"), "bob's local commit survived the rebase");
    assert!(subjects.contains("insert alpha/one"), "alice's remote commit was pulled");

    println!("[step 6] alice syncs and sees bob's entry arrive");
    sync(&alice)?;
    let alice_head = git_stdout(&alice.store_root.join("store"), &["rev-parse", "HEAD"])?;
    assert_eq!(alice_head, remote_head, "alice fast-forwards to the same tip");
    Ok(())
}

// ─── Diverged, same file: stop loudly, lose nothing ──────────────────────

/// "One person, two laptops": the same age identity working from two
/// clones. Same identity means edits on both machines rewrite the
/// *same* `<hash>/<fp>.age` file — the guaranteed-conflict case.
fn second_machine(of: &Actor, label: &str) -> anyhow::Result<Actor> {
    use secrecy::ExposeSecret;
    let home = TempDir::new()?;
    let key_dir = home.path().join(".config/age");
    std::fs::create_dir_all(&key_dir)?;
    let identity_path = key_dir.join("keys.txt");
    let secret = of.identity.to_string();
    let secret_text: &str = secret.expose_secret();
    std::fs::write(&identity_path, format!("# {label}\n{secret_text}\n"))?;
    let identity: age::x25519::Identity = secret_text
        .parse()
        .map_err(|e: &str| anyhow::anyhow!("reparse identity: {e}"))?;
    let store_root = home.path().join(".rageveil");
    Ok(Actor {
        identity,
        recipient: of.recipient.clone(),
        identity_path,
        home,
        store_root,
    })
}

#[test]
fn conflicting_rebase_fails_loudly_and_loses_neither_side() -> anyhow::Result<()> {
    let scratch = TempDir::new()?;
    let bare = make_bare_remote(scratch.path())?;
    let remote_url = format!("file://{}", bare.display());

    let laptop = Actor::fresh("pa");
    let desktop = second_machine(&laptop, "pa-desktop")?;

    println!("[step 1] laptop init + insert v1 + seed the remote");
    init_actor(&laptop, &remote_url)?;
    insert(&laptop, "deploy/token", "v1")?;
    push_upstream(&laptop)?;

    println!("[step 2] desktop clones and indexes the entry");
    init_actor(&desktop, &remote_url)?;
    sync(&desktop)?;
    assert_eq!(show(&desktop, "deploy/token")?, "v1");

    println!("[step 3] laptop rotates the secret and pushes");
    edit(&laptop, "deploy/token", "from-laptop")?;
    sync(&laptop)?;

    println!("[step 4] desktop rotates the same secret locally");
    edit(&desktop, "deploy/token", "from-desktop")?;

    println!("[step 5] desktop sync — same .age rewritten on both sides, must fail loudly");
    let msg = match sync(&desktop) {
        Ok(()) => anyhow::bail!("conflicting rebase must fail, not auto-pick a side"),
        Err(err) => err.to_string(),
    };
    println!("[step 5] sync failed as it should:\n{msg}");
    assert!(msg.contains("rebase"), "error should name the stopped rebase: {msg}");
    assert!(msg.contains("--abort"), "error should offer the abort path: {msg}");

    let desktop_store = desktop.store_root.join("store");
    let in_rebase = exists(desktop_store.join(".git/rebase-merge"))
        || exists(desktop_store.join(".git/rebase-apply"));
    assert!(in_rebase, "the rebase should be stopped mid-flight, awaiting the operator");

    println!("[step 6] operator aborts — the local rotation must still be intact");
    let abort = git_in(&desktop_store, &["rebase", "--abort"])?;
    anyhow::ensure!(
        abort.status.success(),
        "rebase --abort failed: {}",
        String::from_utf8_lossy(&abort.stderr)
    );
    assert_eq!(
        show(&desktop, "deploy/token")?,
        "from-desktop",
        "local rotation survives the aborted pull"
    );

    // And the remote side was never clobbered: a fresh third clone
    // still decrypts the laptop's rotation.
    println!("[step 7] fresh clone still sees the laptop's rotation");
    let checker = second_machine(&laptop, "pa-checker")?;
    init_actor(&checker, &remote_url)?;
    sync(&checker)?;
    assert_eq!(
        show(&checker, "deploy/token")?,
        "from-laptop",
        "remote rotation was never overwritten"
    );
    Ok(())
}
