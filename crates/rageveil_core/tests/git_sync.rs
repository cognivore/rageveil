//! End-to-end **real git** sync test.
//!
//! No mocks. No test theatre. We:
//!
//!   1. Spin up a bare git repository in a temp dir (the
//!      "coordination node" — the user's words: "deployed on a
//!      semi-central server as a coordination node").
//!   2. Have *alice* `init` her store cloning that bare remote.
//!   3. Have alice `insert` a secret, then `sync` to push.
//!   4. Have *bob* `init` his store cloning the *same* remote.
//!   5. Have alice `allow bob` for that secret, then `sync` again.
//!   6. Have bob `sync` to pull alice's commits.
//!   7. Verify bob can `show` the secret using his own identity.
//!
//! Then a temp-dir wipe at end-of-test.
//!
//! Each step is journalled to stdout so the test reads like a
//! recipe; if anything goes wrong, the failure shows you exactly
//! how far the run got.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::types::EntryPath;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Set up a bare git repo at `<dir>/origin.git` that both actors
/// will use as their `--remote`.
fn make_bare_remote(dir: &std::path::Path) -> anyhow::Result<PathBuf> {
    let bare = dir.join("origin.git");
    std::fs::create_dir_all(&bare)?;
    let out = Command::new("git")
        .args(["init", "--bare", "--initial-branch", "main", "--quiet"])
        .arg(&bare)
        .output()?;
    if !out.status.success() {
        anyhow::bail!(
            "git init --bare failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    println!("[remote] bare repo at {}", bare.display());
    Ok(bare)
}

#[test]
fn alice_inserts_shares_bob_pulls_and_decrypts() -> anyhow::Result<()> {
    let scratch = TempDir::new()?;
    println!("[setup] scratch dir = {}", scratch.path().display());

    let bare = make_bare_remote(scratch.path())?;
    let remote_url = format!("file://{}", bare.display());

    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
    println!("[setup] alice recipient = {}", alice.recipient);
    println!("[setup] bob   recipient = {}", bob.recipient);

    // ── Step 1: alice initialises with the bare remote ──────────
    println!("[step 1] alice init --remote {remote_url}");
    let s_alice = live_for(&alice);
    run_blocking({
        let s = s_alice.clone();
        let store = alice.store_root.clone();
        let identity = alice.identity_path.clone();
        let url = remote_url.clone();
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
    })?;
    assert!(exists(alice.store_root.join("store/.git")));

    // ── Step 2: alice inserts a secret ──────────────────────────
    println!("[step 2] alice insert deploy/token = 'rotate-quarterly'");
    run_blocking({
        let s = s_alice.clone();
        let store = alice.store_root.clone();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root: store,
                    path: EntryPath::new("deploy/token"),
                    payload: Some("rotate-quarterly".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;

    // Alice needs an upstream tracking ref before push can guess
    // where to send commits. Set it now — git's "do this for me
    // automatically" defaults haven't held still over the years
    // and we want the test to be robust.
    let push_setup = Command::new("git")
        .args(["-C"])
        .arg(alice.store_root.join("store"))
        .args(["push", "-u", "origin", "main", "--quiet"])
        .output()?;
    assert!(
        push_setup.status.success(),
        "first push failed: {}",
        String::from_utf8_lossy(&push_setup.stderr)
    );
    println!("[step 2] alice → remote initial push OK");

    // ── Step 3: alice syncs (idempotent) ────────────────────────
    println!("[step 3] alice sync");
    run_blocking({
        let s = s_alice.clone();
        let store = alice.store_root.clone();
        async move {
            commands::sync(s, commands::sync::SyncArgs { root: store, offline: false })
                .await
        }
    })?;

    // ── Step 4: bob initialises by cloning the same remote ──────
    println!("[step 4] bob init --remote {remote_url}");
    let s_bob = live_for(&bob);
    run_blocking({
        let s = s_bob.clone();
        let store = bob.store_root.clone();
        let identity = bob.identity_path.clone();
        let url = remote_url.clone();
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
    })?;
    assert!(
        exists(bob.store_root.join("store/.git")),
        "bob's store should have a git repo after init+clone"
    );

    // Bob has alice's encrypted blob in his clone but no copy
    // for *his* recipient yet — show should fail gracefully.
    println!("[step 4] bob attempts show before alice allows him (expect failure)");
    let attempt = run_blocking({
        let s = s_bob.clone();
        let store = bob.store_root.clone();
        async move {
            commands::show(
                s,
                commands::show::ShowArgs {
                    root: store,
                    path: EntryPath::new("deploy/token"),
                },
            )
            .await
        }
    });
    assert!(attempt.is_err(), "bob shouldn't have access yet");
    println!("[step 4] bob.show failed as expected: {}", attempt.unwrap_err());

    // ── Step 5: alice allows bob, then sync (push) ──────────────
    println!("[step 5] alice allow deploy/token {}", bob.recipient);
    run_blocking({
        let s = s_alice.clone();
        let store = alice.store_root.clone();
        let bob_recipient = bob.recipient.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("deploy/token"),
                    recipients: vec![bob_recipient],
                },
            )
            .await
        }
    })?;
    println!("[step 5] alice sync (pushes new bob.age file)");
    run_blocking({
        let s = s_alice.clone();
        let store = alice.store_root.clone();
        async move {
            commands::sync(s, commands::sync::SyncArgs { root: store, offline: false })
                .await
        }
    })?;

    // ── Step 6: bob syncs (pulls alice's allow commit) ──────────
    println!("[step 6] bob sync (pulls alice's allow)");
    run_blocking({
        let s = s_bob.clone();
        let store = bob.store_root.clone();
        async move {
            commands::sync(s, commands::sync::SyncArgs { root: store, offline: false })
                .await
        }
    })?;

    // ── Step 7: bob can now show the secret ─────────────────────
    println!("[step 7] bob show deploy/token");
    let out = run_blocking({
        let s = s_bob.clone();
        let store = bob.store_root.clone();
        async move {
            commands::show(
                s,
                commands::show::ShowArgs {
                    root: store,
                    path: EntryPath::new("deploy/token"),
                },
            )
            .await
        }
    })?;
    assert_eq!(out.content.payload, "rotate-quarterly");
    println!("[step 7] bob decrypted payload: {}", out.content.payload);

    // Bob's index should also include the entry now.
    let names = run_blocking({
        let s = s_bob.clone();
        let store = bob.store_root.clone();
        async move { commands::list(s, commands::list::ListArgs { root: store }).await }
    })?;
    assert!(
        names.contains(&"deploy/token".to_string()),
        "bob's index should have the entry after sync"
    );

    println!("[done] tearing down — temp dirs will be wiped on TempDir drop");
    Ok(())
}
