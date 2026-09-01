//! The invite loop, end to end against a real (file) remote:
//! admin issues → "phone" answers with its real key using ONLY
//! what the invite URL carries → admin syncs, sees the response,
//! accepts → the book holds the real key, the ephemeral invite
//! entry is gone, and the swap reached the remote as one commit.
//! Plus the revoke path.
//!
//! The invitee side here drives plain git as test tooling; the
//! sister repo's suite exercises the same protocol through its
//! libgit2 interpreter.

#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use rageveil_core::commands::{self, invite};
use rageveil_core::{AddressBook, InvitePayload};
use std::path::{Path, PathBuf};
use std::process::Command;

fn make_bare_remote(dir: &Path) -> PathBuf {
    let bare = dir.join("origin.git");
    std::fs::create_dir_all(&bare).expect("mk bare");
    let out = Command::new("git")
        .args(["init", "--bare", "--initial-branch", "main", "--quiet"])
        .arg(&bare)
        .output()
        .expect("spawn git");
    assert!(out.status.success());
    bare
}

fn git_in(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn setup_admin(remote: &str) -> Actor {
    let admin = Actor::fresh("admin");
    let s = live_for(&admin);
    run_blocking({
        let root = admin.store_root.clone();
        let identity = admin.identity_path.clone();
        let url = remote.to_owned();
        async move {
            commands::init(
                s,
                commands::init::InitArgs {
                    root,
                    identity_path: identity,
                    remote: commands::init::InitRemote::Clone(url),
                },
            )
            .await
        }
    })
    .expect("admin init");
    // A clone of an empty bare repo has no commits and no
    // upstream; seed one entry then establish tracking — the state
    // every real store lives in.
    let s = live_for(&admin);
    run_blocking({
        let root = admin.store_root.clone();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root,
                    path: rageveil_core::EntryPath::new("seed/base"),
                    payload: Some("seed".into()),
                    payload_from_stdin: false,
                    generate: None,
                    symbols: true,
                },
            )
            .await
        }
    })
    .expect("seed insert");
    git_in(
        &admin.store_root.join("store"),
        &["push", "-u", "origin", "main", "--quiet"],
    );
    admin
}

fn issue(admin: &Actor, name: &str) -> InvitePayload {
    let s = live_for(admin);
    run_blocking({
        let root = admin.store_root.clone();
        let name = name.to_owned();
        async move {
            commands::invite_issue(
                s,
                invite::InviteIssueArgs { root, name, ttl_hours: 72, force: true },
            )
            .await
        }
    })
    .expect("issue")
}

fn sync(admin: &Actor) {
    let s = live_for(admin);
    run_blocking({
        let root = admin.store_root.clone();
        async move {
            commands::sync(
                s,
                commands::sync::SyncArgs { root, offline: false, reindex: false },
            )
            .await
        }
    })
    .expect("sync");
}

fn read_book(admin: &Actor) -> AddressBook {
    let bytes =
        std::fs::read(admin.store_root.join("store/addressbook.json")).expect("read book");
    serde_json::from_slice(&bytes).expect("parse book")
}

/// Simulate the invited phone using nothing but the payload: clone
/// the remote, drop its real public key at `invites/<name>.pub`,
/// push. (Transport auth is the server hook's business; a file
/// remote accepts anyone, which is exactly what `--force` invites
/// are for in tests.)
fn respond(scratch: &Path, payload: &InvitePayload, real_public_key: &str) {
    let clone_dir = scratch.join("phone-clone");
    let out = Command::new("git")
        .args(["clone", "--quiet"])
        .arg(&payload.remote)
        .arg(&clone_dir)
        .output()
        .expect("spawn git clone");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    std::fs::create_dir_all(clone_dir.join("invites")).expect("mk invites");
    std::fs::write(
        clone_dir.join(format!("invites/{}.pub", payload.name)),
        format!("{real_public_key}\n"),
    )
    .expect("write response");
    git_in(&clone_dir, &["add", "-A"]);
    git_in(
        &clone_dir,
        &[
            "-c", "user.name=phone", "-c", "user.email=phone@test",
            "commit", "--quiet", "-m", "invite response",
        ],
    );
    git_in(&clone_dir, &["push", "--quiet"]);
}

#[test]
fn invite_issue_respond_accept_enrolls_and_revokes_ephemeral() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let bare = make_bare_remote(scratch.path());
    let remote = format!("file://{}", bare.display());
    let admin = setup_admin(&remote);

    // Issue: the URL round-trips, and the book grew the ephemeral
    // transport entry (pushed — the bare's book must have it too).
    let payload = issue(&admin, "lucia-phone");
    let url = payload.to_url().expect("to_url");
    let reparsed = InvitePayload::from_url(&url).expect("from_url");
    assert_eq!(reparsed, payload);
    assert_eq!(payload.remote, remote, "payload carries the store remote");
    let book = read_book(&admin);
    assert!(book.people.contains_key("invite:lucia-phone"));
    assert!(!book.people.contains_key("lucia-phone"));

    // The "phone" answers with a fresh real key.
    let real = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPhoneRealKey0000000000000000000000000000 visageveil@lucia";
    respond(scratch.path(), &reparsed, real);

    // Admin fetches; status shows the response; accept swaps.
    sync(&admin);
    let pending = run_blocking({
        let s = live_for(&admin);
        let root = admin.store_root.clone();
        async move {
            commands::invite_status(s, invite::InviteStatusArgs { root }).await
        }
    })
    .expect("status");
    let expected_digest = rageveil_core::RecipientSpec::new(real).fingerprint().digest();
    assert_eq!(
        pending,
        vec![invite::PendingInvite {
            name: "lucia-phone".into(),
            responded: true,
            fingerprint_digest: Some(expected_digest.clone()),
        }],
        "status must show the digest the invitee would read aloud"
    );

    // The ceremony teeth: a WRONG spoken digest refuses to enroll…
    let err = run_blocking({
        let s = live_for(&admin);
        let root = admin.store_root.clone();
        async move {
            commands::invite_accept(
                s,
                invite::InviteAcceptArgs {
                    root,
                    name: "lucia-phone".into(),
                    expected_fingerprint: Some("dead beef dead beef".into()),
                },
            )
            .await
        }
    });
    assert!(err.is_err(), "mismatched fingerprint must refuse");
    assert!(
        format!("{:#}", err.expect_err("mismatch")).contains("fingerprint mismatch"),
        "refusal must name the mismatch"
    );

    // …and the RIGHT one (spoken with sloppy spacing/case) enrolls.
    run_blocking({
        let s = live_for(&admin);
        let root = admin.store_root.clone();
        let spoken = expected_digest.to_uppercase();
        async move {
            commands::invite_accept(
                s,
                invite::InviteAcceptArgs {
                    root,
                    name: "lucia-phone".into(),
                    expected_fingerprint: Some(spoken),
                },
            )
            .await
        }
    })
    .expect("accept");

    let book = read_book(&admin);
    assert_eq!(
        book.people.get("lucia-phone").map(|k| k.as_str().to_owned()),
        Some(real.to_owned()),
        "real key enrolled under the invited name"
    );
    assert!(
        !book.people.contains_key("invite:lucia-phone"),
        "ephemeral transport entry revoked in the same swap"
    );
    assert!(
        !admin.store_root.join("store/invites/lucia-phone.pub").exists(),
        "response drop file removed"
    );

    // On a git@ store the accept's propagate pushes immediately
    // (that push IS the ephemeral-key revocation); on this plain
    // file remote the next sync publishes the swap instead.
    sync(&admin);

    // And the swap reached the remote: a fresh clone agrees.
    let check = scratch.path().join("check-clone");
    let out = Command::new("git")
        .args(["clone", "--quiet"])
        .arg(&remote)
        .arg(&check)
        .output()
        .expect("spawn git clone");
    assert!(out.status.success());
    let remote_book: AddressBook =
        serde_json::from_slice(&std::fs::read(check.join("addressbook.json")).expect("read"))
            .expect("parse");
    assert!(remote_book.people.contains_key("lucia-phone"));
    assert!(!remote_book.people.contains_key("invite:lucia-phone"));
    assert!(!check.join("invites/lucia-phone.pub").exists());
}

#[test]
fn revoke_removes_pending_invite() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let bare = make_bare_remote(scratch.path());
    let remote = format!("file://{}", bare.display());
    let admin = setup_admin(&remote);

    let _payload = issue(&admin, "pa-phone");
    assert!(read_book(&admin).people.contains_key("invite:pa-phone"));

    run_blocking({
        let s = live_for(&admin);
        let root = admin.store_root.clone();
        async move {
            commands::invite_revoke(
                s,
                invite::InviteRevokeArgs { root, name: "pa-phone".into() },
            )
            .await
        }
    })
    .expect("revoke");

    let book = read_book(&admin);
    assert!(!book.people.contains_key("invite:pa-phone"));

    // Accepting after revoke must fail loudly.
    let err = run_blocking({
        let s = live_for(&admin);
        let root = admin.store_root.clone();
        async move {
            commands::invite_accept(
                s,
                invite::InviteAcceptArgs {
                    root,
                    name: "pa-phone".into(),
                    expected_fingerprint: None,
                },
            )
            .await
        }
    });
    assert!(err.is_err(), "accept after revoke must fail");
}
