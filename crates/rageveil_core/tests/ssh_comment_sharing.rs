//! **Regression: sharing to an OpenSSH recipient across comment drift.**
//!
//! The recipient (a PA) uses an OpenSSH key, so her `whoami` — the
//! first line of her `.pub` — carries a free-form comment. The owner
//! shares one secret by pasting her *exact* public-key line and a
//! second via an address-book entry holding the *same key with the
//! comment dropped* (the everyday way a key gets copied without its
//! tail). After she syncs, **both** secrets must appear in her
//! `list`, because the per-recipient `.age` filename is keyed on the
//! canonical key, not the verbatim string.
//!
//! Before the fix, `RecipientSpec::fingerprint()` hashed the raw
//! string: the address-book share landed under a different
//! fingerprint than the one the PA's `sync` looked for, so the entry
//! silently never entered her index — `list` showed only the
//! raw-key share. This test reproduces that exact setup (real
//! ssh-keygen keys, a throwaway store) and guards the fix.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::types::{EntryPath, RecipientSpec};
use rageveil_core::{Config, Live, StoreLayout, Vault};
use std::path::Path;

/// Generate an OpenSSH ed25519 keypair at `priv_path` with `comment`,
/// returning the first line of the sibling `.pub` (what
/// `recipient_of` reads at init). `None` when `ssh-keygen` isn't on
/// PATH so the suite still runs on stripped-down hosts — the
/// assertion-heavy body is then skipped loudly rather than failing
/// spuriously.
fn ssh_keygen(priv_path: &Path, comment: &str) -> Option<String> {
    let out = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(priv_path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = std::fs::read_to_string(priv_path.with_extension("pub"))
        .ok()?
        .lines()
        .next()?
        .trim()
        .to_owned();
    Some(line)
}

fn run<F, T>(f: F) -> T
where
    F: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    run_blocking(f).expect("op")
}

#[test]
fn pa_on_ssh_key_sees_both_raw_and_address_book_shares() {
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);

    // --- PA's OpenSSH identity; her .pub carries a comment. ---
    let pa_home = tempfile::tempdir().expect("tempdir");
    let pa_priv = pa_home.path().join("id_ed25519");
    let Some(pa_pub_line) = ssh_keygen(&pa_priv, "pa@laptop") else {
        eprintln!("skipping pa_on_ssh_key_*: ssh-keygen unavailable on PATH");
        return;
    };

    // What `rageveil init --identity <pa_priv>` would record as whoami.
    let pa_whoami: RecipientSpec = run({
        let s = s.clone();
        let p = pa_priv.clone();
        async move { s.recipient_of(p).await }
    });
    assert_eq!(pa_whoami, RecipientSpec::new(pa_pub_line.clone()));

    // The address-book copy: same key, comment dropped.
    let key_no_comment = {
        let mut it = pa_pub_line.split_whitespace();
        format!("{} {}", it.next().unwrap(), it.next().unwrap())
    };
    assert_ne!(key_no_comment, pa_pub_line, "the comment really was dropped");

    // --- Owner: init + two secrets. ---
    run({
        let s = s.clone();
        let store = alice.store_root.clone();
        let identity = alice.identity_path.clone();
        async move {
            commands::init(
                s,
                commands::init::InitArgs {
                    root: store,
                    identity_path: identity,
                    remote: commands::init::InitRemote::None,
                },
            )
            .await
        }
    });
    for (path, payload) in [("secretA", "aaa"), ("secretB", "bbb")] {
        run({
            let s = s.clone();
            let store = alice.store_root.clone();
            async move {
                commands::insert(
                    s,
                    commands::insert::InsertArgs {
                        root: store,
                        path: EntryPath::new(path),
                        payload: Some(payload.into()),
                        payload_from_stdin: false,
                    },
                )
                .await
            }
        });
    }

    // secretA: shared by the PA's EXACT pubkey line (matches whoami).
    run({
        let s = s.clone();
        let store = alice.store_root.clone();
        let r = pa_whoami.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("secretA"),
                    recipients: vec![r],
                },
            )
            .await
        }
    });

    // secretB: shared via the address book (same key, comment dropped).
    run({
        let s = s.clone();
        let store = alice.store_root.clone();
        let k = key_no_comment.clone();
        async move {
            commands::address_add(
                s,
                commands::address::AddressAddArgs {
                    root: store,
                    name: "pa".into(),
                    key: Some(k),
                    key_file: None,
                },
            )
            .await
        }
    });
    let resolved = run({
        let s = s.clone();
        let ab = StoreLayout::new(alice.store_root.clone()).addressbook_path();
        async move { commands::address::resolve_recipients(s, ab, vec!["pa".into()]).await }
    });
    run({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("secretB"),
                    recipients: resolved,
                },
            )
            .await
        }
    });

    // --- Build the PA's store view (what a clone/pull delivers) and
    //     rebuild her index exactly as `rageveil sync` does. ---
    let pa_root = pa_home.path().join(".rageveil");
    std::fs::create_dir_all(&pa_root).expect("mk pa root");
    let cp = std::process::Command::new("cp")
        .arg("-R")
        .arg(alice.store_root.join("store"))
        .arg(&pa_root)
        .output()
        .expect("cp -R store");
    assert!(cp.status.success(), "cp store: {}", String::from_utf8_lossy(&cp.stderr));
    std::fs::write(
        pa_root.join("config.json"),
        serde_json::to_vec(&Config {
            whoami: pa_whoami.clone(),
            identity_path: pa_priv.clone(),
        })
        .unwrap(),
    )
    .unwrap();

    let pa_s = Live::new();
    run({
        let s = pa_s.clone();
        let root = pa_root.clone();
        async move {
            commands::sync(
                s,
                commands::sync::SyncArgs { root, offline: true, reindex: true },
            )
            .await
        }
    });

    let mut listed = run({
        let s = pa_s.clone();
        let root = pa_root.clone();
        async move { commands::list(s, commands::list::ListArgs { root }).await }
    });
    listed.sort();
    assert_eq!(
        listed,
        vec!["secretA".to_string(), "secretB".to_string()],
        "PA must see BOTH the raw-key (A) and the address-book (B) share"
    );

    // And the address-book share is addressable through her own
    // canonical entry file — indexed *and* decryptable, not a fluke.
    let b_file = StoreLayout::new(pa_root.clone())
        .entry_file(&EntryPath::new("secretB").hash(), &pa_whoami.fingerprint());
    let plain = run({
        let s = pa_s.clone();
        let id = pa_priv.clone();
        async move {
            let cipher = s.read_file(b_file).await?;
            s.decrypt(cipher, vec![id]).await
        }
    });
    let content: rageveil_core::Content = serde_json::from_slice(&plain).unwrap();
    assert_eq!(content.payload, "bbb");
}
