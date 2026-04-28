//! `init → insert → show` end-to-end round trip on the Live
//! interpreter. Confirms the on-disk shape is consistent and the
//! payload survives an encrypt/decrypt cycle.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::types::EntryPath;

#[test]
fn init_insert_show_round_trip() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");

    let s = live_for(&alice);
    run_blocking({
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
    })?;

    // After init, config + index + store/.git should be on disk.
    assert!(exists(alice.store_root.join("config.json")));
    assert!(exists(alice.store_root.join("index.json")));
    assert!(exists(alice.store_root.join("store/.git")));

    // Insert a secret with a multi-segment path.
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root: store,
                    path: EntryPath::new("database/prod/password"),
                    payload: Some("hunter2".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;

    let entry_dir = alice.store_root.join(format!(
        "store/{}",
        EntryPath::new("database/prod/password").hash().as_str()
    ));
    assert!(
        exists(&entry_dir),
        "expected entry dir at {}",
        entry_dir.display()
    );
    let recipient_file = entry_dir.join(format!(
        "{}.age",
        alice.recipient.fingerprint().as_str()
    ));
    assert!(exists(&recipient_file), "expected per-recipient file");

    // Round-trip: show should return the same plaintext.
    let out = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::show(
                s,
                commands::show::ShowArgs {
                    root: store,
                    path: EntryPath::new("database/prod/password"),
                },
            )
            .await
        }
    })?;
    assert_eq!(out.content.payload, "hunter2");

    // Index should contain the path now.
    let names = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move { commands::list(s, commands::list::ListArgs { root: store }).await }
    })?;
    assert_eq!(names, vec!["database/prod/password".to_string()]);

    Ok(())
}
