//! **Address-book tests** — the named-recipient sharing flow.
//!
//! Proves the chain a PA grant actually runs through:
//!
//!   * `address_add` registers `pa → bob's key` in the shared book
//!     (`store/addressbook.json`).
//!   * `address_list` surfaces it back.
//!   * `resolve_recipients(["pa"])` resolves the name to bob's
//!     recipient, while a raw `age1…`/`ssh-…` token passes straight
//!     through.
//!   * Feeding that resolved recipient to `allow` lets bob decrypt —
//!     i.e. `allow <secret> pa` is equivalent to pasting the key.
//!   * An unknown name fails loudly rather than silently dropping a
//!     recipient.

mod common;

use age::Decryptor;
use age::armor::ArmoredReader;
use common::*;
use rageveil_core::addressbook::AddressBook;
use rageveil_core::commands;
use rageveil_core::store::StoreLayout;
use rageveil_core::types::EntryPath;
use std::io::Read;

fn decrypt_as(identity: &age::x25519::Identity, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let armored = ArmoredReader::new(ciphertext);
    let dec = Decryptor::new_buffered(armored).map_err(|e| anyhow::anyhow!("decryptor: {e}"))?;
    let id_dyn: &dyn age::Identity = identity;
    let mut reader = dec
        .decrypt(std::iter::once(id_dyn))
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

/// `init alice` + `insert secret` — the shared prelude.
fn init_and_insert(s: &rageveil_core::Live, alice: &Actor, path: &str, payload: &str) {
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
    })
    .expect("init");
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let path = path.to_owned();
        let payload = payload.to_owned();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root: store,
                    path: EntryPath::new(path),
                    payload: Some(payload),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })
    .expect("insert");
}

#[test]
fn allow_by_address_book_name_grants_access() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
    let s = live_for(&alice);

    init_and_insert(&s, &alice, "api-key", "super-secret-token");

    // Alice registers her PA (bob) under the name "pa".
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let bob_key = bob.recipient.0.clone();
        async move {
            commands::address_add(
                s,
                commands::address::AddressAddArgs {
                    root: store,
                    name: "pa".into(),
                    key: Some(bob_key),
                    key_file: None,
                },
            )
            .await
        }
    })?;

    // The book file lives inside the git working tree and round-trips.
    let ab_path = StoreLayout::new(alice.store_root.clone()).addressbook_path();
    assert!(exists(&ab_path), "addressbook.json should be in store/");
    let book: AddressBook = serde_json::from_slice(&std::fs::read(&ab_path)?)?;
    assert_eq!(book.get("pa"), Some(&bob.recipient));

    // `address_list` surfaces it.
    let listed = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::address_list(s, commands::address::AddressListArgs { root: store }).await
        }
    })?;
    assert_eq!(listed, vec![("pa".to_string(), bob.recipient.clone())]);

    // Resolve the name → bob's recipient, then `allow` with it.
    let resolved = run_blocking({
        let s = s.clone();
        let ab_path = ab_path.clone();
        async move { commands::address::resolve_recipients(s, ab_path, vec!["pa".into()]).await }
    })?;
    assert_eq!(resolved, vec![bob.recipient.clone()]);

    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let resolved = resolved.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("api-key"),
                    recipients: resolved,
                },
            )
            .await
        }
    })?;

    // Bob can now decrypt his copy.
    let entry_dir = alice.store_root.join(format!(
        "store/{}",
        EntryPath::new("api-key").hash().as_str()
    ));
    let bob_file = entry_dir.join(format!("{}.age", bob.recipient.fingerprint().as_str()));
    assert!(
        exists(&bob_file),
        "bob's copy was created via the named allow"
    );
    let plain = decrypt_as(&bob.identity, &std::fs::read(&bob_file)?)?;
    let content: rageveil_core::Content = serde_json::from_slice(&plain)?;
    assert_eq!(content.payload, "super-secret-token");

    Ok(())
}

#[test]
fn resolve_passes_raw_keys_through_and_rejects_unknown_names() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
    let s = live_for(&alice);

    init_and_insert(&s, &alice, "creds", "x");
    let ab_path = StoreLayout::new(alice.store_root.clone()).addressbook_path();

    // A raw age key passes through verbatim even with no book present.
    let raw = run_blocking({
        let s = s.clone();
        let ab_path = ab_path.clone();
        let key = bob.recipient.0.clone();
        async move { commands::address::resolve_recipients(s, ab_path, vec![key]).await }
    })?;
    assert_eq!(raw, vec![bob.recipient.clone()]);

    // An unregistered name is a hard error, not a silent drop.
    let err = run_blocking({
        let s = s.clone();
        let ab_path = ab_path.clone();
        async move { commands::address::resolve_recipients(s, ab_path, vec!["ghost".into()]).await }
    });
    assert!(err.is_err(), "unknown name must fail");
    assert!(
        format!("{:#}", err.unwrap_err()).contains("ghost"),
        "error should name the unknown recipient"
    );

    Ok(())
}

#[test]
fn add_rejects_keylike_name_and_remove_drops_entry() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
    let s = live_for(&alice);

    init_and_insert(&s, &alice, "creds", "x");

    // A name that looks like a raw key is refused (would be
    // ambiguous at resolve time).
    let bad = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::address_add(
                s,
                commands::address::AddressAddArgs {
                    root: store,
                    name: "age1bogus".into(),
                    key: Some("age1whatever".into()),
                    key_file: None,
                },
            )
            .await
        }
    });
    assert!(bad.is_err(), "key-like name must be rejected");

    // Add then remove "pa".
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let bob_key = bob.recipient.0.clone();
        async move {
            commands::address_add(
                s,
                commands::address::AddressAddArgs {
                    root: store,
                    name: "pa".into(),
                    key: Some(bob_key),
                    key_file: None,
                },
            )
            .await
        }
    })?;
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::address_remove(
                s,
                commands::address::AddressRemoveArgs {
                    root: store,
                    name: "pa".into(),
                },
            )
            .await
        }
    })?;

    let listed = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::address_list(s, commands::address::AddressListArgs { root: store }).await
        }
    })?;
    assert!(listed.is_empty(), "pa should be gone after remove");

    // Removing a name that isn't there is an error.
    let missing = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::address_remove(
                s,
                commands::address::AddressRemoveArgs {
                    root: store,
                    name: "nobody".into(),
                },
            )
            .await
        }
    });
    assert!(missing.is_err(), "removing an absent name must fail");

    Ok(())
}
