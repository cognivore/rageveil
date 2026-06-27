//! `edit` changes an entry's value while leaving its trust model
//! untouched: every currently-trusted recipient is re-keyed to the
//! *new* value, and the metadata log (and therefore "insiders ever")
//! survives verbatim. This is the property that distinguishes `edit`
//! from re-running `insert`, which would reset the entry to the
//! operator alone.

mod common;

use age::armor::ArmoredReader;
use age::Decryptor;
use common::*;
use rageveil_core::commands;
use rageveil_core::types::{EntryPath, RecipientSpec};
use std::collections::BTreeSet;
use std::io::Read;

fn decrypt_as(
    identity: &age::x25519::Identity,
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let armored = ArmoredReader::new(ciphertext);
    let dec = Decryptor::new_buffered(armored)
        .map_err(|e| anyhow::anyhow!("decryptor: {e}"))?;
    let id_dyn: &dyn age::Identity = identity;
    let mut reader = dec
        .decrypt(std::iter::once(id_dyn))
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

fn keys(specs: &[RecipientSpec]) -> BTreeSet<String> {
    specs.iter().map(|r| r.canonical_key()).collect()
}

fn entry_file(actor: &Actor, owner_fp: &str, path: &str) -> std::path::PathBuf {
    actor
        .store_root
        .join("store")
        .join(EntryPath::new(path).hash().as_str())
        .join(format!("{owner_fp}.age"))
}

#[test]
fn edit_rekeys_every_trusted_recipient_and_preserves_the_log() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
    let charlie = Actor::fresh("charlie");
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
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root: store,
                    path: EntryPath::new("db/prod"),
                    payload: Some("old-password".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let (b, c) = (bob.recipient.clone(), charlie.recipient.clone());
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("db/prod"),
                    recipients: vec![b, c],
                },
            )
            .await
        }
    })?;
    println!("[setup] alice inserted db/prod, shared with bob+charlie");

    // Rotate the value via `edit`.
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::edit(
                s,
                commands::edit::EditArgs {
                    root: store,
                    path: EntryPath::new("db/prod"),
                    payload: Some("new-rotated-password".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;
    println!("[act] alice edited db/prod");

    // All three recipients must now decrypt the *new* value.
    for (label, ident) in [
        ("alice", &alice.identity),
        ("bob", &bob.identity),
        ("charlie", &charlie.identity),
    ] {
        let fp = actor_fp(label, &alice, &bob, &charlie);
        let cipher = std::fs::read(entry_file(&alice, &fp, "db/prod"))?;
        let plain = decrypt_as(ident, &cipher)?;
        let content: rageveil_core::Content = serde_json::from_slice(&plain)?;
        assert_eq!(
            content.payload, "new-rotated-password",
            "{label} should see the rotated value"
        );
        println!("[crypto] {label} decrypts the new value");
    }

    // The metadata log — and "insiders ever" — survived the edit.
    let alice_fp = alice.recipient.fingerprint();
    let cipher = std::fs::read(entry_file(&alice, alice_fp.as_str(), "db/prod"))?;
    let content: rageveil_core::Content =
        serde_json::from_slice(&decrypt_as(&alice.identity, &cipher)?)?;
    let everyone = keys(&[
        alice.recipient.clone(),
        bob.recipient.clone(),
        charlie.recipient.clone(),
    ]);
    assert_eq!(keys(&content.metadata.insiders()), everyone, "insiders preserved");
    assert_eq!(keys(&content.metadata.trusted()), everyone, "trusted preserved");
    assert!(content.metadata.updated.is_some(), "edit stamps `updated`");
    println!("[audit] log + insiders preserved across the edit");
    Ok(())
}

#[test]
fn edit_after_deny_keeps_the_insider_audit_but_not_access() -> anyhow::Result<()> {
    // The exact scenario from the design discussion: disallow, then
    // rotate. `bob` saw the old value, so he stays in "insiders
    // ever" — but he is no longer trusted and cannot read the new
    // value (his per-recipient file was removed at deny time and
    // edit only re-keys the trusted set).
    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
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
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root: store,
                    path: EntryPath::new("oauth/prod"),
                    payload: Some("secret-v1".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let b = bob.recipient.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("oauth/prod"),
                    recipients: vec![b],
                },
            )
            .await
        }
    })?;
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let b = bob.recipient.clone();
        async move {
            commands::deny(
                s,
                commands::deny::DenyArgs {
                    root: store,
                    path: EntryPath::new("oauth/prod"),
                    recipients: vec![b],
                },
            )
            .await
        }
    })?;
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::edit(
                s,
                commands::edit::EditArgs {
                    root: store,
                    path: EntryPath::new("oauth/prod"),
                    payload: Some("secret-v2".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;
    println!("[act] alice allowed bob, denied bob, then edited oauth/prod");

    // bob's file is gone — he cannot read the rotated value.
    let bob_file = entry_file(&alice, bob.recipient.fingerprint().as_str(), "oauth/prod");
    assert!(!exists(&bob_file), "bob's per-recipient file must stay removed after edit");

    // alice reads the new value; the audit still records bob as a
    // past insider, no longer trusted.
    let alice_file = entry_file(&alice, alice.recipient.fingerprint().as_str(), "oauth/prod");
    let content: rageveil_core::Content =
        serde_json::from_slice(&decrypt_as(&alice.identity, &std::fs::read(&alice_file)?)?)?;
    assert_eq!(content.payload, "secret-v2");

    let insiders = keys(&content.metadata.insiders());
    let trusted = keys(&content.metadata.trusted());
    assert!(
        insiders.contains(&bob.recipient.canonical_key()),
        "bob saw v1 — he stays an insider-ever"
    );
    assert!(
        !trusted.contains(&bob.recipient.canonical_key()),
        "bob was denied — not trusted now"
    );
    assert!(trusted.contains(&alice.recipient.canonical_key()));
    println!("[audit] bob: insider-ever ✓, trusted-now ✗, cannot read v2 ✓");
    Ok(())
}

/// Fingerprint of the actor named `label`, as the per-recipient
/// filename uses it.
fn actor_fp(label: &str, alice: &Actor, bob: &Actor, charlie: &Actor) -> String {
    match label {
        "alice" => alice.recipient.fingerprint().as_str().to_owned(),
        "bob" => bob.recipient.fingerprint().as_str().to_owned(),
        "charlie" => charlie.recipient.fingerprint().as_str().to_owned(),
        other => panic!("unknown actor {other}"),
    }
}
