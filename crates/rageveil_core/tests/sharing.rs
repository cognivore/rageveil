//! **Sharing-to-key tests** — the headline requirement.
//!
//! Each test sets up an `alice` store, inserts a secret, then
//! exercises the sharing flow:
//!
//!   * `share_to_bob` — alice allows bob; bob can decrypt his
//!     copy with his own identity. Eve (a third key) can't.
//!   * `deny_revokes` — alice denies bob; bob's per-recipient
//!     file is gone, the remaining trusted set still works.
//!
//! These run entirely on the Live interpreter with x25519 keys
//! generated in-process — no system age install required.

mod common;

use age::Decryptor;
use age::armor::ArmoredReader;
use common::*;
use rageveil_core::commands;
use rageveil_core::types::EntryPath;
use std::io::Read;

/// Decrypt a `.age` file with a raw `x25519::Identity`. Used in
/// tests that need to verify "can bob actually read this?"
/// without going through `commands::show` (which only knows about
/// the operator's own copy).
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

#[test]
fn allow_shares_to_new_recipient() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
    let eve = Actor::fresh("eve");

    let s = live_for(&alice);

    // Alice initialises her store and inserts a secret.
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
                    remote: None,
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
                    path: EntryPath::new("api-key"),
                    payload: Some("super-secret-token".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;

    // Alice allows bob.
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let bob_recipient = bob.recipient.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("api-key"),
                    recipients: vec![bob_recipient],
                },
            )
            .await
        }
    })?;

    // The on-disk layout should now include a recipient file
    // for bob's fingerprint.
    let entry_dir = alice.store_root.join(format!(
        "store/{}",
        EntryPath::new("api-key").hash().as_str()
    ));
    let bob_file = entry_dir.join(format!("{}.age", bob.recipient.fingerprint().as_str()));
    let alice_file =
        entry_dir.join(format!("{}.age", alice.recipient.fingerprint().as_str()));
    assert!(exists(&alice_file), "alice's own copy is still there");
    assert!(exists(&bob_file), "bob's copy was created");

    // Bob can decrypt his copy with his own identity.
    let bob_cipher = std::fs::read(&bob_file)?;
    let plain = decrypt_as(&bob.identity, &bob_cipher)?;
    let content: rageveil_core::Content = serde_json::from_slice(&plain)?;
    assert_eq!(content.payload, "super-secret-token");

    // Eve cannot — her identity wasn't in the recipient list.
    let eve_attempt = decrypt_as(&eve.identity, &bob_cipher);
    assert!(
        eve_attempt.is_err(),
        "eve must not be able to decrypt bob's copy"
    );

    // Alice's metadata log records the Allow event.
    assert!(
        content
            .metadata
            .log
            .iter()
            .any(|e| matches!(e, rageveil_core::LogEntry::Allow { subject, .. }
                if subject == &bob.recipient)),
        "metadata log should record bob's allow"
    );

    Ok(())
}

#[test]
fn deny_revokes_recipient() -> anyhow::Result<()> {
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
                    remote: None,
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
                    path: EntryPath::new("creds"),
                    payload: Some("rotate-me".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let bob_recipient = bob.recipient.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("creds"),
                    recipients: vec![bob_recipient],
                },
            )
            .await
        }
    })?;

    // After allow, bob has a file.
    let entry_dir = alice.store_root.join(format!(
        "store/{}",
        EntryPath::new("creds").hash().as_str()
    ));
    let bob_file = entry_dir.join(format!("{}.age", bob.recipient.fingerprint().as_str()));
    assert!(exists(&bob_file), "bob's file present after allow");

    // Now alice denies bob.
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let bob_recipient = bob.recipient.clone();
        async move {
            commands::deny(
                s,
                commands::deny::DenyArgs {
                    root: store,
                    path: EntryPath::new("creds"),
                    recipients: vec![bob_recipient],
                },
            )
            .await
        }
    })?;

    assert!(
        !exists(&bob_file),
        "bob's file should have been removed by deny"
    );

    // Alice can still decrypt her own copy.
    let out = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::show(
                s,
                commands::show::ShowArgs {
                    root: store,
                    path: EntryPath::new("creds"),
                },
            )
            .await
        }
    })?;
    assert_eq!(out.content.payload, "rotate-me");

    // The trust log shows the deny.
    assert!(
        out.content
            .metadata
            .log
            .iter()
            .any(|e| matches!(e, rageveil_core::LogEntry::Deny { subject, .. }
                if subject == &bob.recipient)),
        "metadata log should record bob's deny"
    );
    assert!(
        !out.content
            .metadata
            .trusted()
            .iter()
            .any(|r| r == &bob.recipient),
        "bob should not be in the trusted set after deny"
    );

    Ok(())
}

#[test]
fn allow_idempotent_on_already_trusted_recipient() -> anyhow::Result<()> {
    // Alice allows herself again — should be a no-op rather than
    // an error or a redundant log entry.
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
                    remote: None,
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
                    path: EntryPath::new("dup"),
                    payload: Some("x".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let alice_self = alice.recipient.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("dup"),
                    recipients: vec![alice_self],
                },
            )
            .await
        }
    })?;

    let out = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::show(
                s,
                commands::show::ShowArgs {
                    root: store,
                    path: EntryPath::new("dup"),
                },
            )
            .await
        }
    })?;
    let allow_count = out
        .content
        .metadata
        .log
        .iter()
        .filter(|e| matches!(e, rageveil_core::LogEntry::Allow { .. }))
        .count();
    // One Allow from the initial insert (the operator), and no
    // additional from the redundant `allow` call.
    assert_eq!(allow_count, 1, "redundant allow should not append a log entry");
    Ok(())
}
