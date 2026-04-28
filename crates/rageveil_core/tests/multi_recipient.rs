//! Multi-recipient sharing: alice allows bob *and* charlie in
//! one call; both can decrypt their per-recipient files; per-key
//! ciphertexts are byte-for-byte distinct (age uses fresh
//! ephemeral keys per recipient, so two encryptions of the same
//! plaintext are not equal even if the recipient is the same).

mod common;

use age::Decryptor;
use age::armor::ArmoredReader;
use common::*;
use rageveil_core::commands;
use rageveil_core::types::EntryPath;
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

#[test]
fn alice_shares_with_bob_and_charlie_in_one_call() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
    let charlie = Actor::fresh("charlie");

    let s = live_for(&alice);
    println!("[setup] alice@{} bob@{} charlie@{}", alice.recipient.fingerprint(), bob.recipient.fingerprint(), charlie.recipient.fingerprint());

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
                    path: EntryPath::new("team-secret"),
                    payload: Some("shared-with-the-team".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;
    println!("[step 1] alice inserted team-secret");

    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let bob_recipient = bob.recipient.clone();
        let charlie_recipient = charlie.recipient.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new("team-secret"),
                    recipients: vec![bob_recipient, charlie_recipient],
                },
            )
            .await
        }
    })?;
    println!("[step 2] alice allowed bob+charlie");

    let entry_dir = alice.store_root.join(format!(
        "store/{}",
        EntryPath::new("team-secret").hash().as_str()
    ));
    let alice_file =
        entry_dir.join(format!("{}.age", alice.recipient.fingerprint().as_str()));
    let bob_file = entry_dir.join(format!("{}.age", bob.recipient.fingerprint().as_str()));
    let charlie_file = entry_dir.join(format!(
        "{}.age",
        charlie.recipient.fingerprint().as_str()
    ));
    for (label, p) in [("alice", &alice_file), ("bob", &bob_file), ("charlie", &charlie_file)] {
        assert!(exists(p), "{label} file should exist at {}", p.display());
        println!("[fs] {label}.age — {} bytes", std::fs::metadata(p)?.len());
    }

    let bob_cipher = std::fs::read(&bob_file)?;
    let charlie_cipher = std::fs::read(&charlie_file)?;
    let alice_cipher = std::fs::read(&alice_file)?;

    // age encrypts each recipient with a fresh ephemeral X25519 —
    // even if the plaintext and recipient set were identical
    // across runs, the ciphertext won't match. Cross-recipient
    // ciphertexts on the *same* plaintext absolutely shouldn't.
    assert_ne!(alice_cipher, bob_cipher);
    assert_ne!(alice_cipher, charlie_cipher);
    assert_ne!(bob_cipher, charlie_cipher);
    println!("[crypto] all three ciphertexts are byte-distinct");

    // All three can decrypt to the same plaintext (when each uses
    // their own identity).
    let alice_plain = decrypt_as(&alice.identity, &alice_cipher)?;
    let bob_plain = decrypt_as(&bob.identity, &bob_cipher)?;
    let charlie_plain = decrypt_as(&charlie.identity, &charlie_cipher)?;
    assert_eq!(alice_plain, bob_plain);
    assert_eq!(alice_plain, charlie_plain);
    let content: rageveil_core::Content = serde_json::from_slice(&alice_plain)?;
    assert_eq!(content.payload, "shared-with-the-team");
    println!("[crypto] all three decryptions agree on payload");

    // Cross-decryption must fail (bob's key on charlie's file).
    assert!(
        decrypt_as(&bob.identity, &charlie_cipher).is_err(),
        "bob shouldn't be able to read charlie's file"
    );
    assert!(
        decrypt_as(&charlie.identity, &bob_cipher).is_err(),
        "charlie shouldn't be able to read bob's file"
    );
    println!("[crypto] cross-decryption fails as required");

    Ok(())
}
