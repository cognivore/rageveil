//! Confirms our on-disk `.age` files are *standard* age — i.e.,
//! the same bytes ragenix would produce, mutually decryptable
//! with any age-compatible implementation.
//!
//! Two directions:
//!
//!   1. **Encrypt with rageveil → decrypt with raw age.**
//!      Read the `.age` file produced by `commands::insert`, run
//!      it through `age::Decryptor` directly with the bare
//!      `x25519::Identity`. If the byte format weren't standard
//!      age, this would fail.
//!
//!   2. **Encrypt with raw age → decrypt via the Vault DSL.**
//!      Hand-build an ASCII-armored age blob with the `age`
//!      crate's API, drop it where the store layout expects, and
//!      `show` it through our normal command. This proves we can
//!      *read* anything ragenix wrote.
//!
//! Both directions exercise real bytes — no mocks.

mod common;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::{Decryptor, Encryptor};
use common::*;
use rageveil_core::commands;
use rageveil_core::content::Content;
use rageveil_core::metadata::Metadata;
use rageveil_core::types::{EntryPath, Salt};
use std::io::{Read, Write};

#[test]
fn rageveil_output_is_decryptable_by_raw_age() -> anyhow::Result<()> {
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
                    path: EntryPath::new("interop"),
                    payload: Some("hello-from-rageveil".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;

    let entry_file = alice.store_root.join(format!(
        "store/{}/{}.age",
        EntryPath::new("interop").hash().as_str(),
        alice.recipient.fingerprint().as_str(),
    ));
    let cipher = std::fs::read(&entry_file)?;
    println!(
        "[interop] rageveil wrote {} bytes to {}",
        cipher.len(),
        entry_file.display()
    );

    // Verify ASCII-armor framing — same form ragenix produces.
    let head = std::str::from_utf8(&cipher[..cipher.len().min(40)])?;
    assert!(
        head.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "expected ASCII armor; got {head:?}"
    );

    // Decrypt with the bare age crate — no DSL involved.
    let armored = ArmoredReader::new(cipher.as_slice());
    let dec = Decryptor::new_buffered(armored)
        .map_err(|e| anyhow::anyhow!("decryptor: {e}"))?;
    let id_dyn: &dyn age::Identity = &alice.identity;
    let mut reader = dec
        .decrypt(std::iter::once(id_dyn))
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
    let mut plain = Vec::new();
    reader.read_to_end(&mut plain)?;
    let content: Content = serde_json::from_slice(&plain)?;
    assert_eq!(content.payload, "hello-from-rageveil");
    println!("[interop] raw `age` decrypted rageveil's output ✓");
    Ok(())
}

#[test]
fn raw_age_blob_is_readable_via_dsl_show() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);

    // Stand up a vanilla store first so config.json + index
    // exist and `show` has its preconditions.
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

    // Hand-build a Content blob and encrypt it ourselves with raw
    // age — bypassing rageveil entirely. The file ends up at the
    // exact path `commands::show` expects to find it.
    let now = chrono::Utc::now();
    let content = Content {
        path: EntryPath::new("imported"),
        salt: Salt::from_bytes(&[0u8; 32]),
        payload: "hand-rolled-by-raw-age".to_owned(),
        metadata: Metadata::new(alice.recipient.clone(), now),
    };
    let plaintext = serde_json::to_vec(&content)?;

    let recipient = alice.recipient.as_str().parse::<age::x25519::Recipient>()
        .map_err(|e| anyhow::anyhow!("parse recipient: {e}"))?;
    let recipient_dyn: Box<dyn age::Recipient + Send> = Box::new(recipient);
    let recipient_refs: Vec<&dyn age::Recipient> = vec![recipient_dyn.as_ref()];
    let encryptor = Encryptor::with_recipients(recipient_refs.into_iter())
        .map_err(|e| anyhow::anyhow!("encryptor: {e}"))?;

    let mut cipher = Vec::new();
    {
        let armored = ArmoredWriter::wrap_output(&mut cipher, Format::AsciiArmor)
            .map_err(|e| anyhow::anyhow!("armor wrap: {e}"))?;
        let mut writer = encryptor
            .wrap_output(armored)
            .map_err(|e| anyhow::anyhow!("age wrap: {e}"))?;
        writer.write_all(&plaintext)?;
        let armored = writer.finish().map_err(|e| anyhow::anyhow!("finish: {e}"))?;
        armored.finish().map_err(|e| anyhow::anyhow!("armor finish: {e}"))?;
    }

    let entry_dir = alice.store_root.join(format!(
        "store/{}",
        EntryPath::new("imported").hash().as_str()
    ));
    std::fs::create_dir_all(&entry_dir)?;
    let target =
        entry_dir.join(format!("{}.age", alice.recipient.fingerprint().as_str()));
    std::fs::write(&target, &cipher)?;
    println!(
        "[interop] hand-rolled {} bytes of raw-age into {}",
        cipher.len(),
        target.display()
    );

    let out = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::show(
                s,
                commands::show::ShowArgs {
                    root: store,
                    path: EntryPath::new("imported"),
                },
            )
            .await
        }
    })?;
    assert_eq!(out.content.payload, "hand-rolled-by-raw-age");
    println!("[interop] DSL `show` decrypted raw-age input ✓");
    Ok(())
}
