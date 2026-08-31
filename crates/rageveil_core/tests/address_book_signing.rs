//! **Address-book signing** — the doorman that needs no server.
//!
//! On a `git@` store the `pre-receive` hook keeps `addressbook.json`
//! admin-only. Host the same store on github.com and that hook is
//! gone: anyone who can push can rewrite the book, and because
//! `allow`/`deny` resolve names through it, a rewritten book
//! redirects the next share to a key the attacker holds.
//!
//! These tests run that attack against a signed store and require it
//! to fail — both the crude version (edit the book, leave the
//! signature) and the competent one (edit the book and re-sign it
//! with your own key).

use rageveil_core::commands;
use rageveil_core::signing;
use rageveil_core::store::StoreLayout;
use rageveil_core::Live;
use ssh_key::rand_core::OsRng;
use ssh_key::{LineEnding, PrivateKey};
use std::path::PathBuf;
use tempfile::TempDir;

/// An operator whose identity is an ssh key, so it can sign. The
/// shared `Actor` fixture is age-based and deliberately cannot.
struct SshActor {
    home: TempDir,
    identity_path: PathBuf,
    public: String,
    store_root: PathBuf,
}

fn ssh_actor(label: &str) -> SshActor {
    let key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
        .expect("generate ed25519");
    let home = TempDir::new().expect("tempdir");
    let ssh_dir = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh_dir).expect("mkdir .ssh");
    let identity_path = ssh_dir.join("id_ed25519");
    std::fs::write(
        &identity_path,
        key.to_openssh(LineEnding::LF).expect("encode private").as_bytes(),
    )
    .expect("write key");
    let public = key
        .public_key()
        .to_openssh()
        .expect("encode public")
        + " "
        + label;
    // rageveil reads the public half from `<private>.pub`, the way
    // ssh-keygen leaves it.
    std::fs::write(ssh_dir.join("id_ed25519.pub"), format!("{public}\n"))
        .expect("write public key");
    let store_root = home.path().join(".rageveil");
    SshActor { home, identity_path, public, store_root }
}

fn run<F, T>(fut: F) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(fut)
}

/// init + one `address add`, leaving a signed book behind.
fn signed_store(admin: &SshActor) -> (Live, StoreLayout) {
    let s = Live::new().with_home(admin.home.path().to_path_buf());
    run({
        let (s, root, identity) =
            (s.clone(), admin.store_root.clone(), admin.identity_path.clone());
        async move {
            commands::init(
                s,
                commands::init::InitArgs {
                    root,
                    identity_path: identity,
                    remote: commands::init::InitRemote::None,
                },
            )
            .await
        }
    })
    .expect("init");

    run({
        let (s, root) = (s.clone(), admin.store_root.clone());
        async move {
            commands::address::address_add(
                s,
                commands::address::AddressAddArgs {
                    root,
                    name: "bob".into(),
                    key: Some(
                        "ssh-ed25519 \
                         AAAAC3NzaC1lZDI1NTE5AAAAIKk7Z5GF0s3dZcY27zg+BIK1M80N9qt+J0tLJ5vXQkE7 bob"
                            .into(),
                    ),
                    key_file: None,
                    force: true,
                },
            )
            .await
        }
    })
    .expect("address add");

    (s, StoreLayout::new(admin.store_root.clone()))
}

fn read_book(s: &Live, layout: &StoreLayout) -> anyhow::Result<rageveil_core::AddressBook> {
    run({
        let (s, path) = (s.clone(), layout.addressbook_path());
        async move { commands::address::load_or_empty(s, path).await }
    })
}

#[test]
fn an_ssh_operator_signs_the_book_and_trusts_itself() {
    let admin = ssh_actor("admin");
    let (s, layout) = signed_store(&admin);

    // The trust anchor is local, outside the git tree, so a push
    // cannot reach it.
    let admins = signing::admins_path(&admin.store_root);
    assert!(admins.is_file(), "init records the creator as admin");
    assert!(
        !admins.starts_with(layout.store_dir()),
        "admins.json must live outside the working tree"
    );

    assert!(
        signing::signature_path(&layout.addressbook_path()).is_file(),
        "address add signs the book"
    );
    let book = read_book(&s, &layout).expect("signed book loads");
    assert!(book.people.contains_key("bob"));
}

/// The crude attack: rewrite the book, leave the signature alone.
#[test]
fn a_rewritten_book_is_refused() {
    let admin = ssh_actor("admin");
    let (s, layout) = signed_store(&admin);

    std::fs::write(
        layout.addressbook_path(),
        r#"{"bob":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILAnVQk2tUJT0LDJjqVUhXiyxAA32g5WPW3kskoJo3x7 attacker"}"#,
    )
    .expect("swap the book");

    let err = read_book(&s, &layout).expect_err("a tampered book must not load");
    assert!(
        format!("{err:#}").contains("signature"),
        "error should name the signature: {err:#}"
    );
}

/// The competent attack: rewrite the book *and* re-sign it with a
/// key you control. Push access lets you do both; neither helps,
/// because the trust list is not in the repository.
#[test]
fn a_book_resigned_by_an_outsider_is_refused() {
    let admin = ssh_actor("admin");
    let (s, layout) = signed_store(&admin);

    let poisoned = br#"{"bob":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILAnVQk2tUJT0LDJjqVUhXiyxAA32g5WPW3kskoJo3x7 attacker"}"#;
    std::fs::write(layout.addressbook_path(), poisoned).expect("swap the book");

    let attacker = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
        .expect("attacker key");
    let forged = signing::sign(
        attacker.to_openssh(LineEnding::LF).expect("encode").as_str(),
        signing::ADDRESSBOOK_NAMESPACE,
        poisoned,
    )
    .expect("attacker signs");
    std::fs::write(
        signing::signature_path(&layout.addressbook_path()),
        forged.as_bytes(),
    )
    .expect("swap the signature");

    read_book(&s, &layout).expect_err("a book signed by an outsider must not load");
}

/// Stores that never opted in keep working — the switch is the
/// local `admins.json`, and an attacker with push access cannot
/// create it for you.
#[test]
fn an_unsigned_store_still_loads() {
    let admin = ssh_actor("admin");
    let (s, layout) = signed_store(&admin);

    std::fs::remove_file(signing::admins_path(&admin.store_root)).expect("opt out");
    std::fs::remove_file(signing::signature_path(&layout.addressbook_path()))
        .expect("drop signature");

    let book = read_book(&s, &layout).expect("unsigned store loads");
    assert!(book.people.contains_key("bob"));
}
