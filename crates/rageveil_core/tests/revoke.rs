//! **Revoke tests** — a device, or a whole person, off every entry.
//!
//! The cast: alice runs the store. `jonn` is a persona whose
//! canonical name is also his laptop, with `octoprophet` and `phone`
//! as further devices. `bob` is someone else entirely.
//!
//!   * `revoke octoprophet` takes that one key off every entry that
//!     trusts it and forgets the name; jonn's laptop and phone, and
//!     bob, keep exactly what they had. Entries that never trusted
//!     octoprophet are not rewritten at all.
//!   * `revoke jonn` takes every device of the person and drops the
//!     group.
//!   * The operator's own key — directly, or through their persona —
//!     is refused with nothing written, while another device of the
//!     operator's persona may be revoked.
//!   * Each revocation is in the entry's trust log, so `info` flags
//!     it.

mod common;

use common::*;
use rageveil_core::Live;
use rageveil_core::addressbook::{AddressBook, Personas};
use rageveil_core::commands;
use rageveil_core::commands::address::{AddressAddArgs, resolve_recipients};
use rageveil_core::commands::persona::PersonaAddArgs;
use rageveil_core::commands::revoke::RevokeArgs;
use rageveil_core::index::Index;
use rageveil_core::metadata::LogEntry;
use rageveil_core::store::StoreLayout;
use rageveil_core::types::EntryPath;

use std::collections::BTreeMap;
use std::path::PathBuf;

fn init(s: &Live, a: &Actor) {
    run_blocking({
        let s = s.clone();
        let store = a.store_root.clone();
        let identity = a.identity_path.clone();
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
}

fn insert(s: &Live, a: &Actor, path: &str) {
    run_blocking({
        let s = s.clone();
        let store = a.store_root.clone();
        let path = path.to_owned();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root: store,
                    path: EntryPath::new(path),
                    payload: Some("hunter2".into()),
                    payload_from_stdin: false,
                    generate: None,
                    symbols: true,
                },
            )
            .await
        }
    })
    .expect("insert");
}

fn register(s: &Live, a: &Actor, name: &str, who: &Actor) {
    run_blocking({
        let s = s.clone();
        let store = a.store_root.clone();
        let key = who.recipient.0.clone();
        let name = name.to_owned();
        async move {
            commands::address_add(
                s,
                AddressAddArgs {
                    root: store,
                    name,
                    key: Some(key),
                    key_file: None,
                    force: true,
                },
            )
            .await
        }
    })
    .expect("address add");
}

fn persona_add(s: &Live, a: &Actor, canonical: &str, members: &[&str]) {
    run_blocking({
        let s = s.clone();
        let store = a.store_root.clone();
        let canonical = canonical.to_owned();
        let members: Vec<String> = members.iter().map(|m| (*m).to_owned()).collect();
        async move {
            commands::persona_add(
                s,
                PersonaAddArgs {
                    root: store,
                    canonical,
                    members,
                },
            )
            .await
        }
    })
    .expect("persona add");
}

fn allow(s: &Live, a: &Actor, path: &str, tokens: &[&str]) {
    run_blocking({
        let s = s.clone();
        let store = a.store_root.clone();
        let ab = StoreLayout::new(store.clone()).addressbook_path();
        let path = path.to_owned();
        let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
        async move {
            let recipients = resolve_recipients(s.clone(), ab, tokens).await?;
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new(path),
                    recipients,
                },
            )
            .await
        }
    })
    .expect("allow");
}

fn revoke(s: &Live, a: &Actor, names: &[&str]) -> anyhow::Result<()> {
    run_blocking({
        let s = s.clone();
        let store = a.store_root.clone();
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        async move { commands::revoke(s, RevokeArgs { root: store, names }).await }
    })
}

fn holds(a: &Actor, path: &str, who: &Actor) -> bool {
    StoreLayout::new(a.store_root.clone())
        .entry_file_candidates(&EntryPath::new(path).hash(), &who.recipient)
        .iter()
        .any(|p| exists(p))
}

fn read<T: serde::de::DeserializeOwned + Default>(p: PathBuf) -> T {
    match std::fs::read(&p) {
        Ok(bytes) => serde_json::from_slice(&bytes).expect("json"),
        Err(_) => T::default(),
    }
}

fn book(a: &Actor) -> AddressBook {
    read(StoreLayout::new(a.store_root.clone()).addressbook_path())
}

fn personas(a: &Actor) -> Personas {
    read(StoreLayout::new(a.store_root.clone()).personas_path())
}

fn index(a: &Actor) -> Index {
    read(StoreLayout::new(a.store_root.clone()).index_path())
}

/// Every file under an entry's directory, with its bytes — to show an
/// entry was not rewritten at all.
fn snapshot(a: &Actor, path: &str) -> BTreeMap<PathBuf, Vec<u8>> {
    let dir = StoreLayout::new(a.store_root.clone()).entry_dir(&EntryPath::new(path).hash());
    std::fs::read_dir(dir)
        .expect("entry dir")
        .map(|e| {
            let p = e.expect("dirent").path();
            let bytes = std::fs::read(&p).expect("read");
            (p, bytes)
        })
        .collect()
}

fn head(a: &Actor) -> String {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(StoreLayout::new(a.store_root.clone()).store_dir())
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

struct Cast {
    s: Live,
    alice: Actor,
    laptop: Actor,
    octo: Actor,
    phone: Actor,
    bob: Actor,
}

/// alice's store: `jonn` = {jonn (laptop), octoprophet, phone};
/// `shared` is held by all of jonn and by bob, `bobs` by bob only,
/// `private` by alice only.
fn cast() -> Cast {
    let alice = Actor::fresh("alice");
    let laptop = Actor::fresh("jonn");
    let octo = Actor::fresh("octoprophet");
    let phone = Actor::fresh("phone");
    let bob = Actor::fresh("bob");
    let s = live_for(&alice);
    init(&s, &alice);
    register(&s, &alice, "jonn", &laptop);
    register(&s, &alice, "octoprophet", &octo);
    register(&s, &alice, "phone", &phone);
    register(&s, &alice, "bob", &bob);
    persona_add(&s, &alice, "jonn", &["octoprophet", "phone"]);
    insert(&s, &alice, "shared");
    insert(&s, &alice, "bobs");
    insert(&s, &alice, "private");
    allow(&s, &alice, "shared", &["jonn", "bob"]);
    allow(&s, &alice, "bobs", &["bob"]);
    Cast {
        s,
        alice,
        laptop,
        octo,
        phone,
        bob,
    }
}

#[test]
fn a_device_goes_and_its_siblings_stay() -> anyhow::Result<()> {
    let c = cast();
    assert!(holds(&c.alice, "shared", &c.octo));
    let bobs_before = snapshot(&c.alice, "bobs");
    let private_before = snapshot(&c.alice, "private");

    revoke(&c.s, &c.alice, &["octoprophet"])?;

    assert!(
        !holds(&c.alice, "shared", &c.octo),
        "the named device is out"
    );
    assert!(
        holds(&c.alice, "shared", &c.laptop),
        "its persona keeps access"
    );
    assert!(
        holds(&c.alice, "shared", &c.phone),
        "its persona keeps access"
    );
    assert!(holds(&c.alice, "shared", &c.bob), "strangers keep access");
    assert!(holds(&c.alice, "shared", &c.alice));

    assert_eq!(
        snapshot(&c.alice, "bobs"),
        bobs_before,
        "an entry that never trusted it is not rewritten"
    );
    assert_eq!(snapshot(&c.alice, "private"), private_before);

    let book = book(&c.alice);
    assert!(book.get("octoprophet").is_none(), "name forgotten");
    assert!(book.get("jonn").is_some() && book.get("phone").is_some());
    let group = personas(&c.alice)
        .groups
        .get("jonn")
        .cloned()
        .expect("group stays");
    assert_eq!(
        group.into_iter().collect::<Vec<_>>(),
        vec!["phone".to_owned()]
    );

    // The trust log records it, the way `deny` does.
    let idx = index(&c.alice);
    let meta = &idx.entries[&EntryPath::new("shared")].metadata;
    assert!(meta.log.iter().any(|e| matches!(
        e,
        LogEntry::Deny { subject, .. } if *subject == c.octo.recipient
    )));
    let trusted = meta.trusted();
    assert_eq!(trusted.len(), 4, "alice, jonn, phone, bob: {trusted:?}");
    let info = run_blocking({
        let s = c.s.clone();
        let store = c.alice.store_root.clone();
        async move {
            commands::info(
                s,
                commands::info::InfoArgs {
                    root: store,
                    path: EntryPath::new("shared"),
                },
            )
            .await
        }
    })?
    .join("\n");
    assert!(info.contains("(revoked)"), "{info}");
    Ok(())
}

#[test]
fn a_persona_goes_with_every_device() -> anyhow::Result<()> {
    let c = cast();
    revoke(&c.s, &c.alice, &["jonn"])?;

    for device in [&c.laptop, &c.octo, &c.phone] {
        assert!(!holds(&c.alice, "shared", device));
    }
    assert!(holds(&c.alice, "shared", &c.bob), "bob untouched");
    assert!(holds(&c.alice, "shared", &c.alice));
    assert!(personas(&c.alice).groups.is_empty(), "group dropped");
    assert_eq!(
        book(&c.alice).people.keys().cloned().collect::<Vec<_>>(),
        vec!["bob".to_owned()]
    );
    let trusted = index(&c.alice).entries[&EntryPath::new("shared")]
        .metadata
        .trusted();
    assert_eq!(trusted.len(), 2, "alice and bob: {trusted:?}");
    Ok(())
}

#[test]
fn the_operator_cannot_revoke_themselves() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let phone = Actor::fresh("alice-phone");
    let s = live_for(&alice);
    init(&s, &alice);
    register(&s, &alice, "alice", &alice);
    register(&s, &alice, "alice-phone", &phone);
    persona_add(&s, &alice, "alice", &["alice-phone"]);
    insert(&s, &alice, "mine");
    assert!(holds(&alice, "mine", &phone));
    let before = head(&alice);

    // Her own key: by persona name — which is also her device name —
    // and raw.
    let raw = alice.recipient.0.clone();
    for name in ["alice", raw.as_str()] {
        let err = revoke(&s, &alice, &[name]).expect_err("own key");
        assert!(format!("{err:#}").contains("own key"), "{err:#}");
    }
    assert_eq!(head(&alice), before, "nothing committed");
    assert!(holds(&alice, "mine", &phone), "nothing rewritten");
    assert!(book(&alice).get("alice").is_some());

    // Her other device is fair game, and she keeps her own access.
    revoke(&s, &alice, &["alice-phone"])?;
    assert!(!holds(&alice, "mine", &phone));
    assert!(holds(&alice, "mine", &alice));
    assert!(personas(&alice).groups.is_empty(), "group emptied, dropped");
    Ok(())
}

#[test]
fn unknown_names_change_nothing() -> anyhow::Result<()> {
    let c = cast();
    let before = head(&c.alice);
    let err = revoke(&c.s, &c.alice, &["octoprophet", "nobody"]).expect_err("unknown");
    assert!(format!("{err:#}").contains("nobody"), "{err:#}");
    assert_eq!(head(&c.alice), before);
    assert!(
        holds(&c.alice, "shared", &c.octo),
        "not even the known name"
    );
    Ok(())
}

/// The guard `revoke` shares with `deny`: an entry is never left
/// with nobody able to read it.
#[test]
fn deny_never_leaves_an_entry_unreadable() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);
    init(&s, &alice);
    insert(&s, &alice, "solo");
    let err = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let me = alice.recipient.clone();
        async move {
            commands::deny(
                s,
                commands::deny::DenyArgs {
                    root: store,
                    path: EntryPath::new("solo"),
                    recipients: vec![me],
                },
            )
            .await
        }
    })
    .expect_err("last recipient");
    assert!(
        format!("{err:#}").contains("nobody would be left"),
        "{err:#}"
    );
    assert!(holds(&alice, "solo", &alice));
    Ok(())
}
