//! **Persona tests** — one person, several devices.
//!
//!   * `persona_add lucia lucia-work-phone` groups two address-book
//!     names, and `resolve_recipients(["lucia"])` (or the phone's
//!     name) yields both keys.
//!   * `allow <secret> lucia` therefore lets both devices decrypt.
//!     `deny <secret> lucia-work-phone` takes it from the phone
//!     only; `deny <secret> lucia` (the canonical name) from both.
//!   * A canonical name with no key of its own (`jonn` = `phone`)
//!     still resolves through its members.
//!   * Joining a group backfills what the group already holds.
//!   * `insert` by a grouped operator reaches their other devices
//!     from the start; an ungrouped operator's insert reaches
//!     nobody else.
//!   * A member of another group, or an unregistered name, is
//!     refused.

mod common;

use common::*;
use rageveil_core::Live;
use rageveil_core::commands;
use rageveil_core::commands::address::{
    AddressAddArgs, resolve_deny_recipients, resolve_recipients,
};
use rageveil_core::commands::persona::{PersonaAddArgs, PersonaRemoveArgs};
use rageveil_core::store::StoreLayout;
use rageveil_core::types::{EntryPath, RecipientSpec};

fn init(s: &Live, alice: &Actor) {
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
}

fn insert(s: &Live, alice: &Actor, path: &str) {
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
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

fn register(s: &Live, alice: &Actor, name: &str, who: &Actor) {
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
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

fn persona_add(s: &Live, alice: &Actor, canonical: &str, members: &[&str]) -> anyhow::Result<()> {
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
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
}

fn resolve(s: &Live, alice: &Actor, tokens: &[&str]) -> anyhow::Result<Vec<RecipientSpec>> {
    run_blocking({
        let s = s.clone();
        let ab = StoreLayout::new(alice.store_root.clone()).addressbook_path();
        let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
        async move { resolve_recipients(s, ab, tokens).await }
    })
}

fn allow(s: &Live, alice: &Actor, path: &str, tokens: &[&str]) -> anyhow::Result<()> {
    let recipients = resolve(s, alice, tokens)?;
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let path = path.to_owned();
        async move {
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
}

fn deny(s: &Live, alice: &Actor, path: &str, tokens: &[&str]) -> anyhow::Result<()> {
    let recipients = run_blocking({
        let s = s.clone();
        let ab = StoreLayout::new(alice.store_root.clone()).addressbook_path();
        let tokens: Vec<String> = tokens.iter().map(|t| (*t).to_owned()).collect();
        async move { resolve_deny_recipients(s, ab, tokens).await }
    })?;
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let path = path.to_owned();
        async move {
            commands::deny(
                s,
                commands::deny::DenyArgs {
                    root: store,
                    path: EntryPath::new(path),
                    recipients,
                },
            )
            .await
        }
    })
}

fn holds(alice: &Actor, path: &str, who: &Actor) -> bool {
    let layout = StoreLayout::new(alice.store_root.clone());
    layout
        .entry_file_candidates(&EntryPath::new(path).hash(), &who.recipient)
        .iter()
        .any(|p| exists(p))
}

#[test]
fn a_group_name_resolves_to_every_device() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let laptop = Actor::fresh("lucia");
    let phone = Actor::fresh("lucia-work-phone");
    let s = live_for(&alice);
    init(&s, &alice);
    register(&s, &alice, "lucia", &laptop);
    register(&s, &alice, "lucia-work-phone", &phone);
    persona_add(&s, &alice, "lucia", &["lucia-work-phone"])?;

    let both = |r: &[RecipientSpec]| {
        r.iter().any(|k| *k == laptop.recipient) && r.iter().any(|k| *k == phone.recipient)
    };
    let by_canonical = resolve(&s, &alice, &["lucia"])?;
    assert_eq!(by_canonical.len(), 2);
    assert!(both(&by_canonical), "canonical name fans out");
    let by_member = resolve(&s, &alice, &["lucia-work-phone"])?;
    assert_eq!(by_member.len(), 2);
    assert!(both(&by_member), "a member name fans out too");
    let listed_twice = resolve(&s, &alice, &["lucia", "lucia-work-phone"])?;
    assert_eq!(listed_twice.len(), 2, "no duplicate recipients");
    Ok(())
}

#[test]
fn allow_reaches_every_device_and_deny_only_what_is_named() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let laptop = Actor::fresh("lucia");
    let phone = Actor::fresh("lucia-work-phone");
    let s = live_for(&alice);
    init(&s, &alice);
    insert(&s, &alice, "db/prod");
    register(&s, &alice, "lucia", &laptop);
    register(&s, &alice, "lucia-work-phone", &phone);
    persona_add(&s, &alice, "lucia", &["lucia-work-phone"])?;

    allow(&s, &alice, "db/prod", &["lucia"])?;
    assert!(holds(&alice, "db/prod", &laptop));
    assert!(holds(&alice, "db/prod", &phone));

    deny(&s, &alice, "db/prod", &["lucia-work-phone"])?;
    assert!(!holds(&alice, "db/prod", &phone), "the named device");
    assert!(
        holds(&alice, "db/prod", &laptop),
        "a member name is one device, never the whole group"
    );

    allow(&s, &alice, "db/prod", &["lucia"])?;
    deny(&s, &alice, "db/prod", &["lucia"])?;
    assert!(!holds(&alice, "db/prod", &laptop), "the canonical name is the person");
    assert!(!holds(&alice, "db/prod", &phone));
    Ok(())
}

#[test]
fn a_canonical_name_needs_no_key_of_its_own() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let phone = Actor::fresh("phone");
    let s = live_for(&alice);
    init(&s, &alice);
    register(&s, &alice, "phone", &phone);
    persona_add(&s, &alice, "jonn", &["phone"])?;

    let r = resolve(&s, &alice, &["jonn"])?;
    assert_eq!(r, vec![phone.recipient.clone()]);
    Ok(())
}

#[test]
fn joining_a_group_backfills_what_it_already_holds() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let laptop = Actor::fresh("pupina");
    let phone = Actor::fresh("pupina-iphone16");
    let s = live_for(&alice);
    init(&s, &alice);
    insert(&s, &alice, "shared/one");
    insert(&s, &alice, "shared/two");
    insert(&s, &alice, "private");
    register(&s, &alice, "pupina", &laptop);
    register(&s, &alice, "pupina-iphone16", &phone);
    allow(&s, &alice, "shared/one", &["pupina"])?;
    allow(&s, &alice, "shared/two", &["pupina"])?;
    assert!(!holds(&alice, "shared/one", &phone));

    persona_add(&s, &alice, "pupina", &["pupina-iphone16"])?;
    assert!(holds(&alice, "shared/one", &phone), "backfilled");
    assert!(holds(&alice, "shared/two", &phone), "backfilled");
    assert!(
        !holds(&alice, "private", &phone),
        "only what the group already held"
    );
    assert!(!holds(&alice, "private", &laptop));
    Ok(())
}

/// The other direction of membership: a secret made on one of a
/// person's devices is made for all of them, with no `allow`.
#[test]
fn insert_reaches_the_operators_other_devices() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let phone = Actor::fresh("alice-phone");
    let bob = Actor::fresh("bob");
    let s = live_for(&alice);
    init(&s, &alice);
    register(&s, &alice, "alice", &alice);
    register(&s, &alice, "alice-phone", &phone);
    register(&s, &alice, "bob", &bob);
    persona_add(&s, &alice, "alice", &["alice-phone"])?;

    insert(&s, &alice, "new/secret");
    assert!(holds(&alice, "new/secret", &alice));
    assert!(holds(&alice, "new/secret", &phone), "her phone gets it too");
    assert!(!holds(&alice, "new/secret", &bob), "nobody else does");

    // The log says so: both keys trusted, phone allowed by alice.
    let index: rageveil_core::index::Index = serde_json::from_slice(&std::fs::read(
        StoreLayout::new(alice.store_root.clone()).index_path(),
    )?)?;
    let cached = index
        .entries
        .get(&EntryPath::new("new/secret"))
        .ok_or_else(|| anyhow::anyhow!("indexed"))?;
    let trusted = cached.metadata.trusted();
    assert_eq!(trusted.len(), 2, "{trusted:?}");
    assert!(trusted.contains(&phone.recipient));
    Ok(())
}

/// Registered but in no group: `insert` is the operator's alone,
/// as before personas existed.
#[test]
fn an_ungrouped_insert_stays_private() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let phone = Actor::fresh("alice-phone");
    let s = live_for(&alice);
    init(&s, &alice);
    register(&s, &alice, "alice", &alice);
    register(&s, &alice, "alice-phone", &phone);

    insert(&s, &alice, "mine");
    assert!(holds(&alice, "mine", &alice));
    assert!(!holds(&alice, "mine", &phone));
    Ok(())
}

#[test]
fn refuses_unregistered_and_already_grouped_names() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let a = Actor::fresh("a");
    let s = live_for(&alice);
    init(&s, &alice);
    register(&s, &alice, "a-phone", &a);

    let err = persona_add(&s, &alice, "a", &["nobody"]).expect_err("unregistered member");
    assert!(err.to_string().contains("not in the address book"), "{err}");

    persona_add(&s, &alice, "a", &["a-phone"])?;
    let err = persona_add(&s, &alice, "b", &["a-phone"]).expect_err("already grouped");
    assert!(err.to_string().contains("already a member"), "{err}");

    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::persona_remove(
                s,
                PersonaRemoveArgs {
                    root: store,
                    canonical: "a".into(),
                    members: vec![],
                },
            )
            .await
        }
    })?;
    persona_add(&s, &alice, "b", &["a-phone"])?;
    assert_eq!(resolve(&s, &alice, &["b"])?, vec![a.recipient.clone()]);
    Ok(())
}
