//! `info` tests — the trust-history audit (`who was granted / revoked`).
//!
//! Drives a real allow → allow → deny sequence and checks `info`
//! reports the current trusted set, everyone who's ever had access
//! (with the revoked one flagged), the chronological allow/deny log,
//! and that recipient keys resolve to their address-book names while
//! the operator's own actions read as `you`.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::types::{EntryPath, RecipientSpec};

/// Strip ANSI colour so assertions match on plain text.
fn strip(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn run<F, T>(f: F) -> T
where
    F: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    run_blocking(f).expect("op")
}

fn init(s: &rageveil_core::Live, a: &Actor) {
    run({
        let s = s.clone();
        let store = a.store_root.clone();
        let id = a.identity_path.clone();
        async move {
            commands::init(
                s,
                commands::init::InitArgs {
                    root: store,
                    identity_path: id,
                    remote: commands::init::InitRemote::None,
                },
            )
            .await
        }
    });
}

fn insert(s: &rageveil_core::Live, a: &Actor, path: &str) {
    run({
        let s = s.clone();
        let store = a.store_root.clone();
        let path = path.to_owned();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root: store,
                    path: EntryPath::new(path),
                    payload: Some("x".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    });
}

fn address_add(s: &rageveil_core::Live, a: &Actor, name: &str, key: &RecipientSpec) {
    run({
        let s = s.clone();
        let store = a.store_root.clone();
        let name = name.to_owned();
        let key = key.0.clone();
        async move {
            commands::address_add(
                s,
                commands::address::AddressAddArgs { root: store, name, key: Some(key), key_file: None, force: true },
            )
            .await
        }
    });
}

fn allow(s: &rageveil_core::Live, a: &Actor, path: &str, who: &RecipientSpec) {
    run({
        let s = s.clone();
        let store = a.store_root.clone();
        let path = path.to_owned();
        let who = who.clone();
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs {
                    root: store,
                    path: EntryPath::new(path),
                    recipients: vec![who],
                },
            )
            .await
        }
    });
}

fn deny(s: &rageveil_core::Live, a: &Actor, path: &str, who: &RecipientSpec) {
    run({
        let s = s.clone();
        let store = a.store_root.clone();
        let path = path.to_owned();
        let who = who.clone();
        async move {
            commands::deny(
                s,
                commands::deny::DenyArgs {
                    root: store,
                    path: EntryPath::new(path),
                    recipients: vec![who],
                },
            )
            .await
        }
    });
}

#[test]
fn info_reports_trust_history_with_names() {
    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
    let carol = Actor::fresh("carol");
    let s = live_for(&alice);

    init(&s, &alice);
    insert(&s, &alice, "svc/token");
    address_add(&s, &alice, "bob", &bob.recipient);
    address_add(&s, &alice, "carol", &carol.recipient);

    // grant bob, grant carol, revoke bob.
    allow(&s, &alice, "svc/token", &bob.recipient);
    allow(&s, &alice, "svc/token", &carol.recipient);
    deny(&s, &alice, "svc/token", &bob.recipient);

    let lines = run({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::info(s, commands::info::InfoArgs { root: store, path: EntryPath::new("svc/token") }).await
        }
    });
    let text = strip(&lines.join("\n"));
    eprintln!("\n{text}\n");

    // Header + the operator's own actions read as `you`.
    assert!(text.contains("entry: svc/token"));
    assert!(text.contains("created"));
    assert!(text.contains("you"), "operator should render as `you`");

    // Current trust: alice (you) + carol; bob was revoked.
    assert!(text.contains("trusted now (2):"), "alice + carol trusted\n{text}");
    assert!(text.contains("insiders ever (3):"), "alice, bob, carol ever\n{text}");
    assert!(text.contains("(revoked)"), "bob should be flagged revoked\n{text}");

    // Names resolve, not raw age1 keys.
    assert!(text.contains("bob") && text.contains("carol"));
    assert!(!text.contains(bob.recipient.as_str()), "bob's raw key should not appear");

    // The audit log: bob granted then revoked, carol granted.
    assert!(text.contains("+ bob"), "log should show bob granted\n{text}");
    assert!(text.contains("- bob"), "log should show bob revoked\n{text}");
    assert!(text.contains("+ carol"), "log should show carol granted\n{text}");
}

#[test]
fn info_on_unknown_entry_fails() {
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);
    init(&s, &alice);

    let res = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::info(s, commands::info::InfoArgs { root: store, path: EntryPath::new("nope") }).await
        }
    });
    assert!(res.is_err(), "info on a missing entry must fail");
    assert!(format!("{:#}", res.unwrap_err()).contains("nope"));
}
