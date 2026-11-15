//! Human-only entries: only gated keys hold a copy, the laptop's plain
//! key loses its copy and gets it back, and the operator still opens the
//! entry through their Touch ID key. A software key listed as gated
//! stands in for the Secure Enclave, which a test cannot touch.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::config::{Config, TouchIdentity};
use rageveil_core::index::Index;
use rageveil_core::tier::Tier;
use rageveil_core::types::EntryPath;

fn copy_of(store: &std::path::Path, entry: &str, who: &Actor) -> std::path::PathBuf {
    store.join(format!(
        "store/{}/{}.age",
        EntryPath::new(entry).hash().as_str(),
        who.recipient.fingerprint().as_str()
    ))
}

fn set_tier(alice: &Actor, entry: &str, tier: Tier) -> anyhow::Result<()> {
    let s = live_for(alice);
    let root = alice.store_root.clone();
    let path = EntryPath::new(entry);
    run_blocking(async move { commands::tier(s, commands::tier::TierArgs { root, path, tier }).await })
}

fn show(alice: &Actor, entry: &str) -> anyhow::Result<String> {
    let s = live_for(alice);
    let root = alice.store_root.clone();
    let path = EntryPath::new(entry);
    let out = run_blocking(async move {
        commands::show(s, commands::show::ShowArgs { root, path }).await
    })?;
    Ok(out.content.payload)
}

#[test]
fn a_human_only_entry_reaches_gated_keys_alone() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let phone = Actor::fresh("phone");
    let s = live_for(&alice);
    let root = alice.store_root.clone();
    let google = "accounts.google.com/alice@example.com";
    let api = "api.example.com/alice";

    run_blocking({
        let (s, root, identity_path) = (s.clone(), root.clone(), alice.identity_path.clone());
        async move {
            commands::init(
                s,
                commands::init::InitArgs {
                    root,
                    identity_path,
                    remote: commands::init::InitRemote::None,
                },
            )
            .await
        }
    })?;
    for (entry, payload) in [(google, "google-password"), (api, "api-key")] {
        let (s, root) = (s.clone(), root.clone());
        run_blocking(async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root,
                    path: EntryPath::new(entry),
                    payload: Some(payload.into()),
                    payload_from_stdin: false,
                    generate: None,
                    symbols: true,
                },
            )
            .await
        })?;
    }

    // Nobody gated yet: making an entry human-only would lock everyone out.
    assert!(set_tier(&alice, api, Tier::Human).is_err());
    assert!(copy_of(&root, api, &alice).exists(), "a refused tier change leaves the entry as it was");
    assert_eq!(show(&alice, api)?, "api-key");

    // The phone joins as a gated device and is given the Google entry.
    run_blocking({
        let (s, root, key) = (s.clone(), root.clone(), phone.recipient.0.clone());
        async move {
            commands::address_add(
                s,
                commands::address::AddressAddArgs {
                    root,
                    name: "alice-phone".into(),
                    key: Some(key),
                    key_file: None,
                    force: true,
                },
            )
            .await
        }
    })?;
    run_blocking({
        let (s, root) = (s.clone(), root.clone());
        async move {
            commands::gate(
                s,
                commands::tier::GateArgs { root, names: vec!["alice-phone".into()], gated: true },
            )
            .await
        }
    })?;
    run_blocking({
        let (s, root, r) = (s.clone(), root.clone(), phone.recipient.clone());
        async move {
            commands::allow(
                s,
                commands::allow::AllowArgs { root, path: EntryPath::new(google), recipients: vec![r] },
            )
            .await
        }
    })?;
    assert!(copy_of(&root, google, &alice).exists() && copy_of(&root, google, &phone).exists());

    // Human-only: the laptop's plain key loses its copy, the gated key keeps one.
    set_tier(&alice, google, Tier::Human)?;
    assert!(!copy_of(&root, google, &alice).exists(), "the plain key still holds a copy");
    assert!(copy_of(&root, google, &phone).exists(), "the gated key lost its copy");
    assert!(copy_of(&root, api, &alice).exists(), "another entry was touched");
    assert!(show(&alice, google).is_err(), "the plain key opened a human-only entry");

    // With a Touch ID key configured, the operator opens it through that key.
    let cfg_path = root.join("config.json");
    let cfg: Config = serde_json::from_slice(&std::fs::read(&cfg_path)?)?;
    let with_touch = Config {
        touch: Some(TouchIdentity {
            whoami: phone.recipient.clone(),
            identity_path: phone.identity_path.clone(),
        }),
        ..cfg
    };
    std::fs::write(&cfg_path, serde_json::to_vec(&with_touch)?)?;
    assert_eq!(show(&alice, google)?, "google-password");

    // A sync without --touch keeps what the index knew; it opens nothing.
    run_blocking({
        let (s, root) = (s.clone(), root.clone());
        async move {
            commands::sync(
                s,
                commands::sync::SyncArgs { root, offline: true, reindex: false, touch: false },
            )
            .await
        }
    })?;
    let index: Index = serde_json::from_slice(&std::fs::read(root.join("index.json"))?)?;
    let cached = index.entries.get(&EntryPath::new(google));
    assert_eq!(cached.map(|c| c.metadata.tier), Some(Tier::Human));
    assert!(index.entries.contains_key(&EntryPath::new(api)));

    // And back: every trusted key holds a copy again.
    set_tier(&alice, google, Tier::Automation)?;
    assert!(copy_of(&root, google, &alice).exists() && copy_of(&root, google, &phone).exists());
    Ok(())
}
