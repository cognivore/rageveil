//! `move`: an entry under a new name keeps its readers, its log and its
//! exposure, and the old name is gone.
//!
//! AI-generated test: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::types::EntryPath;

fn mv(alice: &Actor, from: &str, to: &str) -> anyhow::Result<()> {
    let s = live_for(alice);
    let root = alice.store_root.clone();
    let (from, to) = (EntryPath::new(from), EntryPath::new(to));
    run_blocking(async move {
        commands::move_entry(s, commands::move_entry::MoveArgs { root, from, to }).await
    })
}

#[test]
fn a_moved_entry_keeps_its_readers_and_exposure() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let bob = Actor::fresh("bob");
    let s = live_for(&alice);
    let root = alice.store_root.clone();
    run_blocking({
        let (s, root, identity_path) = (s.clone(), root.clone(), alice.identity_path.clone());
        async move {
            commands::init(s, commands::init::InitArgs {
                root, identity_path, remote: commands::init::InitRemote::None,
            }).await
        }
    })?;
    for (path, value) in [("oldname", "secret"), ("example.com/taken", "other")] {
        let (s, root) = (s.clone(), root.clone());
        run_blocking(async move {
            commands::insert(s, commands::insert::InsertArgs {
                root, path: EntryPath::new(path), payload: Some(value.into()),
                payload_from_stdin: false, generate: None, symbols: true,
                tier: Default::default(),
            }).await
        })?;
    }
    run_blocking({
        let (s, root, r) = (s.clone(), root.clone(), bob.recipient.clone());
        async move {
            commands::allow(s, commands::allow::AllowArgs {
                root, path: EntryPath::new("oldname"), recipients: vec![r],
            }).await
        }
    })?;
    let old_hash = EntryPath::new("oldname").hash();
    std::fs::write(root.join("store/exposed.txt"), format!("{}\n", old_hash.as_str()))?;

    assert!(mv(&alice, "oldname", "not a name").is_err(), "a new name must fit");
    assert!(mv(&alice, "oldname", "example.com/taken").is_err(), "a taken name is refused");
    mv(&alice, "oldname", "example.com/alice")?;

    let new_hash = EntryPath::new("example.com/alice").hash();
    assert!(!root.join("store").join(old_hash.as_str()).exists(), "the old folder stays");
    let bob_copy = root.join(format!(
        "store/{}/{}.age", new_hash.as_str(), bob.recipient.fingerprint().as_str()
    ));
    assert!(bob_copy.exists(), "bob lost his copy");
    let shown = run_blocking({
        let (s, root) = (s.clone(), root.clone());
        async move {
            commands::show(s, commands::show::ShowArgs { root, path: EntryPath::new("example.com/alice") }).await
        }
    })?;
    assert_eq!(shown.content.payload, "secret");
    assert!(shown.content.metadata.trusted().iter().any(|r| *r == bob.recipient), "bob left the log");
    let exposed = std::fs::read_to_string(root.join("store/exposed.txt"))?;
    assert!(exposed.contains(new_hash.as_str()) && !exposed.contains(old_hash.as_str()));
    Ok(())
}
