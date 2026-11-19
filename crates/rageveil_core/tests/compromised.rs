//! The graver of the two levels: an entry a person has said leaked.
//!
//! AI-generated tests: model Claude Fable 5.2 (`claude-fable-5-2`);
//! reasoning effort xhigh.
//!
//! `compromised` marks an entry of either tier without opening it,
//! `list` and `info` say "rotate now" for it, a new value or `--undo`
//! takes the mark away, and a move carries it to the new name.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::types::EntryPath;

fn init_with(alice: &Actor, entries: &[&str]) -> anyhow::Result<()> {
    let s = live_for(alice);
    let (root, identity_path) = (alice.store_root.clone(), alice.identity_path.clone());
    run_blocking({
        let s = s.clone();
        let root = root.clone();
        async move {
            commands::init(s, commands::init::InitArgs { root, identity_path, remote: commands::init::InitRemote::None }).await
        }
    })?;
    for entry in entries {
        let (s, root, path) = (s.clone(), root.clone(), EntryPath::new(*entry));
        run_blocking(async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root,
                    path,
                    payload: Some("first-value".into()),
                    payload_from_stdin: false,
                    generate: None,
                    symbols: true,
                    tier: Default::default(),
                },
            )
            .await
        })?;
    }
    Ok(())
}

fn mark(alice: &Actor, entry: &str, undo: bool, because: Option<&str>) -> anyhow::Result<()> {
    let s = live_for(alice);
    let args = commands::compromised::CompromisedArgs {
        root: alice.store_root.clone(),
        path: EntryPath::new(entry),
        undo,
        because: because.map(str::to_owned),
    };
    run_blocking(async move { commands::compromised(s, args).await })
}

fn decoration(alice: &Actor, entry: &str) -> anyhow::Result<Option<&'static str>> {
    let s = live_for(alice);
    let root = alice.store_root.clone();
    let listed = run_blocking(async move { commands::list::list_marked(s, commands::list::ListArgs { root }).await })?;
    Ok(listed.into_iter().find(|l| l.path == entry).and_then(|l| l.decoration()))
}

fn info(alice: &Actor, entry: &str) -> anyhow::Result<String> {
    let s = live_for(alice);
    let args = commands::info::InfoArgs { root: alice.store_root.clone(), path: EntryPath::new(entry) };
    Ok(run_blocking(async move { commands::info(s, args).await })?.join("\n"))
}

fn last_commit(alice: &Actor) -> String {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(alice.store_root.join("store"))
        .args(["log", "-1", "--format=%s"])
        .output()
        .expect("git log");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn a_person_marks_a_leak_and_a_new_value_ends_it() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let (api, other) = ("api.example.com/alice", "mail.example.com/alice");
    init_with(&alice, &[api, other])?;
    assert_eq!(decoration(&alice, api)?, None, "an ordinary entry carries no mark");

    mark(&alice, api, false, Some("printed into\na session log"))?;
    assert_eq!(decoration(&alice, api)?, Some("[compromised: rotate now]"));
    assert_eq!(decoration(&alice, other)?, None, "one entry's leak marks no other");
    assert!(info(&alice, api)?.contains("known to have leaked"));
    assert_eq!(last_commit(&alice), format!("compromised {api}: printed into a session log"));
    assert!(alice.store_root.join("store/compromised.txt").exists());

    // Marking twice changes nothing; taking it back removes the record.
    mark(&alice, api, false, None)?;
    mark(&alice, api, true, None)?;
    assert_eq!(decoration(&alice, api)?, None);
    assert!(!alice.store_root.join("store/compromised.txt").exists(), "an empty record is no file");
    assert_eq!(last_commit(&alice), format!("not compromised {api}"));

    // A new value is the cure.
    mark(&alice, api, false, None)?;
    let s = live_for(&alice);
    let args = commands::edit::EditArgs {
        root: alice.store_root.clone(),
        path: EntryPath::new(api),
        payload: Some("second-value".into()),
        payload_from_stdin: false,
    };
    run_blocking(async move { commands::edit(s, args).await })?;
    assert_eq!(decoration(&alice, api)?, None, "the new value has leaked nowhere");
    assert!(!info(&alice, api)?.contains("known to have leaked"));
    Ok(())
}

#[test]
fn the_mark_follows_a_moved_entry_and_refuses_an_unknown_one() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let (old, new) = ("api.example.com/alice", "api.example.com/alice/token");
    init_with(&alice, &[old])?;
    mark(&alice, old, false, None)?;

    let s = live_for(&alice);
    let args = commands::move_entry::MoveArgs {
        root: alice.store_root.clone(),
        from: EntryPath::new(old),
        to: EntryPath::new(new),
    };
    run_blocking(async move { commands::move_entry(s, args).await })?;
    assert_eq!(decoration(&alice, new)?, Some("[compromised: rotate now]"), "a name is not a value");
    let record = std::fs::read_to_string(alice.store_root.join("store/compromised.txt"))?;
    assert_eq!(record.trim(), EntryPath::new(new).hash().as_str());

    let refused = mark(&alice, "nowhere.example.com/nobody", false, None).expect_err("not in the index");
    assert!(format!("{refused:#}").contains("no entry"), "{refused:#}");
    Ok(())
}
