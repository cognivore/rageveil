//! `delete` end-to-end: insert, delete, verify on-disk
//! consequences and that the local index reflects the change.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::types::EntryPath;

#[test]
fn insert_then_delete_clears_disk_and_index() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);
    println!("[setup] store at {}", alice.store_root.display());

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
    println!("[step 1] init OK");

    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::insert(
                s,
                commands::insert::InsertArgs {
                    root: store,
                    path: EntryPath::new("ephemeral"),
                    payload: Some("temporary".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        }
    })?;
    let entry_dir = alice.store_root.join(format!(
        "store/{}",
        EntryPath::new("ephemeral").hash().as_str()
    ));
    assert!(exists(&entry_dir), "entry dir present after insert");
    println!("[step 2] insert OK; entry dir {}", entry_dir.display());

    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move {
            commands::delete(
                s,
                commands::delete::DeleteArgs {
                    root: store,
                    path: EntryPath::new("ephemeral"),
                },
            )
            .await
        }
    })?;
    assert!(!exists(&entry_dir), "entry dir gone after delete");
    println!("[step 3] delete OK; entry dir wiped");

    let names = run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        async move { commands::list(s, commands::list::ListArgs { root: store }).await }
    })?;
    assert!(
        names.is_empty(),
        "index should be empty; saw {names:?}"
    );
    println!("[step 4] list confirms empty");

    Ok(())
}
