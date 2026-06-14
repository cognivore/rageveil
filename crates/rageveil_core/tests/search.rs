//! `search` tests — `list` narrowed by a case-insensitive substring
//! over the local index. Runs on the Live interpreter: init, insert
//! a handful of entries, then assert the filter.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::types::EntryPath;

/// `init alice` once, then `insert` each path with a throwaway
/// payload — enough to populate the local index, which is all
/// `search` reads.
fn init_with_entries(s: &rageveil_core::Live, alice: &Actor, paths: &[&str]) {
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

    for p in paths {
        run_blocking({
            let s = s.clone();
            let store = alice.store_root.clone();
            let path = (*p).to_owned();
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
        })
        .expect("insert");
    }
}

fn search(s: &rageveil_core::Live, alice: &Actor, query: &str) -> Vec<String> {
    run_blocking({
        let s = s.clone();
        let store = alice.store_root.clone();
        let query = query.to_owned();
        async move {
            commands::search(s, commands::search::SearchArgs { root: store, query }).await
        }
    })
    .expect("search")
}

#[test]
fn search_filters_by_substring_case_insensitively() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);
    init_with_entries(
        &s,
        &alice,
        &["database/prod/password", "database/staging/password", "email/work"],
    );

    // Substring across a path segment, sorted (BTreeMap order).
    assert_eq!(
        search(&s, &alice, "database"),
        vec![
            "database/prod/password".to_string(),
            "database/staging/password".to_string(),
        ],
    );

    // Case-insensitive: an upper-case query still matches.
    assert_eq!(
        search(&s, &alice, "PROD"),
        vec!["database/prod/password".to_string()],
    );

    // Matches anywhere in the path, not just the leading segment.
    assert_eq!(
        search(&s, &alice, "work"),
        vec!["email/work".to_string()],
    );

    // No match → empty, not an error.
    assert!(search(&s, &alice, "nonexistent").is_empty());

    // Empty query degenerates to `list` — every entry, sorted.
    assert_eq!(
        search(&s, &alice, ""),
        vec![
            "database/prod/password".to_string(),
            "database/staging/password".to_string(),
            "email/work".to_string(),
        ],
    );

    Ok(())
}

#[test]
fn search_on_empty_store_is_empty() -> anyhow::Result<()> {
    // No index on disk yet (never inited) → empty result, mirroring
    // `list`'s behaviour rather than failing.
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);
    assert!(search(&s, &alice, "anything").is_empty());
    Ok(())
}
