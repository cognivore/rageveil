//! New entries must fit SERVICE/ACCOUNT[/PURPOSE][/MISC]*; entries made
//! before the rule keep working under the names they have.
//!
//! AI-generated test: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::entry_name::{Field, NameError};
use rageveil_core::types::EntryPath;
use rageveil_core::{Live, StoreLayout};

fn init(s: &Live, a: &Actor) -> anyhow::Result<()> {
    let (s, root, identity_path) = (s.clone(), a.store_root.clone(), a.identity_path.clone());
    run_blocking(async move {
        commands::init(
            s,
            commands::init::InitArgs {
                root,
                identity_path,
                remote: commands::init::InitRemote::None,
            },
        )
        .await
    })
}

fn args(a: &Actor, path: &str, payload: &str) -> commands::insert::InsertArgs {
    commands::insert::InsertArgs {
        root: a.store_root.clone(),
        path: EntryPath::new(path),
        payload: Some(payload.into()),
        payload_from_stdin: false,
        generate: None,
        symbols: true,
        tier: Default::default(),
    }
}

fn insert_checked(s: &Live, a: &Actor, path: &str, payload: &str) -> anyhow::Result<()> {
    let (s, args) = (s.clone(), args(a, path, payload));
    run_blocking(async move { commands::insert::insert_checked(s, args).await })
}

fn insert_unchecked(s: &Live, a: &Actor, path: &str, payload: &str) -> anyhow::Result<()> {
    let (s, args) = (s.clone(), args(a, path, payload));
    run_blocking(async move { commands::insert(s, args).await })
}

fn show(s: &Live, a: &Actor, path: &str) -> anyhow::Result<String> {
    let (s, root, path) = (s.clone(), a.store_root.clone(), EntryPath::new(path));
    run_blocking(async move {
        Ok(commands::show(s, commands::show::ShowArgs { root, path }).await?.content.payload)
    })
}

fn report(s: &Live, a: &Actor) -> anyhow::Result<commands::names::NamesReport> {
    let (s, root) = (s.clone(), a.store_root.clone());
    run_blocking(async move {
        commands::unfit_names(s, commands::names::NamesArgs { root }).await
    })
}

#[test]
fn a_new_entry_must_fit_the_rule() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);
    init(&s, &alice)?;
    let layout = StoreLayout::new(alice.store_root.clone());

    for bad in ["github.com", "x.com/jane doe", "x.com/../etc", "x.com/-rf", "GitHub.com/jane"] {
        let err = insert_checked(&s, &alice, bad, "v").expect_err(bad);
        assert!(format!("{err:#}").contains("not inserting"), "{bad}: {err:#}");
        assert!(
            !exists(layout.entry_dir(&EntryPath::new(bad).hash())),
            "{bad}: nothing is written for a refused name"
        );
    }

    insert_checked(&s, &alice, "accounts.google.com/jane@example.com/recovery", "v1")?;
    assert_eq!(show(&s, &alice, "accounts.google.com/jane@example.com/recovery")?, "v1");
    Ok(())
}

#[test]
fn an_old_name_keeps_working_and_is_reported() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);
    init(&s, &alice)?;

    // Made before the rule, through the unchecked insert.
    insert_unchecked(&s, &alice, "legacy", "old")?;
    insert_unchecked(&s, &alice, "x.com/a:b", "old")?;
    insert_checked(&s, &alice, "x.com/jane", "fits")?;

    // Replacing it under its own name is still allowed.
    insert_checked(&s, &alice, "legacy", "replaced")?;
    assert_eq!(show(&s, &alice, "legacy")?, "replaced");

    // So is changing its value.
    {
        let (s, root) = (s.clone(), alice.store_root.clone());
        run_blocking(async move {
            commands::edit(
                s,
                commands::edit::EditArgs {
                    root,
                    path: EntryPath::new("x.com/a:b"),
                    payload: Some("edited".into()),
                    payload_from_stdin: false,
                },
            )
            .await
        })?;
    }
    assert_eq!(show(&s, &alice, "x.com/a:b")?, "edited");

    let r = report(&s, &alice)?;
    assert_eq!(r.total, 3);
    assert_eq!(
        r.unfit,
        vec![
            (EntryPath::new("legacy"), NameError::NoAccount),
            (
                EntryPath::new("x.com/a:b"),
                NameError::UnsafeCharacter { field: Field::Account, character: ':' }
            ),
        ]
    );
    assert_eq!(r.lines().len(), 2);
    assert!(r.summary().starts_with("2 of 3 "), "{}", r.summary());
    Ok(())
}

#[test]
fn a_store_without_an_index_has_nothing_to_report() -> anyhow::Result<()> {
    let alice = Actor::fresh("alice");
    let s = live_for(&alice);
    init(&s, &alice)?;
    assert_eq!(report(&s, &alice)?, commands::names::NamesReport::default());
    Ok(())
}
