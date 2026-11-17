//! A Linux laptop's TPM key as its human-only key, against the real
//! age-plugin-tpm.
//!
//! AI-generated test: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! The plugin carries the TCG reference TPM as a simulator
//! (`_AGE_TPM_SIMULATOR=1`), seeded the same in every process, so a key
//! made by one run of the plugin loads in the next. rageveil encrypts to
//! the key natively (`age1tag1`, stanza `p256tag`) and opens its copy
//! through the plugin, which takes the PIN from `AGE_TPM_PIN`. The test
//! runs itself again to give the plugin that environment, since the
//! test process cannot set its own.
//!
//! Without `age-plugin-tpm` on PATH the test says so and passes; the dev
//! shell puts it there, and `RAGEVEIL_REQUIRE_TPM_PLUGIN=1` makes its
//! absence a failure.

mod common;

use common::*;
use rageveil_core::commands;
use rageveil_core::config::Config;
use rageveil_core::tier::Tier;
use rageveil_core::types::{EntryPath, RecipientSpec};
use std::path::{Path, PathBuf};
use std::process::Command;

const PIN: &str = "4711";
const ENTRY: &str = "accounts.google.com/alice@example.com";
const INNER: &str = "RAGEVEIL_TPM_INNER_ROOT";

fn plugin_on_path() -> anyhow::Result<bool> {
    let found = Command::new("age-plugin-tpm").arg("--help").output().is_ok();
    anyhow::ensure!(
        found || std::env::var_os("RAGEVEIL_REQUIRE_TPM_PLUGIN").is_none(),
        "age-plugin-tpm is not on PATH, and RAGEVEIL_REQUIRE_TPM_PLUGIN is set"
    );
    if !found {
        eprintln!("skipped: age-plugin-tpm is not on PATH (`nix develop` puts it there)");
    }
    Ok(found)
}

/// Make a TPM key in the plugin's simulator, with `pin` or without one.
fn tpm_key(dir: &Path, name: &str, pin: Option<&str>) -> anyhow::Result<PathBuf> {
    let out = dir.join(name);
    let mut cmd = Command::new("age-plugin-tpm");
    cmd.env("_AGE_TPM_SIMULATOR", "1").arg("--generate").arg("-o").arg(&out);
    if let Some(pin) = pin {
        cmd.arg("--pin").env("AGE_TPM_PIN", pin);
    }
    let status = cmd.status()?;
    anyhow::ensure!(status.success(), "age-plugin-tpm --generate failed: {status}");
    Ok(out)
}

fn show(alice: &Actor, root: PathBuf) -> anyhow::Result<String> {
    let s = live_for(alice);
    let out = run_blocking(async move {
        commands::show(s, commands::show::ShowArgs { root, path: EntryPath::new(ENTRY) }).await
    })?;
    Ok(out.content.payload)
}

/// Run [`opened_by_the_plugin`] in a child with the plugin's environment.
fn show_as_child(root: &Path, home: &Path, pin: &str) -> anyhow::Result<std::process::Output> {
    Ok(Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "--nocapture", "opened_by_the_plugin"])
        .env(INNER, root)
        .env("RAGEVEIL_TPM_INNER_HOME", home)
        .env("_AGE_TPM_SIMULATOR", "1")
        .env("AGE_TPM_PIN", pin)
        .output()?)
}

/// The child half: open the entry through the TPM key and print it.
#[test]
#[ignore = "run by a_tpm_key_holds_human_only_entries, with the plugin's environment"]
fn opened_by_the_plugin() -> anyhow::Result<()> {
    let (Some(root), Some(home)) =
        (std::env::var_os(INNER), std::env::var_os("RAGEVEIL_TPM_INNER_HOME"))
    else {
        return Ok(());
    };
    let s = rageveil_core::Live::new().with_home(PathBuf::from(home));
    let out = run_blocking(async move {
        commands::show(s, commands::show::ShowArgs {
            root: PathBuf::from(root),
            path: EntryPath::new(ENTRY),
        })
        .await
    })?;
    println!("OPENED:{}", out.content.payload);
    Ok(())
}

#[test]
fn a_tpm_key_holds_human_only_entries() -> anyhow::Result<()> {
    if !plugin_on_path()? {
        return Ok(());
    }
    let alice = Actor::fresh("alice");
    let keys = tempfile::tempdir()?;
    let with_pin = tpm_key(keys.path(), "tpm.txt", Some(PIN))?;
    let without_pin = tpm_key(keys.path(), "tpm-nopin.txt", None)?;
    let s = live_for(&alice);
    let root = alice.store_root.clone();

    run_blocking({
        let (s, root, identity_path) = (s.clone(), root.clone(), alice.identity_path.clone());
        async move {
            commands::init(s, commands::init::InitArgs {
                root,
                identity_path,
                remote: commands::init::InitRemote::None,
            })
            .await
        }
    })?;
    run_blocking({
        let (s, root) = (s.clone(), root.clone());
        async move {
            commands::insert(s, commands::insert::InsertArgs {
                root,
                path: EntryPath::new(ENTRY),
                payload: Some("google-password".into()),
                payload_from_stdin: false,
                generate: None,
                symbols: true,
                tier: Default::default(),
            })
            .await
        }
    })?;

    // A key without a PIN is refused: nothing but the laptop releases it.
    let refused = run_blocking({
        let (s, root) = (s.clone(), root.clone());
        async move {
            commands::tpm(s, commands::tier::TouchArgs { root, identity_path: without_pin }).await
        }
    });
    let refused = refused.err().map(|e| format!("{e:#}")).unwrap_or_default();
    assert!(refused.contains("without a PIN"), "a PIN-less key was accepted: {refused:?}");

    // The key with a PIN becomes this laptop's human-only key.
    let recipient: RecipientSpec = run_blocking({
        let (s, root, id) = (s.clone(), root.clone(), with_pin.clone());
        async move { commands::tpm(s, commands::tier::TouchArgs { root, identity_path: id }).await }
    })?;
    assert!(recipient.as_str().starts_with("age1tag1"), "{}", recipient.as_str());
    let cfg: Config = serde_json::from_slice(&std::fs::read(root.join("config.json"))?)?;
    assert_eq!(cfg.touch.as_ref().map(|t| t.whoami.as_str()), Some(recipient.as_str()));

    // The address book names it as the tree does, and the store gates it.
    run_blocking({
        let (s, root, key) = (s.clone(), root.clone(), recipient.0.clone());
        async move {
            commands::address_add(s, commands::address::AddressAddArgs {
                root,
                name: "alice-framework-tpm".into(),
                key: Some(key),
                key_file: None,
                force: true,
            })
            .await
        }
    })?;
    run_blocking({
        let (s, root) = (s.clone(), root.clone());
        async move {
            commands::gate(s, commands::tier::GateArgs {
                root,
                names: vec!["alice-framework-tpm".into()],
                gated: true,
            })
            .await
        }
    })?;
    run_blocking({
        let (s, root, r) = (s.clone(), root.clone(), recipient.clone());
        async move {
            commands::allow(s, commands::allow::AllowArgs {
                root,
                path: EntryPath::new(ENTRY),
                recipients: vec![r],
            })
            .await
        }
    })?;
    run_blocking({
        let (s, root) = (s.clone(), root.clone());
        async move {
            commands::tier(s, commands::tier::TierArgs {
                root,
                path: EntryPath::new(ENTRY),
                tier: Tier::Human,
            })
            .await
        }
    })?;

    // Only the TPM key holds a copy now, written natively as p256tag.
    let hash = EntryPath::new(ENTRY).hash();
    let tpm_copy = root.join(format!(
        "store/{}/{}.age",
        hash.as_str(),
        recipient.fingerprint().as_str()
    ));
    let mut binary = Vec::new();
    std::io::Read::read_to_end(
        &mut age::armor::ArmoredReader::new(std::fs::File::open(&tpm_copy)?),
        &mut binary,
    )?;
    assert!(
        String::from_utf8_lossy(&binary).contains("\n-> p256tag "),
        "the TPM key's copy has no p256tag stanza"
    );
    assert!(show(&alice, root.clone()).is_err(), "the plain key opened a human-only entry");

    // The plugin opens it with the PIN, and refuses a wrong one.
    let opened = show_as_child(&root, alice.home.path(), PIN)?;
    let stdout = String::from_utf8_lossy(&opened.stdout);
    assert!(
        stdout.contains("OPENED:google-password"),
        "the TPM key did not open its copy.\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&opened.stderr)
    );
    let wrong = show_as_child(&root, alice.home.path(), "0000")?;
    assert!(
        !String::from_utf8_lossy(&wrong.stdout).contains("OPENED:"),
        "a wrong PIN opened the entry"
    );
    Ok(())
}

