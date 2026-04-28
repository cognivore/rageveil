//! End-to-end shell test for the `--dumb-remote` bootstrap.
//!
//! The remote-side bootstrap is built from string-formatting plus
//! POSIX-quoting rules — a class of bug ("tilde expansion only
//! fires at word-start") that string-level unit tests can't catch.
//! This test runs the *generated remote command* under a real
//! bash with a synthetic `HOME` and asserts the resulting bare
//! repo is shaped right. No ssh involved (we don't depend on a
//! remote being reachable); we're testing the shell semantics.
//!
//! If this passes, the only remaining concern with `--dumb-remote`
//! is the SSH transport itself — which is a system concern, not a
//! rageveil-code concern.

use rageveil_core::commands;
use rageveil_core::types::EntryPath;
use rageveil_core::{Plan, PlanNode};
use std::path::PathBuf;
use std::process::Command;

/// Render the init plan, pull the `ssh …` line out, extract the
/// remote command argument (everything after the host).
fn extract_remote_cmd(url: &str) -> String {
    let plan = commands::init(
        Plan::new(),
        commands::init::InitArgs {
            root: "/tmp/dumb-remote-shell-test".into(),
            identity_path: PathBuf::from("/dev/null"),
            remote: commands::init::InitRemote::DumbBootstrap(url.to_string()),
        },
    );
    let trace = bind_to_unit(plan).render_text();

    // The first `shell `…`` line in a `--dumb-remote` plan is
    // the bootstrap. Pull that out and strip the `shell ` prefix
    // and surrounding backticks so we're left with the actual
    // command line ssh would run.
    let line = trace
        .lines()
        .find(|l| l.contains("shell `ssh"))
        .unwrap_or_else(|| panic!("no ssh line in trace:\n{trace}"));
    let inner = line
        .trim()
        .strip_prefix("shell `")
        .and_then(|s| s.strip_suffix('`'))
        .unwrap_or_else(|| panic!("malformed shell line: {line}"));

    // ssh's last positional argument is the remote command. Our
    // builder always ends `args` with `[host, remote_cmd]`, so
    // we split off the prefix that is `ssh -o … host` and keep
    // everything after.
    let mut tokens = inner.split_whitespace();
    // ssh
    assert_eq!(tokens.next(), Some("ssh"));
    // -o StrictHostKeyChecking=accept-new
    assert_eq!(tokens.next(), Some("-o"));
    let _ = tokens.next();
    // host
    let _host = tokens.next().expect("host");
    // remote_cmd is everything left
    tokens.collect::<Vec<_>>().join(" ")
}

/// `Plan::R<()>` shape so we can render any init Plan, regardless
/// of its concrete output type, by binding the result to `()`.
fn bind_to_unit<A: Send + 'static>(p: PlanNode<A>) -> PlanNode<()> {
    p.bind(|_| PlanNode::Pure(()))
}

#[test]
fn tilde_path_bootstrap_runs_under_bash() {
    let _ = EntryPath::new("dummy"); // ensure rageveil_core is linked

    let tmp = tempfile::tempdir().expect("tempdir");
    let cmd = extract_remote_cmd("ssh://example.com/~/.rageveil");

    let status = Command::new("bash")
        .arg("-c")
        .arg(&cmd)
        .env("HOME", tmp.path())
        .status()
        .expect("spawn bash");
    assert!(status.success(), "remote bootstrap failed:\n  {cmd}");

    let head = std::fs::read_to_string(tmp.path().join(".rageveil/HEAD"))
        .expect("read HEAD");
    assert_eq!(head.trim(), "ref: refs/heads/main");
}

#[test]
fn scp_style_relative_bootstrap_runs_under_bash() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cmd = extract_remote_cmd("example.com:.rageveil");

    let status = Command::new("bash")
        .arg("-c")
        .arg(&cmd)
        .env("HOME", tmp.path())
        .current_dir(tmp.path())
        .status()
        .expect("spawn bash");
    assert!(status.success(), "remote bootstrap failed:\n  {cmd}");

    let head = std::fs::read_to_string(tmp.path().join(".rageveil/HEAD"))
        .expect("read HEAD");
    assert_eq!(head.trim(), "ref: refs/heads/main");
}

#[test]
fn absolute_path_bootstrap_runs_under_bash() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let abs = tmp.path().join("nested/store.git");
    let url = format!("ssh://example.com{}", abs.display());
    let cmd = extract_remote_cmd(&url);

    let status = Command::new("bash")
        .arg("-c")
        .arg(&cmd)
        .status()
        .expect("spawn bash");
    assert!(status.success(), "remote bootstrap failed:\n  {cmd}");

    let head = std::fs::read_to_string(abs.join("HEAD")).expect("read HEAD");
    assert_eq!(head.trim(), "ref: refs/heads/main");
}
