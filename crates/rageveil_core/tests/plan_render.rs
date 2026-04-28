//! Plan-rendering smoke tests.
//!
//! Two layers of property here:
//!
//! 1. **Without registered stubs**, `decode_json` under Plan
//!    fails honestly with a "no stub registered" message. The
//!    trace records the read and the decode-step *and* the
//!    failure — no fake decoded value, no silent walk-through.
//!
//! 2. **With registered stubs**, traces of full commands walk
//!    past the decode and reach the per-recipient encrypt /
//!    write / git-add / git-commit chain. That's the property
//!    `--plan` needs in production.

use chrono::{TimeZone, Utc};
use rageveil_core::commands;
use rageveil_core::types::{EntryPath, RecipientSpec, Salt};
use rageveil_core::{Config, Content, Index, Metadata, Plan, PlanNode, Vault};
use std::path::PathBuf;

fn stub_recipient() -> RecipientSpec {
    RecipientSpec::new(
        "age1plan0stub00000000000000000000000000000000000000000000000000".to_string(),
    )
}

/// A `Plan` pre-loaded with the same fixtures the CLI's `--plan`
/// uses. Tests that want to render a full command should start
/// from this.
fn plan_with_fixtures() -> Plan {
    let r = stub_recipient();
    let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().expect("stub-now");
    let metadata = Metadata::new(r.clone(), now);

    Plan::new()
        .with_stub(&Config {
            whoami: r.clone(),
            identity_path: PathBuf::from("/plan-stub/identity.txt"),
        })
        .with_stub(&Index::empty())
        .with_stub(&Content {
            path: EntryPath::new("plan/example"),
            salt: Salt(String::new()),
            payload: "<plan-stub-payload>".into(),
            metadata,
        })
}

#[test]
fn no_stub_registered_fails_honestly() {
    let s = Plan::new();
    let plan: PlanNode<()> = commands::insert(
        s,
        commands::insert::InsertArgs {
            root: "/tmp/rageveil-plan-test".into(),
            path: EntryPath::new("a/b/c"),
            payload: Some("plain".into()),
            payload_from_stdin: false,
        },
    );
    let trace = plan.render_text();
    println!("--- no-stub trace ---\n{trace}---------------------");

    assert!(trace.contains("read /tmp/rageveil-plan-test/config.json"));
    assert!(trace.contains("decode-json Config"));
    assert!(
        trace.contains("no Plan stub registered"),
        "decode without stub should fail with the registry hint:\n{trace}"
    );
}

#[test]
fn insert_walks_through_with_fixtures() {
    let plan = plan_with_fixtures();
    let plan: PlanNode<()> = commands::insert(
        plan,
        commands::insert::InsertArgs {
            root: "/tmp/rageveil-plan-test".into(),
            path: EntryPath::new("ops/api"),
            payload: Some("p".into()),
            payload_from_stdin: false,
        },
    );
    let trace = plan.render_text();
    println!("--- insert trace ---\n{trace}--------------------");

    // Initial config read + decode go through the stub.
    assert!(trace.contains("read /tmp/rageveil-plan-test/config.json"));
    assert!(trace.contains("decode-json Config"));
    // Insert-specific effects come *after* the decode — proves
    // the trace walked past the boundary.
    assert!(trace.contains("random-bytes 32"));
    assert!(trace.contains("now"));
    assert!(trace.contains("encode-json Content"));
    assert!(trace.contains("encrypt"));
    // Hash + recipient fingerprint show up inside the entry-file
    // path, derived in plain Rust now (no DSL round-trip).
    let expected_hash = EntryPath::new("ops/api").hash().0;
    let expected_fp = stub_recipient().fingerprint().0;
    assert!(
        trace.contains(&expected_hash) && trace.contains(&expected_fp),
        "entry path should embed the real hash + fingerprint:\n{trace}"
    );
    assert!(trace.contains("write"));
    assert!(trace.contains("shell `git add -A"));
    assert!(trace.contains("shell `git -c"));
    assert!(trace.contains("commit"));
}

/// `allow` includes a deliberate `exists?` UX gate (so Live can
/// surface a clean "no entry for X" instead of relying on
/// read_file's path-only error). Plan's `exists?` defaults to
/// `false`, so the trace dead-ends at that gate — *but* it still
/// walks past the config decode, which is the property the
/// typed-stubs registry is responsible for. Assert exactly that
/// shape, not a fictional walkthrough.
#[test]
fn allow_walks_past_config_decode_then_hits_existence_gate() {
    let plan = plan_with_fixtures();
    let plan: PlanNode<()> = commands::allow(
        plan,
        commands::allow::AllowArgs {
            root: "/tmp/rageveil-plan-test".into(),
            path: EntryPath::new("shared"),
            recipients: vec![RecipientSpec::new("age1guestrecipient".to_string())],
        },
    );
    let trace = plan.render_text();
    println!("--- allow trace ---\n{trace}-------------------");

    // Property A: walked past the config decode (registry works).
    assert!(trace.contains("decode-json Config"));
    // Property B: derived the entry-file path from real hash +
    // real fingerprint of the registered whoami.
    let expected_hash = EntryPath::new("shared").hash().0;
    let expected_fp = stub_recipient().fingerprint().0;
    assert!(trace.contains(&expected_hash));
    assert!(trace.contains(&expected_fp));
    // Property C: dead-end at the existence gate is the deliberate
    // UX behaviour, not a Plan bug. The trace records `exists?`
    // and the resulting `fail` line.
    assert!(trace.contains("exists?"));
    assert!(
        trace.contains("no entry for shared"),
        "expected the existence-gate error, got:\n{trace}"
    );
}

#[test]
fn list_renders_index_lookup() {
    let plan = plan_with_fixtures();
    let plan: PlanNode<()> = commands::list(
        plan,
        commands::list::ListArgs { root: "/tmp/rageveil-plan-test".into() },
    )
    .bind(|_names| PlanNode::Pure(()));
    let trace = plan.render_text();
    println!("--- list trace ---\n{trace}------------------");

    // Index is registered; with `exists?` stubbed `false` the
    // command short-circuits to an empty Vec without touching
    // index.json. That's the honest happy-path: `exists?` returns
    // its default (`false`) and the trace stops there.
    assert!(trace.contains("exists? /tmp/rageveil-plan-test/index.json"));
}

#[test]
fn stdout_effect_is_labelled() {
    let s = Plan::new();
    let plan: PlanNode<()> = s.stdout(b"hello\n".to_vec());
    let trace = plan.render_text();
    println!("--- stdout-only trace ---\n{trace}-------------------------");
    assert!(trace.contains("stdout (6 bytes)"));
}

/// `handle` lifts an upstream `fail` into the value channel —
/// proves traversal continues even when the wrapped subprogram
/// would have aborted.
#[test]
fn handle_recovers_fail_into_value() {
    let s = Plan::new();
    // Build: handle(fail("boom")) — the program would otherwise
    // be a single Fail leaf. After handle, it's Pure(Err("boom")).
    let inner: PlanNode<i32> = s.fail("boom".to_string());
    let recovered: PlanNode<Result<i32, String>> = s.handle(inner);
    let trace = recovered.render_text();
    println!("--- handle trace ---\n{trace}--------------------");
    // `Pure(_)` renders as `└ pure` — proves we no longer hit Fail.
    assert!(trace.contains("pure"));
    assert!(!trace.contains("fail"));
}
