//! `rageveil` CLI.
//!
//! Thin shell: parses argv, *builds a single program tree* via
//! [`build_program`] generic over `S: Vault`, then either runs
//! it under [`Live`] or renders it under [`Plan`]. There is no
//! direct `print!` / `println!` here — output goes through
//! [`Vault::stdout`] so a Plan trace shows it.

use anyhow::{anyhow, Context, Result};
use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use rageveil_core::commands;
use rageveil_core::types::{EntryPath, RecipientSpec, Salt};
use rageveil_core::{vault_do, Config, Content, Index, Live, Metadata, Plan, Vault};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "rageveil", version, about = "git+age password manager")]
struct Cli {
    /// Store root. Defaults to `$HOME/.rageveil`.
    #[arg(long, env = "RAGEVEIL_STORE")]
    store: Option<PathBuf>,

    /// Render the program as a Plan AST instead of running it.
    /// Useful for "what would this do?" without touching disk or
    /// the network.
    #[arg(long, global = true)]
    plan: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Initialise a new store.
    Init {
        /// Path to an age private key file or OpenSSH private key
        /// (must have a sibling `.pub`).
        #[arg(long)]
        identity: PathBuf,
        /// Clone an existing remote that already holds a rageveil
        /// store. Pass any URL `git clone` accepts. Mutually
        /// exclusive with `--dumb-remote`.
        #[arg(long, conflicts_with = "dumb_remote")]
        remote: Option<String>,
        /// Bootstrap a brand-new bare repo at this SSH URL using
        /// only `ssh` + `git` on the remote — no rageveil install
        /// needed there. Two accepted shapes (same as git):
        /// `[user@]host:path` (SCP-style; path is home-relative)
        /// or `ssh://[user@]host[:port]/path` (path is absolute).
        /// For "put it in my home directory", use SCP-style:
        /// `host:.rageveil`. Mutually exclusive with `--remote`.
        #[arg(long)]
        dumb_remote: Option<String>,
    },
    /// Insert a secret. Pipe the payload via `--batch` or pass
    /// `--payload`.
    Insert {
        path: String,
        #[arg(long)]
        payload: Option<String>,
        #[arg(long)]
        batch: bool,
    },
    /// Decrypt and print a secret.
    Show { path: String },
    /// List entries in the local index.
    List,
    /// Share an entry with one or more additional recipients.
    Allow {
        path: String,
        #[arg(required = true)]
        recipients: Vec<String>,
    },
    /// Revoke shares for one or more recipients.
    Deny {
        path: String,
        #[arg(required = true)]
        recipients: Vec<String>,
    },
    /// Drop an entry entirely.
    Delete { path: String },
    /// Pull/push the underlying git repo and rebuild the local index.
    Sync {
        #[arg(long)]
        offline: bool,
    },
}

fn main() -> ExitCode {
    let mut cli = Cli::parse();
    let store = match resolve_store(&cli.store) {
        Some(p) => p,
        None => {
            eprintln!("rageveil: cannot locate store ($HOME unset?)");
            return ExitCode::FAILURE;
        }
    };

    // `rageveil insert PATH` with neither `--payload` nor `--batch`
    // is the interactive form — open `$EDITOR` on a temp file and
    // use whatever the user saves. Same shape passveil ships, and
    // it lives here at the binding layer rather than in the DSL
    // because the editor needs an inherited TTY (which `Vault::shell`
    // intentionally doesn't surface — it captures stdio to make
    // every other shell call introspectable).
    if let Cmd::Insert {
        ref mut payload,
        batch,
        ..
    } = cli.cmd
    {
        if payload.is_none() && !batch {
            match prompt_editor() {
                Ok(p) => *payload = Some(p),
                Err(e) => {
                    eprintln!("rageveil: {e:#}");
                    return ExitCode::FAILURE;
                }
            }
        }
    }

    let result: Result<()> = if cli.plan {
        let plan = build_program(plan_with_default_stubs(), store, cli.cmd);
        // Plan rendering is the only place the binary calls
        // `print!` directly — Plan AST text is strictly an
        // operator-facing diagnostic, not user-facing data.
        print!("{}", plan.render_text());
        Ok(())
    } else {
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("rageveil: tokio init: {e}");
                return ExitCode::FAILURE;
            }
        };
        let prog = build_program(Live::new(), store, cli.cmd);
        rt.block_on(prog)
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rageveil: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn resolve_store(explicit: &Option<PathBuf>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.clone());
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".rageveil"))
}

/// Open `$EDITOR` (falling back to `$VISUAL`) on a fresh temp file,
/// wait for the user to save+quit, return the trimmed contents.
///
/// Mirrors the passveil editor flow: empty content is treated as
/// "nothing to do" and aborts. Non-zero editor exit aborts. Both
/// stdio and TTY are inherited from the parent (the default for
/// `Command::status`), so vim/emacs/nano behave normally.
///
/// The temp file is auto-deleted on drop. The plaintext does land
/// in `$TMPDIR` briefly; for paranoid use cases pipe the secret in
/// via `--batch` instead — same caveat passveil ships with.
fn prompt_editor() -> Result<String> {
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .map_err(|_| {
            anyhow!(
                "$EDITOR not set; pass --payload or --batch (and pipe a secret in)"
            )
        })?;

    let temp = tempfile::Builder::new()
        .prefix("rageveil-")
        .suffix(".txt")
        .tempfile()
        .context("create editor tempfile")?;

    // `sh -c '<editor> "$1"' -- <path>` so any shell-arg-bearing
    // EDITOR (e.g. `vim -p`) works the same way it does for git.
    // The path goes through "$1" rather than being interpolated
    // into the script, so paths with spaces are safe.
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("--")
        .arg(temp.path())
        .status()
        .with_context(|| format!("spawn editor ({editor})"))?;

    if !status.success() {
        return Err(anyhow!(
            "editor exited with non-zero status; aborting insert"
        ));
    }

    let mut content = String::new();
    std::fs::File::open(temp.path())
        .context("reopen editor tempfile")?
        .read_to_string(&mut content)
        .context("read editor tempfile (not utf-8?)")?;

    let trimmed = content.trim_end_matches('\n').to_owned();
    if trimmed.is_empty() {
        return Err(anyhow!(
            "nothing to do (editor produced an empty secret)"
        ));
    }
    Ok(trimmed)
}

/// A [`Plan`] pre-loaded with stand-in fixtures for the types our
/// commands deserialise (`Config`, `Index`, `Content`). Without
/// these the renderer dead-ends at the first `decode_json` —
/// upstream stub bytes don't parse, and `--plan` would never
/// reach the per-recipient encrypt / write steps for `insert`,
/// `allow`, `deny`, etc. The values are obviously synthetic
/// (`age1plan-stub-…`, `<plan-stub-payload>`) so a reader doesn't
/// mistake the trace for a real run's output.
fn plan_with_default_stubs() -> Plan {
    let stub_recipient = RecipientSpec::new(
        "age1plan0stub00000000000000000000000000000000000000000000000000".to_string(),
    );
    let stub_now = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .single()
        .unwrap_or_else(Utc::now);
    let stub_metadata = Metadata::new(stub_recipient.clone(), stub_now);

    Plan::new()
        .with_stub(&Config {
            whoami: stub_recipient.clone(),
            identity_path: PathBuf::from("/plan-stub/identity.txt"),
        })
        .with_stub(&Index::empty())
        .with_stub(&Content {
            path: EntryPath::new("<plan-stub>"),
            salt: Salt(String::new()),
            payload: "<plan-stub-payload>".into(),
            metadata: stub_metadata,
        })
}

/// Build a single `S::R<()>`-shaped program for the chosen
/// subcommand. Both `--plan` and Live share this — Plan renders
/// the resulting AST, Live awaits it.
fn build_program<S>(s: S, store: PathBuf, cmd: Cmd) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    use commands::*;
    match cmd {
        Cmd::Init { identity, remote, dumb_remote } => {
            // clap's `conflicts_with` rules out the (Some, Some)
            // case at parse time; the remaining shapes map 1:1
            // onto the `InitRemote` enum.
            let remote = match (remote, dumb_remote) {
                (Some(url), None) => init::InitRemote::Clone(url),
                (None, Some(url)) => init::InitRemote::DumbBootstrap(url),
                (None, None) => init::InitRemote::None,
                (Some(_), Some(_)) => init::InitRemote::None, // unreachable in practice
            };
            init(
                s,
                init::InitArgs {
                    root: store,
                    identity_path: identity,
                    remote,
                },
            )
        }
        Cmd::Insert { path, payload, batch } => insert(
            s,
            insert::InsertArgs {
                root: store,
                path: EntryPath::new(path),
                payload,
                payload_from_stdin: batch,
            },
        ),
        // ↑ The "no flags" → editor case is handled before
        //   build_program is called (see `main`); by the time we
        //   get here, `payload` is `Some(...)` or `batch` is true.
        Cmd::Show { path } => {
            let s2 = s.clone();
            vault_do! { s ;
                let out = show::show(s2.clone(), show::ShowArgs {
                    root: store,
                    path: EntryPath::new(path),
                }) ;
                emit_payload(s2.clone(), out.content.payload)
            }
        }
        Cmd::List => {
            let s2 = s.clone();
            vault_do! { s ;
                let names = list::list(s2.clone(), list::ListArgs { root: store }) ;
                emit_lines(s2.clone(), names)
            }
        }
        Cmd::Allow { path, recipients } => allow(
            s,
            allow::AllowArgs {
                root: store,
                path: EntryPath::new(path),
                recipients: recipients.into_iter().map(RecipientSpec::new).collect(),
            },
        ),
        Cmd::Deny { path, recipients } => deny(
            s,
            deny::DenyArgs {
                root: store,
                path: EntryPath::new(path),
                recipients: recipients.into_iter().map(RecipientSpec::new).collect(),
            },
        ),
        Cmd::Delete { path } => delete(
            s,
            delete::DeleteArgs { root: store, path: EntryPath::new(path) },
        ),
        Cmd::Sync { offline } => sync(s, sync::SyncArgs { root: store, offline }),
    }
}

/// Emit a single payload line, terminated with `\n` if the
/// payload doesn't already end in one. Mirrors what `show` would
/// print to a TTY pipeline.
fn emit_payload<S>(s: S, payload: String) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let mut bytes = payload.into_bytes();
    if bytes.last() != Some(&b'\n') {
        bytes.push(b'\n');
    }
    s.stdout(bytes)
}

/// Emit a `Vec<String>` as newline-terminated lines, in iteration
/// order. Implemented as a chain of `stdout` effects so a Plan
/// trace shows one line per emit.
fn emit_lines<S>(s: S, lines: Vec<String>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    fn go<S>(s: S, mut iter: std::vec::IntoIter<String>) -> S::R<()>
    where
        S: Vault + Clone + Send + Sync + 'static,
    {
        match iter.next() {
            None => s.pure(()),
            Some(head) => {
                let mut bytes = head.into_bytes();
                bytes.push(b'\n');
                let s2 = s.clone();
                vault_do! { s ;
                    let _ = s.stdout(bytes) ;
                    go(s2, iter)
                }
            }
        }
    }
    let s2 = s.clone();
    go(s2, lines.into_iter())
}
