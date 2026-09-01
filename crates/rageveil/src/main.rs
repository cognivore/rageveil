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
use rageveil_core::{
    vault_do, Config, Content, Index, Live, Metadata, Plan, StoreLayout, Vault,
};
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
        /// exclusive with `--lightweight-node`.
        #[arg(long, conflicts_with = "lightweight_node")]
        remote: Option<String>,
        /// Bootstrap a brand-new bare repo at this SSH URL — the
        /// remote runs only `ssh` + `git`, no rageveil install
        /// needed. Two accepted URL shapes (same as git):
        /// `[user@]host:path` (SCP-style; path is home-relative)
        /// or `ssh://[user@]host[:port]/path` (path is absolute).
        /// For "put it in my home directory", use SCP-style:
        /// `host:.rageveil`. Mutually exclusive with `--remote`.
        #[arg(long)]
        lightweight_node: Option<String>,
    },
    /// Insert a secret. Pipe the payload via `--batch` or pass
    /// `--payload`.
    Insert {
        path: String,
        #[arg(long, conflicts_with_all = ["batch", "generate"])]
        payload: Option<String>,
        #[arg(long, conflicts_with = "generate")]
        batch: bool,
        /// Generate a random secret of LEN characters instead of
        /// typing one, and print it so you can paste it where it is
        /// needed. Drawn from letters and digits without modulo
        /// bias — roughly 5.95 bits per character, so 29 is ~172
        /// bits.
        #[arg(long, value_name = "LEN")]
        generate: Option<usize>,
        /// Leave punctuation out of a generated secret, for a field
        /// that rejects it. Symbols are otherwise included.
        #[arg(long, requires = "generate")]
        no_symbols: bool,
    },
    /// Change an entry's value, preserving its trust history (the
    /// allow/deny log and the "insiders ever" audit) and re-keying
    /// everyone currently trusted — unlike re-running `insert`,
    /// which resets the entry to the operator alone. Pass the new
    /// value via `--payload`, pipe it via `--batch`, or omit both to
    /// edit the current value in `$EDITOR`.
    Edit {
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
    /// List entries whose path contains QUERY (case-insensitive).
    /// Reads only the local index — like `list`, never decrypts.
    Search { query: String },
    /// Audit an entry's trust history: who it was created/updated by,
    /// who is trusted now, everyone who has ever had access, and the
    /// full allow/deny log. Reads the local index — never decrypts.
    Info { path: String },
    /// Share an entry with one or more additional recipients. Each
    /// recipient is either a raw key (`age1…`, `ssh-ed25519 …`) or a
    /// name registered in the address book (see `rageveil address`).
    Allow {
        path: String,
        #[arg(required = true)]
        recipients: Vec<String>,
    },
    /// Revoke shares for one or more recipients. Recipients may be
    /// raw keys or address-book names, same as `allow`.
    Deny {
        path: String,
        #[arg(required = true)]
        recipients: Vec<String>,
    },
    /// Manage the shared address book (name → recipient key) that
    /// `allow`/`deny` resolve names against. Stored in the git
    /// working tree, so additions sync to every collaborator.
    Address {
        #[command(subcommand)]
        cmd: AddressCmd,
    },
    /// Issue, accept, revoke, or check device-enrollment invites.
    /// `rageveil invite NAME` mints a `visageveil://invite/…` URL
    /// whose bearer can submit a public key for NAME; `accept`
    /// enrolls the submitted key and revokes the invite's
    /// ephemeral transport key in the same pushed commit.
    Invite {
        #[command(subcommand)]
        cmd: Option<InviteCmd>,
        /// Shorthand: `rageveil invite NAME` == `rageveil invite issue NAME`.
        name: Option<String>,
        #[arg(long, default_value_t = 72)]
        ttl_hours: i64,
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Drop an entry entirely.
    Delete { path: String },
    /// Pull/push the underlying git repo and refresh the local index.
    /// Reports per-entry changes ([+] inserted, [-] removed, [*] modified,
    /// [!] updated) the same way passveil does.
    Sync {
        /// Skip the network round-trip (still refreshes the index).
        #[arg(long)]
        offline: bool,
        /// Drop the local index before refresh so every entry the
        /// operator can decrypt is reported as a fresh insert. Useful
        /// after manual filesystem fiddling.
        #[arg(long)]
        reindex: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum AddressCmd {
    /// Vouch for the address book as it stands, and require
    /// signatures on it from now on.
    ///
    /// Reads the book WITHOUT checking its signature — the one place
    /// that happens — because a store created before signing existed
    /// cannot otherwise adopt it: every reader demands a signature,
    /// and the command that would write one is a reader. Review
    /// `rageveil address list` first; whatever is in there becomes
    /// what the team trusts.
    Sign {
        /// Sign even if the store isn't backed by a `git@…` host.
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Register (or overwrite) a name → public-key mapping.
    Add {
        /// Short handle to refer to this recipient by (e.g. `pa`).
        /// Must be a single word and must not look like a raw key.
        name: String,
        /// The public key: an `age1…` recipient or an OpenSSH public
        /// key (`ssh-ed25519 AAAA…`). Multiple tokens are joined with
        /// spaces, so an unquoted ssh key works. Omit when using
        /// `--file`.
        key: Vec<String>,
        /// Read the public key from a file (e.g.
        /// `~/.ssh/id_ed25519.pub`) instead of the command line.
        #[arg(long, conflicts_with = "key")]
        file: Option<PathBuf>,
        /// Register the name even if the store isn't backed by the
        /// dedicated `git@…` host. Normally `add` refuses, because on
        /// that host the address book doubles as the SSH access list
        /// (its push hook rebuilds `authorized_keys`); elsewhere a
        /// registration grants no access. `--force` waives the check.
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// List every registered name → key, one `name<TAB>key` per line.
    List,
    /// Remove a name from the address book.
    Remove { name: String },
}

#[derive(Subcommand, Debug, Clone)]
enum InviteCmd {
    /// Mint an invite for NAME and print the URL to send them.
    Issue {
        /// Address-book name the invitee will enroll as.
        name: String,
        /// Hours until the invite payload expires (the app refuses
        /// an expired invite).
        #[arg(long, default_value_t = 72)]
        ttl_hours: i64,
        /// Waive the `git@…`-host requirement (grants no
        /// server-side access; useful against test remotes).
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Enroll the key an invitee submitted (run `sync` first).
    Accept {
        name: String,
        /// The digest the invitee read out to you (from their
        /// device's identity screen), e.g. `7c092cf144df0890` or
        /// `7c09 2cf1 44df 0890`. Refuses on mismatch.
        #[arg(long)]
        fingerprint: Option<String>,
    },
    /// Cancel a pending invite and revoke its transport key.
    Revoke { name: String },
    /// Pending invites and whether each has a response yet.
    Status,
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
        generate,
        ..
    } = cli.cmd
        && payload.is_none()
        && !batch
        && generate.is_none()
    {
        match prompt_editor() {
            Ok(p) => *payload = Some(p),
            Err(e) => {
                eprintln!("rageveil: {e:#}");
                return ExitCode::FAILURE;
            }
        }
    }

    let result: Result<()> = if cli.plan {
        // `--plan edit PATH` with no value can't decrypt the current
        // secret to seed an editor — a dry-run must not touch real
        // keys or disk — so render the flow against a synthetic value.
        if let Cmd::Edit {
            payload,
            batch: false,
            ..
        } = &mut cli.cmd
            && payload.is_none()
        {
            *payload = Some("<plan-stub-secret>".into());
        }
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

        // `rageveil edit PATH` with neither `--payload` nor `--batch`
        // is the interactive form. Unlike `insert`'s empty buffer, it
        // seeds the editor with the *current* secret — which means
        // decrypting it first, so (unlike the insert block above) it
        // runs here, after the runtime exists and never under `--plan`.
        if let Cmd::Edit {
            payload,
            batch: false,
            path,
        } = &mut cli.cmd
            && payload.is_none()
        {
            let seeded = rt
                .block_on(current_secret(store.clone(), path.clone()))
                .and_then(|cur| prompt_editor_with(Some(&cur)));
            match seeded {
                Ok(p) => *payload = Some(p),
                Err(e) => {
                    eprintln!("rageveil: {e:#}");
                    return ExitCode::FAILURE;
                }
            }
        }

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

/// Decrypt an entry's current value to seed the `edit` editor buffer
/// — a thin wrapper over the `show` program on [`Live`]. Surfaces
/// the same "no entry" error `show` would, so editing a missing path
/// fails before any editor opens.
async fn current_secret(store: PathBuf, path: String) -> Result<String> {
    let out = commands::show(
        Live::new(),
        commands::show::ShowArgs { root: store, path: EntryPath::new(path) },
    )
    .await
    .context("decrypt the current value to seed the editor")?;
    Ok(out.content.payload)
}

/// Open `$EDITOR` on an empty buffer — the `insert` interactive form.
fn prompt_editor() -> Result<String> {
    prompt_editor_with(None)
}

/// Open `$EDITOR` (falling back to `$VISUAL`) on a temp file,
/// optionally seeded with `initial` (the `edit` form loads the
/// current secret so it can be tweaked in place), wait for the user
/// to save+quit, return the trimmed contents.
///
/// Mirrors the passveil editor flow: empty content is treated as
/// "nothing to do" and aborts. Non-zero editor exit aborts. Both
/// stdio and TTY are inherited from the parent (the default for
/// `Command::status`), so vim/emacs/nano behave normally.
///
/// The temp file is auto-deleted on drop. The plaintext does land
/// in `$TMPDIR` briefly; for paranoid use cases pipe the secret in
/// via `--batch` instead — same caveat passveil ships with.
fn prompt_editor_with(initial: Option<&str>) -> Result<String> {
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

    if let Some(text) = initial {
        std::fs::write(temp.path(), text).context("seed editor tempfile")?;
    }

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
            "editor exited with non-zero status; aborting"
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
        Cmd::Init { identity, remote, lightweight_node } => {
            // clap's `conflicts_with` rules out the (Some, Some)
            // case at parse time; the remaining shapes map 1:1
            // onto the `InitRemote` enum.
            let remote = match (remote, lightweight_node) {
                (Some(url), None) => init::InitRemote::Clone(url),
                (None, Some(url)) => init::InitRemote::LightweightNode(url),
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
        Cmd::Insert { path, payload, batch, generate, no_symbols } => insert(
            s,
            insert::InsertArgs {
                root: store,
                path: EntryPath::new(path),
                payload,
                payload_from_stdin: batch,
                generate,
                symbols: !no_symbols,
            },
        ),
        // ↑ The "no flags" → editor case is handled before
        //   build_program is called (see `main`); by the time we
        //   get here, `payload` is `Some(...)` or `batch` is true.
        Cmd::Edit { path, payload, batch } => edit(
            s,
            edit::EditArgs {
                root: store,
                path: EntryPath::new(path),
                payload,
                payload_from_stdin: batch,
            },
        ),
        // ↑ Same "no flags" → editor handling as `insert`, except the
        //   buffer is seeded with the current secret first (see `main`).
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
        Cmd::Search { query } => {
            let s2 = s.clone();
            vault_do! { s ;
                let names = search::search(s2.clone(), search::SearchArgs { root: store, query }) ;
                emit_lines(s2.clone(), names)
            }
        }
        Cmd::Info { path } => {
            let s2 = s.clone();
            vault_do! { s ;
                let lines = info::info(s2.clone(), info::InfoArgs {
                    root: store,
                    path: EntryPath::new(path),
                }) ;
                emit_lines(s2.clone(), lines)
            }
        }
        // `allow`/`deny` take resolved `RecipientSpec`s; the CLI
        // accepts either raw keys or address-book names, so we thread
        // the tokens through `resolve_recipients` first — itself a DSL
        // effect, so `--plan` shows the address-book lookup too.
        Cmd::Allow { path, recipients } => {
            let ab_path = StoreLayout::new(store.clone()).addressbook_path();
            let ep = EntryPath::new(path);
            let s2 = s.clone();
            vault_do! { s ;
                let resolved = address::resolve_recipients(s2.clone(), ab_path, recipients) ;
                allow(s2.clone(), allow::AllowArgs { root: store, path: ep, recipients: resolved })
            }
        }
        Cmd::Deny { path, recipients } => {
            let ab_path = StoreLayout::new(store.clone()).addressbook_path();
            let ep = EntryPath::new(path);
            let s2 = s.clone();
            vault_do! { s ;
                let resolved = address::resolve_recipients(s2.clone(), ab_path, recipients) ;
                deny(s2.clone(), deny::DenyArgs { root: store, path: ep, recipients: resolved })
            }
        }
        Cmd::Address { cmd } => build_address_program(s, store, cmd),
        Cmd::Invite { cmd, name, ttl_hours, force } => {
            let cmd = match (cmd, name) {
                (Some(c), _) => c,
                (None, Some(name)) => InviteCmd::Issue { name, ttl_hours, force },
                (None, None) => InviteCmd::Status,
            };
            build_invite_program(s, store, cmd)
        }
        Cmd::Delete { path } => delete(
            s,
            delete::DeleteArgs { root: store, path: EntryPath::new(path) },
        ),
        Cmd::Sync { offline, reindex } => sync(
            s,
            sync::SyncArgs { root: store, offline, reindex },
        ),
    }
}

/// Dispatch the `address` subcommand. `add`/`remove` mutate and
/// commit the shared book; `list` prints `name<TAB>key` lines through
/// `stdout` (so a Plan trace shows the emits like every other
/// output).
fn build_address_program<S>(s: S, store: PathBuf, cmd: AddressCmd) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    use commands::address;
    match cmd {
        AddressCmd::Add { name, key, file, force } => {
            // Join unquoted ssh-key tokens (`ssh-ed25519 AAAA…`) back
            // into one recipient string; empty ⇒ rely on `--file`.
            let key = if key.is_empty() { None } else { Some(key.join(" ")) };
            address::address_add(
                s,
                address::AddressAddArgs { root: store, name, key, key_file: file, force },
            )
        }
        AddressCmd::Sign { force } => address::address_sign(
            s,
            address::AddressSignArgs { root: store, force },
        ),
        AddressCmd::Remove { name } => address::address_remove(
            s,
            address::AddressRemoveArgs { root: store, name },
        ),
        AddressCmd::List => {
            let s2 = s.clone();
            vault_do! { s ;
                let entries = address::address_list(
                    s2.clone(),
                    address::AddressListArgs { root: store },
                ) ;
                emit_address_lines(s2.clone(), entries)
            }
        }
    }
}

/// Dispatch the `invite` subcommand.
fn build_invite_program<S>(s: S, store: PathBuf, cmd: InviteCmd) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    use commands::invite;
    match cmd {
        InviteCmd::Issue { name, ttl_hours, force } => {
            let s2 = s.clone();
            vault_do! { s ;
                let payload = invite::invite_issue(
                    s2.clone(),
                    invite::InviteIssueArgs { root: store, name, ttl_hours, force },
                ) ;
                emit_invite_url_line(s2.clone(), payload)
            }
        }
        InviteCmd::Accept { name, fingerprint } => invite::invite_accept(
            s,
            invite::InviteAcceptArgs { root: store, name, expected_fingerprint: fingerprint },
        ),
        InviteCmd::Revoke { name } => invite::invite_revoke(
            s,
            invite::InviteRevokeArgs { root: store, name },
        ),
        InviteCmd::Status => {
            let s2 = s.clone();
            vault_do! { s ;
                let pending = invite::invite_status(
                    s2.clone(),
                    invite::InviteStatusArgs { root: store },
                ) ;
                emit_invite_status(s2.clone(), pending)
            }
        }
    }
}

/// Print the minted invite URL on stdout (the one machine-readable
/// line; everything narrative went to logs).
fn emit_invite_url_line<S>(s: S, payload: rageveil_core::InvitePayload) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    match payload.to_url() {
        Ok(url) => s.stdout(format!("{url}\n").into_bytes()),
        Err(e) => s.fail(format!("encode invite: {e:#}")),
    }
}

/// Render pending invites, one per line.
fn emit_invite_status<S>(s: S, pending: Vec<commands::invite::PendingInvite>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    if pending.is_empty() {
        return s.stdout(b"no pending invites\n".to_vec());
    }
    let mut out = String::new();
    for p in pending {
        let state = match (&p.responded, &p.fingerprint_digest) {
            (true, Some(digest)) => format!(
                "responded — key digest {digest} (have them read theirs aloud, then \
                 `rageveil invite accept {} --fingerprint '{digest}'`)",
                p.name
            ),
            (true, None) => "responded".to_owned(),
            _ => "waiting".to_owned(),
        };
        out.push_str(&format!("{}\t{}\n", p.name, state));
    }
    s.stdout(out.into_bytes())
}

/// Render the address book as `name<TAB>key` lines.
fn emit_address_lines<S>(s: S, entries: Vec<(String, RecipientSpec)>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let lines: Vec<String> = entries
        .into_iter()
        .map(|(name, key)| format!("{name}\t{}", key.as_str()))
        .collect();
    emit_lines(s, lines)
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
