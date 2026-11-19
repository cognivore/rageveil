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
    vault_do, Config, Content, EntryName, Index, Live, Metadata, Plan, StoreLayout, Vault,
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
    /// `--payload`. Encrypted to you and, if your key is in a
    /// persona group, to your other devices as well. A new entry's
    /// PATH must be SERVICE/ACCOUNT[/PURPOSE][/MISC]*: SERVICE the
    /// host that asks for the secret, every part made of letters,
    /// digits and `. _ - @ +`.
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
        /// Make the entry human-only from the start: no plain key ever
        /// holds it, so it is never exposed. Needs a gated key among
        /// your devices, such as your Touch ID key.
        #[arg(long)]
        noauto: bool,
    },
    /// List the entry names in the local index that do not fit
    /// SERVICE/ACCOUNT[/PURPOSE][/MISC]*, each with why, and fail when
    /// there is one. Such entries keep working under their names; new
    /// entries must fit. Reads only the index, never decrypts. (Draft.)
    CheckNames,
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
    /// List entries in the local index. A human-only entry is marked
    /// on the right, after its path, and so is one whose value a plain
    /// key once held and that still needs rotating.
    ///
    /// A tree of the paths' parts by default; `--no-tree` (`-nt`) prints
    /// one whole path per line, `--no-descriptors` (`-nd`) leaves the
    /// marks out. Both together print bare paths, to paste or pipe.
    List {
        /// One whole path per line instead of a tree.
        #[arg(long = "no-tree")]
        no_tree: bool,
        /// Leave out the marks after each path.
        #[arg(long = "no-descriptors")]
        no_descriptors: bool,
        /// Deprecated: the same as `--no-tree --no-descriptors`.
        #[arg(long, hide = true)]
        no_decoration: bool,
    },
    /// List entries whose path contains QUERY (case-insensitive).
    /// Reads only the local index — like `list`, never decrypts.
    Search { query: String },
    /// Audit an entry's trust history: who it was created/updated by,
    /// who is trusted now, everyone who has ever had access, and the
    /// full allow/deny log. Reads the local index — never decrypts.
    Info { path: String },
    /// Share an entry with one or more additional recipients. Each
    /// recipient is a raw key (`age1…`, `ssh-ed25519 …`) or a name read
    /// as a node of the people tree (see `persona tree`): a person
    /// reaches all their keys, a device (`jons-macbook`) all of its keys,
    /// a key's own name (`jons-iphone`) that key alone. A human-only
    /// entry gives plain keys a name card only, not the secret.
    Allow {
        path: String,
        #[arg(required = true)]
        recipients: Vec<String>,
    },
    /// Revoke one entry's shares for one or more recipients.
    /// Recipients are raw keys or names read as in `allow`: a person
    /// revokes all their keys, a device its keys, a key itself alone. To take a
    /// device or person off every entry at once, use `revoke`.
    Deny {
        path: String,
        #[arg(required = true)]
        recipients: Vec<String>,
    },
    /// Take a device, or a whole person, out of the vault: its key
    /// comes off every entry that trusts it (logged as a deny, so
    /// `info` shows it), and its name leaves the address book and its
    /// persona group. A device name revokes that device only — the
    /// rest of its persona keeps its access; a persona's canonical
    /// name revokes every device and drops the group; a raw key
    /// revokes that key and any name bound to it. Refuses to revoke
    /// your own key. Commits locally; `sync` publishes. Run `sync`
    /// first so every entry you can read is in the index.
    Revoke {
        #[arg(required = true, value_name = "NAME")]
        names: Vec<String>,
    },
    /// Manage the shared address book (name → recipient key) that
    /// `allow`/`deny` resolve names against. Stored in the git
    /// working tree, so additions sync to every collaborator.
    Address {
        #[command(subcommand)]
        cmd: AddressCmd,
    },
    /// Group several address-book names as one person, so `allow` and
    /// `deny` on the person's name reach every key they carry, and a new
    /// secret made on one of their keys reaches the others.
    Persona {
        #[command(subcommand)]
        cmd: PersonaCmd,
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
    /// Rename an entry, keeping who may read it, its trust log, its
    /// tier and its exposure. The new name must fit
    /// SERVICE/ACCOUNT[/PURPOSE]; a human-only entry asks for Touch ID.
    /// Whatever refers to the old name must change with it.
    Move { from: String, to: String },
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
        /// Also open human-only entries this laptop has not seen yet,
        /// which asks for Touch ID once for each.
        #[arg(long)]
        touch: bool,
    },
    /// Make entries automation-tolerant again: every trusted key holds a
    /// copy, a laptop's plain key included, so anything running as you —
    /// an AI agent too — can read them without a finger. Opening a
    /// human-only entry to do this asks for Touch ID.
    Auto {
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Make an entry human-only: only gated keys — Touch ID keys and
    /// phones — keep a copy, so opening it takes a finger. A plain key
    /// that held it can still read the old value in the store's git
    /// history, so `noauto` then rotates it, as `rotate` does. With
    /// `--force` it skips the rotation, and `list` and `info` show the
    /// entry as exposed until it is rotated.
    Noauto {
        #[arg(required = true)]
        paths: Vec<String>,
        /// Change the tier without rotating. Allows several paths.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        value: NewValue,
    },
    /// Replace a secret: open a Kagi search for how to change the
    /// password at its service (the path up to the first `/`), then
    /// store the new value, keeping who may read the entry and its tier.
    /// The new value is given as for `insert`; with none, `$EDITOR`
    /// opens on an empty buffer. Clears the entry's exposure.
    Rotate {
        path: String,
        #[command(flatten)]
        value: NewValue,
        /// Do not open the search in the browser.
        #[arg(long)]
        no_open: bool,
    },
    /// Give human-only entries made before name cards existed their
    /// cards, so that every laptop lists them without a finger, and every
    /// device of yours its copy. Opens each entry that has no card for
    /// this laptop once, with Touch ID, rewrites it to all your devices
    /// (gated ones get the secret, plain keys a name card), and commits;
    /// `sync` publishes.
    Cards,
    /// Use a Secure Enclave key as this laptop's Touch ID key. Make one
    /// with `age-plugin-se keygen --access-control any-biometry -o FILE`;
    /// this prints its recipient, which you then add to the address book
    /// and group under yourself with `persona add`.
    Touch {
        /// The identity file `age-plugin-se keygen` wrote.
        identity: PathBuf,
    },
    /// Use a TPM key as this laptop's human-only key (Linux; draft), as
    /// `touch` uses a Secure Enclave key on a Mac. Make one with
    /// `age-plugin-tpm --generate --pin -o FILE`: a key without a PIN is
    /// refused. This prints its recipient (`age1tag1…`); add it to the
    /// address book as PERSON-DEVICE-tpm, group it under yourself with
    /// `persona add`, and `gate` it.
    Tpm {
        /// The identity file `age-plugin-tpm --generate --pin` wrote.
        identity: PathBuf,
    },
    /// Mark address-book names as gated: device keys that a person's
    /// biometrics guard, such as a phone's, which may hold human-only
    /// entries. Secure Enclave keys are gated by what they are; an
    /// accepted invite gates its device by itself.
    Gate {
        #[arg(required = true)]
        names: Vec<String>,
        /// Take the names off the list instead.
        #[arg(long)]
        remove: bool,
    },
}

/// A replacement value, given the ways `insert` takes one.
#[derive(clap::Args, Debug, Clone, Default)]
struct NewValue {
    /// The new value itself.
    #[arg(long, conflicts_with_all = ["batch", "generate"])]
    payload: Option<String>,
    /// Read the new value from stdin.
    #[arg(long, conflicts_with = "generate")]
    batch: bool,
    /// Generate a new value of LEN characters and print it.
    #[arg(long, value_name = "LEN")]
    generate: Option<usize>,
    /// Leave punctuation out of a generated value.
    #[arg(long, requires = "generate")]
    no_symbols: bool,
    /// Set when the search was already opened, before `$EDITOR` ran.
    #[arg(skip)]
    searched: bool,
}

impl NewValue {
    fn given(&self) -> bool {
        self.payload.is_some() || self.batch || self.generate.is_some()
    }
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
    /// Show every registered key as a tree: each person, their devices
    /// and each device's keys by kind, with every key in full, then the
    /// names in no group. `--no-tree` (`-nt`) prints one `name<TAB>key`
    /// per line; `--no-descriptors` (`-nd`) leaves the keys out.
    List {
        /// One `name<TAB>key` per line instead of a tree.
        #[arg(long = "no-tree")]
        no_tree: bool,
        /// Leave the keys out: names only.
        #[arg(long = "no-descriptors")]
        no_descriptors: bool,
    },
    /// Remove a name from the address book. Existing shares stay;
    /// use `revoke` to take the device off every entry too.
    Remove { name: String },
    /// Rename one key, keeping its key and its place in a person's
    /// group: `rageveil address rename phone jons-iphone`. Keys are
    /// named PERSON-DEVICE-KIND (touch, touchssh, tpm, ssh, humanssh),
    /// PERSON-DEVICE for a device with one key, or PERSON-NAME for a key
    /// outside any device, such as a YubiKey. Entries and their sharing do not
    /// change. An administrator's change: it is signed and pushed like
    /// `address add`.
    Rename {
        from: String,
        to: String,
        /// Waive the dedicated-host check, as `address add --force` does.
        #[arg(short = 'f', long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum PersonaCmd {
    /// Put address-book names under one canonical name, then share
    /// every entry any of them already holds to the rest.
    /// `rageveil persona add lucia lucia-work-phone`.
    Add {
        /// The name the person is known by. Need not have a key of
        /// its own.
        canonical: String,
        /// Address-book names that are the same person.
        #[arg(required = true)]
        members: Vec<String>,
    },
    /// Take names out of a group, or drop the group when none are
    /// named. Existing shares stay; use `revoke` to take a device or
    /// person off every entry.
    Remove {
        canonical: String,
        members: Vec<String>,
    },
    /// List every group, one `canonical<TAB>member member…` per line.
    List,
    /// Rename a person: their group, and every key of theirs whose name
    /// begins with `FROM-`, which then begins with `TO-`. Keys named
    /// otherwise stay as they are and are listed, for `address rename`.
    /// An administrator's change, signed and pushed in one commit.
    Rename {
        from: String,
        to: String,
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Show every person as a tree: their devices and each device's
    /// keys, read from the names, then the names in no group.
    Tree,
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

/// The two-letter short spellings of the listing flags, `-nt` and `-nd`,
/// which clap's one-letter shorts cannot spell, read as their long forms.
/// Only after a `list` word (`rageveil list`, `rageveil address list`),
/// only those exact words, and never after `--`, so no other command's
/// arguments can be rewritten.
fn expand_short_flags(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Vec<std::ffi::OsString> {
    let mut listing = false;
    let mut past_dashes = false;
    args.into_iter()
        .map(|a| {
            match a.to_str() {
                _ if past_dashes => a,
                Some("--") => {
                    past_dashes = true;
                    a
                }
                Some("list") => {
                    listing = true;
                    a
                }
                Some("-nt") if listing => "--no-tree".into(),
                Some("-nd") if listing => "--no-descriptors".into(),
                _ => a,
            }
        })
        .collect()
}

fn main() -> ExitCode {
    let mut cli = Cli::parse_from(expand_short_flags(std::env::args_os()));
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
    //
    // A new entry's name is checked first, so nobody types a secret
    // only to have it refused.
    if let Cmd::Insert {
        ref path,
        ref mut payload,
        batch,
        generate,
        ..
    } = cli.cmd
        && payload.is_none()
        && !batch
        && generate.is_none()
    {
        let entry = EntryPath::new(path.clone());
        if let Err(why) = EntryName::try_from(&entry)
            && !StoreLayout::new(store.clone()).entry_dir(&entry.hash()).exists()
        {
            eprintln!("rageveil: {}", commands::insert::refusal(&entry, &why));
            return ExitCode::FAILURE;
        }
        match prompt_editor() {
            Ok(p) => *payload = Some(p),
            Err(e) => {
                eprintln!("rageveil: {e:#}");
                return ExitCode::FAILURE;
            }
        }
    }

    // `rotate`, and `noauto` without `--force`, take a new value. With
    // none given, open the search first, so the person can find the
    // service's page, and then ask for the value in `$EDITOR`.
    if !cli.plan {
        let pending = match &mut cli.cmd {
            Cmd::Rotate { path, value, no_open } if !value.given() => {
                Some((path.clone(), value, !*no_open))
            }
            Cmd::Noauto { paths, force: false, value } if !value.given() && paths.len() == 1 => {
                Some((paths[0].clone(), value, true))
            }
            _ => None,
        };
        if let Some((path, value, open)) = pending {
            if open {
                open_search_now(&path);
            }
            value.searched = true;
            match prompt_editor() {
                Ok(p) => value.payload = Some(p),
                Err(e) => {
                    eprintln!("rageveil: {e:#}");
                    return ExitCode::FAILURE;
                }
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
        // `rageveil list | head`: the reader took what it wanted and left.
        // That is how a pipe ends, not a failure to report.
        Err(e) if reader_left(&e) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rageveil: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Whether `e` is stdout's reader closing the pipe.
fn reader_left(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
    })
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
            touch: None,
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
        Cmd::Insert { path, payload, batch, generate, no_symbols, noauto } => insert::insert_checked(
            s,
            insert::InsertArgs {
                root: store,
                path: EntryPath::new(path),
                payload,
                payload_from_stdin: batch,
                generate,
                symbols: !no_symbols,
                tier: if noauto {
                    rageveil_core::tier::Tier::Human
                } else {
                    rageveil_core::tier::Tier::Automation
                },
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
        Cmd::List { no_tree, no_descriptors, no_decoration } => {
            let layout = list::Layout {
                tree: !(no_tree || no_decoration),
                descriptors: !(no_descriptors || no_decoration),
            };
            let s2 = s.clone();
            vault_do! { s ;
                let entries = list::list_marked(s2.clone(), list::ListArgs { root: store.clone() }) ;
                let unopened = list::unopened_human_only(s2.clone(), list::ListArgs { root: store }) ;
                let _ = emit_lines(s2.clone(), list::render(&entries, layout)) ;
                match list::unopened_hint(unopened) {
                    None => s2.pure(()),
                    Some(hint) => s2.log(hint),
                }
            }
        }
        Cmd::CheckNames => {
            let s2 = s.clone();
            vault_do! { s ;
                let report = names::unfit_names(s2.clone(), names::NamesArgs { root: store }) ;
                let _ = emit_lines(s2.clone(), report.lines()) ;
                match report.unfit.is_empty() {
                    true => s2.log(report.summary()),
                    false => s2.fail(report.summary()),
                }
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
                let resolved = address::resolve_deny_recipients(s2.clone(), ab_path, recipients) ;
                deny(s2.clone(), deny::DenyArgs { root: store, path: ep, recipients: resolved })
            }
        }
        Cmd::Revoke { names } => revoke(s, revoke::RevokeArgs { root: store, names }),
        Cmd::Address { cmd } => build_address_program(s, store, cmd),
        Cmd::Persona { cmd } => build_persona_program(s, store, cmd),
        Cmd::Invite { cmd, name, ttl_hours, force } => {
            let cmd = match (cmd, name) {
                (Some(c), _) => c,
                (None, Some(name)) => InviteCmd::Issue { name, ttl_hours, force },
                (None, None) => InviteCmd::Status,
            };
            build_invite_program(s, store, cmd)
        }
        Cmd::Move { from, to } => move_entry(
            s,
            move_entry::MoveArgs { root: store, from: EntryPath::new(from), to: EntryPath::new(to) },
        ),
        Cmd::Delete { path } => delete(
            s,
            delete::DeleteArgs { root: store, path: EntryPath::new(path) },
        ),
        Cmd::Sync { offline, reindex, touch } => sync(
            s,
            sync::SyncArgs { root: store, offline, reindex, touch },
        ),
        Cmd::Auto { paths } => retier_each(s, store, rageveil_core::tier::Tier::Automation, paths),
        Cmd::Noauto { paths, force: true, .. } => {
            retier_each(s, store, rageveil_core::tier::Tier::Human, paths)
        }
        Cmd::Noauto { mut paths, force: false, value } => match paths.len() {
            1 => {
                let path = paths.remove(0);
                let s2 = s.clone();
                let store2 = store.clone();
                let open = !value.searched;
                vault_do! { s ;
                    let _ = retier_each(s2.clone(), store, rageveil_core::tier::Tier::Human, vec![path.clone()]) ;
                    rotate_with(s2.clone(), store2, path, value, open)
                }
            }
            _ => s.fail(
                "noauto rotates each entry it changes, one at a time: give one path, \
                 or pass --force to change several without rotating"
                    .into(),
            ),
        },
        Cmd::Rotate { path, value, no_open } => {
            let open = !no_open && !value.searched;
            rotate_with(s, store, path, value, open)
        }
        Cmd::Cards => commands::cards(s, commands::cards::CardsArgs { root: store }),
        Cmd::Touch { identity } => {
            let s2 = s.clone();
            vault_do! { s ;
                let recipient = commands::touch(s2.clone(), commands::tier::TouchArgs {
                    root: store,
                    identity_path: identity,
                }) ;
                emit_lines(s2.clone(), vec![recipient.0])
            }
        }
        Cmd::Tpm { identity } => {
            let s2 = s.clone();
            vault_do! { s ;
                let recipient = commands::tpm(s2.clone(), commands::tier::TouchArgs {
                    root: store,
                    identity_path: identity,
                }) ;
                emit_lines(s2.clone(), vec![recipient.0])
            }
        }
        Cmd::Gate { names, remove } => commands::gate(
            s,
            commands::tier::GateArgs { root: store, names, gated: !remove },
        ),
    }
}

/// Store a new value for `path` the way `rotate` does.
fn rotate_with<S>(s: S, store: PathBuf, path: String, value: NewValue, open: bool) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    commands::rotate(
        s,
        commands::rotate::RotateArgs {
            root: store,
            path: EntryPath::new(path),
            payload: value.payload,
            payload_from_stdin: value.batch,
            generate: value.generate,
            symbols: !value.no_symbols,
            open,
        },
    )
}

/// Open the rotation search from the binding layer, before `$EDITOR`
/// takes the terminal. A missing browser is not an error.
fn open_search_now(path: &str) {
    let url = rageveil_core::exposure::rotation_search_url(&EntryPath::new(path));
    eprintln!("rageveil: how to change it: {url}");
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    if !std::process::Command::new(opener)
        .arg(&url)
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
    {
        eprintln!("rageveil: could not open a browser with `{opener}`; open the address above");
    }
}

/// Change the tier of each path in turn; stop at the first refusal so
/// nothing after it changes unseen.
fn retier_each<S>(s: S, store: PathBuf, tier: rageveil_core::tier::Tier, paths: Vec<String>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let mut iter = paths.into_iter();
    match iter.next() {
        None => s.pure(()),
        Some(path) => {
            let s2 = s.clone();
            let store2 = store.clone();
            let rest: Vec<String> = iter.collect();
            vault_do! { s ;
                let _ = commands::tier(s2.clone(), commands::tier::TierArgs {
                    root: store,
                    path: EntryPath::new(path),
                    tier,
                }) ;
                retier_each(s2, store2, tier, rest)
            }
        }
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
        AddressCmd::Rename { from, to, force } => commands::address_rename(
            s,
            commands::rename::RenameArgs { root: store, from, to, force },
        ),
        AddressCmd::List { no_tree: true, no_descriptors } => {
            let s2 = s.clone();
            vault_do! { s ;
                let entries = address::address_list(
                    s2.clone(),
                    address::AddressListArgs { root: store },
                ) ;
                match no_descriptors {
                    true => emit_lines(s2.clone(), entries.into_iter().map(|(n, _)| n).collect()),
                    false => emit_address_lines(s2.clone(), entries),
                }
            }
        }
        AddressCmd::List { no_tree: false, no_descriptors } => {
            let s2 = s.clone();
            vault_do! { s ;
                let lines = commands::address_tree(s2.clone(), store, !no_descriptors) ;
                emit_lines(s2.clone(), lines)
            }
        }
    }
}

/// Dispatch the `persona` subcommand.
fn build_persona_program<S>(s: S, store: PathBuf, cmd: PersonaCmd) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    use commands::persona;
    match cmd {
        PersonaCmd::Add { canonical, members } => persona::persona_add(
            s,
            persona::PersonaAddArgs { root: store, canonical, members },
        ),
        PersonaCmd::Remove { canonical, members } => persona::persona_remove(
            s,
            persona::PersonaRemoveArgs { root: store, canonical, members },
        ),
        PersonaCmd::Rename { from, to, force } => commands::persona_rename(
            s,
            commands::rename::RenameArgs { root: store, from, to, force },
        ),
        PersonaCmd::Tree => {
            let s2 = s.clone();
            vault_do! { s ;
                let lines = commands::persona_tree(s2.clone(), store) ;
                emit_lines(s2.clone(), lines)
            }
        }
        PersonaCmd::List => {
            let s2 = s.clone();
            vault_do! { s ;
                let groups = persona::persona_list(
                    s2.clone(),
                    persona::PersonaListArgs { root: store },
                ) ;
                emit_lines(
                    s2.clone(),
                    groups
                        .into_iter()
                        .map(|(c, m)| format!("{c}\t{}", m.join(" ")))
                        .collect(),
                )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<std::ffi::OsString> {
        words.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn two_letter_shorts_read_as_their_long_flags() {
        assert_eq!(
            expand_short_flags(args(&["rageveil", "list", "-nt", "-nd"])),
            args(&["rageveil", "list", "--no-tree", "--no-descriptors"])
        );
        assert_eq!(
            expand_short_flags(args(&["rageveil", "list", "--", "-nt"])),
            args(&["rageveil", "list", "--", "-nt"])
        );
        assert_eq!(
            expand_short_flags(args(&["rageveil", "insert", "-nt"])),
            args(&["rageveil", "insert", "-nt"]),
            "only a listing reads them"
        );
        let cli = Cli::parse_from(expand_short_flags(args(&[
            "rageveil", "address", "list", "-nt", "-nd",
        ])));
        assert!(matches!(
            cli.cmd,
            Cmd::Address { cmd: AddressCmd::List { no_tree: true, no_descriptors: true } }
        ));
    }
}
