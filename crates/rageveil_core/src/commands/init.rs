//! `rageveil init` — bring a store into existence.
//!
//! Inputs:
//!   * `root` — `~/.rageveil` by default.
//!   * `identity_path` — operator's age key file (or SSH private
//!     key); used to derive `whoami`.
//!   * `remote` — three modes (see [`InitRemote`]).
//!
//! Effects, in order: derive `whoami` from the identity, create
//! the root directory, write `config.json` and an empty
//! `index.json`, then set up the git working tree according to
//! the chosen remote mode (no remote → `git init` + seed; clone →
//! `git clone`; dumb-remote → ssh-bootstrap a bare repo on a
//! plain shell host, then `git init` + seed + push).

use crate::config::Config;
use crate::dsl::Vault;
use crate::index::Index;
use crate::store::StoreLayout;
use crate::sugar::write_json;
use crate::types::RecipientSpec;
use crate::{git, vault_do};

use std::path::PathBuf;

/// Three init shapes:
///   * `None` — local-only store, no upstream.
///   * `Clone(url)` — `git clone` from an existing remote that
///     *already* contains a rageveil store. Used when joining
///     someone else's vault.
///   * `DumbBootstrap(url)` — bring up a brand-new bare repo at
///     `url` over plain SSH (`git init --bare`), then push the
///     seed commit. The remote needs SSH + `git`; no rageveil
///     install.
#[derive(Clone, Debug)]
pub enum InitRemote {
    None,
    Clone(String),
    DumbBootstrap(String),
}

#[derive(Clone, Debug)]
pub struct InitArgs {
    pub root: PathBuf,
    pub identity_path: PathBuf,
    pub remote: InitRemote,
}

pub fn init<S>(s: S, args: InitArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let identity_path = args.identity_path.clone();
    let remote = args.remote.clone();

    vault_do! { s ;
        let exists = s.exists(layout.root.clone()) ;

        // Empty directory is fine — that's how `mkdir
        // ~/.rageveil && rageveil init` is expected to go. A
        // *non-empty* directory might be someone else's store;
        // refuse rather than clobbering. `mkdir_p` short-circuits
        // when the dir already exists, so a single call suffices.
        let _ = match exists {
            true  => bail_if_nonempty(s.clone(), layout.root.clone()),
            false => s.mkdir_p(layout.root.clone()),
        } ;
        let recipient = s.recipient_of(identity_path.clone()) ;
        let _ = write_initial_files(s.clone(), &layout, recipient, identity_path) ;
        let _ = init_git(s.clone(), &layout, remote) ;
        s.log(format!("rageveil store initialised at {}", layout.root.display()))
    }
}

fn bail_if_nonempty<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    root: PathBuf,
) -> S::R<()> {
    vault_do! { s ;
        let entries = s.list_dir(root.clone()) ;
        match entries.is_empty() {
            true  => s.pure(()),
            false => s.fail(format!(
                "refusing to init: {} is non-empty",
                root.display()
            )),
        }
    }
}

fn write_initial_files<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: &StoreLayout,
    whoami: RecipientSpec,
    identity_path: PathBuf,
) -> S::R<()> {
    let layout = layout.clone();
    let cfg = Config { whoami, identity_path };
    let s2 = s.clone();
    vault_do! { s ;
        let _ = write_json(s2.clone(), layout.config_path(), cfg) ;
        write_json(s2.clone(), layout.index_path(), Index::empty())
    }
}

fn init_git<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: &StoreLayout,
    remote: InitRemote,
) -> S::R<()> {
    let layout = layout.clone();
    let store_dir = layout.store_dir();
    match remote {
        InitRemote::Clone(url) => {
            let parent = layout.root.clone();
            vault_do! { s ;
                let _ = s.mkdir_p(parent.clone()) ;
                let out = git::clone(&s, parent, url, "store".into()) ;
                match out.success() {
                    true => s.pure(()),
                    false => s.fail(format!(
                        "git clone failed: {}",
                        out.stderr_str()
                    )),
                }
            }
        }
        InitRemote::None => {
            vault_do! { s ;
                let _ = s.mkdir_p(store_dir.clone()) ;
                let out = git::init(&s, store_dir.clone()) ;
                match out.success() {
                    true => seed_initial_commit(s.clone(), store_dir),
                    false => s.fail(format!(
                        "git init failed: {}",
                        out.stderr_str()
                    )),
                }
            }
        }
        InitRemote::DumbBootstrap(url) => bootstrap_dumb_remote(s, store_dir, url),
    }
}

/// `init --dumb-remote URL`: SSH to `URL`, run `git init --bare`
/// there, then locally `git init` + seed-commit + `git remote add
/// origin URL` + `git push -u origin main`.
///
/// Tradeoffs vs `--remote` (clone):
///   * No round-trip to a forge — works against any host you can
///     SSH to (`server:repo.git`, e.g. a personal VPS).
///   * Requires that the operator already has key-based SSH auth
///     working; the host-key prompt would otherwise need an
///     interactive tty, which our [`Vault::shell`] effect doesn't
///     surface. We pass `-o StrictHostKeyChecking=accept-new` so
///     a fresh host gets pinned without prompting (same security
///     posture as git's default).
fn bootstrap_dumb_remote<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    url: String,
) -> S::R<()> {
    let (ssh_target, remote_path, port_args) = match parse_dumb_url(&url) {
        Ok(t) => t,
        Err(e) => return s.fail(format!("--dumb-remote: {e}")),
    };

    let url_for_remote_add = url.clone();
    let url_for_msg = url.clone();
    let store_dir_for_init = store_dir.clone();
    let store_dir_for_seed = store_dir.clone();
    let store_dir_for_remote = store_dir.clone();
    let store_dir_for_push = store_dir;

    vault_do! { s ;
        // 1. Bring up the remote bare repo over SSH.
        let init_remote_out = ssh_init_bare(
            &s, ssh_target, port_args, remote_path,
        ) ;
        let _ = match init_remote_out.success() {
            true => s.pure(()),
            false => s.fail(format!(
                "ssh+git init --bare {} failed: {}",
                url_for_msg,
                init_remote_out.stderr_str().trim()
            )),
        } ;

        // 2. Local git init + seed the first commit.
        let _ = s.mkdir_p(store_dir_for_init.clone()) ;
        let local_init = git::init(&s, store_dir_for_init) ;
        let _ = match local_init.success() {
            true => s.pure(()),
            false => s.fail(format!(
                "local git init failed: {}",
                local_init.stderr_str().trim()
            )),
        } ;
        let _ = seed_initial_commit(s.clone(), store_dir_for_seed) ;

        // 3. Wire the remote and push tracking.
        let remote_add_out = git::remote_add(
            &s, store_dir_for_remote, "origin".into(), url_for_remote_add,
        ) ;
        let _ = match remote_add_out.success() {
            true => s.pure(()),
            false => s.fail(format!(
                "git remote add origin failed: {}",
                remote_add_out.stderr_str().trim()
            )),
        } ;
        let push_out = git::push_set_upstream(
            &s, store_dir_for_push, "origin".into(), "main".into(),
        ) ;
        match push_out.success() {
            true => s.pure(()),
            false => s.fail(format!(
                "git push -u origin main failed: {}",
                push_out.stderr_str().trim()
            )),
        }
    }
}

/// `ssh [-p port] target "mkdir -p <parent> && git init --bare <remote_path> && cd <remote_path> && git symbolic-ref HEAD refs/heads/main"`.
///
/// Two-step rather than `git init --bare --initial-branch main`
/// because that flag landed in git 2.28 (July 2020); some hosts
/// (the canonical case: a long-lived VPS) ship older git. The
/// `symbolic-ref` form has been stable for ~15 years and points
/// the bare repo's HEAD at `main` before we push, so the remote
/// agrees with our local default branch.
///
/// We `cd PATH && git symbolic-ref …` rather than `git
/// --git-dir=PATH symbolic-ref …` deliberately: in bash, tilde
/// expansion only fires when `~` is at the *start* of a word, and
/// `--git-dir=~/foo` puts the tilde mid-word so the shell hands
/// git the literal string `~/foo` (which git rightly says isn't a
/// repository). `cd PATH` keeps the path at word-start; same for
/// the `mkdir` and `git init` arguments above.
fn ssh_init_bare<S: Vault>(
    s: &S,
    target: String,
    extra_ssh_args: Vec<String>,
    remote_path: String,
) -> S::R<crate::types::ProcessOut> {
    let parent = parent_dir(&remote_path);
    let quoted_path = quote_remote_path(&remote_path);
    let remote_cmd = format!(
        "mkdir -p {parent} && \
         git init --bare --quiet {path} && \
         cd {path} && \
         git symbolic-ref HEAD refs/heads/main",
        parent = quote_remote_path(&parent),
        path = quoted_path,
    );
    let mut args: Vec<String> = vec![
        // Pin a previously-unknown host without prompting; reject
        // mismatches on subsequent connects. Same posture git uses
        // for SSH remotes by default.
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
    ];
    args.extend(extra_ssh_args);
    args.push(target);
    args.push(remote_cmd);
    s.shell("ssh".into(), args, None, Vec::new())
}

/// Drop a `.gitkeep` and make an empty initial commit so subsequent
/// `git pull` / `git push` invocations have a base. Without it,
/// `git pull` against a brand-new bare remote produces "couldn't
/// find remote ref main" the first time.
fn seed_initial_commit<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
) -> S::R<()> {
    vault_do! { s ;
        let _ = s.write_file(store_dir.join(".gitkeep"), Vec::new()) ;
        let _ = git::add_all(&s, store_dir.clone()) ;
        let _ = git::commit(&s, store_dir, "rageveil: initial commit".into()) ;
        s.pure(())
    }
}

// ─── URL plumbing ───────────────────────────────────────────────────────

/// Parse a dumb-remote URL into `(ssh_target, remote_path, extra_ssh_args)`.
///
/// Three accepted shapes:
///   * `ssh://[user@]host[:port]/path` — port becomes `-p <port>`
///     in `extra_ssh_args`. By the URL spec the path is *absolute*
///     on the remote, so we restore the leading `/` we lost when
///     splitting host from path.
///   * `ssh://[user@]host[:port]/~user/path` (or `/~/path`) —
///     tilde-expanded by the remote login shell. We *don't*
///     prepend a slash in front of `~`; git itself handles this
///     same way.
///   * `[user@]host:path` (SCP-style) — `path` resolves against
///     the remote user's home, same as `git clone user@host:foo.git`.
///     This is the simplest form for "put it in my home dir".
fn parse_dumb_url(url: &str) -> Result<(String, String, Vec<String>), String> {
    if let Some(rest) = url.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/').ok_or_else(|| {
            format!("ssh:// URL missing a path component: {url}")
        })?;
        if path.is_empty() {
            return Err(format!("ssh:// URL missing a path component: {url}"));
        }
        let (host_part, extra) = match authority.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_owned(), vec!["-p".into(), p.into()])
            }
            _ => (authority.to_owned(), Vec::new()),
        };
        // Tilde-prefixed paths (`~/foo`, `~alice/foo`) stay as-is
        // so the remote shell can expand them. Anything else gets
        // its leading slash restored to match the strict URL
        // spec — git interprets ssh://host/path as absolute on the
        // remote, and we must agree because the same `url` will
        // be passed verbatim to `git remote add` later.
        let remote_path = if path.starts_with('~') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        Ok((host_part, remote_path, extra))
    } else if let Some((host, path)) = url.split_once(':') {
        // SCP-style. Reject anything that looks like a local path
        // (contains a slash before the colon) — git's own SCP
        // disambiguation rule.
        if host.contains('/') {
            return Err(format!(
                "expected an SSH URL or SCP-style `[user@]host:path`; got {url}"
            ));
        }
        if host.is_empty() || path.is_empty() {
            return Err(format!(
                "expected an SSH URL or SCP-style `[user@]host:path`; got {url}"
            ));
        }
        Ok((host.to_owned(), path.to_owned(), Vec::new()))
    } else {
        Err(format!(
            "expected an SSH URL or SCP-style `[user@]host:path`; got {url}"
        ))
    }
}

fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        // Absolute path with non-empty parent: keep everything up
        // to (and including) the final slash, except don't strip
        // the leading `/`.
        Some(0) => "/".to_owned(),
        Some(i) => path[..i].to_owned(),
        // No slash → relative path with no parent component;
        // remote shell's cwd (the user's home) already exists, so
        // `mkdir -p .` is a safe no-op.
        None => ".".to_owned(),
    }
}

/// POSIX shell single-quote: wrap in `'…'` and escape any embedded
/// `'` as `'\''`. Safe to embed user-controlled text inside the
/// `ssh remote_command` we build.
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Quote a path for embedding inside an `ssh host '<remote_cmd>'`.
/// Identical to [`shell_single_quote`] for ordinary paths, but
/// special-cases a leading `~` / `~user/` prefix: the prefix
/// stays unquoted so the remote login shell can expand it (the
/// way git does for `ssh://host/~/repo.git`), while everything
/// past the first slash is single-quoted to neutralise shell
/// metacharacters in the path component.
fn quote_remote_path(path: &str) -> String {
    if !path.starts_with('~') {
        return shell_single_quote(path);
    }
    match path.find('/') {
        // `~` or `~alice` standalone — refers to the user's home
        // directory. POSIX usernames have no shell metacharacters,
        // so passing them unquoted is safe and they'll expand.
        None => path.to_owned(),
        Some(i) => {
            let prefix = &path[..i]; // ~ or ~user
            let rest = &path[i + 1..]; // path under home
            if rest.is_empty() {
                format!("{prefix}/")
            } else {
                format!("{prefix}/{}", shell_single_quote(rest))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scp_style() {
        let (t, p, e) = parse_dumb_url("user@host.example:/srv/git/store.git").unwrap();
        assert_eq!(t, "user@host.example");
        assert_eq!(p, "/srv/git/store.git");
        assert!(e.is_empty());
    }

    #[test]
    fn parse_scp_style_relative_path() {
        let (t, p, e) = parse_dumb_url("alice@vault:store.git").unwrap();
        assert_eq!(t, "alice@vault");
        assert_eq!(p, "store.git");
        assert!(e.is_empty());
    }

    #[test]
    fn parse_ssh_url_with_port() {
        let (t, p, e) =
            parse_dumb_url("ssh://alice@host.example:2222/srv/git/store.git").unwrap();
        assert_eq!(t, "alice@host.example");
        assert_eq!(p, "/srv/git/store.git");
        assert_eq!(e, vec!["-p".to_string(), "2222".to_string()]);
    }

    #[test]
    fn parse_ssh_url_without_port() {
        let (t, p, e) = parse_dumb_url("ssh://host.example/srv/store.git").unwrap();
        assert_eq!(t, "host.example");
        assert_eq!(p, "/srv/store.git");
        assert!(e.is_empty());
    }

    #[test]
    fn parse_ssh_url_with_tilde_home() {
        // `ssh://host/~/foo` → home-relative on the remote, the
        // way git itself interprets it. Our parser must NOT
        // prepend a leading slash here.
        let (t, p, e) = parse_dumb_url("ssh://doma.dev/~/.rageveil").unwrap();
        assert_eq!(t, "doma.dev");
        assert_eq!(p, "~/.rageveil");
        assert!(e.is_empty());
    }

    #[test]
    fn parse_ssh_url_with_tilde_other_user() {
        let (t, p, _) = parse_dumb_url("ssh://host/~alice/store.git").unwrap();
        assert_eq!(t, "host");
        assert_eq!(p, "~alice/store.git");
    }

    #[test]
    fn rejects_local_path() {
        assert!(parse_dumb_url("/local/path").is_err());
        assert!(parse_dumb_url("./relative").is_err());
        assert!(parse_dumb_url("../sibling").is_err());
    }

    #[test]
    fn rejects_path_only() {
        assert!(parse_dumb_url("just-a-name").is_err());
    }

    #[test]
    fn shell_quoting_handles_embedded_quote() {
        assert_eq!(shell_single_quote("simple"), "'simple'");
        assert_eq!(
            shell_single_quote("it's mine"),
            "'it'\\''s mine'"
        );
        assert_eq!(shell_single_quote("/srv/git/repo.git"), "'/srv/git/repo.git'");
    }

    #[test]
    fn quote_remote_path_preserves_tilde_for_shell_expansion() {
        // Plain absolute / relative paths: identical to single-quote.
        assert_eq!(quote_remote_path("/srv/git/repo.git"), "'/srv/git/repo.git'");
        assert_eq!(quote_remote_path("relative/repo.git"), "'relative/repo.git'");

        // Tilde paths: prefix unquoted, rest single-quoted.
        assert_eq!(quote_remote_path("~/.rageveil"), "~/'.rageveil'");
        assert_eq!(quote_remote_path("~/foo/bar"), "~/'foo/bar'");
        assert_eq!(quote_remote_path("~alice/store.git"), "~alice/'store.git'");

        // Bare ~ / ~user: pass through; home dir always exists,
        // mkdir -p ~ is a harmless no-op once the shell expands.
        assert_eq!(quote_remote_path("~"), "~");
        assert_eq!(quote_remote_path("~root"), "~root");
    }

    #[test]
    fn parent_dir_cases() {
        assert_eq!(parent_dir("/srv/git/repo.git"), "/srv/git");
        assert_eq!(parent_dir("/repo.git"), "/");
        assert_eq!(parent_dir("repo.git"), ".");
        assert_eq!(parent_dir("nested/repo.git"), "nested");
    }
}
