//! `rageveil init` — bring a store into existence.
//!
//! Inputs:
//!   * `root` — `~/.rageveil` by default.
//!   * `identity_path` — operator's age key file (or SSH private
//!     key); used to derive `whoami`.
//!   * `remote` — optional git URL to clone instead of `git init`.
//!
//! Effects, in order: derive `whoami` from the identity, create
//! the root directory, write `config.json` and an empty
//! `index.json`, then either `git init` or `git clone` the
//! shared store.

use crate::config::Config;
use crate::dsl::Vault;
use crate::index::Index;
use crate::store::StoreLayout;
use crate::sugar::write_json;
use crate::types::RecipientSpec;
use crate::{git, vault_do};

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct InitArgs {
    pub root: PathBuf,
    pub identity_path: PathBuf,
    pub remote: Option<String>,
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
    remote: Option<String>,
) -> S::R<()> {
    let layout = layout.clone();
    let store_dir = layout.store_dir();
    match remote {
        Some(url) => {
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
        None => {
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
    }
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
