//! `rageveil delete PATH` — drop an entry from the store.
//!
//! Removes the entire `<entry-hash>/` directory (every recipient
//! copy goes with it), prunes the local index, and commits.
//! Intentionally simple — there's no "undo" beyond `git revert`.

use crate::config::Config;
use crate::dsl::Vault;
use crate::index::Index;
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::EntryPath;
use crate::{git, vault_do};

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct DeleteArgs {
    pub root: PathBuf,
    pub path: EntryPath,
}

pub fn delete<S>(s: S, args: DeleteArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let cfg_path = layout.config_path();
    let path = args.path.clone();
    let entry_dir = layout.entry_dir(&path.hash());

    vault_do! { s ;
        let _cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let _ = s.remove_dir_all(entry_dir) ;
        let _ = remove_from_index(s.clone(), layout.index_path(), path.clone()) ;
        let out_add = git::add_all(&s, layout.store_dir()) ;
        match out_add.success() {
            true => commit_delete(s.clone(), layout.store_dir(), path),
            false => s.fail(format!("git add failed: {}", out_add.stderr_str())),
        }
    }
}

fn remove_from_index<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    index_path: PathBuf,
    path: EntryPath,
) -> S::R<()> {
    let s2 = s.clone();
    vault_do! { s ;
        let exists = s.exists(index_path.clone()) ;
        match exists {
            false => s.pure(()),
            true  => {
                let s3 = s2.clone();
                let path2 = path.clone();
                let index_path2 = index_path.clone();
                vault_do! { s2 ;
                    let mut idx = read_json::<S, Index>(s2.clone(), index_path2.clone()) ;
                    {
                        idx.entries.remove(&path2);
                        write_json(s3.clone(), index_path2, idx)
                    }
                }
            }
        }
    }
}

fn commit_delete<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    path: EntryPath,
) -> S::R<()> {
    vault_do! { s ;
        let out = git::commit(&s, store_dir, format!("delete {}", path)) ;
        match out.success() {
            true => s.log(format!("deleted {}", path)),
            false if out.stderr_str().contains("nothing to commit") => s.pure(()),
            false => s.fail(format!("git commit failed: {}", out.stderr_str())),
        }
    }
}
