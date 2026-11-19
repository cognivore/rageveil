//! `rageveil move FROM TO` — rename an entry.
//!
//! AI-generated module: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! An entry's path is inside its encrypted copies and its folder is named
//! by the path's hash, so a new name means a new folder. `move` opens the
//! entry (with Touch ID if it is human-only), writes it under the new name
//! for exactly the keys it trusted, with its trust log, tier and exposure
//! kept, removes the old folder, and commits both in one commit. The new
//! name must fit SERVICE/ACCOUNT[/PURPOSE][/MISC]*; the old one need not,
//! which is how a misnamed entry is put right. Whatever refers to the old
//! name (scripts, services, prompts) must be changed with it.

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::metadata::Stamp;
use crate::own::decrypt_own;
use crate::store::StoreLayout;
use crate::sugar::read_json;
use crate::types::{CommitOutcome, EntryPath};
use crate::{git, vault_do};

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct MoveArgs {
    pub root: PathBuf,
    pub from: EntryPath,
    pub to: EntryPath,
}

pub fn move_entry<S>(s: S, args: MoveArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let MoveArgs { root, from, to } = args;
    if let Err(e) = crate::entry_name::EntryName::parse(&to.0) {
        return s.fail(format!("{to} does not fit SERVICE/ACCOUNT[/PURPOSE]: {e}"));
    }
    if from == to {
        return s.fail(format!("{from} is already its name"));
    }
    let layout = StoreLayout::new(root);
    let (old_hash, new_hash) = (from.hash(), to.hash());
    let s2 = s.clone();
    vault_do! { s ;
        let taken = s.exists(layout.entry_dir(&new_hash)) ;
        let _ = match taken {
            true => s.fail(format!("{to} already exists; delete or move it first")),
            false => s.pure(()),
        } ;
        let cfg = read_json::<S, Config>(s.clone(), layout.config_path()) ;
        let content = decrypt_own(s.clone(), layout.clone(), cfg.clone(), from.clone()) ;
        let exposed = crate::exposure::load_exposed_or_empty(s.clone(), &layout) ;
        let compromised = crate::exposure::load_compromised_or_empty(s.clone(), &layout) ;
        let now = s.now() ;
        let mut metadata = s.pure(content.metadata.clone()) ;
        let plaintext = {
            metadata.updated = Some(Stamp { at: now, by: cfg.whoami.clone() });
            s.encode_json(Content { path: to.clone(), metadata: metadata.clone(), ..content })
        } ;
        let _ = s.mkdir_p(layout.entry_dir(&new_hash)) ;
        let _ = crate::tier::write_entry(s.clone(), layout.clone(), new_hash.clone(), plaintext, metadata.clone()) ;
        let _ = crate::exposure::mark(s.clone(), layout.clone(), new_hash.clone(), exposed.holds(&old_hash)) ;
        let _ = crate::exposure::mark(s.clone(), layout.clone(), old_hash.clone(), false) ;
        // A name is not a value: what leaked under the old name has leaked under the new.
        let _ = crate::exposure::mark_compromised(s.clone(), layout.clone(), new_hash.clone(), compromised.holds(&old_hash)) ;
        let _ = crate::exposure::mark_compromised(s.clone(), layout.clone(), old_hash.clone(), false) ;
        let _ = s.remove_dir_all(layout.entry_dir(&old_hash)) ;
        let _ = crate::commands::delete::remove_from_index(s.clone(), layout.index_path(), from.clone()) ;
        let _ = crate::commands::allow::update_index(s.clone(), layout.clone(), to.clone(), new_hash, metadata, now) ;
        let _ = git::add_all(&s, layout.store_dir()) ;
        let out = git::commit(&s, layout.store_dir(), format!("move {from} {to}")) ;
        match out {
            CommitOutcome::Committed | CommitOutcome::NothingToCommit => s2.log(format!("moved {from} to {to}")),
        }
    }
}
