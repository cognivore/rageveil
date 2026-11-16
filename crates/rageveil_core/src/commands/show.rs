//! `rageveil show PATH` — decrypt and surface a stored secret.
//!
//! The operator's own copy is at `<entry-hash>/<whoami-fp>.age`;
//! we decrypt it with `cfg.identity_path` and return the parsed
//! [`crate::Content`] payload. The CLI then prints it (or pipes
//! it onward, when stdout isn't a TTY).

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::store::StoreLayout;
use crate::sugar::read_json;
use crate::types::EntryPath;
use crate::vault_do;

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct ShowArgs {
    pub root: PathBuf,
    pub path: EntryPath,
}

#[derive(Clone, Debug)]
pub struct ShowOutput {
    pub content: Content,
}

pub fn show<S>(s: S, args: ShowArgs) -> S::R<ShowOutput>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let path = args.path.clone();
    let cfg_path = layout.config_path();

    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let content = decrypt_for_self(s.clone(), layout.clone(), cfg, path) ;
        let _ = remember(s.clone(), layout.clone(), content.clone()) ;
        s.pure(ShowOutput { content })
    }
}

/// A human-only entry that the index does not know yet goes into it once
/// opened, so that `list` and `info` show it from then on without another
/// touch. Nothing else is written: `show` stays a read for every entry the
/// index already holds.
fn remember<S>(s: S, layout: StoreLayout, content: Content) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    if content.metadata.tier.is_automation() {
        return s.pure(());
    }
    let index_path = layout.index_path();
    let s2 = s.clone();
    vault_do! { s ;
        let there = s.exists(index_path.clone()) ;
        let idx = match there {
            true => read_json::<S, crate::index::Index>(s.clone(), index_path),
            false => s.pure(crate::index::Index::empty()),
        } ;
        let now = s.now() ;
        match idx.entries.contains_key(&content.path) {
            true => s2.pure(()),
            false => crate::commands::allow::update_index(
                s2.clone(),
                layout,
                content.path.clone(),
                content.path.hash(),
                content.metadata,
                now,
            ),
        }
    }
}

use crate::own::decrypt_own as decrypt_for_self;
