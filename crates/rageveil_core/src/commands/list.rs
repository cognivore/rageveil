//! `rageveil list` — print every entry path the local index knows
//! about, one per line, sorted.
//!
//! Lives entirely off `index.json`; never decrypts. If the index
//! is stale (a teammate inserted upstream and we haven't `sync`ed
//! yet), this won't show their entry — that's by design and
//! mirrors passveil.

use crate::dsl::Vault;
use crate::index::Index;
use crate::store::StoreLayout;
use crate::sugar::read_json;
use crate::vault_do;

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct ListArgs {
    pub root: PathBuf,
}

pub fn list<S>(s: S, args: ListArgs) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let index_path = layout.index_path();

    vault_do! { s ;
        let exists = s.exists(index_path.clone()) ;
        match exists {
            true  => collect(s.clone(), index_path),
            false => s.pure(Vec::new()),
        }
    }
}

fn collect<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    index_path: PathBuf,
) -> S::R<Vec<String>> {
    vault_do! { s ;
        let idx = read_json::<S, Index>(s.clone(), index_path) ;
        s.pure(idx.entries.keys().map(|p| p.0.clone()).collect())
    }
}
