//! `rageveil search QUERY` — `list`, narrowed to entry paths that
//! contain QUERY (case-insensitive substring).
//!
//! Same discipline as [`super::list`]: lives entirely off
//! `index.json`, never decrypts. A stale index won't surface a
//! teammate's freshly-shared entry until you `sync` — by design,
//! and the same caveat `list` carries. The index doc-comment names
//! `search` as one of the read-only-over-the-index consumers, so
//! this is its intended shape: a pure filter over the cached paths,
//! not a content grep (which would have to decrypt every entry).

use crate::dsl::Vault;
use crate::index::Index;
use crate::store::StoreLayout;
use crate::sugar::read_json;
use crate::vault_do;

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct SearchArgs {
    pub root: PathBuf,
    /// Substring to match against entry paths. Matched
    /// case-insensitively; an empty query matches every entry (so
    /// `search ""` degenerates to `list`).
    pub query: String,
}

pub fn search<S>(s: S, args: SearchArgs) -> S::R<Vec<String>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let index_path = layout.index_path();
    let query = args.query;

    vault_do! { s ;
        let exists = s.exists(index_path.clone()) ;
        match exists {
            true  => collect(s.clone(), index_path, query),
            false => s.pure(Vec::new()),
        }
    }
}

fn collect<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    index_path: PathBuf,
    query: String,
) -> S::R<Vec<String>> {
    vault_do! { s ;
        let idx = read_json::<S, Index>(s.clone(), index_path) ;
        s.pure(matching(&idx, &query))
    }
}

/// Entry paths containing `query`, case-insensitive, in the index's
/// (already sorted) `BTreeMap` order. Pure — the only DSL effects
/// are the `exists`/`read_json` above, so a Plan trace shows exactly
/// the same index lookup `list` does.
fn matching(idx: &Index, query: &str) -> Vec<String> {
    let needle = query.to_lowercase();
    idx.entries
        .keys()
        .filter(|p| p.0.to_lowercase().contains(&needle))
        .map(|p| p.0.clone())
        .collect()
}
