//! `rageveil search TERM…` — `list`, narrowed to the entry paths the
//! terms find, best first: each term a piece of the path, in any case
//! and any order, or letters in order when no path holds the pieces
//! (the rule is [`crate::find`]'s; `workspace j` finds
//! `workspace.google.com/jm@memorici.de`).
//!
//! AI-assisted update (the terms and their ranking, 2026-11-19): model
//! Claude Fable 5.2 (`claude-fable-5-2`); reasoning effort xhigh.
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
    /// The terms, separated by spaces. An empty query finds every
    /// entry (so `search ""` degenerates to `list`).
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

/// Entry paths that `query` finds, best first: every space-separated
/// term of it as a piece of the path, or, when no path has them all,
/// as letters in order ([`crate::find`]). Pure — the only DSL effects
/// are the `exists`/`read_json` above, so a Plan trace shows exactly
/// the same index lookup `list` does.
fn matching(idx: &Index, query: &str) -> Vec<String> {
    crate::find::find(query, idx.entries.keys().map(|p| p.0.as_str()))
        .into_iter()
        .map(str::to_owned)
        .collect()
}
