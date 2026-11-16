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

/// One line of `list`: the path, and how far it falls short of being as
/// safe as its tier says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub path: String,
    pub tier: crate::tier::Tier,
    /// A plain key held this value; the store's history keeps that copy.
    pub exposed: bool,
}

impl Listed {
    /// What `list` prints after the path, or nothing for an ordinary
    /// automation-tolerant entry.
    pub fn decoration(&self) -> Option<&'static str> {
        match (self.tier, self.exposed) {
            (crate::tier::Tier::Automation, _) => None,
            (crate::tier::Tier::Human, false) => Some("[human-only]"),
            (crate::tier::Tier::Human, true) => Some("[human-only, exposed: rotate]"),
        }
    }
}

/// Every entry in the local index with its tier and exposure, sorted by
/// path. Like [`list`], it never decrypts.
pub fn list_marked<S>(s: S, args: ListArgs) -> S::R<Vec<Listed>>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let index_path = layout.index_path();
    let s2 = s.clone();
    vault_do! { s ;
        let exists = s.exists(index_path.clone()) ;
        let idx = match exists {
            true => read_json::<S, Index>(s.clone(), index_path),
            false => s.pure(Index::empty()),
        } ;
        let exposed = crate::exposure::load_exposed_or_empty(s.clone(), &layout) ;
        s2.pure(
            idx.entries
                .iter()
                .map(|(path, cached)| Listed {
                    path: path.0.clone(),
                    tier: cached.metadata.tier,
                    exposed: exposed.holds(&cached.hash),
                })
                .collect(),
        )
    }
}

/// Lines for `list`: each decoration after the path, aligned in one
/// column on the right so that a path can still be copied whole.
pub fn render_decorated(entries: &[Listed]) -> Vec<String> {
    let width = entries
        .iter()
        .filter(|e| e.decoration().is_some())
        .map(|e| e.path.chars().count())
        .max()
        .unwrap_or(0);
    entries
        .iter()
        .map(|e| match e.decoration() {
            None => e.path.clone(),
            Some(mark) => format!("{:<width$}  {mark}", e.path),
        })
        .collect()
}
