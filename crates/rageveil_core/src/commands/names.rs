//! `rageveil check-names` — entry names that do not fit the naming rule.
//!
//! AI-generated module: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! **Draft.** New entries must fit `SERVICE/ACCOUNT[/PURPOSE][/MISC]*`
//! ([`crate::entry_name`]); entries made before the rule keep their names
//! and keep working. Nothing renames them: an entry's name is in every
//! copy of it and in other people's scripts, so renaming is the owner's
//! call, one entry at a time. This lists them, with why each does not
//! fit, so the owner can decide. Like `list`, it reads only the local
//! index and never decrypts.

use crate::dsl::Vault;
use crate::entry_name::{EntryName, NameError};
use crate::index::Index;
use crate::store::StoreLayout;
use crate::sugar::read_json;
use crate::types::EntryPath;
use crate::vault_do;

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct NamesArgs {
    pub root: PathBuf,
}

/// What `check-names` found in the local index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamesReport {
    /// How many entries the index holds.
    pub total: usize,
    /// The names that do not fit, sorted by path, each with its reason.
    pub unfit: Vec<(EntryPath, NameError)>,
}

impl NamesReport {
    pub fn from_index(idx: &Index) -> Self {
        Self {
            total: idx.entries.len(),
            unfit: idx
                .entries
                .keys()
                .filter_map(|p| EntryName::try_from(p).err().map(|e| (p.clone(), e)))
                .collect(),
        }
    }

    /// One line per unfit name: the path, then why.
    pub fn lines(&self) -> Vec<String> {
        let width = self.unfit.iter().map(|(p, _)| p.as_str().chars().count()).max().unwrap_or(0);
        self.unfit.iter().map(|(p, why)| format!("{:<width$}  {why}", p.as_str())).collect()
    }

    pub fn summary(&self) -> String {
        format!(
            "{} of {} entry names do not fit SERVICE/ACCOUNT[/PURPOSE][/MISC]*",
            self.unfit.len(),
            self.total
        )
    }
}

pub fn unfit_names<S>(s: S, args: NamesArgs) -> S::R<NamesReport>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let index_path = StoreLayout::new(args.root).index_path();
    let s2 = s.clone();
    vault_do! { s ;
        let there = s.exists(index_path.clone()) ;
        let idx = match there {
            true => read_json::<S, Index>(s.clone(), index_path),
            false => s.pure(Index::empty()),
        } ;
        s2.pure(NamesReport::from_index(&idx))
    }
}
