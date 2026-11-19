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
    /// The value is known to have leaked: the graver level, of either tier.
    pub compromised: bool,
}

impl Listed {
    /// What `list` prints after the path, or nothing for an ordinary
    /// automation-tolerant entry.
    pub fn decoration(&self) -> Option<&'static str> {
        // The graver level is the one shown: a compromised value needs
        // rotating whatever else is true of it.
        match (self.tier, self.compromised, self.exposed) {
            (crate::tier::Tier::Automation, false, _) => None,
            (crate::tier::Tier::Automation, true, _) => Some("[compromised: rotate now]"),
            (crate::tier::Tier::Human, true, _) => Some("[noauto, compromised: rotate now]"),
            (crate::tier::Tier::Human, false, false) => Some("[noauto]"),
            (crate::tier::Tier::Human, false, true) => Some("[noauto, exposed: rotate]"),
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
        let compromised = crate::exposure::load_compromised_or_empty(s.clone(), &layout) ;
        s2.pure(
            idx.entries
                .iter()
                .map(|(path, cached)| Listed {
                    path: path.0.clone(),
                    tier: cached.metadata.tier,
                    exposed: exposed.holds(&cached.hash),
                    compromised: compromised.holds(&cached.hash),
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

/// How `list` and `address list` lay their lines out: a tree by
/// default, or flat (`--no-tree`), with descriptors by default, or
/// bare (`--no-descriptors`). Flat and bare is one name per line, to
/// paste or pipe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub tree: bool,
    pub descriptors: bool,
}

/// Lines for `list` in `layout`.
pub fn render(entries: &[Listed], layout: Layout) -> Vec<String> {
    match (layout.tree, layout.descriptors) {
        (false, true) => render_decorated(entries),
        (false, false) => entries.iter().map(|e| e.path.clone()).collect(),
        (true, descriptors) => render_tree(entries, descriptors),
    }
}

/// `list` as a tree of the path's `/`-separated parts, two spaces of
/// indent per level: `workspace.google.com`, then `  info@memorici.de`
/// under it. An entry's descriptor follows its last part, aligned in
/// one column. Entries are ordered by their parts, not their whole
/// strings: `-` and `.` sort before `/`, so `jons-work` would otherwise
/// come between `jons` and `jons/pat` and print `jons` twice.
fn render_tree(entries: &[Listed], descriptors: bool) -> Vec<String> {
    let mut ordered: Vec<&Listed> = entries.iter().collect();
    ordered.sort_by(|a, b| a.path.split('/').cmp(b.path.split('/')));
    let mut lines: Vec<(String, Option<&'static str>)> = Vec::new();
    let mut previous: Vec<&str> = Vec::new();
    for e in ordered {
        let parts: Vec<&str> = e.path.split('/').collect();
        let shared = previous.iter().zip(&parts).take_while(|(a, b)| a == b).count();
        // A path that is all of the one before it still gets its own
        // line, for its descriptor.
        let first = shared.min(parts.len().saturating_sub(1));
        for (depth, part) in parts.iter().enumerate().skip(first) {
            let leaf = depth + 1 == parts.len();
            let mark = if leaf && descriptors { e.decoration() } else { None };
            lines.push((format!("{}{part}", "  ".repeat(depth)), mark));
        }
        previous = parts;
    }
    let width = lines
        .iter()
        .filter(|(_, m)| m.is_some())
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0);
    lines
        .into_iter()
        .map(|(line, mark)| match mark {
            None => line,
            Some(mark) => format!("{line:<width$}  {mark}"),
        })
        .collect()
}

/// How many human-only entries this laptop's Touch ID key holds that the
/// local index does not know yet. Their paths are inside the encrypted
/// copies, so they cannot be listed until each is opened once, by
/// `cards`, `sync --touch` or `show`.
pub fn unopened_human_only<S>(s: S, args: ListArgs) -> S::R<usize>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let s2 = s.clone();
    vault_do! { s ;
        let cfg = read_json::<S, crate::config::Config>(s.clone(), layout.config_path()) ;
        let there = s.exists(layout.index_path()) ;
        let idx = match there {
            true => read_json::<S, Index>(s.clone(), layout.index_path()),
            false => s.pure(Index::empty()),
        } ;
        let dirs = s.list_dir(layout.store_dir()) ;
        {
            let known: std::collections::BTreeSet<String> =
                idx.entries.values().map(|c| c.hash.0.clone()).collect();
            match cfg.touch {
                None => s2.pure(0),
                Some(touch) => {
                    let candidates: Vec<Vec<PathBuf>> = dirs
                        .iter()
                        .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
                        .filter(|n| super::sync::is_entry_dir_name(n) && !known.contains(*n))
                        .map(|n| layout.entry_file_candidates(
                            &crate::types::EntryHash(n.to_owned()),
                            &touch.whoami,
                        ))
                        .collect();
                    count_present(s2.clone(), candidates, 0)
                }
            }
        }
    }
}

/// What to say about the entries [`unopened_human_only`] counted, or
/// nothing when there are none. `cards` opens each once: it indexes every
/// one, and gives a human-only one of the operator's a name card for each
/// laptop of theirs and a copy for each gated device, so later syncs list
/// it without a finger.
pub fn unopened_hint(n: usize) -> Option<String> {
    let entries = if n == 1 { "1 entry is".to_owned() } else { format!("{n} entries are") };
    (n > 0).then(|| {
        format!(
            "{entries} behind Touch ID alone and not listed yet: this laptop has no copy \
             and no name card. `rageveil cards` opens each once with Touch ID and lists it \
             from then on; a human-only one of yours also reaches every device of yours"
        )
    })
}

fn count_present<S>(s: S, mut rest: Vec<Vec<PathBuf>>, n: usize) -> S::R<usize>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    match rest.pop() {
        None => s.pure(n),
        Some(paths) => {
            let s2 = s.clone();
            vault_do! { s ;
                let found = crate::sugar::first_existing(s.clone(), paths) ;
                count_present(s2.clone(), rest, n + usize::from(found.is_some()))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::tier::Tier;

    fn entry(path: &str, tier: Tier, exposed: bool) -> Listed {
        Listed { path: path.into(), tier, exposed, compromised: false }
    }

    fn entries() -> Vec<Listed> {
        vec![
            entry("github.com/jons", Tier::Automation, false),
            entry("github.com/jons/token", Tier::Automation, false),
            entry("mana-vault/lituk.editor", Tier::Automation, false),
            entry("workspace.google.com/info@memorici.de", Tier::Human, true),
        ]
    }

    const BOTH: Layout = Layout { tree: true, descriptors: true };

    #[test]
    fn the_tree_prints_each_shared_part_once() {
        assert_eq!(
            render(&entries(), BOTH),
            [
                "github.com",
                "  jons",
                "    token",
                "mana-vault",
                "  lituk.editor",
                "workspace.google.com",
                "  info@memorici.de  [noauto, exposed: rotate]",
            ]
        );
    }

    #[test]
    fn a_part_is_printed_once_whatever_sorts_between() {
        let entries = [
            entry("github.com/jons", Tier::Automation, false),
            entry("github.com/jons-work", Tier::Automation, false),
            entry("github.com/jons/pat", Tier::Automation, false),
        ];
        assert_eq!(
            render(&entries, BOTH),
            ["github.com", "  jons", "    pat", "  jons-work"]
        );
    }

    #[test]
    fn the_tree_without_descriptors_has_no_marks() {
        let lines = render(&entries(), Layout { tree: true, descriptors: false });
        assert_eq!(lines.last().map(String::as_str), Some("  info@memorici.de"));
    }

    #[test]
    fn flat_and_bare_is_one_path_per_line() {
        let lines = render(&entries(), Layout { tree: false, descriptors: false });
        assert_eq!(lines, entries().into_iter().map(|e| e.path).collect::<Vec<_>>());
        let marked = render(&entries(), Layout { tree: false, descriptors: true });
        assert!(marked[3].starts_with("workspace.google.com/info@memorici.de  [noauto"));
    }
}
