//! `rageveil compromised ENTRY`: say that an entry's current value is
//! known to have leaked. **Draft.**
//!
//! AI-generated module: model Claude Fable 5.2 (`claude-fable-5-2`);
//! reasoning effort xhigh.
//!
//! This is the graver of the two levels in [`crate::exposure`]. *Exposed*
//! is something the store works out for itself: a plain key once held a
//! human-only value. *Compromised* is something only a person knows: the
//! value was printed into a log, shown on a shared screen, pasted into a
//! chat, or named in a breach. So a person records it, for an entry of
//! either tier, and `list`, `info` and the apps then say "rotate now"
//! rather than "rotate".
//!
//! Like exposure, the mark lives outside the encrypted entry, in
//! `compromised.txt`: setting it must not need the finger that opening
//! the entry needs, and everybody who shares the entry sees it. It reads
//! only the local index and never decrypts. A new value (`rotate`,
//! `edit`) takes the mark away; `--undo` takes it away when it was set
//! by mistake. The change is committed here and published by `sync`.

use std::path::PathBuf;

use crate::dsl::Vault;
use crate::exposure::{load_compromised_or_empty, mark_compromised};
use crate::index::Index;
use crate::store::StoreLayout;
use crate::sugar::read_json;
use crate::types::{CommitOutcome, EntryPath};
use crate::{git, vault_do};

#[derive(Clone, Debug)]
pub struct CompromisedArgs {
    pub root: PathBuf,
    pub path: EntryPath,
    /// Take the mark back: it was set by mistake.
    pub undo: bool,
    /// Where the value leaked, in a few words. It goes into the store's
    /// history, which everybody with the store can read.
    pub because: Option<String>,
}

pub fn compromised<S>(s: S, args: CompromisedArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let path = args.path.clone();
    let s2 = s.clone();
    vault_do! { s ;
        let idx = read_json::<S, Index>(s.clone(), layout.index_path()) ;
        let _ = match idx.entries.contains_key(&path) {
            true => s.pure(()),
            false => s.fail(format!(
                "no entry {path} in the local index: `rageveil sync` first, and for a \
                 human-only entry this laptop has never opened, `rageveil cards`"
            )),
        } ;
        let marked = load_compromised_or_empty(s.clone(), &layout) ;
        match (marked.holds(&path.hash()), args.undo) {
            (true, false) => s2.log(format!("{path} is already marked compromised")),
            (false, true) => s2.log(format!("{path} is not marked compromised")),
            (false, false) => record(s2.clone(), layout, path, true, args.because),
            (true, true) => record(s2.clone(), layout, path, false, None),
        }
    }
}

fn record<S>(s: S, layout: StoreLayout, path: EntryPath, on: bool, because: Option<String>) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let store_dir = layout.store_dir();
    // One line of history: a reason may not start another.
    let reason = because
        .map(|b| b.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|b| !b.is_empty());
    let message = match (on, reason) {
        (true, Some(reason)) => format!("compromised {path}: {reason}"),
        (true, None) => format!("compromised {path}"),
        (false, _) => format!("not compromised {path}"),
    };
    let s2 = s.clone();
    vault_do! { s ;
        let _ = mark_compromised(s.clone(), layout, path.hash(), on) ;
        let _ = git::add_all(&s, store_dir.clone()) ;
        let out = git::commit(&s, store_dir, message) ;
        match (out, on) {
            (CommitOutcome::Committed | CommitOutcome::NothingToCommit, true) => s2.log(format!(
                "{path} is marked compromised: rotate it now with `rageveil rotate {path}`. \
                 `rageveil sync` publishes the mark"
            )),
            (CommitOutcome::Committed | CommitOutcome::NothingToCommit, false) => s2.log(format!(
                "{path} is no longer marked compromised. `rageveil sync` publishes that"
            )),
        }
    }
}
