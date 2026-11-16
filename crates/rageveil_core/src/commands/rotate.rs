//! `rageveil rotate PATH` — replace a secret the service still accepts.
//!
//! AI-generated module: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! rageveil cannot change a password at the service: every site does it
//! its own way. So `rotate` opens a Kagi search for "SERVICE change
//! password", where SERVICE is the entry's path up to its first `/`, and
//! leaves finding the page to the person. Then it stores the new value
//! the way `edit` does, keeping who may read the entry and its tier, and
//! clears the entry's exposure (see [`crate::exposure`]).
//!
//! The old value is not kept beside the new one. It stays in the store's
//! git history, readable by whoever held it, until the service no longer
//! accepts it.

use super::edit::{edit, EditArgs};
use super::insert::{emit_generated, resolve_payload};
use crate::dsl::Vault;
use crate::exposure::rotation_search_url;
use crate::types::EntryPath;
use crate::vault_do;

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct RotateArgs {
    pub root: PathBuf,
    pub path: EntryPath,
    /// The new value: given, read from stdin, or generated, as for `insert`.
    pub payload: Option<String>,
    pub payload_from_stdin: bool,
    pub generate: Option<usize>,
    pub symbols: bool,
    /// Open the search in the browser. Off when the caller already did,
    /// or has no browser.
    pub open: bool,
}

pub fn rotate<S>(s: S, args: RotateArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let RotateArgs { root, path, payload, payload_from_stdin, generate, symbols, open } = args;
    let s2 = s.clone();
    vault_do! { s ;
        let _ = match open {
            true => open_search(s.clone(), &path),
            false => s.pure(()),
        } ;
        let value = resolve_payload(s.clone(), payload, payload_from_stdin, generate, symbols) ;
        let _ = edit(s.clone(), EditArgs {
            root,
            path,
            payload: Some(value.clone()),
            payload_from_stdin: false,
        }) ;
        emit_generated(s2.clone(), value, generate, symbols)
    }
}

/// Open the search for how to change the entry's secret at its service.
/// A missing browser is reported, not fatal: the address is in the log.
pub fn open_search<S>(s: S, path: &EntryPath) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let url = rotation_search_url(path);
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    let s2 = s.clone();
    vault_do! { s ;
        let _ = s.log(format!("how to change it: {url}")) ;
        let out = s.handle(s.shell(opener.into(), vec![url], None, Vec::new())) ;
        match out {
            Ok(p) if p.status == 0 => s2.pure(()),
            _ => s2.log(format!("could not open a browser with `{opener}`; open the address above")),
        }
    }
}
