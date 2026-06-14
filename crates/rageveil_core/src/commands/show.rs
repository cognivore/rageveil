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
use crate::sugar::{first_existing, read_json};
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
        s.pure(ShowOutput { content })
    }
}

fn decrypt_for_self<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    path: EntryPath,
) -> S::R<Content> {
    let identity_path = cfg.identity_path.clone();
    let hash = path.hash();
    // Canonical name first, legacy (pre-fix verbatim) name as fallback.
    let candidates = layout.entry_file_candidates(&hash, &cfg.whoami);
    let where_msg = candidates
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" or ");
    let s2 = s.clone();
    vault_do! { s ;
        let found = first_existing(s.clone(), candidates) ;
        let entry_file = match found {
            Some(f) => s2.pure(f),
            None => s2.fail(format!("no entry for {} (looked at {})", path, where_msg)),
        } ;
        let cipher = s.read_file(entry_file) ;
        let plain = s.decrypt(cipher, vec![identity_path]) ;
        s.decode_json::<Content>(plain)
    }
}
