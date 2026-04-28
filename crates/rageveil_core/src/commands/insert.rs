//! `rageveil insert PATH [--batch]`.
//!
//! Encrypts a payload to the operator's own recipient and drops
//! it on disk under `<store>/<entry-hash>/<recipient-fp>.age`.
//! `--batch` reads the secret from stdin (the only path we ship —
//! no editor integration in V1, deliberately, since interactive
//! editing isn't on the critical-path requirements list).

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::index::{Cached, Index};
use crate::metadata::Metadata;
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::{EntryPath, Salt};
use crate::{git, vault_do};

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct InsertArgs {
    pub root: PathBuf,
    pub path: EntryPath,
    /// Either supplied directly (`--payload`, mostly used in
    /// tests) or read from stdin when `payload_from_stdin` is set.
    pub payload: Option<String>,
    pub payload_from_stdin: bool,
}

pub fn insert<S>(s: S, args: InsertArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());

    let cfg_path = layout.config_path();
    let payload_supplied = args.payload.clone();
    let payload_from_stdin = args.payload_from_stdin;
    let path = args.path.clone();

    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let payload = resolve_payload(s.clone(), payload_supplied, payload_from_stdin) ;
        let salt_bytes = s.random_bytes(32) ;
        let now = s.now() ;
        let _ = do_insert(
            s.clone(),
            layout.clone(),
            cfg,
            path.clone(),
            payload,
            Salt::from_bytes(&salt_bytes),
            now,
        ) ;
        let out = git::add_all(&s, layout.store_dir()) ;
        match out.success() {
            true => commit_insert(s.clone(), layout.store_dir(), path),
            false => s.fail(format!("git add failed: {}", out.stderr_str())),
        }
    }
}

fn resolve_payload<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    supplied: Option<String>,
    from_stdin: bool,
) -> S::R<String> {
    match (supplied, from_stdin) {
        (Some(p), _) => s.pure(p),
        (None, true) => {
            vault_do! { s ;
                let bytes = s.read_stdin() ;
                match String::from_utf8(bytes) {
                    Ok(s2) => s.pure(s2.trim_end_matches('\n').to_owned()),
                    Err(e) => s.fail(format!("stdin not utf-8: {e}")),
                }
            }
        }
        (None, false) => s.fail(
            "no payload supplied; pass --payload or --batch and pipe one in".into(),
        ),
    }
}

fn do_insert<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    path: EntryPath,
    payload: String,
    salt: Salt,
    now: chrono::DateTime<chrono::Utc>,
) -> S::R<()> {
    let metadata = Metadata::new(cfg.whoami.clone(), now);
    let content = Content {
        path: path.clone(),
        salt,
        payload,
        metadata: metadata.clone(),
    };
    let recipients = vec![cfg.whoami.clone()];

    // Pure derivations — sha256 of the path and the operator's
    // recipient. No reason to round-trip through the DSL; the
    // values feed straight into the layout helpers below.
    let hash = path.hash();
    let fp = cfg.whoami.fingerprint();
    let entry_dir = layout.entry_dir(&hash);
    let entry_file = layout.entry_file(&hash, &fp);

    let s2 = s.clone();
    let layout2 = layout.clone();
    let path2 = path.clone();
    vault_do! { s ;
        let plaintext = s.encode_json(content) ;
        let ciphertext = s.encrypt(plaintext, recipients) ;
        let _ = s.mkdir_p(entry_dir) ;
        let _ = s.write_file(entry_file, ciphertext) ;
        update_index_after_insert(s2, layout2, path2, hash, metadata, now)
    }
}

fn update_index_after_insert<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    path: EntryPath,
    hash: crate::types::EntryHash,
    metadata: Metadata,
    now: chrono::DateTime<chrono::Utc>,
) -> S::R<()> {
    let s2 = s.clone();
    let index_path = layout.index_path();
    vault_do! { s ;
        let mut idx = read_index_or_empty(s2.clone(), index_path.clone()) ;
        {
            idx.entries.insert(path.clone(), Cached { hash, metadata, seen: now });
            write_json(s2.clone(), index_path, idx)
        }
    }
}

fn read_index_or_empty<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    path: PathBuf,
) -> S::R<Index> {
    let s2 = s.clone();
    vault_do! { s ;
        let exists = s.exists(path.clone()) ;
        match exists {
            true  => read_json::<S, Index>(s2.clone(), path),
            false => s.pure(Index::empty()),
        }
    }
}

fn commit_insert<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    path: EntryPath,
) -> S::R<()> {
    vault_do! { s ;
        let out = git::commit(&s, store_dir, format!("insert {}", path)) ;
        match out.success() {
            true => s.log(format!("inserted {}", path)),
            // `git commit` returns 1 with "nothing to commit" when
            // re-inserting an unchanged value — that's not a
            // failure, so swallow it.
            false if out.stderr_str().contains("nothing to commit") => s.pure(()),
            false => s.fail(format!("git commit failed: {}", out.stderr_str())),
        }
    }
}
