//! `rageveil allow PATH RECIPIENT...` — the sharing-to-key
//! operation.
//!
//! The invariant carried over from passveil: **only someone who
//! can decrypt is allowed to share**. We decrypt the entry with
//! the operator's own identity, append `Allow` log entries for
//! the new recipients, then re-encrypt one copy of the resulting
//! [`Content`] per *currently trusted* recipient (the union of
//! existing + newly added).
//!
//! Each recipient gets their own `<entry-hash>/<recipient-fp>.age`
//! file. They are mutually decryptable because they all encode
//! the same plaintext, but they are *different ciphertexts* — the
//! age stream cipher uses fresh per-recipient ephemeral X25519,
//! so the blobs are not even bytewise comparable.

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::index::{Cached, Index};
use crate::metadata::{LogEntry, Metadata, Stamp};
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::{EntryHash, EntryPath, RecipientSpec};
use crate::{git, vault_do};

use chrono::{DateTime, Utc};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct AllowArgs {
    pub root: PathBuf,
    pub path: EntryPath,
    pub recipients: Vec<RecipientSpec>,
}

pub fn allow<S>(s: S, args: AllowArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let cfg_path = layout.config_path();
    let path = args.path.clone();
    let new_recipients = args.recipients.clone();

    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let content = decrypt_self(s.clone(), layout.clone(), cfg.clone(), path.clone()) ;
        let now = s.now() ;
        let _ = reshare(
            s.clone(),
            layout.clone(),
            cfg,
            path.clone(),
            content,
            new_recipients,
            now,
        ) ;
        let out_add = git::add_all(&s, layout.store_dir()) ;
        match out_add.success() {
            true => commit_allow(s.clone(), layout.store_dir(), path),
            false => s.fail(format!("git add failed: {}", out_add.stderr_str())),
        }
    }
}

fn decrypt_self<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    path: EntryPath,
) -> S::R<Content> {
    let identity_path = cfg.identity_path.clone();
    let hash = path.hash();
    let fp = cfg.whoami.fingerprint();
    let file = layout.entry_file(&hash, &fp);
    let file_for_msg = file.clone();
    let path_for_msg = path.clone();
    let whoami_for_msg = cfg.whoami.clone();
    vault_do! { s ;
        let exists = s.exists(file.clone()) ;
        let _ = match exists {
            true  => s.pure(()),
            false => s.fail(format!(
                "no entry for {} as {} (looked at {})",
                path_for_msg, whoami_for_msg, file_for_msg.display()
            )),
        } ;
        let cipher = s.read_file(file) ;
        let plain = s.decrypt(cipher, vec![identity_path]) ;
        s.decode_json::<Content>(plain)
    }
}

fn reshare<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    path: EntryPath,
    content: Content,
    new_recipients: Vec<RecipientSpec>,
    now: DateTime<Utc>,
) -> S::R<()> {
    // Update the metadata log with Allow entries for *new* names.
    // Already-trusted recipients are silently no-ops — passveil's
    // exact behaviour ("nothing to do" for entirely-redundant
    // calls is for the CLI to decide; here we just don't bloat
    // the log).
    let already: std::collections::BTreeSet<String> = content
        .metadata
        .trusted()
        .into_iter()
        .map(|r| r.0)
        .collect();

    let mut metadata = content.metadata.clone();
    let mut added: Vec<RecipientSpec> = Vec::new();
    for r in new_recipients {
        if already.contains(&r.0) {
            continue;
        }
        added.push(r.clone());
        metadata.log.push(LogEntry::Allow {
            subject: r,
            stamp: Stamp { at: now, by: cfg.whoami.clone() },
        });
    }
    metadata.updated = Some(Stamp { at: now, by: cfg.whoami.clone() });

    let updated_content = Content {
        path: path.clone(),
        salt: content.salt,
        payload: content.payload,
        metadata: metadata.clone(),
    };

    let trusted = metadata.trusted();
    let hash = path.hash();
    let entry_dir = layout.entry_dir(&hash);
    let s2 = s.clone();
    let layout2 = layout.clone();
    let path2 = path.clone();
    let added_for_log = added.clone();
    let metadata_for_index = metadata.clone();
    vault_do! { s ;
        let plaintext = s.encode_json(updated_content) ;
        // mkdir once: per-recipient writes all land in the same
        // entry-dir, no need to repeat the syscall in the loop.
        let _ = s.mkdir_p(entry_dir) ;
        let _ = write_per_recipient(s2.clone(), layout2.clone(), hash.clone(), plaintext, trusted) ;
        let _ = update_index(s2.clone(), layout2.clone(), path2, hash, metadata_for_index, now) ;
        log_added(s2.clone(), added_for_log)
    }
}

fn write_per_recipient<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    hash: EntryHash,
    plaintext: Vec<u8>,
    trusted: Vec<RecipientSpec>,
) -> S::R<()> {
    fn go<S: Vault + Clone + Send + Sync + 'static>(
        s: S,
        layout: StoreLayout,
        hash: EntryHash,
        plaintext: Vec<u8>,
        rest: Vec<RecipientSpec>,
    ) -> S::R<()> {
        let mut iter = rest.into_iter();
        match iter.next() {
            None => s.pure(()),
            Some(r) => {
                let s2 = s.clone();
                let layout2 = layout.clone();
                let hash2 = hash.clone();
                let plaintext2 = plaintext.clone();
                let entry_file = layout.entry_file(&hash, &r.fingerprint());
                let remaining: Vec<RecipientSpec> = iter.collect();
                vault_do! { s ;
                    let cipher = s.encrypt(plaintext2, vec![r]) ;
                    let _ = s.write_file(entry_file, cipher) ;
                    go(s2, layout2, hash2, plaintext, remaining)
                }
            }
        }
    }
    let s2 = s.clone();
    go(s2, layout, hash, plaintext, trusted)
}

fn update_index<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    path: EntryPath,
    hash: EntryHash,
    metadata: Metadata,
    now: DateTime<Utc>,
) -> S::R<()> {
    let s2 = s.clone();
    let index_path = layout.index_path();
    vault_do! { s ;
        let mut idx = read_index_or_empty(s2.clone(), index_path.clone()) ;
        // sync block: mutate the loaded index, then chain the
        // write effect — `write_json` is the value of the block,
        // which feeds into the macro's tail-position rule.
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

fn log_added<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    added: Vec<RecipientSpec>,
) -> S::R<()> {
    if added.is_empty() {
        return s.log("allow: nothing to do (all recipients already trusted)".into());
    }
    let names: Vec<String> = added.iter().map(|r| r.0.clone()).collect();
    s.log(format!("allowed: {}", names.join(", ")))
}

fn commit_allow<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    path: EntryPath,
) -> S::R<()> {
    vault_do! { s ;
        let out = git::commit(&s, store_dir, format!("allow {}", path)) ;
        match out.success() {
            true => s.pure(()),
            false if out.stderr_str().contains("nothing to commit") => s.pure(()),
            false => s.fail(format!("git commit failed: {}", out.stderr_str())),
        }
    }
}
