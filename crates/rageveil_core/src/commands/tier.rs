//! `rageveil tier`, `rageveil touch`, `rageveil tpm` and `rageveil gate`: deciding who may
//! open an entry without a person present. See [`crate::tier`].

use std::path::PathBuf;

use chrono::{DateTime, Utc};

use crate::config::{Config, TouchIdentity};
use crate::content::Content;
use crate::dsl::Vault;
use crate::metadata::Stamp;
use crate::own::decrypt_own;
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::tier::{Tier, gated_path, load_gated_or_empty, write_entry};
use crate::types::{CommitOutcome, EntryPath, RecipientSpec};
use crate::{git, vault_do};

#[derive(Clone, Debug)]
pub struct TierArgs {
    pub root: PathBuf,
    pub path: EntryPath,
    pub tier: Tier,
}

/// Set an entry's tier and rewrite its copies to match: a human-only entry
/// keeps copies for gated keys alone and takes them from plain ones.
pub fn tier<S>(s: S, args: TierArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let cfg_path = layout.config_path();
    let s2 = s.clone();
    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let content = decrypt_own(s.clone(), layout.clone(), cfg.clone(), args.path.clone()) ;
        let now = s.now() ;
        retier(s2.clone(), layout.clone(), cfg, content, args.tier, now)
    }
}

fn retier<S>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    content: Content,
    tier: Tier,
    now: DateTime<Utc>,
) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let path = content.path.clone();
    if content.metadata.tier == tier {
        return s.log(format!("{path} is already {}", tier.word()));
    }
    let mut metadata = content.metadata.clone();
    metadata.tier = tier;
    metadata.updated = Some(Stamp { at: now, by: cfg.whoami.clone() });
    let updated = Content { metadata: metadata.clone(), ..content.clone() };
    let hash = path.hash();
    let store_dir = layout.store_dir();
    let s2 = s.clone();
    vault_do! { s ;
        let gated = load_gated_or_empty(s.clone(), gated_path(&layout)) ;
        let plaintext = s.encode_json(updated) ;
        let _ = write_entry(s.clone(), layout.clone(), hash.clone(), plaintext, metadata.clone()) ;
        let _ = crate::commands::allow::update_index(s.clone(), layout.clone(), path.clone(), hash.clone(), metadata, now) ;
        // Going human-only from automation-tolerant: every plain key the
        // entry trusted held a copy, and git history keeps it.
        let exposed = s.pure(
            tier == Tier::Human && content.metadata.trusted().iter().any(|r| !gated.holds(r)),
        ) ;
        let _ = crate::exposure::mark(s.clone(), layout.clone(), hash, exposed) ;
        let _ = git::add_all(&s, store_dir.clone()) ;
        let out = git::commit(&s, store_dir, format!("{} {path}", tier.verb())) ;
        match out {
            CommitOutcome::Committed | CommitOutcome::NothingToCommit => match exposed {
                false => s2.log(format!("{path} is now {}", tier.word())),
                true => s2.log(format!(
                    "{path} is now {}, but a plain key held its value and the store's \
                     history keeps that copy: rotate it with `rageveil rotate {path}`",
                    tier.word()
                )),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct TouchArgs {
    pub root: PathBuf,
    /// A Secure Enclave identity file, as `age-plugin-se keygen` writes it.
    pub identity_path: PathBuf,
}

/// Record this laptop's Touch ID key in its config, and return its
/// recipient, so that it can be added to the address book and grouped
/// under the person.
pub fn touch<S>(s: S, args: TouchArgs) -> S::R<RecipientSpec>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let cfg_path = layout.config_path();
    let identity = args.identity_path.clone();
    let s2 = s.clone();
    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path.clone()) ;
        let whoami = s.recipient_of(identity.clone()) ;
        let _ = if crate::se::is_se_recipient(whoami.as_str()) {
            s.pure(())
        } else {
            s.fail(format!(
                "{} is not a Secure Enclave key (its recipient is not age1se1…)",
                identity.display()
            ))
        } ;
        let _ = write_json(
            s.clone(),
            cfg_path,
            Config {
                touch: Some(TouchIdentity { whoami: whoami.clone(), identity_path: identity }),
                ..cfg
            },
        ) ;
        s2.pure(whoami)
    }
}

/// Record this laptop's TPM key in its config, the Linux counterpart of
/// [`touch`], and return its recipient for the address book. Draft.
///
/// AI-assisted addition (2026-11-17): model Claude Opus 5.5
/// (`claude-opus-5-5`); reasoning effort unavailable (not exposed by the
/// harness).
///
/// The key goes where a Mac keeps its Touch ID key, so every path that
/// opens a human-only copy through that key serves it. It must be an
/// age-plugin-tpm identity made with a PIN (`age-plugin-tpm --generate
/// --pin`): without one, anything running as this user could ask the
/// TPM to open it, and it would be no better than the plain key. The
/// store gates it by name (`rageveil gate`), since its recipient does
/// not say that it has a PIN.
pub fn tpm<S>(s: S, args: TouchArgs) -> S::R<RecipientSpec>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let cfg_path = layout.config_path();
    let identity = args.identity_path.clone();
    let s2 = s.clone();
    let s3 = s.clone();
    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path.clone()) ;
        let text = s.read_file(identity.clone()) ;
        let _ = {
            let checked = crate::tag::tpm_identity_info(&String::from_utf8_lossy(&text))
                .map_err(|e| format!("{} is not a TPM key: {e}", identity.display()))
                .and_then(|info| if info.pin {
                    Ok(())
                } else {
                    Err(format!(
                        "{} is a TPM key without a PIN: anything running as you could open it. \
                         Make one with `age-plugin-tpm --generate --pin`.",
                        identity.display()
                    ))
                });
            crate::sugar::lift_result(&s3, checked)
        } ;
        let whoami = s.recipient_of(identity.clone()) ;
        let _ = if crate::tag::is_tag_recipient(whoami.as_str()) {
            s.pure(())
        } else {
            s.fail(format!(
                "{} names the recipient {}, not a TPM key's age1tag1…",
                identity.display(),
                whoami.as_str()
            ))
        } ;
        let _ = write_json(
            s.clone(),
            cfg_path,
            Config {
                touch: Some(TouchIdentity { whoami: whoami.clone(), identity_path: identity }),
                ..cfg
            },
        ) ;
        s2.pure(whoami)
    }
}

#[derive(Clone, Debug)]
pub struct GateArgs {
    pub root: PathBuf,
    /// Address-book names whose keys a person's biometrics guard.
    pub names: Vec<String>,
    /// `false` takes the names off the list again.
    pub gated: bool,
}

/// Mark device keys as gated: they may then hold human-only entries.
pub fn gate<S>(s: S, args: GateArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());
    let path = gated_path(&layout);
    let store_dir = layout.store_dir();
    let s2 = s.clone();
    let names = args.names.clone();
    vault_do! { s ;
        let book = crate::commands::address::load_or_empty(s.clone(), layout.addressbook_path()) ;
        let mut gated = load_gated_or_empty(s.clone(), path.clone()) ;
        let keys = {
            let found: Result<Vec<String>, String> = names
                .iter()
                .map(|n| {
                    book.get(n)
                        .map(RecipientSpec::canonical_key)
                        .ok_or_else(|| format!("{n:?} is not in the address book"))
                })
                .collect();
            crate::sugar::lift_result(&s, found)
        } ;
        let _ = {
            for k in keys {
                if args.gated {
                    gated.keys.insert(k);
                } else {
                    gated.keys.remove(&k);
                }
            }
            write_json(s.clone(), path.clone(), gated)
        } ;
        let _ = git::add_path(&s, store_dir.clone(), path) ;
        let out = git::commit(&s, store_dir, format!(
            "{} {}",
            if args.gated { "gate" } else { "ungate" },
            names.join(" ")
        )) ;
        match out {
            CommitOutcome::Committed | CommitOutcome::NothingToCommit => s2.pure(()),
        }
    }
}
