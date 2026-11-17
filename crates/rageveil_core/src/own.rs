//! Opening an entry as the operator of this laptop.
//!
//! The laptop's plain key opens automation-tolerant entries with no one
//! present. A human-only entry has no copy for that key; it has one for
//! the laptop's Touch ID key, if one is configured, and opening that copy
//! runs the Secure Enclave plugin, which asks for a finger on the sensor.
//! On Linux that key is a TPM key, and age-plugin-tpm asks for its PIN.

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::store::StoreLayout;
use crate::sugar::first_existing;
use crate::types::EntryPath;
use crate::vault_do;

/// Decrypt the operator's copy of `path`: the plain key's copy if there
/// is one, otherwise the Touch ID key's.
pub fn decrypt_own<S>(s: S, layout: StoreLayout, cfg: Config, path: EntryPath) -> S::R<Content>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let hash = path.hash();
    let plain = layout.entry_file_candidates(&hash, &cfg.whoami);
    let touch = cfg
        .touch
        .as_ref()
        .map(|t| (layout.entry_file_candidates(&hash, &t.whoami), t.identity_path.clone()));
    let s2 = s.clone();
    vault_do! { s ;
        let found = first_existing(s.clone(), plain.clone()) ;
        match found {
            Some(file) => open(s2.clone(), file, cfg.identity_path.clone()),
            None => open_touch(s2.clone(), path, plain, touch),
        }
    }
}

fn open_touch<S>(
    s: S,
    path: EntryPath,
    plain: Vec<std::path::PathBuf>,
    touch: Option<(Vec<std::path::PathBuf>, std::path::PathBuf)>,
) -> S::R<Content>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let looked = plain
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(" or ");
    let Some((candidates, identity)) = touch else {
        return s.fail(format!("no entry for {path} (looked at {looked})"));
    };
    let s2 = s.clone();
    vault_do! { s ;
        let found = first_existing(s.clone(), candidates) ;
        match found {
            None => s2.fail(format!(
                "no entry for {path} (looked at {looked}, and for this laptop's Touch ID key)"
            )),
            Some(file) => {
                let s3 = s2.clone();
                vault_do! { s2 ;
                    let _ = s2.log(format!("{path} is human-only: {}", release_hint(&identity))) ;
                    open(s3, file, identity)
                }
            }
        }
    }
}

/// What the person does to release the key at `identity`: a TPM key
/// asks for its PIN, a Secure Enclave key for a finger.
fn release_hint(identity: &std::path::Path) -> &'static str {
    let tpm = std::fs::read_to_string(identity)
        .map(|t| t.contains("AGE-PLUGIN-TPM-1"))
        .unwrap_or(false);
    if tpm { "enter the TPM key's PIN to open it" } else { "touch the sensor to open it" }
}

fn open<S>(s: S, file: std::path::PathBuf, identity: std::path::PathBuf) -> S::R<Content>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    vault_do! { s ;
        let cipher = s.read_file(file) ;
        let plain = s.decrypt(cipher, vec![identity]) ;
        s.decode_json::<Content>(plain)
    }
}
