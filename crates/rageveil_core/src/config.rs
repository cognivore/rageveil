//! `~/.rageveil/config.json` — store-level configuration.
//!
//! Two fields, deliberately. `whoami` is the recipient string for
//! the operator's own age key (used as a re-encrypt target on every
//! `allow`); `identity_path` is where we look up the matching
//! private key when we need to decrypt. Keeping the private side
//! at a *path* (not embedded) means the config file is fine to
//! commit — there are no secrets in it.

use crate::types::RecipientSpec;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// The operator's own age recipient (public-key-equivalent
    /// string). Embedded into entry metadata as the `created.by` /
    /// `updated.by` issuer, and added to the recipient list of
    /// every `allow` so the operator can always read what they
    /// shared.
    pub whoami: RecipientSpec,

    /// Filesystem path to the operator's private identity. Read
    /// every time we decrypt; never embedded in serialised data.
    pub identity_path: PathBuf,
}
