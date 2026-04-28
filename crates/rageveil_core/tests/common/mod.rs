//! Shared test plumbing — generates fresh age identities, lays out
//! per-test temp directories, and executes Live programs on a
//! tokio runtime.

use age::x25519;
use rageveil_core::types::RecipientSpec;
use rageveil_core::Live;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// One actor in a test scenario — owns an age x25519 identity
/// and the on-disk path where its private half lives.
pub struct Actor {
    pub identity: x25519::Identity,
    pub recipient: RecipientSpec,
    pub identity_path: PathBuf,
    /// Holds the temp dir alive for the duration of the test
    /// even if `identity_path` is the only borrow in flight.
    #[allow(dead_code)]
    pub home: TempDir,
    pub store_root: PathBuf,
}

impl Actor {
    /// Build a fresh actor: random x25519 keypair, key file written
    /// to `<home>/.config/age/keys.txt`, store root at
    /// `<home>/.rageveil`.
    pub fn fresh(label: &str) -> Self {
        let identity = x25519::Identity::generate();
        let recipient_str = identity.to_public().to_string();
        let recipient = RecipientSpec::new(recipient_str);

        let home = TempDir::new().expect("tempdir");
        let key_dir = home.path().join(".config/age");
        std::fs::create_dir_all(&key_dir).expect("mk key dir");
        let identity_path = key_dir.join("keys.txt");
        let secret = identity.to_string();
        // age's x25519 `to_string()` hands back a `SecretString`
        // that wraps the AGE-SECRET-KEY-… form. We need the bytes
        // on disk for `IdentityFile::from_file` to parse.
        use secrecy::ExposeSecret;
        let secret_text: &str = secret.expose_secret();
        std::fs::write(
            &identity_path,
            format!("# {}\n{}\n", label, secret_text),
        )
        .expect("write key");
        let store_root = home.path().join(".rageveil");
        Actor { identity, recipient, identity_path, home, store_root }
    }
}

/// Build a Live interpreter with `home_override` pinned to the
/// actor's home — keeps `default_identity_paths()` deterministic
/// in tests.
pub fn live_for(actor: &Actor) -> Live {
    Live::new().with_home(actor.home.path().to_path_buf())
}

/// Run a `LiveR<()>`-shaped program on a single-thread tokio
/// runtime. Tests use a single-thread runtime so `spawn_blocking`
/// inside age operations doesn't deadlock the harness.
pub fn run_blocking<F, T>(fut: F) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(fut)
}

/// True if `path` exists as a regular file or directory.
#[allow(dead_code)]
pub fn exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().try_exists().unwrap_or(false)
}
