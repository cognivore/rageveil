//! The tagless-final DSL itself: trait [`Vault`], the surface
//! vocabulary every interpreter must answer.
//!
//! The encoding follows Carette / Kiselyov / Shan, *Finally Tagless,
//! Partially Evaluated* — `R<A>` stands in for the Haskell HKT
//! `repr` via a generic associated type.
//!
//! # Picking the surface
//!
//! Methods are kept small and orthogonal — composition happens
//! through [`Vault::bind`] / [`Vault::seq`]. The trait answers a
//! single question for each method: **does this need
//! interpreter-specific dispatch?** If yes, it's here. If no
//! (pure function on values), it's a plain method on the value
//! type — `EntryPath::hash`, `RecipientSpec::fingerprint` — not a
//! DSL effect.
//!
//! That's why you won't find `hash_path` or `recipient_fingerprint`
//! on this trait: under any interpreter they would do the same
//! sha256, so the trait round-trip is dead weight. Conversely
//! `encode_json` / `decode_json` *are* effects: under [`Live`]
//! they call serde, under [`Plan`] they substitute stub values,
//! and the rendered trace lists them as their own steps.
//!
//! [`Live`]: crate::Live
//! [`Plan`]: crate::Plan

use crate::types::{ProcessOut, RecipientSpec};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};
use std::path::PathBuf;

/// The DSL.
///
/// `R<A>` is the interpreter's chosen result-type constructor. In
/// the Live interpreter it's a boxed future; in Plan it's an AST
/// node carrying the effect spec and a continuation.
///
/// The trait is **not** object-safe (GATs forbid `dyn Vault`);
/// commands are generic over `S: Vault` and the binary picks one
/// interpreter at compile time.
///
/// Bound `A: Send + 'static` is global because every interpreter we
/// ship stores `A` either inside a `Send` future or inside an owned
/// AST node.
pub trait Vault {
    /// The interpreter's result-type constructor — Haskell's
    /// `repr`. The `Send + 'static` supertrait bound is what lets
    /// helper combinators (`sugar::sequence`, the `vault_do!`
    /// closures) capture intermediate `R<A>` values without a
    /// `where S::R<A>: Send` clause at every call site.
    ///
    /// Both shipped interpreters satisfy this:
    ///   * [`crate::Live`] uses `BoxFuture<'static, Result<A>>`
    ///     (Send + 'static by construction).
    ///   * [`crate::Plan`] uses `PlanNode<A>` whose variants only
    ///     hold `Send + 'static` data and `Box<dyn FnOnce + Send
    ///     + 'static>` continuations.
    type R<A>: Send + 'static
    where
        A: Send + 'static;

    // ── Monad-ish core ────────────────────────────────────────────────

    fn pure<A>(&self, a: A) -> Self::R<A>
    where
        A: Send + 'static;

    fn bind<A, B, F>(&self, m: Self::R<A>, k: F) -> Self::R<B>
    where
        A: Send + 'static,
        B: Send + 'static,
        F: FnOnce(A) -> Self::R<B> + Send + 'static;

    fn seq<A, B>(&self, m: Self::R<A>, n: Self::R<B>) -> Self::R<B>
    where
        A: Send + 'static,
        B: Send + 'static;

    fn map<A, B, F>(&self, m: Self::R<A>, f: F) -> Self::R<B>
    where
        A: Send + 'static,
        B: Send + 'static,
        F: FnOnce(A) -> B + Send + 'static;

    /// Lift a fallible synchronous computation. Lets callers fail
    /// inside `bind` chains without inventing a per-op `Result`.
    fn fail<A>(&self, msg: String) -> Self::R<A>
    where
        A: Send + 'static;

    /// Catch a [`Vault::fail`] anywhere upstream and lift it into
    /// the value channel. `Ok(a)` if the program succeeded,
    /// `Err(msg)` if any `fail` was raised. Use this when a single
    /// step's failure should be recoverable rather than aborting
    /// the whole program — the canonical use is `sync` skipping a
    /// corrupt entry instead of bailing on the rebuild.
    ///
    /// This is the generalisation of "try" combinators (e.g. the
    /// removed `try_decode_json`); compose with any effect that
    /// can `fail`.
    fn handle<A>(&self, m: Self::R<A>) -> Self::R<Result<A, String>>
    where
        A: Send + 'static;

    // ── Filesystem ────────────────────────────────────────────────────
    //
    // These exist so commands don't have to escape the DSL via
    // `std::fs` / `tokio::fs`. Live runs them for real; Plan records
    // them as effects so a renderer can emit equivalent code.

    fn read_file(&self, path: PathBuf) -> Self::R<Vec<u8>>;
    fn write_file(&self, path: PathBuf, body: Vec<u8>) -> Self::R<()>;
    fn remove_file(&self, path: PathBuf) -> Self::R<()>;
    fn list_dir(&self, path: PathBuf) -> Self::R<Vec<PathBuf>>;
    fn mkdir_p(&self, path: PathBuf) -> Self::R<()>;
    fn exists(&self, path: PathBuf) -> Self::R<bool>;
    fn remove_dir_all(&self, path: PathBuf) -> Self::R<()>;
    fn rename(&self, from: PathBuf, to: PathBuf) -> Self::R<()>;

    // ── JSON ─────────────────────────────────────────────────────────
    //
    // serde encode/decode is the typed boundary between bytes and
    // values. Live runs the real codec; Plan records the step and
    // — for `decode_json` — substitutes a typed stub registered via
    // `Plan::with_stub::<T>(&value)`. Without a stub, decode under
    // Plan returns `fail` and propagates honestly through `bind`.

    fn encode_json<T>(&self, value: T) -> Self::R<Vec<u8>>
    where
        T: Serialize + Send + 'static;

    fn decode_json<T>(&self, bytes: Vec<u8>) -> Self::R<T>
    where
        T: DeserializeOwned + Send + 'static;

    // ── age encryption ────────────────────────────────────────────────
    //
    // The DSL deliberately speaks in *paths* and *strings*, never
    // in age's parsed identity types — so a Plan trace can render
    // an "encrypt to N recipients" line without leaking key
    // material, and so identity discovery (where do private keys
    // live on disk?) is the interpreter's problem rather than the
    // command author's.

    /// Encrypt `plaintext` to a list of recipient specs (age1…,
    /// ssh-ed25519…, ssh-rsa…). Output is ASCII-armored age — the
    /// same format ragenix produces, so the resulting `.age` files
    /// are mutually decryptable.
    fn encrypt(
        &self,
        plaintext: Vec<u8>,
        recipients: Vec<RecipientSpec>,
    ) -> Self::R<Vec<u8>>;

    /// Decrypt `ciphertext` using each identity file in turn until
    /// one succeeds. The interpreter is responsible for parsing
    /// each path as either an age key file or an OpenSSH private
    /// key.
    fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        identity_paths: Vec<PathBuf>,
    ) -> Self::R<Vec<u8>>;

    /// Derive the recipient (public key) corresponding to the
    /// identity file at `path`. Used at `init` time to record the
    /// store's `whoami`.
    fn recipient_of(&self, identity_path: PathBuf) -> Self::R<RecipientSpec>;

    /// The default identity paths the interpreter searches when no
    /// explicit identity file was passed — typically
    /// `~/.config/age/keys.txt`, `~/.ssh/id_ed25519`,
    /// `~/.ssh/id_rsa`. Returned filtered to those that exist.
    fn default_identity_paths(&self) -> Self::R<Vec<PathBuf>>;

    // ── Shell (git, mostly) ───────────────────────────────────────────

    /// Run a subprocess. The DSL goes through here rather than
    /// `std::process::Command` so git invocations are visible to
    /// renderers.
    fn shell(
        &self,
        program: String,
        args: Vec<String>,
        cwd: Option<PathBuf>,
        envs: Vec<(String, String)>,
    ) -> Self::R<ProcessOut>;

    // ── System ────────────────────────────────────────────────────────

    fn now(&self) -> Self::R<DateTime<Utc>>;
    fn random_bytes(&self, n: usize) -> Self::R<Vec<u8>>;

    /// Read all of stdin to a `Vec<u8>`. Used by `insert --batch`
    /// to ingest a secret from a pipeline. Plan stubs this to an
    /// empty vec.
    fn read_stdin(&self) -> Self::R<Vec<u8>>;

    /// Best-effort home directory lookup so the CLI can default
    /// `--store` to `~/.rageveil`. Wrapped as an effect so Plan
    /// can render it as such.
    fn home_dir(&self) -> Self::R<Option<PathBuf>>;

    // ── Reporting / output ───────────────────────────────────────────
    //
    // `stdout` is the primary channel for command output (the
    // payload of `show`, the lines of `list`). It's a DSL effect
    // — not a `print!` at the binding layer — so a future replay
    // / audit interpreter can capture "the program would print
    // these bytes" without any I/O escaping.

    fn stdout(&self, bytes: Vec<u8>) -> Self::R<()>;

    fn log(&self, msg: String) -> Self::R<()>;

    /// Scoped progress report. The body's effect tree runs under a
    /// labelled section in the Plan trace and a printed banner in
    /// Live.
    fn step<A, F>(&self, label: String, body: F) -> Self::R<A>
    where
        A: Send + 'static,
        F: FnOnce() -> Self::R<A> + Send + 'static;
}
