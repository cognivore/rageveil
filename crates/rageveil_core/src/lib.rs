//! Tagless-final core for **rageveil** — a git-backed, age-encrypted
//! drop-in replacement for the Haskell+darcs+gpg `passveil`.
//!
//! The encoding follows Carette / Kiselyov / Shan, *Finally Tagless,
//! Partially Evaluated* (J. Functional Programming 19(5), 2009), and
//! the Rust shape mirrors `orim_probe` in this author's other repo
//! (see `CLAUDE.md` next to this crate). One trait — [`Vault`] — is
//! the surface vocabulary; commands are written *once*, polymorphic
//! over `S: Vault`, and the binary picks an interpreter at runtime:
//!
//!   * [`Live`] — tokio + age + real subprocesses; the path the
//!     CLI actually takes.
//!   * [`Plan`] — captures the program as a [`PlanNode`] tree
//!     without executing it; useful for `--plan` dry-runs and
//!     would be the entry point for any future renderer
//!     (auditor report, JSON dump, …).
//!
//! ### Effect surface, in one breath
//!
//! Filesystem (`read_file`, `write_file`, `mkdir_p`, …), age
//! crypto (`encrypt`, `decrypt`, `recipient_of`,
//! `default_identity_paths`), shell (one method, used to drive
//! `git`), system (`now`, `random_bytes`, `read_stdin`, `home_dir`),
//! and reporting (`log`, `step`). Every external thing rageveil
//! does has to come back to one of these — no `std::fs` or
//! `Command::new` inside command code, ever.
//!
//! ### What's intentionally not here
//!
//! There's no `git` effect — git invocation goes through [`Vault::shell`]
//! and the helpers in [`git`]. A future interpreter wanting to
//! emulate git (testing a network-partitioned sync, say) replaces
//! `shell` and the rest of the pattern keeps working.

pub mod commands;
pub mod config;
pub mod content;
pub mod dsl;
pub mod git;
pub mod index;
pub mod live;
pub mod metadata;
pub mod plan;
pub mod store;
pub mod sugar;
pub mod types;

pub use config::Config;
pub use content::Content;
pub use dsl::Vault;
pub use index::{diff as index_diff, Cached, Index, IndexMod};
pub use live::{Live, LiveR};
pub use metadata::{LogEntry, Metadata, Stamp};
pub use plan::{Plan, PlanNode};
pub use store::StoreLayout;
pub use types::{
    EntryHash, EntryPath, ProcessOut, RecipientFingerprint, RecipientSpec, Salt,
};

/// Do-notation for the [`Vault`] DSL.
///
/// Desugars `let name = effect ; rest` and `effect ; rest` into
/// nested [`Vault::bind`] calls so a polymorphic command reads
/// top-to-bottom instead of being a right-rotated tower of
/// closures. `S` must be `Clone` (both [`Live`] and [`Plan`] are).
///
/// Mirrors `orim_probe::probe_do!` byte-for-byte except for the
/// crate path. The `$s:ident` (rather than `$s:expr`) capture is
/// load-bearing: it lets us shadow the binding inside each
/// generated closure with a freshly-cloned copy, so the user's
/// `&s` references inside `$expr` and the recursive expansion can
/// both refer to the right scope's `s` without tripping the
/// borrow checker.
///
/// ```ignore
/// vault_do! { s ;
///     let bytes = s.read_file(path) ;
///     s.write_file(other, bytes) ;
///     s.pure(())
/// }
/// ```
#[macro_export]
macro_rules! vault_do {
    // Final tail expression — just the value, no further binds.
    ($s:ident ; $tail:expr) => { $tail };

    // Discard form: `let _ = effect ; rest`. Same as the
    // sequenced form below but reads more obviously as "do this,
    // ignore its `()` result". Required because `_` can't match
    // `$name:ident`.
    ($s:ident ; let _ = $expr:expr ; $($rest:tt)*) => {{
        let __rageveil_s_clone = ::std::clone::Clone::clone(&$s);
        $s.bind($expr, move |_| {
            #[allow(unused_variables)]
            let $s = __rageveil_s_clone;
            $crate::vault_do!($s ; $($rest)*)
        })
    }};

    // Mutable bind: `let mut name = effect ; rest`. Used when a
    // helper needs to thread a mutable accumulator through.
    ($s:ident ; let mut $name:ident = $expr:expr ; $($rest:tt)*) => {{
        let __rageveil_s_clone = ::std::clone::Clone::clone(&$s);
        $s.bind($expr, move |mut $name| {
            #[allow(unused_variables)]
            let $s = __rageveil_s_clone;
            $crate::vault_do!($s ; $($rest)*)
        })
    }};

    // Explicit bind: `let name = effect ; rest`.
    //
    // We require `$s:ident` (not `$s:expr`) so we can shadow the
    // identifier inside the closure body with a freshly-cloned
    // copy. That way the user's `&s` references inside `$expr`
    // and the recursive expansion both refer to the right scope's
    // `s` without triggering "move out of borrowed value".
    //
    // Calls go through method syntax (`$s.bind(...)`) rather than
    // UFCS (`Vault::bind(&$s, ...)`) so the macro is identifier-
    // type-agnostic — owned `S` or borrowed `&S` both auto-ref to
    // the `&self` of `bind` without us having to pre-deref.
    ($s:ident ; let $name:ident = $expr:expr ; $($rest:tt)*) => {{
        let __rageveil_s_clone = ::std::clone::Clone::clone(&$s);
        $s.bind($expr, move |$name| {
            #[allow(unused_variables)]
            let $s = __rageveil_s_clone;
            $crate::vault_do!($s ; $($rest)*)
        })
    }};

    // Sequenced effect: `effect ; rest` (drops the result).
    ($s:ident ; $expr:expr ; $($rest:tt)*) => {{
        let __rageveil_s_clone = ::std::clone::Clone::clone(&$s);
        $s.bind($expr, move |_| {
            #[allow(unused_variables)]
            let $s = __rageveil_s_clone;
            $crate::vault_do!($s ; $($rest)*)
        })
    }};
}
