//! Helper combinators built on top of [`Vault`] — anything
//! reachable via `vault_do!`, `bind`, and `pure` lives here so the
//! trait stays small.
//!
//! Most are JSON load/save wrappers and a few collection idioms.

use crate::dsl::Vault;
use crate::vault_do;

use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::PathBuf;

/// Read a JSON file off disk and deserialise it. Wraps
/// [`Vault::read_file`] + [`Vault::decode_json`]; both are DSL
/// effects so a Plan trace records the read *and* the decode
/// step, rather than collapsing the decode into a hidden
/// `serde_json::from_slice`.
///
/// Takes `s: S` (owned) — call sites use `s.clone()`. The clone
/// is cheap on both shipped interpreters ([`crate::Live`] holds
/// only `Arc`s, [`crate::Plan`] is unit-shaped). Owned-by-value
/// here matters because the macro's generated closures are
/// `'static` and can't borrow.
pub fn read_json<S, T>(s: S, path: PathBuf) -> S::R<T>
where
    S: Vault + Clone + Send + 'static,
    T: DeserializeOwned + Send + 'static,
{
    vault_do! { s ;
        let bytes = s.read_file(path) ;
        s.decode_json::<T>(bytes)
    }
}

/// Serialise a value as JSON and write it to disk. Uses
/// [`Vault::encode_json`] + [`Vault::write_file`]; the encode
/// shows up as its own step in Plan.
pub fn write_json<S, T>(s: S, path: PathBuf, value: T) -> S::R<()>
where
    S: Vault + Clone + Send + 'static,
    T: Serialize + Send + 'static,
{
    vault_do! { s ;
        let bytes = s.encode_json(value) ;
        s.write_file(path, bytes)
    }
}

/// Sequence a vector of effects, collecting their results in
/// order. Right-fold over [`Vault::bind`] — the obvious shape.
pub fn sequence<S, A>(s: S, mut vs: Vec<S::R<A>>) -> S::R<Vec<A>>
where
    S: Vault + Clone + Send + 'static,
    A: Send + 'static,
{
    fn go<S: Vault + Clone + Send + 'static, A: Send + 'static>(
        s: S,
        rest: Vec<S::R<A>>,
        acc: Vec<A>,
    ) -> S::R<Vec<A>> {
        let mut iter = rest.into_iter();
        match iter.next() {
            None => s.pure(acc),
            Some(first) => {
                let s2 = s.clone();
                let remaining: Vec<S::R<A>> = iter.collect();
                s.bind(first, move |a| {
                    let mut next_acc = acc;
                    next_acc.push(a);
                    go(s2, remaining, next_acc)
                })
            }
        }
    }
    go(s, std::mem::take(&mut vs), Vec::new())
}

/// Convenience: convert a sync `Result<A, E>` (where `E:
/// std::fmt::Display`) into the interpreter's effect type by
/// dispatching to `pure` / `fail`.
pub fn lift_result<S, A, E>(s: &S, r: Result<A, E>) -> S::R<A>
where
    S: Vault,
    A: Send + 'static,
    E: std::fmt::Display,
{
    match r {
        Ok(v) => s.pure(v),
        Err(e) => s.fail(format!("{e}")),
    }
}

/// Same idea for `anyhow::Result`.
pub fn lift_anyhow<S, A>(s: &S, r: Result<A>) -> S::R<A>
where
    S: Vault,
    A: Send + 'static,
{
    match r {
        Ok(v) => s.pure(v),
        Err(e) => s.fail(format!("{e:#}")),
    }
}

/// Used in tests / one-shots to treat an Option as a fallible
/// computation — `None` becomes a [`Vault::fail`] with the
/// supplied message.
pub fn require<S, A>(s: &S, opt: Option<A>, msg: &str) -> S::R<A>
where
    S: Vault,
    A: Send + 'static,
{
    match opt {
        Some(v) => s.pure(v),
        None => s.fail(format!("required: {msg}")),
    }
}
