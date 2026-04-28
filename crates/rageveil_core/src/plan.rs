//! Plan interpreter — a free-monad (CPS) encoding of [`crate::Vault`].
//!
//! Each effect is reified as a [`PlanNode`] variant carrying the
//! effect specification *and* a continuation
//! `Box<dyn FnOnce(R) -> PlanNode<A>>`. [`PlanNode::bind`] walks the
//! tree, pushing the new continuation down to the leaves; the
//! leaves are `Pure(a)`.
//!
//! Same shape as Haskell's free monad transformer:
//!
//! ```haskell
//! data Free f a = Pure a | Impure (f (Free f a))
//! ```
//!
//! Rust doesn't have HKT so we hand-roll one variant per effect
//! method — `f` is fixed (the [`Vault`] vocabulary) and we pay one
//! enum variant per DSL operation.
//!
//! ## Typed stubs — making `--plan` walk
//!
//! A naïve free-monad renderer can't see past the first `decode_json`:
//! upstream `read_file` / `decrypt` produce empty stub bytes, real
//! serde fails, the trace dead-ends. We side-step this with a typed
//! stubs registry: `Plan::with_stub::<T>(&value)` registers a stand-in
//! of type `T` (stored as serialised JSON, not by reference, so the
//! trait method's bound stays narrow), and `decode_json::<T>` returns
//! that value if registered. Without a stub, the decode fails
//! honestly with a `no stub registered for Foo` message.
//!
//! No fake serde happens at construction time — the registry's bytes
//! are deserialised once per `decode_json` call during render, and
//! `encode_json` simply records the step and threads an empty `Vec<u8>`
//! through the continuation. That keeps Plan rendering data-size-
//! independent: traversing a program that "encodes a 10 MB index"
//! costs the same as one that encodes an empty struct.
//!
//! ## What you don't get
//!
//! Continuations carry closures whose bodies can't be inspected —
//! only invoked. So a renderer that branches on effect output
//! still only sees the happy path: a `match` inside a closure
//! commits to one arm at the moment the renderer calls the cont.
//! For the typical "linear pipeline" rageveil command this is
//! invisible; for a heavily-branching program it is the limit of
//! what the encoding can give without dropping into a different
//! shape (CPS-encoded match-as-DSL, see CLAUDE.md).

use crate::dsl::Vault;
use crate::types::{ProcessOut, RecipientSpec};

use chrono::{DateTime, TimeZone, Utc};
use serde::{de::DeserializeOwned, Serialize};
use std::any::TypeId;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// One node in the Plan AST. `A` is the type the program produces
/// once *fully* run; effect variants thread `A` through their
/// continuations.
pub enum PlanNode<A: 'static> {
    Pure(A),
    Fail {
        msg: String,
    },

    // ── Filesystem ─────────────────────────────────────────────────────
    ReadFile {
        path: PathBuf,
        cont: Box<dyn FnOnce(Vec<u8>) -> PlanNode<A> + Send + 'static>,
    },
    WriteFile {
        path: PathBuf,
        body: Vec<u8>,
        cont: Box<dyn FnOnce(()) -> PlanNode<A> + Send + 'static>,
    },
    RemoveFile {
        path: PathBuf,
        cont: Box<dyn FnOnce(()) -> PlanNode<A> + Send + 'static>,
    },
    ListDir {
        path: PathBuf,
        cont: Box<dyn FnOnce(Vec<PathBuf>) -> PlanNode<A> + Send + 'static>,
    },
    MkdirP {
        path: PathBuf,
        cont: Box<dyn FnOnce(()) -> PlanNode<A> + Send + 'static>,
    },
    Exists {
        path: PathBuf,
        cont: Box<dyn FnOnce(bool) -> PlanNode<A> + Send + 'static>,
    },
    RemoveDirAll {
        path: PathBuf,
        cont: Box<dyn FnOnce(()) -> PlanNode<A> + Send + 'static>,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
        cont: Box<dyn FnOnce(()) -> PlanNode<A> + Send + 'static>,
    },

    // ── JSON ──────────────────────────────────────────────────────────
    EncodeJson {
        type_name: &'static str,
        cont: Box<dyn FnOnce(Vec<u8>) -> PlanNode<A> + Send + 'static>,
    },
    DecodeJson {
        type_name: &'static str,
        in_len: usize,
        cont: Box<dyn FnOnce(()) -> PlanNode<A> + Send + 'static>,
    },

    // ── User-facing output ────────────────────────────────────────────
    Stdout {
        bytes_len: usize,
        cont: Box<dyn FnOnce(()) -> PlanNode<A> + Send + 'static>,
    },

    // ── age encryption ────────────────────────────────────────────────
    Encrypt {
        plaintext_len: usize,
        recipients: Vec<RecipientSpec>,
        cont: Box<dyn FnOnce(Vec<u8>) -> PlanNode<A> + Send + 'static>,
    },
    Decrypt {
        ciphertext_len: usize,
        identity_paths: Vec<PathBuf>,
        cont: Box<dyn FnOnce(Vec<u8>) -> PlanNode<A> + Send + 'static>,
    },
    RecipientOf {
        identity_path: PathBuf,
        cont: Box<dyn FnOnce(RecipientSpec) -> PlanNode<A> + Send + 'static>,
    },
    DefaultIdentityPaths {
        cont: Box<dyn FnOnce(Vec<PathBuf>) -> PlanNode<A> + Send + 'static>,
    },

    // ── Shell ─────────────────────────────────────────────────────────
    Shell {
        program: String,
        args: Vec<String>,
        cwd: Option<PathBuf>,
        envs: Vec<(String, String)>,
        cont: Box<dyn FnOnce(ProcessOut) -> PlanNode<A> + Send + 'static>,
    },

    // ── System ────────────────────────────────────────────────────────
    Now {
        cont: Box<dyn FnOnce(DateTime<Utc>) -> PlanNode<A> + Send + 'static>,
    },
    RandomBytes {
        n: usize,
        cont: Box<dyn FnOnce(Vec<u8>) -> PlanNode<A> + Send + 'static>,
    },
    ReadStdin {
        cont: Box<dyn FnOnce(Vec<u8>) -> PlanNode<A> + Send + 'static>,
    },
    HomeDir {
        cont: Box<dyn FnOnce(Option<PathBuf>) -> PlanNode<A> + Send + 'static>,
    },

    // ── Reporting ─────────────────────────────────────────────────────
    Log {
        msg: String,
        cont: Box<dyn FnOnce(()) -> PlanNode<A> + Send + 'static>,
    },
    Step {
        label: String,
        body: Box<dyn FnOnce() -> PlanNode<A> + Send + 'static>,
    },
}

impl<A: Send + 'static> PlanNode<A> {
    /// Compose a continuation onto this node — `bind` for the free
    /// monad. Walks past intermediate effects, threading the new
    /// continuation down to the `Pure(a)` leaves. `Fail` leaves
    /// short-circuit (the new continuation is dropped) — use
    /// [`PlanNode::handle`] to recover.
    pub fn bind<B: Send + 'static>(
        self,
        k: impl FnOnce(A) -> PlanNode<B> + Send + 'static,
    ) -> PlanNode<B> {
        match self {
            PlanNode::Pure(a) => k(a),
            PlanNode::Fail { msg } => PlanNode::Fail { msg },

            PlanNode::ReadFile { path, cont } => PlanNode::ReadFile {
                path,
                cont: Box::new(move |b| cont(b).bind(k)),
            },
            PlanNode::WriteFile { path, body, cont } => PlanNode::WriteFile {
                path,
                body,
                cont: Box::new(move |()| cont(()).bind(k)),
            },
            PlanNode::RemoveFile { path, cont } => PlanNode::RemoveFile {
                path,
                cont: Box::new(move |()| cont(()).bind(k)),
            },
            PlanNode::ListDir { path, cont } => PlanNode::ListDir {
                path,
                cont: Box::new(move |v| cont(v).bind(k)),
            },
            PlanNode::MkdirP { path, cont } => PlanNode::MkdirP {
                path,
                cont: Box::new(move |()| cont(()).bind(k)),
            },
            PlanNode::Exists { path, cont } => PlanNode::Exists {
                path,
                cont: Box::new(move |b| cont(b).bind(k)),
            },
            PlanNode::RemoveDirAll { path, cont } => PlanNode::RemoveDirAll {
                path,
                cont: Box::new(move |()| cont(()).bind(k)),
            },
            PlanNode::Rename { from, to, cont } => PlanNode::Rename {
                from,
                to,
                cont: Box::new(move |()| cont(()).bind(k)),
            },

            PlanNode::EncodeJson { type_name, cont } => PlanNode::EncodeJson {
                type_name,
                cont: Box::new(move |b| cont(b).bind(k)),
            },
            PlanNode::DecodeJson { type_name, in_len, cont } => PlanNode::DecodeJson {
                type_name,
                in_len,
                cont: Box::new(move |()| cont(()).bind(k)),
            },
            PlanNode::Stdout { bytes_len, cont } => PlanNode::Stdout {
                bytes_len,
                cont: Box::new(move |()| cont(()).bind(k)),
            },

            PlanNode::Encrypt { plaintext_len, recipients, cont } => PlanNode::Encrypt {
                plaintext_len,
                recipients,
                cont: Box::new(move |b| cont(b).bind(k)),
            },
            PlanNode::Decrypt { ciphertext_len, identity_paths, cont } => PlanNode::Decrypt {
                ciphertext_len,
                identity_paths,
                cont: Box::new(move |b| cont(b).bind(k)),
            },
            PlanNode::RecipientOf { identity_path, cont } => PlanNode::RecipientOf {
                identity_path,
                cont: Box::new(move |r| cont(r).bind(k)),
            },
            PlanNode::DefaultIdentityPaths { cont } => PlanNode::DefaultIdentityPaths {
                cont: Box::new(move |v| cont(v).bind(k)),
            },

            PlanNode::Shell { program, args, cwd, envs, cont } => PlanNode::Shell {
                program,
                args,
                cwd,
                envs,
                cont: Box::new(move |o| cont(o).bind(k)),
            },

            PlanNode::Now { cont } => PlanNode::Now {
                cont: Box::new(move |t| cont(t).bind(k)),
            },
            PlanNode::RandomBytes { n, cont } => PlanNode::RandomBytes {
                n,
                cont: Box::new(move |v| cont(v).bind(k)),
            },
            PlanNode::ReadStdin { cont } => PlanNode::ReadStdin {
                cont: Box::new(move |v| cont(v).bind(k)),
            },
            PlanNode::HomeDir { cont } => PlanNode::HomeDir {
                cont: Box::new(move |o| cont(o).bind(k)),
            },

            PlanNode::Log { msg, cont } => PlanNode::Log {
                msg,
                cont: Box::new(move |()| cont(()).bind(k)),
            },
            PlanNode::Step { label, body } => PlanNode::Step {
                label,
                body: Box::new(move || body().bind(k)),
            },
        }
    }

    /// Lift any [`PlanNode::Fail`] anywhere in the tree into the
    /// value channel. Mirrors the trait's [`Vault::handle`] but
    /// operates on the AST: every effect's continuation is
    /// rewritten so the eventual leaf becomes `Pure(Ok(a))` for a
    /// `Pure`, or `Pure(Err(msg))` for a `Fail`.
    pub fn handle(self) -> PlanNode<Result<A, String>> {
        match self {
            PlanNode::Pure(a) => PlanNode::Pure(Ok(a)),
            PlanNode::Fail { msg } => PlanNode::Pure(Err(msg)),

            PlanNode::ReadFile { path, cont } => PlanNode::ReadFile {
                path,
                cont: Box::new(move |b| cont(b).handle()),
            },
            PlanNode::WriteFile { path, body, cont } => PlanNode::WriteFile {
                path,
                body,
                cont: Box::new(move |()| cont(()).handle()),
            },
            PlanNode::RemoveFile { path, cont } => PlanNode::RemoveFile {
                path,
                cont: Box::new(move |()| cont(()).handle()),
            },
            PlanNode::ListDir { path, cont } => PlanNode::ListDir {
                path,
                cont: Box::new(move |v| cont(v).handle()),
            },
            PlanNode::MkdirP { path, cont } => PlanNode::MkdirP {
                path,
                cont: Box::new(move |()| cont(()).handle()),
            },
            PlanNode::Exists { path, cont } => PlanNode::Exists {
                path,
                cont: Box::new(move |b| cont(b).handle()),
            },
            PlanNode::RemoveDirAll { path, cont } => PlanNode::RemoveDirAll {
                path,
                cont: Box::new(move |()| cont(()).handle()),
            },
            PlanNode::Rename { from, to, cont } => PlanNode::Rename {
                from,
                to,
                cont: Box::new(move |()| cont(()).handle()),
            },

            PlanNode::EncodeJson { type_name, cont } => PlanNode::EncodeJson {
                type_name,
                cont: Box::new(move |b| cont(b).handle()),
            },
            PlanNode::DecodeJson { type_name, in_len, cont } => PlanNode::DecodeJson {
                type_name,
                in_len,
                cont: Box::new(move |()| cont(()).handle()),
            },
            PlanNode::Stdout { bytes_len, cont } => PlanNode::Stdout {
                bytes_len,
                cont: Box::new(move |()| cont(()).handle()),
            },

            PlanNode::Encrypt { plaintext_len, recipients, cont } => PlanNode::Encrypt {
                plaintext_len,
                recipients,
                cont: Box::new(move |b| cont(b).handle()),
            },
            PlanNode::Decrypt { ciphertext_len, identity_paths, cont } => PlanNode::Decrypt {
                ciphertext_len,
                identity_paths,
                cont: Box::new(move |b| cont(b).handle()),
            },
            PlanNode::RecipientOf { identity_path, cont } => PlanNode::RecipientOf {
                identity_path,
                cont: Box::new(move |r| cont(r).handle()),
            },
            PlanNode::DefaultIdentityPaths { cont } => PlanNode::DefaultIdentityPaths {
                cont: Box::new(move |v| cont(v).handle()),
            },

            PlanNode::Shell { program, args, cwd, envs, cont } => PlanNode::Shell {
                program,
                args,
                cwd,
                envs,
                cont: Box::new(move |o| cont(o).handle()),
            },

            PlanNode::Now { cont } => PlanNode::Now {
                cont: Box::new(move |t| cont(t).handle()),
            },
            PlanNode::RandomBytes { n, cont } => PlanNode::RandomBytes {
                n,
                cont: Box::new(move |v| cont(v).handle()),
            },
            PlanNode::ReadStdin { cont } => PlanNode::ReadStdin {
                cont: Box::new(move |v| cont(v).handle()),
            },
            PlanNode::HomeDir { cont } => PlanNode::HomeDir {
                cont: Box::new(move |o| cont(o).handle()),
            },

            PlanNode::Log { msg, cont } => PlanNode::Log {
                msg,
                cont: Box::new(move |()| cont(()).handle()),
            },
            PlanNode::Step { label, body } => PlanNode::Step {
                label,
                body: Box::new(move || body().handle()),
            },
        }
    }

    /// Render the AST as a flat text trace. Closures are invoked
    /// with stub results so traversal proceeds — empty bytes for
    /// reads, registered values from the [`Plan::with_stub`]
    /// registry for `decode_json` (or `fail` for unregistered
    /// types). Indentation reflects `step` nesting.
    pub fn render_text(self) -> String {
        let mut out = String::new();
        let mut depth: usize = 0;
        render_into(self, &mut out, &mut depth);
        out
    }
}

fn pad(d: usize) -> String {
    "  ".repeat(d)
}

/// Strip leading module path from `std::any::type_name::<T>()`
/// for nicer trace output — `Content` instead of
/// `rageveil_core::content::Content`.
fn short_type(s: &str) -> &str {
    s.rsplit("::").next().unwrap_or(s)
}

fn stub_proc() -> ProcessOut {
    ProcessOut { status: 0, stdout: Vec::new(), stderr: Vec::new() }
}

fn stub_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().unwrap_or_else(Utc::now)
}

fn render_into<A: 'static>(node: PlanNode<A>, out: &mut String, depth: &mut usize) {
    use std::fmt::Write;
    match node {
        PlanNode::Pure(_) => {
            let _ = writeln!(out, "{}└ pure", pad(*depth));
        }
        PlanNode::Fail { msg } => {
            let _ = writeln!(out, "{}fail {msg}", pad(*depth));
        }

        PlanNode::ReadFile { path, cont } => {
            let _ = writeln!(out, "{}read {}", pad(*depth), path.display());
            render_into(cont(Vec::new()), out, depth);
        }
        PlanNode::WriteFile { path, body, cont } => {
            let _ = writeln!(
                out,
                "{}write {} ({} bytes)",
                pad(*depth),
                path.display(),
                body.len()
            );
            render_into(cont(()), out, depth);
        }
        PlanNode::RemoveFile { path, cont } => {
            let _ = writeln!(out, "{}rm {}", pad(*depth), path.display());
            render_into(cont(()), out, depth);
        }
        PlanNode::ListDir { path, cont } => {
            let _ = writeln!(out, "{}ls {}", pad(*depth), path.display());
            render_into(cont(Vec::new()), out, depth);
        }
        PlanNode::MkdirP { path, cont } => {
            let _ = writeln!(out, "{}mkdir -p {}", pad(*depth), path.display());
            render_into(cont(()), out, depth);
        }
        PlanNode::Exists { path, cont } => {
            let _ = writeln!(out, "{}exists? {}", pad(*depth), path.display());
            render_into(cont(false), out, depth);
        }
        PlanNode::RemoveDirAll { path, cont } => {
            let _ = writeln!(out, "{}rm -rf {}", pad(*depth), path.display());
            render_into(cont(()), out, depth);
        }
        PlanNode::Rename { from, to, cont } => {
            let _ = writeln!(
                out,
                "{}mv {} {}",
                pad(*depth),
                from.display(),
                to.display()
            );
            render_into(cont(()), out, depth);
        }

        PlanNode::EncodeJson { type_name, cont } => {
            let _ = writeln!(
                out,
                "{}encode-json {}",
                pad(*depth),
                short_type(type_name)
            );
            // Empty stub bytes — Plan never serialises real values
            // (stays data-size-independent at render time).
            render_into(cont(Vec::new()), out, depth);
        }
        PlanNode::DecodeJson { type_name, in_len, cont } => {
            let _ = writeln!(
                out,
                "{}decode-json {} ({} bytes)",
                pad(*depth),
                short_type(type_name),
                in_len
            );
            // The typed substitution (or Fail) was already
            // captured in `cont` at construction time — see
            // `Plan::decode_json`. The unit closure here just
            // unpacks it.
            render_into(cont(()), out, depth);
        }
        PlanNode::Stdout { bytes_len, cont } => {
            let _ = writeln!(out, "{}stdout ({} bytes)", pad(*depth), bytes_len);
            render_into(cont(()), out, depth);
        }
        PlanNode::Encrypt { plaintext_len, recipients, cont } => {
            let _ = writeln!(
                out,
                "{}encrypt {} bytes to {} recipients",
                pad(*depth),
                plaintext_len,
                recipients.len()
            );
            render_into(cont(Vec::new()), out, depth);
        }
        PlanNode::Decrypt { ciphertext_len, identity_paths, cont } => {
            let _ = writeln!(
                out,
                "{}decrypt {} bytes with {} identities",
                pad(*depth),
                ciphertext_len,
                identity_paths.len()
            );
            render_into(cont(Vec::new()), out, depth);
        }
        PlanNode::RecipientOf { identity_path, cont } => {
            let _ = writeln!(out, "{}recipient-of {}", pad(*depth), identity_path.display());
            render_into(cont(RecipientSpec::new("age1stub")), out, depth);
        }
        PlanNode::DefaultIdentityPaths { cont } => {
            let _ = writeln!(out, "{}default-identity-paths", pad(*depth));
            render_into(cont(Vec::new()), out, depth);
        }

        PlanNode::Shell { program, args, cont, .. } => {
            let _ = writeln!(out, "{}shell `{program} {}`", pad(*depth), args.join(" "));
            render_into(cont(stub_proc()), out, depth);
        }

        PlanNode::Now { cont } => {
            let _ = writeln!(out, "{}now", pad(*depth));
            render_into(cont(stub_now()), out, depth);
        }
        PlanNode::RandomBytes { n, cont } => {
            let _ = writeln!(out, "{}random-bytes {n}", pad(*depth));
            render_into(cont(vec![0u8; n]), out, depth);
        }
        PlanNode::ReadStdin { cont } => {
            let _ = writeln!(out, "{}read-stdin", pad(*depth));
            render_into(cont(Vec::new()), out, depth);
        }
        PlanNode::HomeDir { cont } => {
            let _ = writeln!(out, "{}home-dir", pad(*depth));
            render_into(cont(None), out, depth);
        }

        PlanNode::Log { msg, cont } => {
            let _ = writeln!(out, "{}log {msg}", pad(*depth));
            render_into(cont(()), out, depth);
        }
        PlanNode::Step { label, body } => {
            let _ = writeln!(out, "{}── {label} ──", pad(*depth));
            *depth += 1;
            render_into(body(), out, depth);
            *depth -= 1;
        }
    }
}

/// The Plan interpreter.
///
/// State lives in two places: the AST itself ([`PlanNode`]
/// continuations) and a small typed-stubs registry consulted by
/// [`Vault::decode_json`] when the program asks for a `T` that
/// would otherwise be undecodable from the upstream stub bytes.
///
/// Cheap to clone — the stub map is `Arc`-shared.
#[derive(Clone, Default)]
pub struct Plan {
    /// Type-keyed stub registry. Entries are stored as serialised
    /// JSON bytes so:
    ///   * the trait method's `T: DeserializeOwned` bound is
    ///     enough to retrieve them — no extra `Clone + Send + Sync`
    ///     propagation back through `Vault::decode_json`'s where-
    ///     clause;
    ///   * the registry itself is serde-shaped, which makes it
    ///     trivial to load fixtures from a JSON file in the future.
    stubs: Arc<HashMap<TypeId, Vec<u8>>>,
}

impl Plan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a stand-in value for `T`. `decode_json::<T>` under
    /// this Plan will return a clone (deserialised from the stored
    /// bytes) instead of failing.
    ///
    /// Re-registering the same `T` overwrites the previous stub.
    /// Builder-style returns `self`.
    ///
    /// Serialisation of the stub is done eagerly here (once, on
    /// registration) so the registry stays type-erased. If the
    /// `Serialize` impl somehow yields an error, the stub is
    /// silently dropped — `decode_json::<T>` then falls back to
    /// the standard "no Plan stub registered" failure, which is
    /// exactly the behaviour an unregistered type gets. No panic,
    /// no silent success-with-fake-data.
    pub fn with_stub<T>(mut self, value: &T) -> Self
    where
        T: Serialize + 'static,
    {
        if let Ok(bytes) = serde_json::to_vec(value) {
            Arc::make_mut(&mut self.stubs).insert(TypeId::of::<T>(), bytes);
        }
        self
    }

    fn lookup<T>(&self) -> Option<T>
    where
        T: DeserializeOwned + 'static,
    {
        self.stubs
            .get(&TypeId::of::<T>())
            .and_then(|bytes| serde_json::from_slice::<T>(bytes).ok())
    }
}

impl Vault for Plan {
    type R<A>
        = PlanNode<A>
    where
        A: Send + 'static;

    fn pure<A: Send + 'static>(&self, a: A) -> Self::R<A> {
        PlanNode::Pure(a)
    }

    fn bind<A, B, F>(&self, m: Self::R<A>, k: F) -> Self::R<B>
    where
        A: Send + 'static,
        B: Send + 'static,
        F: FnOnce(A) -> Self::R<B> + Send + 'static,
    {
        m.bind(k)
    }

    fn seq<A, B>(&self, m: Self::R<A>, n: Self::R<B>) -> Self::R<B>
    where
        A: Send + 'static,
        B: Send + 'static,
    {
        m.bind(move |_| n)
    }

    fn map<A, B, F>(&self, m: Self::R<A>, f: F) -> Self::R<B>
    where
        A: Send + 'static,
        B: Send + 'static,
        F: FnOnce(A) -> B + Send + 'static,
    {
        m.bind(move |a| PlanNode::Pure(f(a)))
    }

    fn fail<A: Send + 'static>(&self, msg: String) -> Self::R<A> {
        PlanNode::Fail { msg }
    }

    fn handle<A: Send + 'static>(&self, m: Self::R<A>) -> Self::R<Result<A, String>> {
        m.handle()
    }

    fn read_file(&self, path: PathBuf) -> Self::R<Vec<u8>> {
        PlanNode::ReadFile { path, cont: Box::new(PlanNode::Pure) }
    }

    fn write_file(&self, path: PathBuf, body: Vec<u8>) -> Self::R<()> {
        PlanNode::WriteFile { path, body, cont: Box::new(PlanNode::Pure) }
    }

    fn remove_file(&self, path: PathBuf) -> Self::R<()> {
        PlanNode::RemoveFile { path, cont: Box::new(PlanNode::Pure) }
    }

    fn list_dir(&self, path: PathBuf) -> Self::R<Vec<PathBuf>> {
        PlanNode::ListDir { path, cont: Box::new(PlanNode::Pure) }
    }

    fn mkdir_p(&self, path: PathBuf) -> Self::R<()> {
        PlanNode::MkdirP { path, cont: Box::new(PlanNode::Pure) }
    }

    fn exists(&self, path: PathBuf) -> Self::R<bool> {
        PlanNode::Exists { path, cont: Box::new(PlanNode::Pure) }
    }

    fn remove_dir_all(&self, path: PathBuf) -> Self::R<()> {
        PlanNode::RemoveDirAll { path, cont: Box::new(PlanNode::Pure) }
    }

    fn rename(&self, from: PathBuf, to: PathBuf) -> Self::R<()> {
        PlanNode::Rename { from, to, cont: Box::new(PlanNode::Pure) }
    }

    fn encode_json<T>(&self, _value: T) -> Self::R<Vec<u8>>
    where
        T: Serialize + Send + 'static,
    {
        // Deliberately ignore the value — render is data-size
        // independent. The trace records the type name; downstream
        // sees an empty `Vec<u8>` (the stub). Real serialisation
        // is Live's job, not Plan's.
        PlanNode::EncodeJson {
            type_name: std::any::type_name::<T>(),
            cont: Box::new(PlanNode::Pure),
        }
    }

    fn decode_json<T>(&self, bytes: Vec<u8>) -> Self::R<T>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let type_name = std::any::type_name::<T>();
        let in_len = bytes.len();
        match self.lookup::<T>() {
            Some(value) => PlanNode::DecodeJson {
                type_name,
                in_len,
                cont: Box::new(move |()| PlanNode::Pure(value)),
            },
            None => PlanNode::DecodeJson {
                type_name,
                in_len,
                cont: Box::new(move |()| PlanNode::Fail {
                    msg: format!(
                        "decode-json {}: no Plan stub registered \
                         (use `Plan::new().with_stub::<{}>(&value)`)",
                        short_type(type_name),
                        short_type(type_name),
                    ),
                }),
            },
        }
    }

    fn encrypt(
        &self,
        plaintext: Vec<u8>,
        recipients: Vec<RecipientSpec>,
    ) -> Self::R<Vec<u8>> {
        PlanNode::Encrypt {
            plaintext_len: plaintext.len(),
            recipients,
            cont: Box::new(PlanNode::Pure),
        }
    }

    fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        identity_paths: Vec<PathBuf>,
    ) -> Self::R<Vec<u8>> {
        PlanNode::Decrypt {
            ciphertext_len: ciphertext.len(),
            identity_paths,
            cont: Box::new(PlanNode::Pure),
        }
    }

    fn recipient_of(&self, identity_path: PathBuf) -> Self::R<RecipientSpec> {
        PlanNode::RecipientOf { identity_path, cont: Box::new(PlanNode::Pure) }
    }

    fn default_identity_paths(&self) -> Self::R<Vec<PathBuf>> {
        PlanNode::DefaultIdentityPaths { cont: Box::new(PlanNode::Pure) }
    }

    fn shell(
        &self,
        program: String,
        args: Vec<String>,
        cwd: Option<PathBuf>,
        envs: Vec<(String, String)>,
    ) -> Self::R<ProcessOut> {
        PlanNode::Shell { program, args, cwd, envs, cont: Box::new(PlanNode::Pure) }
    }

    fn now(&self) -> Self::R<DateTime<Utc>> {
        PlanNode::Now { cont: Box::new(PlanNode::Pure) }
    }

    fn random_bytes(&self, n: usize) -> Self::R<Vec<u8>> {
        PlanNode::RandomBytes { n, cont: Box::new(PlanNode::Pure) }
    }

    fn read_stdin(&self) -> Self::R<Vec<u8>> {
        PlanNode::ReadStdin { cont: Box::new(PlanNode::Pure) }
    }

    fn home_dir(&self) -> Self::R<Option<PathBuf>> {
        PlanNode::HomeDir { cont: Box::new(PlanNode::Pure) }
    }

    fn stdout(&self, bytes: Vec<u8>) -> Self::R<()> {
        PlanNode::Stdout {
            bytes_len: bytes.len(),
            cont: Box::new(PlanNode::Pure),
        }
    }

    fn log(&self, msg: String) -> Self::R<()> {
        PlanNode::Log { msg, cont: Box::new(PlanNode::Pure) }
    }

    fn step<A, F>(&self, label: String, body: F) -> Self::R<A>
    where
        A: Send + 'static,
        F: FnOnce() -> Self::R<A> + Send + 'static,
    {
        PlanNode::Step { label, body: Box::new(body) }
    }
}
