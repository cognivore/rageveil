//! Live interpreter — runs a [`crate::Vault`] program against the
//! real filesystem, real subprocesses, and real age encryption.
//!
//! `R<A>` is `Pin<Box<dyn Future<Output = anyhow::Result<A>> + Send>>`
//! — we accept the per-call heap allocation in exchange for the GAT
//! actually compiling without per-method TAIT gymnastics. The caller
//! is rarely CPU-bound; subprocesses, file I/O, and age's stream
//! cipher dominate.

use crate::dsl::Vault;
use crate::types::{ProcessOut, RecipientSpec};

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::{Decryptor, Encryptor};
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use futures::future::{BoxFuture, FutureExt};
use rand::RngCore;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

pub type LiveR<A> = BoxFuture<'static, Result<A>>;

/// The Live interpreter. Cheap to clone (everything sharable lives
/// behind `Arc`); each effect closure clones what it needs into the
/// async block so `'static` is satisfiable.
#[derive(Clone, Default)]
pub struct Live {
    /// If set, prepended to relative paths handed to `read_file` /
    /// `write_file` / `mkdir_p` etc. Lets a test point at a
    /// throwaway temp directory without rewriting the commands to
    /// thread a base path everywhere.
    chroot: Option<Arc<PathBuf>>,
    /// Override for `home_dir()`. Same motivation as `chroot` — the
    /// integration tests need a deterministic answer.
    home_override: Option<Arc<PathBuf>>,
}

impl Live {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_home(mut self, home: PathBuf) -> Self {
        self.home_override = Some(Arc::new(home));
        self
    }

    fn resolve(&self, p: PathBuf) -> PathBuf {
        match &self.chroot {
            Some(root) if p.is_relative() => root.join(p),
            _ => p,
        }
    }
}

impl Vault for Live {
    type R<A>
        = LiveR<A>
    where
        A: Send + 'static;

    fn pure<A: Send + 'static>(&self, a: A) -> Self::R<A> {
        async move { Ok(a) }.boxed()
    }

    fn bind<A, B, F>(&self, m: Self::R<A>, k: F) -> Self::R<B>
    where
        A: Send + 'static,
        B: Send + 'static,
        F: FnOnce(A) -> Self::R<B> + Send + 'static,
    {
        async move {
            let a = m.await?;
            k(a).await
        }
        .boxed()
    }

    fn seq<A, B>(&self, m: Self::R<A>, n: Self::R<B>) -> Self::R<B>
    where
        A: Send + 'static,
        B: Send + 'static,
    {
        async move {
            let _ = m.await?;
            n.await
        }
        .boxed()
    }

    fn map<A, B, F>(&self, m: Self::R<A>, f: F) -> Self::R<B>
    where
        A: Send + 'static,
        B: Send + 'static,
        F: FnOnce(A) -> B + Send + 'static,
    {
        async move {
            let a = m.await?;
            Ok(f(a))
        }
        .boxed()
    }

    fn fail<A: Send + 'static>(&self, msg: String) -> Self::R<A> {
        async move { Err(anyhow!(msg)) }.boxed()
    }

    fn handle<A: Send + 'static>(&self, m: Self::R<A>) -> Self::R<Result<A, String>> {
        // The `Ok(...)` outer wraps the lifted-into-value-channel
        // result so the future itself never errors — `handle` is
        // total. `{e:#}` formats the full anyhow chain.
        async move {
            match m.await {
                Ok(a) => Ok(Ok(a)),
                Err(e) => Ok(Err(format!("{e:#}"))),
            }
        }
        .boxed()
    }

    fn read_file(&self, path: PathBuf) -> Self::R<Vec<u8>> {
        let path = self.resolve(path);
        async move {
            tokio::fs::read(&path)
                .await
                .with_context(|| format!("read_file {}", path.display()))
        }
        .boxed()
    }

    fn write_file(&self, path: PathBuf, body: Vec<u8>) -> Self::R<()> {
        let path = self.resolve(path);
        async move {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("mkdir -p {}", parent.display()))?;
            }
            tokio::fs::write(&path, &body)
                .await
                .with_context(|| format!("write_file {}", path.display()))
        }
        .boxed()
    }

    fn remove_file(&self, path: PathBuf) -> Self::R<()> {
        let path = self.resolve(path);
        async move {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e).with_context(|| format!("remove_file {}", path.display())),
            }
        }
        .boxed()
    }

    fn list_dir(&self, path: PathBuf) -> Self::R<Vec<PathBuf>> {
        let path = self.resolve(path);
        async move {
            let mut out = Vec::new();
            let mut rd = match tokio::fs::read_dir(&path).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
                Err(e) => {
                    return Err(e).with_context(|| format!("list_dir {}", path.display()))
                }
            };
            while let Some(entry) = rd
                .next_entry()
                .await
                .with_context(|| format!("list_dir iter {}", path.display()))?
            {
                out.push(entry.path());
            }
            out.sort();
            Ok(out)
        }
        .boxed()
    }

    fn mkdir_p(&self, path: PathBuf) -> Self::R<()> {
        let path = self.resolve(path);
        async move {
            tokio::fs::create_dir_all(&path)
                .await
                .with_context(|| format!("mkdir_p {}", path.display()))
        }
        .boxed()
    }

    fn exists(&self, path: PathBuf) -> Self::R<bool> {
        let path = self.resolve(path);
        async move { Ok(tokio::fs::metadata(&path).await.is_ok()) }.boxed()
    }

    fn remove_dir_all(&self, path: PathBuf) -> Self::R<()> {
        let path = self.resolve(path);
        async move {
            match tokio::fs::remove_dir_all(&path).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e).with_context(|| format!("remove_dir_all {}", path.display())),
            }
        }
        .boxed()
    }

    fn rename(&self, from: PathBuf, to: PathBuf) -> Self::R<()> {
        let from = self.resolve(from);
        let to = self.resolve(to);
        async move {
            tokio::fs::rename(&from, &to).await.with_context(|| {
                format!("rename {} -> {}", from.display(), to.display())
            })
        }
        .boxed()
    }

    fn encode_json<T>(&self, value: T) -> Self::R<Vec<u8>>
    where
        T: serde::Serialize + Send + 'static,
    {
        async move {
            serde_json::to_vec(&value)
                .map_err(|e| anyhow!("encode json: {e}"))
        }
        .boxed()
    }

    fn decode_json<T>(&self, bytes: Vec<u8>) -> Self::R<T>
    where
        T: serde::de::DeserializeOwned + Send + 'static,
    {
        async move {
            serde_json::from_slice(&bytes)
                .map_err(|e| anyhow!("decode json: {e}"))
        }
        .boxed()
    }

    fn encrypt(
        &self,
        plaintext: Vec<u8>,
        recipients: Vec<RecipientSpec>,
    ) -> Self::R<Vec<u8>> {
        // age's identity / recipient values are not all
        // `Send + Sync` (the trait objects from
        // `IdentityFile::into_identities` aren't), so we run the
        // crypto in `spawn_blocking` rather than carrying them
        // across an `await`. The CPU work is short either way
        // and this side-steps the auto-trait gymnastics.
        async move {
            tokio::task::spawn_blocking(move || do_encrypt(plaintext, recipients))
                .await
                .map_err(|e| anyhow!("encrypt task: {e}"))?
        }
        .boxed()
    }

    fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        identity_paths: Vec<PathBuf>,
    ) -> Self::R<Vec<u8>> {
        let chroot = self.chroot.clone();
        async move {
            let resolved: Vec<PathBuf> = identity_paths
                .into_iter()
                .map(|p| match (&chroot, p.is_relative()) {
                    (Some(r), true) => r.join(p),
                    _ => p,
                })
                .collect();
            tokio::task::spawn_blocking(move || do_decrypt(&ciphertext, &resolved))
                .await
                .map_err(|e| anyhow!("decrypt task: {e}"))?
        }
        .boxed()
    }

    fn recipient_of(&self, identity_path: PathBuf) -> Self::R<RecipientSpec> {
        let path = self.resolve(identity_path);
        async move {
            tokio::task::spawn_blocking(move || do_recipient_of(&path))
                .await
                .map_err(|e| anyhow!("recipient_of task: {e}"))?
        }
        .boxed()
    }

    fn default_identity_paths(&self) -> Self::R<Vec<PathBuf>> {
        let home = self.home_override.as_ref().map(|h| (**h).clone());
        async move {
            let home = match home {
                Some(h) => h,
                None => match dirs_home() {
                    Some(h) => h,
                    None => return Ok(Vec::new()),
                },
            };
            let candidates = [
                home.join(".config/age/keys.txt"),
                home.join(".ssh/id_ed25519"),
                home.join(".ssh/id_rsa"),
            ];
            let mut out = Vec::new();
            for c in candidates {
                if tokio::fs::metadata(&c).await.is_ok() {
                    out.push(c);
                }
            }
            Ok(out)
        }
        .boxed()
    }

    fn shell(
        &self,
        program: String,
        args: Vec<String>,
        cwd: Option<PathBuf>,
        envs: Vec<(String, String)>,
    ) -> Self::R<ProcessOut> {
        let chroot = self.chroot.clone();
        async move {
            let mut cmd = tokio::process::Command::new(&program);
            cmd.args(&args);
            for (k, v) in envs {
                cmd.env(k, v);
            }
            if let Some(d) = cwd {
                let d = match (&chroot, d.is_relative()) {
                    (Some(r), true) => r.join(d),
                    _ => d,
                };
                cmd.current_dir(d);
            }
            let out = cmd
                .output()
                .await
                .with_context(|| format!("spawn {program}"))?;
            Ok(ProcessOut {
                status: out.status.code().unwrap_or(-1),
                stdout: out.stdout,
                stderr: out.stderr,
            })
        }
        .boxed()
    }

    fn now(&self) -> Self::R<DateTime<Utc>> {
        async move { Ok(Utc::now()) }.boxed()
    }

    fn random_bytes(&self, n: usize) -> Self::R<Vec<u8>> {
        async move {
            let mut buf = vec![0u8; n];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            Ok(buf)
        }
        .boxed()
    }

    fn read_stdin(&self) -> Self::R<Vec<u8>> {
        async move {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            tokio::io::stdin()
                .read_to_end(&mut buf)
                .await
                .context("read stdin")?;
            Ok(buf)
        }
        .boxed()
    }

    fn home_dir(&self) -> Self::R<Option<PathBuf>> {
        let h = self.home_override.as_ref().map(|h| (**h).clone());
        async move { Ok(h.or_else(dirs_home)) }.boxed()
    }

    fn stdout(&self, bytes: Vec<u8>) -> Self::R<()> {
        async move {
            use tokio::io::AsyncWriteExt;
            let mut out = tokio::io::stdout();
            out.write_all(&bytes).await.context("stdout write")?;
            out.flush().await.context("stdout flush")?;
            Ok(())
        }
        .boxed()
    }

    fn log(&self, msg: String) -> Self::R<()> {
        async move {
            eprintln!("{msg}");
            Ok(())
        }
        .boxed()
    }

    fn step<A, F>(&self, label: String, body: F) -> Self::R<A>
    where
        A: Send + 'static,
        F: FnOnce() -> Self::R<A> + Send + 'static,
    {
        async move {
            println!("── {label} ──");
            body().await
        }
        .boxed()
    }
}

// ─── Internals ──────────────────────────────────────────────────────────

fn do_encrypt(plaintext: Vec<u8>, recipients: Vec<RecipientSpec>) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(anyhow!("encrypt: no recipients"));
    }

    // Parse each recipient spec into a boxed `dyn age::Recipient` so
    // we can hand a heterogeneous list (age + ssh) to `Encryptor::
    // with_recipients`. Owning the boxes here keeps lifetimes
    // tractable across the iterator passed below.
    let mut owned: Vec<Box<dyn age::Recipient + Send>> = Vec::with_capacity(recipients.len());
    for r in &recipients {
        owned.push(parse_recipient(r.as_str())?);
    }

    let recipient_refs: Vec<&dyn age::Recipient> =
        owned.iter().map(|b| b.as_ref() as &dyn age::Recipient).collect();

    let encryptor = Encryptor::with_recipients(recipient_refs.into_iter())
        .map_err(|e| anyhow!("age encryptor: {e}"))?;

    let mut out = Vec::new();
    {
        let armored = ArmoredWriter::wrap_output(&mut out, Format::AsciiArmor)
            .map_err(|e| anyhow!("armor wrap: {e}"))?;
        let mut writer = encryptor
            .wrap_output(armored)
            .map_err(|e| anyhow!("age wrap: {e}"))?;
        writer
            .write_all(&plaintext)
            .map_err(|e| anyhow!("age write: {e}"))?;
        let armored = writer.finish().map_err(|e| anyhow!("age finish: {e}"))?;
        armored.finish().map_err(|e| anyhow!("armor finish: {e}"))?;
    }
    Ok(out)
}

fn do_decrypt(ciphertext: &[u8], identity_paths: &[PathBuf]) -> Result<Vec<u8>> {
    if identity_paths.is_empty() {
        return Err(anyhow!("decrypt: no identity files"));
    }

    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
    let mut load_errs: Vec<String> = Vec::new();
    for path in identity_paths {
        match load_identities(path) {
            Ok(mut ids) => identities.append(&mut ids),
            Err(e) => load_errs.push(format!("{}: {e}", path.display())),
        }
    }
    if identities.is_empty() {
        return Err(anyhow!(
            "decrypt: no usable identities loaded ({})",
            load_errs.join("; ")
        ));
    }

    let armored = ArmoredReader::new(ciphertext);
    let decryptor =
        Decryptor::new_buffered(armored).map_err(|e| anyhow!("age decryptor: {e}"))?;
    let identity_refs: Vec<&dyn age::Identity> =
        identities.iter().map(|b| b.as_ref()).collect();
    let mut reader = decryptor
        .decrypt(identity_refs.into_iter())
        .map_err(|e| anyhow!("age decrypt: {e}"))?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out).map_err(|e| anyhow!("age read: {e}"))?;
    Ok(out)
}

/// Parse a recipient spec into a boxed `dyn age::Recipient`.
///
/// Tries native X25519 first (the canonical `age1…` form), then
/// OpenSSH. The age crate's recipient types print with the same
/// canonical syntax they parse from, so a round-trip of the
/// successful branch is stable.
fn parse_recipient(s: &str) -> Result<Box<dyn age::Recipient + Send>> {
    let trimmed = s.trim();
    if let Ok(r) = trimmed.parse::<age::x25519::Recipient>() {
        return Ok(Box::new(r));
    }
    if let Ok(r) = trimmed.parse::<age::ssh::Recipient>() {
        return Ok(Box::new(r));
    }
    Err(anyhow!("unrecognised recipient: {trimmed}"))
}

fn load_identities(path: &std::path::Path) -> Result<Vec<Box<dyn age::Identity>>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read identity file {}", path.display()))?;
    let s = std::str::from_utf8(&bytes).unwrap_or("");

    // SSH private keys are PEM with a recognisable BEGIN line.
    // Try those first; once `IdentityFile::from_buffer` has seen
    // the bytes there is no graceful retry.
    if s.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || s.contains("-----BEGIN RSA PRIVATE KEY-----")
    {
        let id = age::ssh::Identity::from_buffer(
            std::io::BufReader::new(bytes.as_slice()),
            Some(path.display().to_string()),
        )
        .with_context(|| format!("parse SSH identity {}", path.display()))?;
        return match id {
            age::ssh::Identity::Unsupported(reason) => Err(anyhow!(
                "SSH identity {} is unsupported by age: {reason:?}",
                path.display()
            )),
            other => Ok(vec![Box::new(other) as Box<dyn age::Identity>]),
        };
    }

    // Native age key file (or text containing AGE-SECRET-KEY-…).
    let file = age::IdentityFile::from_buffer(std::io::BufReader::new(bytes.as_slice()))
        .with_context(|| format!("parse age identity {}", path.display()))?;
    file.into_identities()
        .map_err(|e| anyhow!("age identity decode: {e}"))
}

fn do_recipient_of(path: &std::path::Path) -> Result<RecipientSpec> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read identity file {}", path.display()))?;
    let s = std::str::from_utf8(&bytes).unwrap_or("");

    // SSH private key — read sibling `.pub` (canonical OpenSSH way
    // to surface the public half) since age's ssh::Identity
    // doesn't expose a `to_public` we can call from outside the
    // crate.
    if s.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || s.contains("-----BEGIN RSA PRIVATE KEY-----")
    {
        // Convention: `id_ed25519` + `id_ed25519.pub` — literal
        // append rather than `with_extension`, which would replace
        // a real suffix (e.g. `key.pem` → `key.pub`, wrong).
        let pub_path = {
            let mut s = path.as_os_str().to_owned();
            s.push(".pub");
            std::path::PathBuf::from(s)
        };
        let pub_bytes = std::fs::read(&pub_path).with_context(|| {
            format!(
                "read SSH public key {} (expected next to private key)",
                pub_path.display()
            )
        })?;
        let line = std::str::from_utf8(&pub_bytes)
            .map_err(|_| anyhow!("ssh public key not utf-8: {}", pub_path.display()))?
            .lines()
            .next()
            .ok_or_else(|| anyhow!("ssh public key file empty: {}", pub_path.display()))?
            .trim()
            .to_owned();
        return Ok(RecipientSpec::new(line));
    }

    // Native age key file. `write_recipients_file` does the
    // conversion for us, including stripping comments and the
    // `# public key:` hint line.
    let file = age::IdentityFile::from_buffer(std::io::BufReader::new(bytes.as_slice()))
        .with_context(|| format!("parse age identity {}", path.display()))?;
    let mut buf = Vec::<u8>::new();
    file.write_recipients_file(&mut buf)
        .map_err(|e| anyhow!("derive recipient: {e}"))?;
    let s = std::str::from_utf8(&buf)
        .map_err(|_| anyhow!("recipient text not utf-8"))?
        .lines()
        .next()
        .ok_or_else(|| anyhow!("no recipient derivable from {}", path.display()))?
        .trim()
        .to_owned();
    Ok(RecipientSpec::new(s))
}

fn dirs_home() -> Option<PathBuf> {
    // Avoid pulling `dirs` for a single function. `$HOME` is
    // sufficient on every platform we ship for.
    std::env::var_os("HOME").map(PathBuf::from)
}
