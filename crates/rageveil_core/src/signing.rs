//! Detached signatures over the shared address book.
//!
//! ## Why this exists
//!
//! On a `git@` store the address book is admin-only because a
//! `pre-receive` hook says so — the doorman lives on the server and
//! reads `~git/admins`, a file outside the repo. That works right up
//! until the store is hosted somewhere that will not run your hooks.
//! github.com will not. There, anyone who can push can rewrite
//! `addressbook.json`, and since `allow`/`deny` resolve names
//! through it, a rewritten book redirects the next share to a key
//! the attacker holds.
//!
//! So the doorman moves off the server and into the artifact.
//! `addressbook.json` carries a detached signature and clients
//! refuse a book no trusted admin signed. That holds on any host —
//! a forge, a dumb remote, a USB stick — because it never asked the
//! host to enforce anything.
//!
//! ## Shape
//!
//! passveil's, updated. It wrote `<file>.sig` beside each encrypted
//! secret with `gpg --detach-sig` and checked the issuer on read;
//! rageveil dropped that because age has no signature primitive. But
//! the operators were already carrying ssh-ed25519 keys the whole
//! time, and SSHSIG — the format behind `ssh-keygen -Y sign` — signs
//! with exactly those. Same detached-`.sig` layout, same
//! issuer-must-match rule, no new key material and no new
//! dependency.
//!
//! ## The trust anchor
//!
//! Trusted admin keys live in `<root>/admins.json`, beside
//! `config.json` and `index.json` — **outside** the git tree, so
//! they are never synced and a push can never edit them. That is the
//! same trick `~git/admins` plays on the server, moved to the
//! client: whoever can write the repo still cannot tell you whom to
//! trust.

use anyhow::{anyhow, Result};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey, SshSig};
use std::path::{Path, PathBuf};

/// SSHSIG namespace. Namespacing is what stops a signature made for
/// one purpose being replayed as another — a git commit signature
/// must not pass as an address-book signature.
pub const ADDRESSBOOK_NAMESPACE: &str = "rageveil-addressbook";

/// `<root>/admins.json` — local, never committed.
pub const ADMINS_FILE: &str = "admins.json";

/// Where the detached signature for `path` lives: `<path>.sig`,
/// passveil's convention.
pub fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// The local list of admin keys this operator trusts to sign the
/// address book.
pub fn admins_path(root: &Path) -> PathBuf {
    root.join(ADMINS_FILE)
}

/// Sign `message`, returning an armored SSHSIG.
pub fn sign(private_openssh: &str, namespace: &str, message: &[u8]) -> Result<String> {
    let key: PrivateKey = private_openssh
        .parse()
        .map_err(|e| anyhow!("unreadable private key: {e}"))?;
    let sig = key
        .sign(namespace, HashAlg::Sha512, message)
        .map_err(|e| anyhow!("sign: {e}"))?;
    sig.to_pem(LineEnding::LF)
        .map_err(|e| anyhow!("encode signature: {e}"))
}

/// Verify `armored` over `message` against any trusted key.
///
/// Returns the key that matched, so callers can report *who*
/// vouched rather than merely that someone did. An empty trust list
/// is an error, never a pass: "nobody is trusted" must not read as
/// "everybody is".
pub fn verify_any(
    trusted: &[String],
    namespace: &str,
    message: &[u8],
    armored: &str,
) -> Result<String> {
    if trusted.is_empty() {
        return Err(anyhow!(
            "no trusted admin keys recorded, so nothing can vouch for this file"
        ));
    }
    let sig: SshSig = armored
        .trim()
        .parse()
        .map_err(|e| anyhow!("unreadable signature: {e}"))?;
    for candidate in trusted {
        let Ok(key) = candidate.parse::<PublicKey>() else {
            continue;
        };
        if key.verify(namespace, message, &sig).is_ok() {
            return Ok(candidate.clone());
        }
    }
    Err(anyhow!(
        "signature is not from any of the {} trusted admin key(s)",
        trusted.len()
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn keypair(comment: &str) -> (String, String) {
        use ssh_key::private::{Ed25519Keypair, KeypairData};
        use ssh_key::rand_core::OsRng;
        let pair = Ed25519Keypair::random(&mut OsRng);
        let private = PrivateKey::new(KeypairData::Ed25519(pair), comment)
            .expect("build private key");
        let pem = private
            .to_openssh(LineEnding::LF)
            .expect("encode private")
            .to_string();
        let public = private
            .public_key()
            .to_openssh()
            .expect("encode public");
        (pem, public)
    }

    #[test]
    fn round_trip_and_rejects_tampering() {
        let (private, public) = keypair("admin");
        let sig = sign(&private, ADDRESSBOOK_NAMESPACE, b"the book").expect("sign");

        let who = verify_any(
            std::slice::from_ref(&public),
            ADDRESSBOOK_NAMESPACE,
            b"the book",
            &sig,
        )
        .expect("verify");
        assert_eq!(who, public);

        verify_any(&[public], ADDRESSBOOK_NAMESPACE, b"a different book", &sig)
            .expect_err("tampered payload must fail");
    }

    /// The attack this whole module exists to stop: someone with
    /// push access swaps the book and signs it with their own key.
    #[test]
    fn rejects_a_signature_from_an_untrusted_key() {
        let (_, admin_public) = keypair("admin");
        let (attacker_private, _) = keypair("attacker");
        let forged = sign(&attacker_private, ADDRESSBOOK_NAMESPACE, b"poisoned book")
            .expect("sign");

        verify_any(
            &[admin_public],
            ADDRESSBOOK_NAMESPACE,
            b"poisoned book",
            &forged,
        )
        .expect_err("a valid signature by the wrong key must not pass");
    }

    /// A signature made for another purpose must not be replayable
    /// as an address-book signature.
    #[test]
    fn namespaces_do_not_cross() {
        let (private, public) = keypair("admin");
        let sig = sign(&private, "some-other-purpose", b"the book").expect("sign");
        verify_any(&[public], ADDRESSBOOK_NAMESPACE, b"the book", &sig)
            .expect_err("namespace mismatch must fail");
    }

    /// Empty trust list is a refusal, not a pass.
    #[test]
    fn no_trusted_keys_is_a_refusal() {
        let (private, _) = keypair("admin");
        let sig = sign(&private, ADDRESSBOOK_NAMESPACE, b"the book").expect("sign");
        verify_any(&[], ADDRESSBOOK_NAMESPACE, b"the book", &sig)
            .expect_err("empty trust list must refuse");
    }
}
