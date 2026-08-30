//! The invite protocol's shared vocabulary — the payload an admin
//! mints with `rageveil invite <name>` and a visageveil app decodes
//! from its `visageveil://invite/v1/<base64url>` URL.
//!
//! ## The polarity
//!
//! Enrollment used to flow device → admin: a phone generated a key
//! and a human ferried it to `rageveil address add`. An invite
//! flips it. The **admin** mints a bearer URL carrying:
//!
//!   * the store's remote and (when scannable) the server's
//!     host-key SHA-256 — so the phone connects **pre-pinned**,
//!     no trust-on-first-use window at all;
//!   * a fresh **ephemeral** ssh-ed25519 private key whose public
//!     half was just registered in the address book as
//!     `invite:<name>` — on a `git@` store the push hook thereby
//!     grants the URL's bearer transport access;
//!   * the invited name and an expiry.
//!
//! The phone uses the ephemeral key once: clone, write its REAL
//! public key to `invites/<name>.pub`, push. `rageveil invite
//! accept <name>` then swaps ephemeral → real in the address book
//! in a single commit (the push that lands it also revokes the
//! ephemeral key's access, because the hook regenerates
//! `authorized_keys` from the book).
//!
//! ## What the URL is worth to a thief
//!
//! The URL is a bearer credential, deliberately: send it over a
//! channel you trust as much as the enrollment itself. Until
//! accepted or revoked its holder can (a) read the store's
//! *ciphertexts* and public metadata — the same exposure any
//! user-tier member has, decrypting nothing — and (b) submit a key
//! for `<name>`. Acceptance is a manual admin act that prints the
//! responding key's fingerprint, expiry bounds the window, and
//! `rageveil invite revoke` kills transport on push.

use anyhow::{anyhow, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// URL prefix every invite carries. The app registers this scheme.
/// The `v1` here is the *route*, not the payload version — iOS
/// binds the scheme, so it stays put while [`PAYLOAD_VERSION`]
/// moves.
pub const URL_PREFIX: &str = "visageveil://invite/v1/";

/// Payload version this build speaks.
///
/// 2 — `host_sha256` became a set of hashes (one per host key the
/// server offers) and is mandatory for ssh remotes. A v1 payload
/// pinned exactly one algorithm, which the phone could not honour,
/// so v1 invites are refused rather than reinterpreted.
pub const PAYLOAD_VERSION: u32 = 2;

/// Wire payload of one invite. Serialized as JSON, base64url'd
/// into the URL. One struct, consumed verbatim by both repos —
/// the sister depends on this crate, so the protocol cannot fork.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitePayload {
    /// Payload version — bump on breaking change.
    pub v: u32,
    /// The address-book name being invited (`lucia-phone`).
    pub name: String,
    /// The store remote (`git@doma.dev:.rageveil`).
    pub remote: String,
    /// SHA-256 (lowercase hex) of *every* ssh host key the issuing
    /// side scanned — the phone writes these as its pin set
    /// *before* first contact and accepts a server presenting any
    /// one of them.
    ///
    /// A set, not a single hash, because the client does not get to
    /// choose which host key it is offered: libssh2 with no
    /// `known_hosts` to steer it negotiates by its own preference
    /// order (ecdsa, in practice), so pinning one algorithm refuses
    /// the very server it was scanned from.
    ///
    /// Empty ONLY for a non-ssh remote (`file://`, tests), where
    /// there is no host to authenticate. For an ssh remote this is
    /// never empty: `issue` refuses to mint an unpinned invite, and
    /// the phone refuses to answer one. An invite is a promise of a
    /// specific server, and a promise with a fallback is not a
    /// promise — an attacker holding the URL could otherwise strip
    /// this field and re-encode it to force the invitee onto
    /// trust-on-first-use, which is exactly the window pinning
    /// exists to close.
    pub host_sha256: Vec<String>,
    /// The ephemeral transport identity (OpenSSH PEM). Its public
    /// half sits in the address book as `invite:<name>` until
    /// accept/revoke.
    pub invite_private_openssh: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl InvitePayload {
    pub fn to_url(&self) -> Result<String> {
        let json = serde_json::to_vec(self).map_err(|e| anyhow!("encode invite: {e}"))?;
        Ok(format!(
            "{URL_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        ))
    }

    /// Parse from the URL (or from a bare pasted base64url blob —
    /// people mangle links; the payload is self-describing).
    pub fn from_url(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let blob = trimmed.strip_prefix(URL_PREFIX).unwrap_or(trimmed);
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(blob.trim_end_matches('='))
            .map_err(|e| anyhow!("invite is not valid base64url: {e}"))?;
        let payload: InvitePayload =
            serde_json::from_slice(&bytes).map_err(|e| anyhow!("invite does not parse: {e}"))?;
        if payload.v != PAYLOAD_VERSION {
            return Err(anyhow!(
                "invite version {} is not the one this build speaks ({PAYLOAD_VERSION}); \
                 have the admin re-issue it from a matching rageveil",
                payload.v
            ));
        }
        Ok(payload)
    }

    pub fn expired_at(&self, now: DateTime<Utc>) -> bool {
        now > self.expires_at
    }
}

/// Whether a remote actually speaks ssh, and so has a host key
/// worth pinning.
///
/// Deliberately stricter than [`ssh_host_of_remote`], which parses
/// `file:///tmp/store` into the "host" `file` — good enough when
/// you already know the remote is ssh, dangerous as a decision
/// procedure. Both repos route the "must this be pinned?" question
/// here so the issuer and the phone cannot disagree about which
/// invites are allowed to be unpinned.
pub fn is_ssh_remote(remote: &str) -> bool {
    match remote.split_once("://") {
        // Explicit scheme: only ssh:// qualifies.
        Some((scheme, _)) => scheme == "ssh",
        // Bare path (`/srv/store`) vs scp-style (`git@host:path`).
        None => remote.contains(':'),
    }
}

/// Extract the ssh host from a store remote. Understands the two
/// shapes rageveil stores use: SCP-style `[user@]host:path` and
/// `ssh://[user@]host[:port]/path`. Returns `(host, Some(port))`.
///
/// Only meaningful once [`is_ssh_remote`] has said yes.
pub fn ssh_host_of_remote(remote: &str) -> Result<(String, Option<u16>)> {
    if let Some(rest) = remote.strip_prefix("ssh://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        let hostport = authority.rsplit('@').next().unwrap_or(authority);
        match hostport.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => Ok((
                h.to_owned(),
                Some(p.parse().map_err(|e| anyhow!("bad port {p}: {e}"))?),
            )),
            _ => Ok((hostport.to_owned(), None)),
        }
    } else if let Some((authority, _path)) = remote.split_once(':') {
        let host = authority.rsplit('@').next().unwrap_or(authority);
        if host.is_empty() || host.contains('/') {
            return Err(anyhow!("cannot extract ssh host from remote {remote:?}"));
        }
        Ok((host.to_owned(), None))
    } else {
        Err(anyhow!("remote {remote:?} is not an ssh-shaped URL"))
    }
}

/// SHA-256 (lowercase hex) of a host key taken from one
/// `ssh-keyscan` output line (`host ssh-ed25519 AAAA…`). This is
/// the same hash libgit2 exposes for the connected server's key,
/// so the phone can compare byte-for-byte.
pub fn host_sha256_of_keyscan_line(line: &str) -> Result<String> {
    let mut parts = line.split_whitespace();
    let _host = parts.next().ok_or_else(|| anyhow!("empty keyscan line"))?;
    let _kind = parts
        .next()
        .ok_or_else(|| anyhow!("keyscan line has no key type"))?;
    let blob_b64 = parts
        .next()
        .ok_or_else(|| anyhow!("keyscan line has no key material"))?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .map_err(|e| anyhow!("keyscan key is not base64: {e}"))?;
    let digest = sha2::Sha256::digest(&blob);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Every host-key hash in one `ssh-keyscan` run, comment lines and
/// unparseable lines dropped. Order is the server's; the phone
/// accepts any member, so it does not matter.
pub fn pins_of_keyscan_output(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| host_sha256_of_keyscan_line(l).ok())
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample() -> InvitePayload {
        InvitePayload {
            v: PAYLOAD_VERSION,
            name: "lucia-phone".into(),
            remote: "git@doma.dev:.rageveil".into(),
            host_sha256: vec!["ab".repeat(32)],
            invite_private_openssh:
                "-----BEGIN OPENSSH PRIVATE KEY-----\nZm9v\n-----END OPENSSH PRIVATE KEY-----\n"
                    .into(),
            issued_at: Utc.with_ymd_and_hms(2026, 8, 27, 12, 0, 0).single().expect("ts"),
            expires_at: Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0).single().expect("ts"),
        }
    }

    #[test]
    fn url_roundtrips() {
        let p = sample();
        let url = p.to_url().expect("to_url");
        assert!(url.starts_with(URL_PREFIX));
        assert_eq!(InvitePayload::from_url(&url).expect("from_url"), p);
        // A bare pasted blob (scheme stripped by some messenger)
        // parses too.
        let blob = url.strip_prefix(URL_PREFIX).expect("prefix");
        assert_eq!(InvitePayload::from_url(blob).expect("bare"), p);
    }

    #[test]
    fn expiry_is_checked_against_now() {
        let p = sample();
        let before = Utc.with_ymd_and_hms(2026, 8, 28, 0, 0, 0).single().expect("ts");
        let after = Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).single().expect("ts");
        assert!(!p.expired_at(before));
        assert!(p.expired_at(after));
    }

    #[test]
    fn host_extraction_covers_both_remote_shapes() {
        assert_eq!(
            ssh_host_of_remote("git@doma.dev:.rageveil").expect("scp"),
            ("doma.dev".into(), None)
        );
        assert_eq!(
            ssh_host_of_remote("ssh://git@doma.dev:2222/srv/store").expect("url"),
            ("doma.dev".into(), Some(2222))
        );
        assert!(ssh_host_of_remote("/local/path").is_err());
    }

    #[test]
    fn keyscan_hash_matches_known_shape() {
        // `echo -n <decoded blob> | sha256` equivalence pinned by
        // construction: hash of the decoded base64, not the text.
        let line = "doma.dev ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC2CPbR76pncAZ3GKtS2HkzxOPMYQuJ823s8EBXqBAHM";
        let hex = host_sha256_of_keyscan_line(line).expect("hash");
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
