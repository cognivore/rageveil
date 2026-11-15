//! Recipients whose private key lives in an Apple Secure Enclave.
//!
//! A Secure Enclave key cannot leave the chip, and the enclave
//! releases its key agreement only after the access control the key
//! was made with — for rageveil, Touch ID. Such a key is how an entry
//! stays **human-only**: whoever can read files on the laptop still
//! cannot open it without a finger on the sensor.
//!
//! The keys are those of [age-plugin-se]: the recipient is
//! `age1se1…`, the bech32 encoding of a compressed P-256 public key,
//! and the stanza is age-plugin-yubikey's `piv-p256`. Encrypting needs
//! only the public key, so it is done here, natively, on every
//! platform — a phone included. Decrypting needs the enclave, so it
//! goes through the plugin on the Mac that holds the key (see
//! [`crate::live`]).
//!
//! Wrapping, exactly as the plugin does it:
//!
//! ```text
//! eph        = fresh P-256 key
//! shared     = ECDH(eph, recipient)                (x coordinate)
//! salt       = compress(eph.pub) || compress(recipient)
//! wrap_key   = HKDF-SHA256(shared, salt, "piv-p256") → 32 bytes
//! body       = ChaCha20-Poly1305(wrap_key, nonce = 0¹², file key)
//! stanza     = piv-p256 <b64(sha256(compress(recipient))[..4])> <b64(compress(eph.pub))>
//! ```
//!
//! [age-plugin-se]: https://github.com/remko/age-plugin-se

use std::collections::HashSet;

use age::secrecy::ExposeSecret;
use age_core::format::{FileKey, Stanza};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bech32::{FromBase32, ToBase32, Variant};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

/// The human-readable part of a Secure Enclave recipient.
pub const HRP: &str = "age1se";
/// The stanza tag, shared with age-plugin-yubikey.
pub const STANZA_TAG: &str = "piv-p256";

/// Whether a recipient string names a Secure Enclave key. Pure string
/// test, so it can decide policy before any key is parsed.
pub fn is_se_recipient(spec: &str) -> bool {
    spec.trim().starts_with("age1se1")
}

/// A Secure Enclave recipient: a P-256 public key.
#[derive(Clone, Debug)]
pub struct SeRecipient {
    key: PublicKey,
}

impl SeRecipient {
    /// Parse `age1se1…`. Refuses any other prefix or a point that is not on the curve.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (hrp, data, variant) =
            bech32::decode(spec.trim()).map_err(|e| format!("not an age1se recipient: {e}"))?;
        if hrp != HRP || variant != Variant::Bech32 {
            return Err(format!("not an age1se recipient: prefix {hrp}"));
        }
        let bytes = Vec::<u8>::from_base32(&data).map_err(|e| format!("age1se recipient: {e}"))?;
        let key = PublicKey::from_sec1_bytes(&bytes)
            .map_err(|_| "age1se recipient: not a P-256 point".to_owned())?;
        Ok(Self { key })
    }

    /// The canonical `age1se1…` string.
    pub fn encode(&self) -> String {
        let compressed = self.compressed();
        // Encoding a byte string we produced cannot fail.
        bech32::encode(HRP, compressed.to_base32(), Variant::Bech32).unwrap_or_default()
    }

    fn compressed(&self) -> Vec<u8> {
        self.key.to_encoded_point(true).as_bytes().to_vec()
    }

    /// The four-byte tag that lets the holder of the key find its stanza.
    pub fn tag(&self) -> [u8; 4] {
        let digest = Sha256::digest(self.compressed());
        [digest[0], digest[1], digest[2], digest[3]]
    }
}

/// HKDF-SHA256 over the ECDH secret, salted with both public points.
fn wrap_key(shared: &[u8], eph_compressed: &[u8], recipient_compressed: &[u8]) -> [u8; 32] {
    let mut salt = Vec::with_capacity(66);
    salt.extend_from_slice(eph_compressed);
    salt.extend_from_slice(recipient_compressed);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 32];
    // 32 bytes is far below HKDF-SHA256's limit of 8160.
    let _ = hk.expand(STANZA_TAG.as_bytes(), &mut okm);
    okm
}

impl age::Recipient for SeRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let eph = EphemeralSecret::random(&mut rand::rngs::OsRng);
        let eph_compressed = eph.public_key().to_encoded_point(true).as_bytes().to_vec();
        let shared = eph.diffie_hellman(&self.key);
        let key = wrap_key(
            shared.raw_secret_bytes().as_slice(),
            &eph_compressed,
            &self.compressed(),
        );
        let cipher = ChaCha20Poly1305::new((&key).into());
        let body = cipher
            .encrypt(&Nonce::default(), file_key.expose_secret().as_slice())
            .map_err(|_| {
                age::EncryptError::Io(std::io::Error::other("piv-p256: wrapping failed"))
            })?;
        let stanza = Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![
                STANDARD_NO_PAD.encode(self.tag()),
                STANDARD_NO_PAD.encode(&eph_compressed),
            ],
            body,
        };
        Ok((vec![stanza], HashSet::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::SecretKey;
    use p256::ecdh::diffie_hellman;

    /// What the enclave does on unwrap, with a software key standing in.
    fn unwrap(secret: &SecretKey, stanza: &Stanza) -> Option<Vec<u8>> {
        let recipient = SeRecipient { key: secret.public_key() };
        if stanza.tag != STANZA_TAG
            || stanza.args.first()? != &STANDARD_NO_PAD.encode(recipient.tag())
        {
            return None;
        }
        let eph_compressed = STANDARD_NO_PAD.decode(stanza.args.get(1)?).ok()?;
        let eph = PublicKey::from_sec1_bytes(&eph_compressed).ok()?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), eph.as_affine());
        let key = wrap_key(
            shared.raw_secret_bytes().as_slice(),
            &eph_compressed,
            &recipient.compressed(),
        );
        ChaCha20Poly1305::new((&key).into())
            .decrypt(&Nonce::default(), stanza.body.as_slice())
            .ok()
    }

    #[test]
    fn wraps_a_file_key_that_the_key_holder_alone_unwraps() -> Result<(), String> {
        let secret = SecretKey::random(&mut rand::rngs::OsRng);
        let recipient = SeRecipient { key: secret.public_key() };
        let spec = recipient.encode();
        assert!(spec.starts_with("age1se1") && is_se_recipient(&spec));
        let parsed = SeRecipient::parse(&spec).map_err(|e| e.to_string());
        assert_eq!(parsed.map(|r| r.encode()), Ok(spec.clone()));

        let file_key = FileKey::new(Box::new([7u8; 16]));
        let (stanzas, labels) =
            age::Recipient::wrap_file_key(&recipient, &file_key).map_err(|e| e.to_string())?;
        assert!(labels.is_empty());
        assert_eq!(stanzas.len(), 1);
        assert_eq!(unwrap(&secret, &stanzas[0]), Some(vec![7u8; 16]));

        let stranger = SecretKey::random(&mut rand::rngs::OsRng);
        assert_eq!(unwrap(&stranger, &stanzas[0]), None);
        Ok(())
    }

    #[test]
    fn refuses_what_is_not_an_enclave_recipient() {
        for spec in [
            "",
            "age1qqqq",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB",
            "age1se1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        ] {
            assert!(SeRecipient::parse(spec).is_err(), "{spec:?}");
        }
    }
}
