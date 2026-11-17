//! Tagged P-256 recipients, `age1tag1…`: keys held by a TPM, and by
//! other hardware that age plugins drive.
//!
//! AI-generated module: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! This is the Linux counterpart of [`crate::se`]. [age-plugin-tpm] 1.0
//! makes a P-256 key inside the TPM and prints its recipient in age's
//! own tagged form (age 1.3, package `filippo.io/age/tag`): `age1tag1`
//! followed by the bech32 of the compressed public point. Encrypting
//! needs only that point, so it is done here, natively, on every
//! platform: a phone or a Mac shares to a Linux laptop's TPM without the
//! plugin. Decrypting needs the TPM, so it goes through the plugin on
//! the laptop that holds the key (see [`crate::live`]), which asks for
//! the key's PIN when it has one.
//!
//! Wrapping, as age's `tag.Recipient` does it (HPKE, RFC 9180, base
//! mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305):
//!
//! ```text
//! enc, ct  = HPKE.SealBase(recipient, info = "age-encryption.org/p256tag", aad = "", file key)
//! tag      = HKDF-Extract(salt = "age-encryption.org/p256tag",
//!                         ikm  = enc || sha256(compress(recipient))[..4])[..4]
//! stanza   = p256tag <b64(tag)> <b64(enc)>     body = ct
//! ```
//!
//! `enc` is the uncompressed ephemeral point, 65 bytes.
//!
//! **Whether such a key is gated is not in the recipient.** A TPM key
//! may have been made with a PIN or without one, and the same `age1tag1`
//! form serves other hardware with other policies. So, unlike a Secure
//! Enclave key, a tagged key is gated only when the store lists it in
//! `gated.json` (`rageveil gate`), after its owner made it with a PIN
//! (`rageveil tpm` refuses a key without one). See [`crate::tier`].
//!
//! [age-plugin-tpm]: https://github.com/Foxboron/age-plugin-tpm

use std::collections::HashSet;

use age::secrecy::ExposeSecret;
use age_core::format::{FileKey, Stanza};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use bech32::{FromBase32, ToBase32, Variant};
use hkdf::Hkdf;
use hpke::{Deserializable, OpModeS, Serializable};
use p256::PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};

type Kem = hpke::kem::DhP256HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;

/// The human-readable part of a tagged P-256 recipient.
pub const HRP: &str = "age1tag";
/// The stanza tag.
pub const STANZA_TAG: &str = "p256tag";
/// HPKE's `info`, and the salt of the tag.
pub const LABEL: &str = "age-encryption.org/p256tag";

/// Whether a recipient string is a tagged P-256 recipient. Pure string
/// test, so it can decide policy before any key is parsed.
pub fn is_tag_recipient(spec: &str) -> bool {
    spec.trim().starts_with("age1tag1")
}

/// A tagged P-256 recipient.
#[derive(Clone, Debug)]
pub struct TagRecipient {
    key: PublicKey,
}

impl TagRecipient {
    /// Parse `age1tag1…`. Refuses any other prefix (the post-quantum
    /// `age1tagpq1…` included) or a point that is not on the curve.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (hrp, data, variant) =
            bech32::decode(spec.trim()).map_err(|e| format!("not an age1tag recipient: {e}"))?;
        if hrp != HRP || variant != Variant::Bech32 {
            return Err(format!("not an age1tag recipient: prefix {hrp}"));
        }
        let bytes =
            Vec::<u8>::from_base32(&data).map_err(|e| format!("age1tag recipient: {e}"))?;
        if bytes.len() != 33 {
            return Err(format!(
                "age1tag recipient: {} bytes, not a compressed P-256 point",
                bytes.len()
            ));
        }
        let key = PublicKey::from_sec1_bytes(&bytes)
            .map_err(|_| "age1tag recipient: not a P-256 point".to_owned())?;
        Ok(Self { key })
    }

    /// The canonical `age1tag1…` string.
    pub fn encode(&self) -> String {
        // Encoding a byte string we produced cannot fail.
        bech32::encode(HRP, self.compressed().to_base32(), Variant::Bech32).unwrap_or_default()
    }

    fn compressed(&self) -> Vec<u8> {
        self.key.to_encoded_point(true).as_bytes().to_vec()
    }

    fn uncompressed(&self) -> Vec<u8> {
        self.key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// The four-byte tag for one ephemeral share `enc`, by which the key
    /// holder finds its stanza without trying the TPM on every one.
    pub fn tag(&self, enc: &[u8]) -> [u8; 4] {
        let digest = Sha256::digest(self.compressed());
        let mut ikm = Vec::with_capacity(enc.len() + 4);
        ikm.extend_from_slice(enc);
        ikm.extend_from_slice(&digest[..4]);
        let (prk, _) = Hkdf::<Sha256>::extract(Some(LABEL.as_bytes()), &ikm);
        [prk[0], prk[1], prk[2], prk[3]]
    }
}

impl age::Recipient for TagRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let failed =
            |what: &str| age::EncryptError::Io(std::io::Error::other(format!("p256tag: {what}")));
        let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&self.uncompressed())
            .map_err(|_| failed("the recipient is not a P-256 point"))?;
        let (enc, body) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
            &OpModeS::Base,
            &pk,
            LABEL.as_bytes(),
            file_key.expose_secret().as_slice(),
            &[],
            &mut rand::rngs::OsRng,
        )
        .map_err(|_| failed("wrapping failed"))?;
        let enc = enc.to_bytes().to_vec();
        let stanza = Stanza {
            tag: STANZA_TAG.to_owned(),
            args: vec![STANDARD_NO_PAD.encode(self.tag(&enc)), STANDARD_NO_PAD.encode(&enc)],
            body,
        };
        Ok((vec![stanza], HashSet::new()))
    }
}

/// What a TPM identity file says about itself, read without a TPM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmIdentityInfo {
    /// The identity format's version (age-plugin-tpm 1.0 writes 2).
    pub version: u8,
    /// Whether the TPM releases the key only with its PIN.
    pub pin: bool,
}

/// Read the header of an `AGE-PLUGIN-TPM-1…` identity: its version and
/// whether the key has a PIN. The rest is the TPM's sealed blob, which
/// only the TPM that made it can load.
///
/// The header is two bytes, as age-plugin-tpm serialises its
/// `Identity`: the version, then `PINStatus` (0 none, 1 PIN).
pub fn tpm_identity_info(text: &str) -> Result<TpmIdentityInfo, String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or("no identity line")?;
    if !line.starts_with("AGE-PLUGIN-TPM-1") {
        return Err("not an age-plugin-tpm identity (AGE-PLUGIN-TPM-1…)".into());
    }
    // Plugin identities are longer than bech32's 90-character limit,
    // which the bech32 crate enforces, so the checksum is checked here.
    let lower = line.to_lowercase();
    let (hrp, data) = lower.rsplit_once('1').ok_or("not bech32")?;
    if hrp != "age-plugin-tpm-" {
        return Err("not an age-plugin-tpm identity".into());
    }
    let fives: Vec<u8> = data
        .chars()
        .map(|c| {
            CHARSET
                .find(c)
                .and_then(|i| u8::try_from(i).ok())
                .ok_or_else(|| format!("identity has a character outside bech32: {c:?}"))
        })
        .collect::<Result<_, _>>()?;
    if fives.len() < 6 || !bech32_checksum_ok(hrp, &fives) {
        return Err("identity checksum does not match: the line is damaged".into());
    }
    let payload: Vec<bech32::u5> = fives[..fives.len() - 6]
        .iter()
        .map(|&v| bech32::u5::try_from_u8(v).map_err(|e| format!("identity: {e}")))
        .collect::<Result<_, _>>()?;
    let bytes = Vec::<u8>::from_base32(&payload).map_err(|e| format!("identity: {e}"))?;
    match bytes.as_slice() {
        [version, pin, ..] if *pin <= 1 => Ok(TpmIdentityInfo { version: *version, pin: *pin == 1 }),
        [_, pin, ..] => Err(format!("identity has an unknown PIN status {pin}")),
        _ => Err("identity is too short".into()),
    }
}

const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BIP 173's checksum: the polymod of the expanded HRP and the data,
/// checksum included, is 1.
fn bech32_checksum_ok(hrp: &str, data: &[u8]) -> bool {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let expanded = hrp
        .bytes()
        .map(|b| b >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|b| b & 31));
    let mut chk: u32 = 1;
    for v in expanded.chain(data.iter().copied()) {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::OpModeR;
    use p256::SecretKey;

    /// What the TPM does on unwrap, with a software key standing in.
    fn unwrap(secret: &SecretKey, stanza: &Stanza) -> Option<Vec<u8>> {
        let recipient = TagRecipient { key: secret.public_key() };
        if stanza.tag != STANZA_TAG {
            return None;
        }
        let enc = STANDARD_NO_PAD.decode(stanza.args.get(1)?).ok()?;
        if stanza.args.first()? != &STANDARD_NO_PAD.encode(recipient.tag(&enc)) {
            return None;
        }
        let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(&secret.to_bytes()).ok()?;
        let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc).ok()?;
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &sk,
            &encapped,
            LABEL.as_bytes(),
            &stanza.body,
            &[],
        )
        .ok()
    }

    #[test]
    fn wraps_a_file_key_that_the_key_holder_alone_unwraps() -> Result<(), String> {
        let secret = SecretKey::random(&mut rand::rngs::OsRng);
        let recipient = TagRecipient { key: secret.public_key() };
        let spec = recipient.encode();
        assert!(spec.starts_with("age1tag1") && is_tag_recipient(&spec));
        let parsed = TagRecipient::parse(&spec).map_err(|e| e.to_string());
        assert_eq!(parsed.map(|r| r.encode()), Ok(spec.clone()));

        let file_key = FileKey::new(Box::new([7u8; 16]));
        let (stanzas, labels) =
            age::Recipient::wrap_file_key(&recipient, &file_key).map_err(|e| e.to_string())?;
        assert!(labels.is_empty());
        assert_eq!(stanzas.len(), 1);
        assert_eq!(stanzas[0].tag, "p256tag");
        let enc = STANDARD_NO_PAD.decode(&stanzas[0].args[1]).map_err(|e| e.to_string())?;
        assert_eq!(enc.len(), 65, "enc is the uncompressed ephemeral point");
        assert_eq!(unwrap(&secret, &stanzas[0]), Some(vec![7u8; 16]));

        let stranger = SecretKey::random(&mut rand::rngs::OsRng);
        assert_eq!(unwrap(&stranger, &stanzas[0]), None);
        Ok(())
    }

    /// The recipient age-plugin-tpm 1.0.1 printed for a key it made in
    /// its simulator: it parses, and prints back the same.
    #[test]
    fn reads_the_plugins_own_recipient() {
        let spec = "age1tag1qgrf86d5uuvzlkweqqffl4vhv77urj68duykcxs0rqgcmd2f0g0uxjpc9rg";
        assert_eq!(TagRecipient::parse(spec).map(|r| r.encode()), Ok(spec.to_owned()));
    }

    #[test]
    fn refuses_what_is_not_a_tagged_recipient() {
        for spec in [
            "",
            "age1qqqq",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB",
            "age1se1qd63u86e3hqd7efs9l5yexpw0yfjmgr8mptgl0fhxf68n4n2mwpl7tuhx9k",
            "age1tag1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
        ] {
            assert!(TagRecipient::parse(spec).is_err(), "{spec:?}");
        }
    }

    /// The header of the identity in age-plugin-tpm's README (made with
    /// no PIN), and the same bytes with the PIN flag set.
    #[test]
    fn reads_whether_a_tpm_identity_has_a_pin() {
        let readme = "AGE-PLUGIN-TPM-1QGQQQKQQYVQQKQQZQPEQQQQQZQQPJQQTQQPSQYQQYR96EDFP3TY6N36FJ5KYQ0YUESP7RDCMM7SJSWZDCREKH6ASH8N3UQPQYE4FZAPQXA3HRLELET3KX2EDSWDRF2ET4DWMTN0AWMKHUPQ8EK8SQLSQYQYMY5ZVWQYDY5D7WZ0W6KEXDWNUAP00DEVQ76AJ7HVV85TWU0DFCQQS0DA7N7E8GN55U6E4G8ECFFNRTP7XJTHD440N3CZW6STXNWQGA89WF3NF3PEDPUAPC8AW5XNZW68E4QG7X85G2CM5TZDKAP2UZ9EEAAC5LQ0R9PJEX5280SG0U47HA09EAFQ6VSVX65HCGRGNQQ3QQZL5H2W3M34CMSTWMRXLR90YRDZPZKWGZK7H7E079KLCCSSVRLFMQYEY547R";
        assert_eq!(
            tpm_identity_info(&format!("# Created: today\n{readme}\n")),
            Ok(TpmIdentityInfo { version: 2, pin: false })
        );
        let damaged = readme.replacen("QGQQQ", "QGQZQ", 1);
        assert!(tpm_identity_info(&damaged).is_err(), "a damaged line must not be read");
        assert!(tpm_identity_info("AGE-PLUGIN-SE-1QQQQ").is_err());
        assert!(tpm_identity_info("# nothing\n").is_err());
    }
}
