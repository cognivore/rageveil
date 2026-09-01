//! `rageveil insert PATH [--batch]`.
//!
//! Encrypts a payload to the operator's own recipient and drops
//! it on disk under `<store>/<entry-hash>/<recipient-fp>.age`.
//! `--batch` reads the secret from stdin (the only path we ship —
//! no editor integration in V1, deliberately, since interactive
//! editing isn't on the critical-path requirements list).

use crate::config::Config;
use crate::content::Content;
use crate::dsl::Vault;
use crate::index::{Cached, Index};
use crate::metadata::Metadata;
use crate::store::StoreLayout;
use crate::sugar::{read_json, write_json};
use crate::types::{CommitOutcome, EntryPath, Salt};
use crate::{git, vault_do};

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct InsertArgs {
    pub root: PathBuf,
    pub path: EntryPath,
    /// Either supplied directly (`--payload`, mostly used in
    /// tests) or read from stdin when `payload_from_stdin` is set.
    pub payload: Option<String>,
    pub payload_from_stdin: bool,
    /// Generate a random secret of this many characters instead of
    /// being given one. Mutually exclusive with the other two.
    pub generate: Option<usize>,
}

pub fn insert<S>(s: S, args: InsertArgs) -> S::R<()>
where
    S: Vault + Clone + Send + Sync + 'static,
{
    let layout = StoreLayout::new(args.root.clone());

    let cfg_path = layout.config_path();
    let payload_supplied = args.payload.clone();
    let payload_from_stdin = args.payload_from_stdin;
    let generate = args.generate;
    let path = args.path.clone();

    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let payload = resolve_payload(s.clone(), payload_supplied, payload_from_stdin, generate) ;
        let salt_bytes = s.random_bytes(32) ;
        let now = s.now() ;
        let _ = do_insert(
            s.clone(),
            layout.clone(),
            cfg,
            path.clone(),
            payload.clone(),
            Salt::from_bytes(&salt_bytes),
            now,
        ) ;
        let _ = git::add_all(&s, layout.store_dir()) ;
        let _ = commit_insert(s.clone(), layout.store_dir(), path) ;
        emit_generated(s.clone(), payload, generate)
    }
}

/// The alphabet a generated secret is drawn from.
///
/// Letters and digits only. Symbols are where generators meet the
/// world badly — sites reject them, shells eat them, people retype
/// them wrong — and they buy little: at 62 characters each position
/// is already ~5.95 bits, so length is a far cheaper way to buy
/// entropy than an exotic alphabet. 29 characters is ~172 bits.
pub(crate) const ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Draw `len` characters from `bytes`, without modulo bias.
///
/// 256 is not a multiple of 62, so mapping every byte with `%`
/// would make the first eight letters about 1.6% likelier than the
/// rest. Bytes at or above the largest multiple of 62 are discarded
/// instead: a few more bytes consumed, a flat distribution out.
///
/// `None` when `bytes` ran out before `len` characters were
/// accepted — the caller draws generously so that cannot happen in
/// practice, and refuses rather than padding with biased output.
pub(crate) fn draw(bytes: &[u8], len: usize) -> Option<String> {
    let n = ALPHABET.len();
    let limit = (256 / n) * n;
    let mut out = String::with_capacity(len);
    for b in bytes {
        if (*b as usize) < limit {
            out.push(ALPHABET[(*b as usize) % n] as char);
            if out.len() == len {
                return Some(out);
            }
        }
    }
    None
}

fn generate_payload<S: Vault + Clone + Send + Sync + 'static>(s: S, len: usize) -> S::R<String> {
    if len == 0 {
        return s.fail("--generate needs a length above zero".into());
    }
    // Four bytes per character against a ~3% rejection rate: running
    // short is not a case that occurs, only one that is refused.
    let draw_bytes = len.saturating_mul(4);
    let s2 = s.clone();
    vault_do! { s ;
        let bytes = s.random_bytes(draw_bytes) ;
        {
            match draw(&bytes, len) {
                Some(p) => s2.pure(p),
                None => s2.fail(
                    "ran out of unbiased entropy while generating; run it again".into(),
                ),
            }
        }
    }
}

/// Print a generated secret, and only a generated one — you cannot
/// paste what you never saw. A supplied or piped payload is already
/// in the caller's hands and never echoed.
fn emit_generated<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    payload: String,
    generate: Option<usize>,
) -> S::R<()> {
    let Some(len) = generate else {
        return s.pure(());
    };
    let bits = (len as f64) * (ALPHABET.len() as f64).log2();
    let s2 = s.clone();
    vault_do! { s ;
        let _ = s.log(format!(
            "generated {len} characters from {} symbols (~{bits:.0} bits)",
            ALPHABET.len()
        )) ;
        s2.stdout(format!("{payload}\n").into_bytes())
    }
}

fn resolve_payload<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    supplied: Option<String>,
    from_stdin: bool,
    generate: Option<usize>,
) -> S::R<String> {
    match (supplied, from_stdin, generate) {
        (Some(p), _, _) => s.pure(p),
        (None, false, Some(len)) => generate_payload(s, len),
        (None, true, _) => {
            vault_do! { s ;
                let bytes = s.read_stdin() ;
                match String::from_utf8(bytes) {
                    Ok(s2) => s.pure(s2.trim_end_matches('\n').to_owned()),
                    Err(e) => s.fail(format!("stdin not utf-8: {e}")),
                }
            }
        }
        (None, false, None) => s.fail(
            "no payload supplied; pass --payload, --generate LEN, or --batch and pipe one in"
                .into(),
        ),
    }
}

fn do_insert<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    cfg: Config,
    path: EntryPath,
    payload: String,
    salt: Salt,
    now: chrono::DateTime<chrono::Utc>,
) -> S::R<()> {
    let metadata = Metadata::new(cfg.whoami.clone(), now);
    let content = Content {
        path: path.clone(),
        salt,
        payload,
        metadata: metadata.clone(),
    };
    let recipients = vec![cfg.whoami.clone()];

    // Pure derivations — sha256 of the path and the operator's
    // recipient. No reason to round-trip through the DSL; the
    // values feed straight into the layout helpers below.
    let hash = path.hash();
    let fp = cfg.whoami.fingerprint();
    let entry_dir = layout.entry_dir(&hash);
    let entry_file = layout.entry_file(&hash, &fp);

    let s2 = s.clone();
    let layout2 = layout.clone();
    let path2 = path.clone();
    vault_do! { s ;
        let plaintext = s.encode_json(content) ;
        let ciphertext = s.encrypt(plaintext, recipients) ;
        let _ = s.mkdir_p(entry_dir) ;
        let _ = s.write_file(entry_file, ciphertext) ;
        update_index_after_insert(s2, layout2, path2, hash, metadata, now)
    }
}

fn update_index_after_insert<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    layout: StoreLayout,
    path: EntryPath,
    hash: crate::types::EntryHash,
    metadata: Metadata,
    now: chrono::DateTime<chrono::Utc>,
) -> S::R<()> {
    let s2 = s.clone();
    let index_path = layout.index_path();
    vault_do! { s ;
        let mut idx = read_index_or_empty(s2.clone(), index_path.clone()) ;
        {
            idx.entries.insert(path.clone(), Cached { hash, metadata, seen: now });
            write_json(s2.clone(), index_path, idx)
        }
    }
}

fn read_index_or_empty<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    path: PathBuf,
) -> S::R<Index> {
    let s2 = s.clone();
    vault_do! { s ;
        let exists = s.exists(path.clone()) ;
        match exists {
            true  => read_json::<S, Index>(s2.clone(), path),
            false => s.pure(Index::empty()),
        }
    }
}

fn commit_insert<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    store_dir: PathBuf,
    path: EntryPath,
) -> S::R<()> {
    vault_do! { s ;
        let out = git::commit(&s, store_dir, format!("insert {}", path)) ;
        match out {
            CommitOutcome::Committed => s.log(format!("inserted {}", path)),
            // Re-inserting an unchanged value is not a failure —
            // swallow it.
            CommitOutcome::NothingToCommit => s.pure(()),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::{draw, ALPHABET};
    use std::collections::BTreeMap;

    #[test]
    fn draws_the_requested_length_from_the_alphabet() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let out = draw(&bytes, 29).expect("enough entropy");
        assert_eq!(out.chars().count(), 29);
        assert!(out.bytes().all(|c| ALPHABET.contains(&c)), "got {out}");
    }

    /// The whole point of rejection sampling. 256 is not a multiple
    /// of 62, so `%` alone would make the first eight letters
    /// likelier. Byte 250 lands in the biased tail and must be
    /// discarded, not folded to 'C' (250 % 62 == 2).
    #[test]
    fn discards_the_biased_tail_rather_than_folding_it() {
        let folded = ALPHABET[250 % ALPHABET.len()] as char;
        assert_eq!(folded, 'C', "precondition: 250 would fold to C");
        let out = draw(&[250, 5], 1).expect("second byte is usable");
        assert_eq!(out, "F", "250 must be rejected, not mapped");
    }

    /// Over one full pass of every byte value, each character must
    /// come up exactly the same number of times — 248 accepted bytes
    /// over 62 symbols is four apiece, exactly.
    #[test]
    fn every_character_is_equally_likely() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let out = draw(&bytes, 248).expect("248 bytes survive rejection");
        let mut counts: BTreeMap<char, usize> = BTreeMap::new();
        for c in out.chars() {
            *counts.entry(c).or_default() += 1;
        }
        assert_eq!(counts.len(), ALPHABET.len(), "every symbol appears");
        assert!(
            counts.values().all(|n| *n == 4),
            "uneven distribution: {counts:?}"
        );
    }

    /// Refuse rather than pad with biased output.
    #[test]
    fn running_out_of_entropy_is_a_refusal() {
        assert!(draw(&[1, 2, 3], 10).is_none());
    }
}
