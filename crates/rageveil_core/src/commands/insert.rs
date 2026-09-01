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
    /// Include punctuation in a generated secret. On by default;
    /// off for the rare field that rejects it.
    pub symbols: bool,
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
    let symbols = args.symbols;
    let path = args.path.clone();

    vault_do! { s ;
        let cfg = read_json::<S, Config>(s.clone(), cfg_path) ;
        let payload =
            resolve_payload(s.clone(), payload_supplied, payload_from_stdin, generate, symbols) ;
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
        emit_generated(s.clone(), payload, generate, symbols)
    }
}

/// The alphabet a generated secret is drawn from.
///
/// Letters, digits, and nine punctuation marks. The symbol set is
/// the intersection of two constraints that pull against each other:
/// the characters password fields usually *suggest* (`!@#$%^&*`) are
/// very nearly the set a shell eats — `!` is history expansion, `#`
/// starts a comment, `$` and backtick substitute, `*?[]{}` glob and
/// expand, `&|;<>()` are control. A password you cannot paste into a
/// command without quoting is a password you will mistype.
///
/// What survives both: `- _ . , : + = @ %`. All are inert to sh,
/// bash and zsh mid-word, and all appear on the usual
/// "allowed special characters" lists. Deliberately absent are `/`
/// (path-shaped, and some sites reject it) and `^` (history
/// substitution in some shells).
const FULL: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.,:+=@%";

/// Letters and digits are the first 62 of [`FULL`]; the rest are
/// the symbols. One literal, so the two can never drift apart.
const ALNUM_LEN: usize = 62;

fn is_symbol(c: char) -> bool {
    FULL[ALNUM_LEN..].contains(&(c as u8))
}

/// Take one character from `alphabet`, advancing `cursor`, without
/// modulo bias.
///
/// 256 is a multiple of neither 62 nor 71, so mapping every byte
/// with `%` would make the first few characters likelier than the
/// rest. Bytes at or above the largest whole multiple are discarded
/// instead: a few more bytes consumed, a flat distribution out.
fn pick(bytes: &[u8], cursor: &mut usize, alphabet: &[u8]) -> Option<char> {
    let n = alphabet.len();
    let limit = (256 / n) * n;
    while *cursor < bytes.len() {
        let b = bytes[*cursor] as usize;
        *cursor += 1;
        if b < limit {
            return Some(alphabet[b % n] as char);
        }
    }
    None
}

/// One candidate: an alphanumeric first character, then the full
/// alphabet.
///
/// The first character is constrained because a secret beginning
/// `-` reads as a command-line flag, and one beginning `=` or `%`
/// confuses a shell in its own ways. Constraining exactly one
/// position costs a fraction of a bit and removes a whole class of
/// paste accident.
fn attempt(bytes: &[u8], cursor: &mut usize, len: usize) -> Option<String> {
    let mut out = String::with_capacity(len);
    out.push(pick(bytes, cursor, &FULL[..ALNUM_LEN])?);
    while out.chars().count() < len {
        out.push(pick(bytes, cursor, FULL)?);
    }
    Some(out)
}

/// Draw `len` characters, guaranteeing at least one symbol.
///
/// Sites that demand punctuation are the reason symbols are on at
/// all, so a generated secret that happens to contain none would
/// defeat the point — with nine symbols in seventy-one that is
/// about a 2% outcome at this length. The fix is to discard such a
/// candidate and draw a fresh one, never to patch a symbol into a
/// chosen position: substituting at a fixed index is what turns a
/// uniform distribution into a guessable pattern.
pub(crate) fn draw(bytes: &[u8], len: usize) -> Option<String> {
    let mut cursor = 0;
    loop {
        let candidate = attempt(bytes, &mut cursor, len)?;
        // A single character cannot be both alphanumeric-first and
        // contain a symbol; the first rule wins.
        if len == 1 || candidate.chars().any(is_symbol) {
            return Some(candidate);
        }
    }
}

/// Letters and digits only, for the rare field that rejects
/// punctuation outright.
pub(crate) fn draw_alnum(bytes: &[u8], len: usize) -> Option<String> {
    let mut cursor = 0;
    let mut out = String::with_capacity(len);
    while out.chars().count() < len {
        out.push(pick(bytes, &mut cursor, &FULL[..ALNUM_LEN])?);
    }
    Some(out)
}

fn generate_payload<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    len: usize,
    symbols: bool,
) -> S::R<String> {
    if len == 0 {
        return s.fail("--generate needs a length above zero".into());
    }
    // Room for several candidates: byte rejection eats a few
    // percent, and a symbol-less candidate is thrown away whole.
    // Running short is not a case that occurs, only one that is
    // refused.
    let draw_bytes = len.saturating_mul(12).max(64);
    let s2 = s.clone();
    vault_do! { s ;
        let bytes = s.random_bytes(draw_bytes) ;
        {
            match if symbols { draw(&bytes, len) } else { draw_alnum(&bytes, len) } {
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
    symbols: bool,
) -> S::R<()> {
    let Some(len) = generate else {
        return s.pure(());
    };
    let size = if symbols { FULL.len() } else { ALNUM_LEN };
    // The first position is drawn from the 62 alphanumerics
    // whatever the setting, so it contributes its own, smaller
    // share. Reporting the whole length at the wide alphabet would
    // overstate the strength, slightly, in the direction that
    // matters.
    let bits = (ALNUM_LEN as f64).log2()
        + (len.saturating_sub(1) as f64) * (size as f64).log2();
    let s2 = s.clone();
    vault_do! { s ;
        let _ = s.log(format!(
            "generated {len} characters from {size} symbols (~{bits:.0} bits)"
        )) ;
        s2.stdout(format!("{payload}\n").into_bytes())
    }
}

fn resolve_payload<S: Vault + Clone + Send + Sync + 'static>(
    s: S,
    supplied: Option<String>,
    from_stdin: bool,
    generate: Option<usize>,
    symbols: bool,
) -> S::R<String> {
    match (supplied, from_stdin, generate) {
        (Some(p), _, _) => s.pure(p),
        (None, false, Some(len)) => generate_payload(s, len, symbols),
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
    use super::{draw, draw_alnum, is_symbol, ALNUM_LEN, FULL};
    use std::collections::BTreeMap;

    /// Deterministic byte source: every value, over and over, so a
    /// test can consume as much as it likes.
    fn stream(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn draws_the_requested_length_from_the_alphabet() {
        let out = draw(&stream(2048), 29).expect("enough entropy");
        assert_eq!(out.chars().count(), 29);
        assert!(out.bytes().all(|c| FULL.contains(&c)), "got {out}");
    }

    /// The reason symbols are on at all: a field that demands
    /// punctuation must never be handed a secret without any.
    #[test]
    fn always_contains_a_symbol() {
        for len in [8usize, 16, 29, 40] {
            for seed in 0..64usize {
                let bytes: Vec<u8> = (0..4096).map(|i| ((i * 7 + seed * 31) % 256) as u8).collect();
                let out = draw(&bytes, len).expect("entropy");
                assert!(
                    out.chars().any(is_symbol),
                    "len {len} seed {seed} produced no symbol: {out}"
                );
            }
        }
    }

    /// A secret starting `-` reads as a command-line flag; one
    /// starting `=` or `%` confuses a shell in its own ways.
    #[test]
    fn never_starts_with_punctuation() {
        for seed in 0..128usize {
            let bytes: Vec<u8> = (0..4096).map(|i| ((i * 13 + seed * 17) % 256) as u8).collect();
            let out = draw(&bytes, 24).expect("entropy");
            let first = out.chars().next().expect("non-empty");
            assert!(!is_symbol(first), "seed {seed} began with {first}: {out}");
        }
    }

    /// Every symbol we ship must be inert to sh/bash/zsh mid-word
    /// and absent from the set that globs, expands or substitutes.
    #[test]
    fn the_symbol_set_is_shell_inert() {
        let hostile = "!#$&*?[]{}()<>|;\\'\"`~^/ \t";
        for c in &FULL[ALNUM_LEN..] {
            assert!(
                !hostile.contains(*c as char),
                "{} is not safe to paste unquoted",
                *c as char
            );
        }
        assert_eq!(FULL.len() - ALNUM_LEN, 9, "nine symbols");
    }

    /// Rejection sampling, checked exactly rather than
    /// statistically: over one full pass of every byte value each
    /// alphanumeric must come up the same number of times.
    #[test]
    fn every_character_is_equally_likely() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let out = draw_alnum(&bytes, 248).expect("248 bytes survive rejection");
        let mut counts: BTreeMap<char, usize> = BTreeMap::new();
        for c in out.chars() {
            *counts.entry(c).or_default() += 1;
        }
        assert_eq!(counts.len(), ALNUM_LEN, "every symbol appears");
        assert!(counts.values().all(|n| *n == 4), "uneven: {counts:?}");
    }

    /// The biased tail is discarded, not folded. Byte 250 would map
    /// to 'C' under plain modulo over 62.
    #[test]
    fn discards_the_biased_tail_rather_than_folding_it() {
        assert_eq!(FULL[250 % ALNUM_LEN] as char, 'C', "precondition");
        assert_eq!(draw_alnum(&[250, 5], 1).expect("second byte"), "F");
    }

    #[test]
    fn no_symbols_mode_stays_alphanumeric() {
        let out = draw_alnum(&stream(2048), 40).expect("entropy");
        assert!(!out.chars().any(is_symbol), "got {out}");
        assert_eq!(out.chars().count(), 40);
    }

    /// Refuse rather than pad with biased output.
    #[test]
    fn running_out_of_entropy_is_a_refusal() {
        assert!(draw(&[1, 2, 3], 10).is_none());
    }
}
