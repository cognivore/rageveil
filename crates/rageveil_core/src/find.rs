//! Finding entries by a few typed pieces of their names. **Draft.**
//!
//! AI-generated module: model Claude Fable 5.2 (`claude-fable-5-2`);
//! reasoning effort xhigh.
//!
//! A person looking for a login types what they remember of it:
//! `workspace j` for `workspace.google.com/jm@memorici.de`. The rule,
//! which the CLI's `search` and the Visageveil apps share:
//!
//! 1. The query is split at spaces into terms. Case is ignored, and so
//!    is the order of the terms. No terms finds every name.
//! 2. A name is found when it contains every term, each as one
//!    unbroken piece.
//! 3. Only when no name at all is found that way are gaps allowed: a
//!    name is then found when every term's letters appear in it in
//!    order (`wrkspc` finds `workspace`). Exact pieces are never mixed
//!    with loose ones, so a short term cannot flood the result.
//!
//! Found names come best first. A piece that begins a part of the name
//! (at its start or after a `/`) counts most, one that begins a word
//! inside a part (after `.`, `@`, `-`, `_`, `+`, `:` or `#`) counts
//! next, and one in the middle of a word least; with gaps, a tighter
//! fit comes first. Ties go to the shorter name, then to the alphabet.
//!
//! Pure: no index, no store, no effect. The caller says which names.

use std::cmp::Reverse;

/// The names among `names` that `query` finds, best first.
pub fn find<'a, I>(query: &str, names: I) -> Vec<&'a str>
where
    I: IntoIterator<Item = &'a str>,
{
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    let names: Vec<&'a str> = names.into_iter().collect();
    if terms.is_empty() {
        return names;
    }
    let lowered: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();

    let mut exact: Vec<(Reverse<u32>, usize, &'a str)> = names
        .iter()
        .zip(&lowered)
        .filter_map(|(name, low)| {
            let scores: Option<Vec<u32>> = terms.iter().map(|t| piece_score(low, t)).collect();
            scores.map(|s| (Reverse(s.iter().sum()), name.len(), *name))
        })
        .collect();
    if !exact.is_empty() {
        exact.sort();
        return exact.into_iter().map(|(_, _, name)| name).collect();
    }

    let mut loose: Vec<(usize, usize, &'a str)> = names
        .iter()
        .zip(&lowered)
        .filter_map(|(name, low)| {
            let spans: Option<Vec<usize>> = terms.iter().map(|t| tightest_span(low, t)).collect();
            spans.map(|s| (s.iter().sum(), name.len(), *name))
        })
        .collect();
    loose.sort();
    loose.into_iter().map(|(_, _, name)| name).collect()
}

/// How well `term` sits in `name` as one unbroken piece: 2 where it
/// begins a part, 1 where it begins a word inside a part, 0 elsewhere;
/// the best of its occurrences. `None` when it is not there. Both are
/// lowercase already.
fn piece_score(name: &str, term: &str) -> Option<u32> {
    name.match_indices(term)
        .map(|(at, _)| match name[..at].chars().next_back() {
            None | Some('/') => 2,
            Some('.' | '@' | '-' | '_' | '+' | ':' | '#') => 1,
            Some(_) => 0,
        })
        .max()
}

/// The length of the shortest stretch of `name` that holds `term`'s
/// letters in order, gaps allowed. `None` when no stretch does.
fn tightest_span(name: &str, term: &str) -> Option<usize> {
    let name: Vec<char> = name.chars().collect();
    let term: Vec<char> = term.chars().collect();
    let first = *term.first()?;
    (0..name.len())
        .filter(|&start| name[start] == first)
        .filter_map(|start| {
            let mut wanted = term.iter().peekable();
            name[start..].iter().position(|c| {
                if wanted.peek() == Some(&c) {
                    wanted.next();
                }
                wanted.peek().is_none()
            })
        })
        .map(|last| last + 1)
        .min()
}

#[cfg(test)]
mod tests {
    use super::find;

    const NAMES: [&str; 8] = [
        "accounts.google.com/jane@example.com",
        "geosurgeworkspace.slack.com/2fa/jons@geosurge.ai",
        "github.com/jane/recovery",
        "workspace.google.com/c/test@doma.dev",
        "workspace.google.com/info@memorici.de",
        "workspace.google.com/jm@memorici.de",
        "workspace.google.com/jm@memorici.de/rclone",
        "workspace.google.com/jons@geosurge.ai",
    ];

    /// The owner's example: `workspace j` finds both logins.
    #[test]
    fn a_few_pieces_find_the_names_that_hold_them_all() {
        let found = find("workspace j", NAMES);
        assert_eq!(
            found,
            [
                "workspace.google.com/jm@memorici.de",
                "workspace.google.com/jons@geosurge.ai",
                "workspace.google.com/jm@memorici.de/rclone",
                // `workspace` sits in the middle of a word here: last.
                "geosurgeworkspace.slack.com/2fa/jons@geosurge.ai",
            ]
        );
        assert_eq!(find("J  WorkSpace", NAMES), found, "order and case of the terms do not matter");
    }

    #[test]
    fn no_terms_find_every_name_as_given() {
        assert_eq!(find("", NAMES), NAMES);
        assert_eq!(find("   ", NAMES), NAMES);
    }

    #[test]
    fn a_piece_that_begins_a_part_comes_before_one_inside_a_word() {
        // `jane` begins the account of github.com and a word of the other.
        assert_eq!(
            find("jane", NAMES),
            ["github.com/jane/recovery", "accounts.google.com/jane@example.com"]
        );
    }

    /// Gaps are a fallback: one exact find anywhere keeps loose ones out.
    #[test]
    fn letters_in_order_are_tried_only_when_no_piece_is_found() {
        assert_eq!(find("github", NAMES), ["github.com/jane/recovery"]);
        // No name holds `gthb` or `wrkspc` as a piece.
        assert_eq!(find("gthb", NAMES), ["github.com/jane/recovery"]);
        let loose = find("wrkspc info", NAMES);
        assert_eq!(loose, ["workspace.google.com/info@memorici.de"]);
        assert!(find("zzz", NAMES).is_empty());
    }

    #[test]
    fn a_tighter_fit_comes_first_among_loose_finds() {
        let names = ["a-x-b-x-c/long", "abc/short", "ab-c/mid"];
        assert_eq!(find("abc x", names), ["a-x-b-x-c/long"], "exact pieces of both terms exist nowhere else");
        assert_eq!(find("acq", names), [] as [&str; 0]);
        assert_eq!(find("ac", ["a--c", "abc", "ac"]), ["ac"], "an exact piece shuts the loose ones out");
        assert_eq!(find("abd", ["a-b-d", "ab-d", "abxd"]), ["ab-d", "abxd", "a-b-d"]);
    }
}
