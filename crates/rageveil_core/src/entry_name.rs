//! What an entry's path says, read by the store's naming rule.
//!
//! AI-generated module: model Claude Opus 5.5 (`claude-opus-5-5`); reasoning
//! effort unavailable (not exposed by the harness).
//!
//! **Draft contract.** An [`EntryPath`] is free text: the store hashes it
//! and never looks inside. The people who use the store name entries by
//! where they are used:
//!
//! ```text
//! SERVICE/ACCOUNT[/PURPOSE][/MISC]*
//! accounts.google.com/jane@example.com            the password itself
//! accounts.google.com/jane@example.com/recovery   what the entry is, when not the password
//! companieshouse.gov.uk/12345678/auth-code
//! revolut.com/card/agent/number                   a card: ACCOUNT `card`, PURPOSE its label
//! ```
//!
//! SERVICE is the host of the page that asks for the secret, ACCOUNT the
//! name it signs in with, PURPOSE what the entry is when it is not the
//! password, and any further parts are left to the person. The fields are
//! positional; nothing here knows what a purpose means.
//!
//! An [`EntryName`] is a path that fits that rule, with every part safe as
//! a file name, so that a tool may one day lay entries out as files, and a
//! name pasted into a shell or a URL cannot surprise anyone:
//!
//! * there are at least two parts, and none is empty;
//! * a part uses only ASCII letters, digits and `. _ - @ +` — no space, no
//!   control character, no `/` (that is what separates parts), nothing a
//!   shell or another file system treats specially, and no non-ASCII
//!   letter, which macOS would store under a different byte spelling;
//! * a part is not `.` or `..`, does not start or end with a dot (hidden
//!   files; Windows drops a trailing dot), does not start with `-` (it
//!   would read as an option), and is at most 255 bytes;
//! * SERVICE is a host name: dot-separated labels of lowercase letters,
//!   digits and hyphens, no label starting or ending with a hyphen, at
//!   most 63 bytes a label and 253 in all. Lowercase keeps one spelling
//!   per host.
//!
//! New entries must fit ([`crate::commands::insert::insert_checked`]).
//! Entries made before the rule keep working under the name they have;
//! [`crate::commands::names::unfit_names`] lists them.

use crate::types::EntryPath;
use std::fmt;

/// Where a part sits in a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Service,
    Account,
    Purpose,
    /// A part after PURPOSE; `0` is the first of them (the fourth part).
    Misc(usize),
}

impl Field {
    fn at(position: usize) -> Self {
        match position {
            0 => Self::Service,
            1 => Self::Account,
            2 => Self::Purpose,
            n => Self::Misc(n - 3),
        }
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service => f.write_str("SERVICE"),
            Self::Account => f.write_str("ACCOUNT"),
            Self::Purpose => f.write_str("PURPOSE"),
            Self::Misc(n) => write!(f, "part {}", n + 4),
        }
    }
}

/// Why a path is not an [`EntryName`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("names only a service; name an entry SERVICE/ACCOUNT[/PURPOSE]")]
    NoAccount,
    #[error("has parts after PURPOSE but no PURPOSE")]
    MiscWithoutPurpose,
    #[error("{field} is empty")]
    Empty { field: Field },
    #[error("{field} is longer than 255 bytes")]
    TooLong { field: Field },
    #[error("{field} has a control character")]
    ControlCharacter { field: Field },
    #[error("{field} is `.` or `..`")]
    DotPart { field: Field },
    #[error("{field} starts or ends with a dot")]
    EdgeDot { field: Field },
    #[error("{field} starts with `-`")]
    LeadingDash { field: Field },
    #[error("{field} has {character:?}; use letters, digits and . _ - @ +")]
    UnsafeCharacter { field: Field, character: char },
    #[error(
        "SERVICE is not a host name: lowercase letters, digits and hyphens \
         in labels separated by dots"
    )]
    ServiceNotHost,
}

impl NameError {
    /// The part at fault, when there is one.
    pub fn field(&self) -> Option<Field> {
        match self {
            Self::NoAccount => Some(Field::Account),
            Self::MiscWithoutPurpose => Some(Field::Purpose),
            Self::ServiceNotHost => Some(Field::Service),
            Self::Empty { field }
            | Self::TooLong { field }
            | Self::ControlCharacter { field }
            | Self::DotPart { field }
            | Self::EdgeDot { field }
            | Self::LeadingDash { field }
            | Self::UnsafeCharacter { field, .. } => Some(*field),
        }
    }
}

const MAX_PART: usize = 255;
const MAX_HOST: usize = 253;
const MAX_LABEL: usize = 63;

fn safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '+')
}

/// Check one part as it would stand at `field`. An app's form can call
/// this on each field as it is typed.
pub fn check_part(field: Field, part: &str) -> Result<(), NameError> {
    if part.is_empty() {
        return Err(NameError::Empty { field });
    }
    if part.len() > MAX_PART {
        return Err(NameError::TooLong { field });
    }
    if part.chars().any(char::is_control) {
        return Err(NameError::ControlCharacter { field });
    }
    if part == "." || part == ".." {
        return Err(NameError::DotPart { field });
    }
    if part.starts_with('.') || part.ends_with('.') {
        return Err(NameError::EdgeDot { field });
    }
    if part.starts_with('-') {
        return Err(NameError::LeadingDash { field });
    }
    if let Some(character) = part.chars().find(|c| !safe_char(*c)) {
        return Err(NameError::UnsafeCharacter { field, character });
    }
    if field == Field::Service && !is_host(part) {
        return Err(NameError::ServiceNotHost);
    }
    Ok(())
}

fn is_host(s: &str) -> bool {
    s.len() <= MAX_HOST
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// The service a path names: its first part. The same reading for every
/// path, whether or not it fits the rule, so `rotate` works on old names.
pub fn service_part(path: &str) -> &str {
    path.split('/').next().unwrap_or(path)
}

/// A path that fits `SERVICE/ACCOUNT[/PURPOSE][/MISC]*`, every part safe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryName {
    service: String,
    account: String,
    purpose: Option<String>,
    misc: Vec<String>,
}

impl EntryName {
    /// Read a path. Parts are separated by `/`.
    pub fn parse(path: &str) -> Result<Self, NameError> {
        let parts: Vec<&str> = path.split('/').collect();
        for (position, part) in parts.iter().enumerate() {
            check_part(Field::at(position), part)?;
        }
        match parts.as_slice() {
            [service, account, rest @ ..] => Ok(Self {
                service: (*service).to_owned(),
                account: (*account).to_owned(),
                purpose: rest.first().map(|p| (*p).to_owned()),
                misc: rest.iter().skip(1).map(|p| (*p).to_owned()).collect(),
            }),
            _ => Err(NameError::NoAccount),
        }
    }

    /// Build a name from its fields, as a form holds them. An empty
    /// `purpose` is no purpose.
    pub fn from_fields(
        service: &str,
        account: &str,
        purpose: Option<&str>,
        misc: &[String],
    ) -> Result<Self, NameError> {
        let purpose = purpose.filter(|p| !p.is_empty());
        if purpose.is_none() && !misc.is_empty() {
            return Err(NameError::MiscWithoutPurpose);
        }
        check_part(Field::Service, service)?;
        check_part(Field::Account, account)?;
        if let Some(p) = purpose {
            check_part(Field::Purpose, p)?;
        }
        for (n, part) in misc.iter().enumerate() {
            check_part(Field::Misc(n), part)?;
        }
        Ok(Self {
            service: service.to_owned(),
            account: account.to_owned(),
            purpose: purpose.map(str::to_owned),
            misc: misc.to_vec(),
        })
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    pub fn misc(&self) -> &[String] {
        &self.misc
    }

    /// The path this name is stored under.
    pub fn path(&self) -> EntryPath {
        EntryPath::new(self.to_string())
    }
}

impl fmt::Display for EntryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.service, self.account)?;
        for part in self.purpose.iter().chain(self.misc.iter()) {
            write!(f, "/{part}")?;
        }
        Ok(())
    }
}

impl TryFrom<&EntryPath> for EntryName {
    type Error = NameError;

    fn try_from(path: &EntryPath) -> Result<Self, Self::Error> {
        Self::parse(path.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn fields(path: &str) -> (String, String, Option<String>, Vec<String>) {
        let n = EntryName::parse(path).expect(path);
        (
            n.service().to_owned(),
            n.account().to_owned(),
            n.purpose().map(str::to_owned),
            n.misc().to_vec(),
        )
    }

    #[test]
    fn the_examples_of_the_naming_rule_fit() {
        assert_eq!(
            fields("account.proton.me/jane@example.com"),
            ("account.proton.me".into(), "jane@example.com".into(), None, vec![])
        );
        assert_eq!(
            fields("account.proton.me/jane@example.com/recovery").2.as_deref(),
            Some("recovery")
        );
        assert_eq!(
            fields("companieshouse.gov.uk/12345678/auth-code").2.as_deref(),
            Some("auth-code")
        );
        assert_eq!(
            fields("revolut.com/card/agent/number"),
            (
                "revolut.com".into(),
                "card".into(),
                Some("agent".into()),
                vec!["number".into()]
            )
        );
        assert_eq!(fields("db/prod").0, "db", "a single-label host fits");
        assert_eq!(fields("github.com/jane+bot@example.com/2fa/a_b").3, vec!["a_b"]);
    }

    #[test]
    fn a_name_prints_back_as_its_path() {
        for p in ["a.example/b", "a.example/b/c", "a.example/b/c/d/e"] {
            assert_eq!(EntryName::parse(p).unwrap().to_string(), p);
            assert_eq!(EntryName::parse(p).unwrap().path(), EntryPath::new(p));
        }
    }

    #[test]
    fn what_is_refused_and_why() {
        let cases: &[(&str, NameError)] = &[
            ("github.com", NameError::NoAccount),
            ("", NameError::Empty { field: Field::Service }),
            ("/jane", NameError::Empty { field: Field::Service }),
            ("x.com//jane", NameError::Empty { field: Field::Account }),
            ("x.com/jane/", NameError::Empty { field: Field::Purpose }),
            ("x.com/jane/a/", NameError::Empty { field: Field::Misc(0) }),
            ("x.com/..", NameError::DotPart { field: Field::Account }),
            ("x.com/jane/.", NameError::DotPart { field: Field::Purpose }),
            ("x.com/.env", NameError::EdgeDot { field: Field::Account }),
            ("x.com/jane.", NameError::EdgeDot { field: Field::Account }),
            ("x.com/-rf", NameError::LeadingDash { field: Field::Account }),
            ("x.com/ja\tne", NameError::ControlCharacter { field: Field::Account }),
            ("x.com/ja\u{7f}ne", NameError::ControlCharacter { field: Field::Account }),
            (
                "x.com/jane doe",
                NameError::UnsafeCharacter { field: Field::Account, character: ' ' },
            ),
            (
                "x.com/jane/a:b",
                NameError::UnsafeCharacter { field: Field::Purpose, character: ':' },
            ),
            (
                "x.com/a/b/c#d",
                NameError::UnsafeCharacter { field: Field::Misc(0), character: '#' },
            ),
            (
                "x.com/j\\ane",
                NameError::UnsafeCharacter { field: Field::Account, character: '\\' },
            ),
            (
                "x.com/jürgen",
                NameError::UnsafeCharacter { field: Field::Account, character: 'ü' },
            ),
            ("GitHub.com/jane", NameError::ServiceNotHost),
            ("git_hub.com/jane", NameError::ServiceNotHost),
            ("a-.example/jane", NameError::ServiceNotHost),
            ("a..example/jane", NameError::ServiceNotHost),
            ("host@x/jane", NameError::ServiceNotHost),
        ];
        for (path, want) in cases {
            assert_eq!(EntryName::parse(path).as_ref(), Err(want), "{path:?}");
        }
    }

    #[test]
    fn lengths_are_bounded() {
        let long = "a".repeat(256);
        assert_eq!(
            EntryName::parse(&format!("x.com/{long}")),
            Err(NameError::TooLong { field: Field::Account })
        );
        assert!(EntryName::parse(&format!("x.com/{}", "a".repeat(255))).is_ok());
        let label = "a".repeat(64);
        assert_eq!(EntryName::parse(&format!("{label}.com/j")), Err(NameError::ServiceNotHost));
        let host = vec!["a".repeat(63); 4].join("."); // 255 bytes
        assert_eq!(EntryName::parse(&format!("{host}/j")), Err(NameError::ServiceNotHost));
    }

    #[test]
    fn fields_build_the_same_name_as_the_path() {
        let built =
            EntryName::from_fields("x.com", "jane", Some("2fa"), &["a".to_owned()]).unwrap();
        assert_eq!(built, EntryName::parse("x.com/jane/2fa/a").unwrap());
        assert_eq!(
            EntryName::from_fields("x.com", "jane", Some(""), &[]).unwrap(),
            EntryName::parse("x.com/jane").unwrap()
        );
        assert_eq!(
            EntryName::from_fields("x.com", "jane", None, &["a".to_owned()]),
            Err(NameError::MiscWithoutPurpose)
        );
        assert_eq!(
            EntryName::from_fields("x.com", "ja/ne", None, &[]),
            Err(NameError::UnsafeCharacter { field: Field::Account, character: '/' })
        );
    }

    #[test]
    fn the_service_part_agrees_with_the_parsed_service() {
        for p in ["accounts.google.com/jane/recovery", "db/prod", "x.com/a/b/c"] {
            assert_eq!(service_part(p), EntryName::parse(p).unwrap().service());
        }
        assert_eq!(service_part("legacy"), "legacy");
    }
}
