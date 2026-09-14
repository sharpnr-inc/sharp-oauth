//! OAuth scopes.
//!
//! A scope is a permission a client asks for, e.g. `email`. On the wire a
//! request carries several scopes as one space-delimited string:
//! `scope=openid profile email`.
//!
//! Scopes are *data* (the registry lives in the `oauth_scopes` table) but a
//! few have built-in behaviour, so they get constants here:
//!
//! | Scope            | Effect                                                  |
//! |------------------|---------------------------------------------------------|
//! | `openid`         | Makes the request OpenID Connect: an ID token is issued |
//! | `profile`        | UserInfo returns `name`                                 |
//! | `email`          | UserInfo returns `email` and `email_verified`           |
//! | `offline_access` | A refresh token is issued                               |

use std::{collections::BTreeSet, fmt};

pub const OPENID: &str = "openid";
pub const PROFILE: &str = "profile";
pub const EMAIL: &str = "email";
pub const OFFLINE_ACCESS: &str = "offline_access";

/// A de-duplicated set of scope names.
///
/// Backed by a `BTreeSet` so the string form is always sorted, which makes
/// stored values and test assertions deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeSet(BTreeSet<String>);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    #[error("scope must not be empty")]
    Empty,
    #[error("scope contains characters that are not allowed")]
    InvalidCharacters,
}

impl ScopeSet {
    /// Parses a space-delimited scope string.
    ///
    /// RFC 6749 section 3.3 allows only printable ASCII except space, `"` and
    /// `\` inside a scope name. Anything else is rejected rather than
    /// silently dropped.
    pub fn parse(raw: &str) -> Result<Self, ScopeError> {
        let mut scopes = BTreeSet::new();
        for token in raw.split(' ').filter(|token| !token.is_empty()) {
            let valid = token
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b));
            if !valid {
                return Err(ScopeError::InvalidCharacters);
            }
            scopes.insert(token.to_owned());
        }
        if scopes.is_empty() {
            return Err(ScopeError::Empty);
        }
        Ok(Self(scopes))
    }

    pub fn contains(&self, scope: &str) -> bool {
        self.0.contains(scope)
    }

    /// True if every scope in `self` is also in `other`.
    pub fn is_subset_of(&self, other: &ScopeSet) -> bool {
        self.0.is_subset(&other.0)
    }

    /// All scopes in either set.
    pub fn union(&self, other: &ScopeSet) -> ScopeSet {
        ScopeSet(self.0.union(&other.0).cloned().collect())
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    pub fn to_vec(&self) -> Vec<String> {
        self.0.iter().cloned().collect()
    }
}

impl FromIterator<String> for ScopeSet {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        ScopeSet(iter.into_iter().collect())
    }
}

/// Formats as the space-delimited wire format, e.g. `"email openid"`.
impl fmt::Display for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined: Vec<&str> = self.iter().collect();
        f.write_str(&joined.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_deduplicates_and_sorts() {
        let scopes = ScopeSet::parse("profile openid  profile email").unwrap();
        assert_eq!(scopes.to_string(), "email openid profile");
    }

    #[test]
    fn empty_scope_is_rejected() {
        assert_eq!(ScopeSet::parse(""), Err(ScopeError::Empty));
        assert_eq!(ScopeSet::parse("   "), Err(ScopeError::Empty));
    }

    #[test]
    fn forbidden_characters_are_rejected() {
        assert_eq!(
            ScopeSet::parse("open\"id"),
            Err(ScopeError::InvalidCharacters)
        );
        assert_eq!(
            ScopeSet::parse("open\\id"),
            Err(ScopeError::InvalidCharacters)
        );
        assert_eq!(
            ScopeSet::parse("openid\tprofile"),
            Err(ScopeError::InvalidCharacters)
        );
    }

    #[test]
    fn subset_and_union() {
        let small = ScopeSet::parse("openid").unwrap();
        let big = ScopeSet::parse("openid email").unwrap();
        assert!(small.is_subset_of(&big));
        assert!(!big.is_subset_of(&small));
        assert_eq!(small.union(&big), big);
    }
}
