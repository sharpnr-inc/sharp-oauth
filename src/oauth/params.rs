//! Parsing OAuth request parameters.
//!
//! Axum can deserialize a query string straight into a struct, but that loses
//! two things OAuth cares about:
//!
//! * RFC 6749 section 3.1: "Request and response parameters MUST NOT be
//!   included more than once." A duplicated `redirect_uri` is a classic way
//!   to confuse servers that validate one copy and use another.
//! * Control over the error response. A deserialization failure in Axum is a
//!   plain-text 400, but OAuth needs structured errors.
//!
//! So handlers extract raw `Vec<(String, String)>` pairs and pass them to
//! [`Params::from_pairs`], which rejects duplicates.

use std::collections::HashMap;

/// A set of request parameters with every name appearing at most once.
#[derive(Debug, Default, Clone)]
pub struct Params(HashMap<String, String>);

/// A parameter name that appeared more than once.
#[derive(Debug, PartialEq, Eq)]
pub struct DuplicateParameter(pub String);

impl Params {
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Result<Self, DuplicateParameter> {
        let mut map = HashMap::with_capacity(pairs.len());
        for (name, value) in pairs {
            if map.contains_key(&name) {
                return Err(DuplicateParameter(name));
            }
            map.insert(name, value);
        }
        Ok(Self(map))
    }

    /// Returns a parameter's value.
    ///
    /// RFC 6749 section 3.1 says parameters "sent without a value MUST be
    /// treated as if they were omitted", so an empty value returns `None`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    /// Like [`Params::get`] but returns an owned `String`.
    pub fn take(&self, name: &str) -> Option<String> {
        self.get(name).map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn duplicate_parameters_are_rejected() {
        let result = Params::from_pairs(pairs(&[("redirect_uri", "a"), ("redirect_uri", "b")]));
        assert_eq!(
            result.unwrap_err(),
            DuplicateParameter("redirect_uri".into())
        );
    }

    #[test]
    fn empty_values_are_treated_as_missing() {
        let params = Params::from_pairs(pairs(&[("state", ""), ("scope", "openid")])).unwrap();
        assert_eq!(params.get("state"), None);
        assert_eq!(params.get("scope"), Some("openid"));
    }
}
