//! A column type for stored secret hashes.
//!
//! SeaORM requires every `Model` to implement `Debug`, and a `Model` has a
//! field for every column, including the SHA-256 hashes of session tokens,
//! authorization codes, refresh tokens and client secrets. A derived `Debug`
//! would print those the first time someone logs a row while debugging.
//!
//! So the hash columns use this newtype instead of `String`. It behaves like
//! a string in queries, but prints as `<redacted>`:
//!
//! ```text
//! Model { id: 0199…, token_hash: <redacted>, family_id: 0199…, … }
//! ```
//!
//! This is defence in depth, not the main protection: the value is already a
//! hash, so it cannot be used as a token even if it did leak.

use std::fmt;

use sea_orm::DeriveValueType;

/// `SHA-256(secret)`, base64url encoded. See [`crate::shared::secret`].
#[derive(Clone, PartialEq, Eq, Hash, DeriveValueType)]
pub struct SecretHash(String);

impl SecretHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretHash {
    fn from(hash: String) -> Self {
        Self(hash)
    }
}

impl From<&str> for SecretHash {
    fn from(hash: &str) -> Self {
        Self(hash.to_owned())
    }
}

impl fmt::Debug for SecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_the_hash() {
        let hash = SecretHash::from("s3cr3t-hash-value");
        assert_eq!(format!("{hash:?}"), "<redacted>");
        assert!(!format!("{hash:?}").contains("s3cr3t"));
        assert_eq!(hash.as_str(), "s3cr3t-hash-value");
    }
}
