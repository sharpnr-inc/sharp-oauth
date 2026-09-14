//! Security primitives shared by the whole server.
//!
//! Sharp-OAuth hands out several kinds of *opaque secrets*: session tokens,
//! authorization codes, refresh tokens, client secrets and CSRF tokens. They
//! all follow the same recipe:
//!
//! 1. **Generate** 32 bytes (256 bits) from a cryptographically secure RNG.
//!    That is far beyond brute-force range. A UUID is *not* a substitute:
//!    UUID v7 is mostly a timestamp and is designed to be predictable.
//! 2. **Encode** as base64url without padding, so the value is safe in URLs,
//!    form bodies and cookies without further escaping.
//! 3. **Store only a SHA-256 hash** in the database. If the database leaks,
//!    the attacker gets hashes that cannot be used as tokens.
//!
//! Why SHA-256 here but Argon2 for passwords? Argon2 is deliberately slow to
//! make guessing *low-entropy* human passwords expensive. Our tokens have 256
//! bits of entropy, so guessing is already impossible and a fast hash lets us
//! look tokens up by hash with a normal database index.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Number of random bytes in every generated secret.
const SECRET_BYTES: usize = 32;

/// Generates a new random secret, base64url encoded (43 characters).
pub fn generate_token() -> String {
    let mut bytes = [0u8; SECRET_BYTES];
    // `rand::rng()` is a CSPRNG (ChaCha) seeded from the operating system.
    rand::rng().fill_bytes(&mut bytes);
    base64url(&bytes)
}

/// Hashes a secret for storage or lookup: `base64url(SHA-256(secret))`.
pub fn hash_token(token: &str) -> String {
    base64url(&sha256(token.as_bytes()))
}

/// SHA-256 digest as a plain byte array.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// base64url encoding without `=` padding (RFC 4648 section 5).
pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Compares two byte strings in constant time.
///
/// A normal `==` stops at the first differing byte, so response timing can
/// reveal how much of a guess was correct. Use this whenever one side is a
/// secret (or the hash of one) supplied by the caller.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Lengths are not secret; `ct_eq` on slices returns false for a mismatch.
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_43_url_safe_characters_and_unique() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 43);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(a, b);
    }

    #[test]
    fn hashing_is_deterministic_and_hides_the_input() {
        let token = generate_token();
        assert_eq!(hash_token(&token), hash_token(&token));
        assert_ne!(hash_token(&token), token);
    }

    #[test]
    fn constant_time_eq_matches_normal_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
