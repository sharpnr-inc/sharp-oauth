//! PKCE: Proof Key for Code Exchange ([RFC 7636]).
//!
//! ## The attack PKCE prevents
//!
//! An authorization code travels through the browser in a redirect URL. A
//! malicious app on the same phone, a leaky proxy log or browser history can
//! see it. Without PKCE, anyone holding the code (and, for public clients,
//! the public `client_id`) can exchange it for tokens.
//!
//! ## How it works
//!
//! 1. The client invents a random `code_verifier` and keeps it private.
//! 2. It sends `code_challenge = BASE64URL(SHA256(code_verifier))` with the
//!    authorization request. We store the challenge with the code.
//! 3. At the token endpoint the client must send the original
//!    `code_verifier`. We hash it and compare it to the stored challenge.
//!
//! Someone who steals the code saw only the challenge, and SHA-256 cannot be
//! reversed, so the stolen code is useless to them.
//!
//! ## Policy
//!
//! Sharp-OAuth requires PKCE for **every** client (as OAuth 2.1 does) and
//! accepts only the `S256` method. The `plain` method sends the verifier
//! itself as the challenge, which defeats the purpose, so it is rejected
//! rather than offered as a downgrade.
//!
//! [RFC 7636]: https://www.rfc-editor.org/rfc/rfc7636

use crate::secret::{base64url, constant_time_eq, sha256};

/// The only code challenge method we accept.
pub const S256: &str = "S256";

/// An S256 challenge is base64url(32 bytes) = exactly 43 characters.
const S256_CHALLENGE_LEN: usize = 43;

/// RFC 7636 section 4.1: the verifier is 43 to 128 characters long.
const VERIFIER_MIN_LEN: usize = 43;
const VERIFIER_MAX_LEN: usize = 128;

/// Checks that a `code_challenge` is well-formed for S256.
pub fn is_valid_s256_challenge(challenge: &str) -> bool {
    challenge.len() == S256_CHALLENGE_LEN
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Checks that a `code_verifier` has the length and alphabet RFC 7636 requires.
///
/// Allowed characters are the "unreserved" URI characters `A-Z a-z 0-9 - . _ ~`.
pub fn is_valid_verifier(verifier: &str) -> bool {
    (VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Computes the S256 challenge for a verifier.
pub fn s256_challenge(verifier: &str) -> String {
    base64url(&sha256(verifier.as_bytes()))
}

/// Returns true if `verifier` is the pre-image of the stored `challenge`.
pub fn verify_s256(verifier: &str, challenge: &str) -> bool {
    is_valid_verifier(verifier)
        && constant_time_eq(s256_challenge(verifier).as_bytes(), challenge.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from RFC 7636 Appendix B.
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn matches_rfc_7636_test_vector() {
        assert_eq!(s256_challenge(RFC_VERIFIER), RFC_CHALLENGE);
        assert!(verify_s256(RFC_VERIFIER, RFC_CHALLENGE));
    }

    #[test]
    fn wrong_verifier_fails() {
        let wrong = "aBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(!verify_s256(wrong, RFC_CHALLENGE));
    }

    #[test]
    fn plain_method_style_verifier_equal_to_challenge_fails() {
        // A "plain" downgrade would send the challenge itself as the verifier.
        assert!(!verify_s256(RFC_CHALLENGE, RFC_CHALLENGE));
    }

    #[test]
    fn verifier_length_limits_are_enforced() {
        assert!(!is_valid_verifier(&"a".repeat(42)));
        assert!(is_valid_verifier(&"a".repeat(43)));
        assert!(is_valid_verifier(&"a".repeat(128)));
        assert!(!is_valid_verifier(&"a".repeat(129)));
        assert!(!is_valid_verifier(&format!("{}+", "a".repeat(43))));
    }

    #[test]
    fn challenge_format_is_checked() {
        assert!(is_valid_s256_challenge(RFC_CHALLENGE));
        assert!(!is_valid_s256_challenge("too-short"));
        assert!(!is_valid_s256_challenge(&format!(
            "{}=",
            &RFC_CHALLENGE[..42]
        )));
    }
}
