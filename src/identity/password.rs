//! Password hashing with Argon2id.
//!
//! Passwords are never stored. We store an Argon2id *PHC string* such as
//! `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`, which records the algorithm,
//! its parameters and a random per-password salt, so verification needs
//! nothing but the string itself.
//!
//! Argon2 is intentionally slow and memory hungry. Running it directly on an
//! async task would block one of Tokio's worker threads for tens of
//! milliseconds, stalling unrelated requests. Both functions therefore move
//! the work onto Tokio's blocking thread pool with `spawn_blocking`.

use std::sync::LazyLock;

use anyhow::{Context, Result, anyhow};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};

/// Hashes a password with Argon2id and a fresh random salt.
pub async fn hash_password(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|hash| hash.to_string())
            .map_err(|err| anyhow!("argon2 hashing failed: {err}"))
    })
    .await
    .context("password hashing task panicked")?
}

/// Checks a password against a stored PHC string.
///
/// Returns `Ok(false)` for a wrong password and `Err` only when the stored
/// hash itself is unusable.
pub async fn verify_password(password: String, password_hash: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || {
        let parsed = PasswordHash::new(&password_hash)
            .map_err(|err| anyhow!("stored password hash is malformed: {err}"))?;
        match Argon2::default().verify_password(password.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
            Err(err) => Err(anyhow!("argon2 verification failed: {err}")),
        }
    })
    .await
    .context("password verification task panicked")?
}

/// A valid hash of a random password, used when the email is unknown.
///
/// Without it, sign-in for an unknown email would return instantly while a
/// known email takes ~50ms to verify, letting an attacker discover which
/// emails have accounts just by timing responses.
pub static DUMMY_PASSWORD_HASH: LazyLock<String> = LazyLock::new(|| {
    Argon2::default()
        .hash_password(crate::secret::generate_token().as_bytes())
        .expect("hashing a random password cannot fail")
        .to_string()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn correct_password_verifies_and_wrong_one_does_not() {
        let hash = hash_password("correct horse battery staple".into())
            .await
            .unwrap();

        assert!(hash.starts_with("$argon2id$"));
        assert!(
            verify_password("correct horse battery staple".into(), hash.clone())
                .await
                .unwrap()
        );
        assert!(!verify_password("wrong".into(), hash).await.unwrap());
    }

    #[tokio::test]
    async fn same_password_gets_different_salts() {
        let a = hash_password("password123".into()).await.unwrap();
        let b = hash_password("password123".into()).await.unwrap();
        assert_ne!(a, b);
    }
}
