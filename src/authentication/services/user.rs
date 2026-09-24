//! Sharpnr user accounts: sign-up and password authentication.

use chrono::Utc;
use sea_orm::{DatabaseConnection, SqlErr};
use uuid::Uuid;

use crate::{
    authentication::{repo::users, services::password},
    shared::{database::SecretHash, error::AppError},
};

/// A Sharpnr account.
///
/// This is the SeaORM model for the `users` table
/// ([`crate::authentication::models::users`]), used directly as the domain type so a
/// column is described in exactly one place. `password_hash` is a
/// [`SecretHash`], so `{:?}` prints `<redacted>`.
pub use crate::authentication::models::users::Model as User;

/// Input for [`sign_up`]. Deliberately has no `Debug` (contains a password).
pub struct NewAccount {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

/// Why a sign-up was refused. The messages are safe to show to the user.
#[derive(Debug, thiserror::Error)]
pub enum SignUpError {
    #[error("Please enter a valid email address.")]
    InvalidEmail,
    #[error("Password must be between {MIN_PASSWORD_CHARS} and {MAX_PASSWORD_BYTES} characters.")]
    InvalidPassword,
    #[error("Display name must be at most {MAX_DISPLAY_NAME_CHARS} characters.")]
    InvalidDisplayName,
    #[error("An account with this email already exists.")]
    EmailTaken,
    #[error(transparent)]
    Internal(#[from] AppError),
}

pub const MIN_PASSWORD_CHARS: usize = 8;
/// Upper bound so a multi-megabyte "password" cannot tie up Argon2.
pub const MAX_PASSWORD_BYTES: usize = 1024;
pub const MAX_DISPLAY_NAME_CHARS: usize = 100;

/// Creates a new account.
pub async fn sign_up(db: &DatabaseConnection, account: NewAccount) -> Result<User, SignUpError> {
    let email = normalize_email(&account.email).ok_or(SignUpError::InvalidEmail)?;

    if account.password.chars().count() < MIN_PASSWORD_CHARS
        || account.password.len() > MAX_PASSWORD_BYTES
    {
        return Err(SignUpError::InvalidPassword);
    }

    let display_name = account
        .display_name
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    if display_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > MAX_DISPLAY_NAME_CHARS)
    {
        return Err(SignUpError::InvalidDisplayName);
    }

    let password_hash = password::hash_password(account.password)
        .await
        .map_err(AppError::from)?;

    let now = Utc::now();
    let user = User {
        id: Uuid::now_v7(),
        email,
        password_hash: SecretHash::from(password_hash),
        display_name,
        email_verified: false,
        created_at: now,
        updated_at: now,
    };

    match users::insert(db, &user).await {
        Ok(()) => {
            tracing::info!(target: "audit", event = "user_signed_up", user_id = %user.id);
            Ok(user)
        }
        // The UNIQUE constraint is the source of truth. Checking "does this
        // email exist?" first would race with a concurrent sign-up.
        Err(err) => match err.sql_err() {
            Some(SqlErr::UniqueConstraintViolation(_)) => Err(SignUpError::EmailTaken),
            _ => Err(AppError::from(err).into()),
        },
    }
}

/// Verifies an email and password. Returns `None` if either is wrong.
///
/// The caller must show the same message in both cases ("invalid email or
/// password") so the response does not reveal whether an account exists.
pub async fn authenticate(
    db: &DatabaseConnection,
    email: &str,
    password: String,
) -> Result<Option<User>, AppError> {
    let user = match normalize_email(email) {
        Some(email) => users::find_by_email(db, &email).await?,
        None => None,
    };

    // Always run Argon2, even for unknown emails, so timing is the same.
    let hash = match &user {
        Some(user) => user.password_hash.as_str().to_owned(),
        None => password::DUMMY_PASSWORD_HASH.clone(),
    };
    let password_ok = password::verify_password(password, hash).await?;

    match user {
        Some(user) if password_ok => {
            tracing::info!(target: "audit", event = "user_signed_in", user_id = %user.id);
            Ok(Some(user))
        }
        _ => {
            tracing::info!(target: "audit", event = "sign_in_failed");
            Ok(None)
        }
    }
}

/// Trims and lower-cases an email, returning `None` if it is clearly invalid.
///
/// This is intentionally a light sanity check, not full RFC 5322 parsing.
/// The only way to truly validate an address is to send mail to it.
pub fn normalize_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    let (local, domain) = email.split_once('@')?;

    let valid = !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && email.len() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c.is_control());

    valid.then_some(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_trimmed_and_lowercased() {
        assert_eq!(
            normalize_email("  Kashif@Sharpnr.COM ").as_deref(),
            Some("kashif@sharpnr.com")
        );
    }

    #[test]
    fn obviously_invalid_emails_are_rejected() {
        for email in [
            "",
            "no-at-sign",
            "@sharpnr.com",
            "a@nodot",
            "a@b@c.com",
            "a b@c.com",
            "a@.com",
        ] {
            assert_eq!(normalize_email(email), None, "{email} should be rejected");
        }
    }

    #[test]
    fn debug_output_does_not_contain_password_hash() {
        let user = User {
            id: Uuid::now_v7(),
            email: "a@b.com".into(),
            password_hash: "$argon2id$secret".into(),
            display_name: None,
            email_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(!format!("{user:?}").contains("argon2id"));
    }
}
