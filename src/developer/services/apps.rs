//! A developer's applications: list, create, edit, rotate secret, delete.
//!
//! The OAuth rules for a client (redirect URL policy, scope registry, secret
//! hashing) live in [`crate::oauth::services::client`]. This service adds
//! what only the portal needs: ownership, a per-user limit, and error
//! messages written for a person rather than a log.

use sea_orm::{DatabaseConnection, DbErr};

use crate::{
    authentication::services::user::User,
    developer::dtos::AppForm,
    oauth::{
        repo::clients,
        services::client::{
            self, ClientDetails, MAX_NAME_LEN, MAX_REDIRECT_URIS, NewClient, OAuthClient,
            RegisteredClient, RegistrationError,
        },
    },
};

/// How many applications one user may register.
pub const MAX_APPS_PER_USER: u64 = 25;

/// Why saving an application failed. The messages are shown on the page.
#[derive(Debug, thiserror::Error)]
pub enum AppFormError {
    #[error(
        "You can register at most {MAX_APPS_PER_USER} applications. Delete one to add another."
    )]
    LimitReached,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Database(#[from] DbErr),
}

impl From<RegistrationError> for AppFormError {
    fn from(err: RegistrationError) -> Self {
        let message = match err {
            RegistrationError::Database(err) => return AppFormError::Database(err),
            RegistrationError::EmptyName => "Please enter an application name.".to_owned(),
            RegistrationError::NameTooLong => {
                format!("The application name must be at most {MAX_NAME_LEN} characters.")
            }
            RegistrationError::NoRedirectUris => "Add at least one redirect URL.".to_owned(),
            RegistrationError::TooManyRedirectUris => {
                format!("You can register at most {MAX_REDIRECT_URIS} redirect URLs.")
            }
            RegistrationError::InvalidRedirectUri { uri, reason } => {
                format!("Redirect URL {uri} {reason}.")
            }
            RegistrationError::NoScopes => "Choose at least one scope.".to_owned(),
            RegistrationError::UnknownScopes(scopes) => {
                format!("Unknown scopes: {}.", scopes.join(", "))
            }
        };
        AppFormError::Invalid(message)
    }
}

/// The user's applications, newest first.
pub async fn list(db: &DatabaseConnection, owner: &User) -> Result<Vec<OAuthClient>, DbErr> {
    clients::list_by_owner(db, owner.id).await
}

/// One of the user's applications. `None` if it does not exist *or* belongs
/// to someone else; callers answer both with the same 404.
pub async fn find(
    db: &DatabaseConnection,
    owner: &User,
    client_id: &str,
) -> Result<Option<OAuthClient>, DbErr> {
    clients::find_owned(db, owner.id, client_id).await
}

pub async fn create(
    db: &DatabaseConnection,
    owner: &User,
    form: &AppForm,
) -> Result<RegisteredClient, AppFormError> {
    // Checked before inserting, so two simultaneous requests could each pass
    // it and end one over the limit. That is harmless: the limit only exists
    // to stop runaway scripts, not to be exact.
    if clients::count_by_owner(db, owner.id).await? >= MAX_APPS_PER_USER {
        return Err(AppFormError::LimitReached);
    }

    let registered = client::register(
        db,
        NewClient {
            name: form.name.clone(),
            redirect_uris: form.redirect_uri_list(),
            scopes: form.scope_set(),
            confidential: !form.is_public(),
            owner_user_id: Some(owner.id),
        },
    )
    .await?;
    Ok(registered)
}

pub async fn update(
    db: &DatabaseConnection,
    app: &OAuthClient,
    form: &AppForm,
) -> Result<(), AppFormError> {
    client::update_details(
        db,
        app,
        ClientDetails {
            name: form.name.clone(),
            redirect_uris: form.redirect_uri_list(),
            scopes: form.scope_set(),
        },
    )
    .await?;
    Ok(())
}

/// Issues a new secret; the old one stops working at once. `None` for a
/// public application, which has no secret.
pub async fn rotate_secret(
    db: &DatabaseConnection,
    app: &OAuthClient,
) -> Result<Option<String>, DbErr> {
    client::rotate_secret(db, app).await
}

pub async fn delete(db: &DatabaseConnection, app: &OAuthClient) -> Result<(), DbErr> {
    client::delete(db, app).await
}
