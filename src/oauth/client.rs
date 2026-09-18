//! OAuth clients: registration, redirect URI rules and client authentication.
//!
//! ## Confidential vs public clients
//!
//! * A **confidential** client runs on a server and can keep a secret. It gets
//!   a `client_secret` and must present it at the token endpoint.
//! * A **public** client (single-page app, mobile or desktop app) ships its
//!   code to users, so any "secret" inside it would be readable by anyone.
//!   It gets no secret and is protected by PKCE instead.
//!
//! ## Redirect URIs
//!
//! The redirect URI is where the authorization code is delivered. If an
//! attacker could choose it, they would receive the code. So:
//!
//! * URIs are registered up front, and requests must match one **exactly**
//!   (string equality, no prefix or "contains" matching; RFC 9700 §2.1).
//! * Registered URIs must be absolute, use `https` (or `http` on loopback for
//!   local development), and must not contain a fragment (RFC 6749 §3.1.2).

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

use crate::{
    config::is_loopback_host,
    db::{self, entities::SecretHash},
    error::AppError,
    oauth::{params::Params, scope::ScopeSet},
    secret::{constant_time_eq, generate_token, hash_token},
};

/// A registered application.
///
/// The SeaORM model for `oauth_clients`
/// ([`crate::db::entities::oauth_clients`]). `client_secret_hash` is a
/// [`SecretHash`], so `{:?}` prints `<redacted>`.
pub use crate::db::entities::oauth_clients::Model as OAuthClient;

impl OAuthClient {
    pub fn is_confidential(&self) -> bool {
        self.client_secret_hash.is_some()
    }

    pub fn is_active(&self) -> bool {
        self.disabled_at.is_none()
    }

    /// Exact, byte-for-byte redirect URI matching.
    pub fn has_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris
            .iter()
            .any(|registered| registered == redirect_uri)
    }

    pub fn allowed_scopes(&self) -> ScopeSet {
        self.allowed_scopes.iter().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Input for [`register`].
pub struct NewClient {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub scopes: ScopeSet,
    pub confidential: bool,
}

/// Result of a successful registration.
pub struct RegisteredClient {
    pub client: OAuthClient,
    /// The raw secret, for confidential clients. This is the only time it
    /// exists in plaintext: show it to the developer once, then drop it.
    pub client_secret: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("client name must not be empty")]
    EmptyName,
    #[error("at least one redirect URI is required")]
    NoRedirectUris,
    #[error("invalid redirect URI {uri:?}: {reason}")]
    InvalidRedirectUri { uri: String, reason: &'static str },
    #[error("unknown scopes: {0:?}")]
    UnknownScopes(Vec<String>),
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
}

/// Registers a new client.
pub async fn register(
    db: &DatabaseConnection,
    new: NewClient,
) -> Result<RegisteredClient, RegistrationError> {
    let name = new.name.trim().to_owned();
    if name.is_empty() {
        return Err(RegistrationError::EmptyName);
    }
    if new.redirect_uris.is_empty() {
        return Err(RegistrationError::NoRedirectUris);
    }
    for uri in &new.redirect_uris {
        validate_redirect_uri_for_registration(uri).map_err(|reason| {
            RegistrationError::InvalidRedirectUri {
                uri: uri.clone(),
                reason,
            }
        })?;
    }

    // Every scope must exist in the oauth_scopes registry.
    let requested = new.scopes.to_vec();
    let known = db::scopes::find_by_names(db, &requested).await?;
    let unknown: Vec<String> = requested
        .iter()
        .filter(|scope| !known.iter().any(|k| &k.name == *scope))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(RegistrationError::UnknownScopes(unknown));
    }

    // Prefixes make leaked credentials easy to recognise (e.g. by secret
    // scanners) and make it obvious which value is which.
    let client_secret = new
        .confidential
        .then(|| format!("sharp_secret_{}", generate_token()));
    let now = Utc::now();
    let client = OAuthClient {
        id: Uuid::now_v7(),
        client_id: format!("sharp_client_{}", &generate_token()[..24]),
        client_secret_hash: client_secret
            .as_deref()
            .map(|secret| SecretHash::from(hash_token(secret))),
        name,
        redirect_uris: new.redirect_uris,
        allowed_scopes: requested,
        created_at: now,
        updated_at: now,
        disabled_at: None,
    };

    db::clients::insert(db, &client).await?;
    tracing::info!(target: "audit", event = "client_registered", client_id = %client.client_id);

    Ok(RegisteredClient {
        client,
        client_secret,
    })
}

/// Rules for a redirect URI at registration time.
pub fn validate_redirect_uri_for_registration(uri: &str) -> Result<(), &'static str> {
    let url = url::Url::parse(uri).map_err(|_| "must be an absolute URL")?;

    if url.fragment().is_some() {
        return Err("must not contain a fragment (#...)");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials");
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(&url) => Ok(()),
        _ => Err("must use https (http is only allowed for localhost)"),
    }
}

// ---------------------------------------------------------------------------
// Client authentication (token and revocation endpoints)
// ---------------------------------------------------------------------------

/// Credentials a client presented, before they are checked.
///
/// No `Debug`: this holds a raw secret.
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
}

/// Collects client credentials from a request.
///
/// Supported methods (advertised in discovery as
/// `token_endpoint_auth_methods_supported`):
///
/// * `client_secret_basic`: `Authorization: Basic base64(id:secret)`
/// * `client_secret_post`: `client_id` and `client_secret` form fields
/// * `none`: only `client_id` (public clients)
///
/// RFC 6749 §2.3 forbids using more than one method in a single request.
pub fn extract_credentials(
    authorization_header: Option<&str>,
    params: &Params,
) -> Result<ClientCredentials, AppError> {
    let basic = match authorization_header {
        Some(header) if has_scheme(header, "Basic") => {
            Some(parse_basic_authorization(header).ok_or(AppError::InvalidClient)?)
        }
        _ => None,
    };

    match (basic, params.take("client_secret")) {
        (Some(_), Some(_)) => Err(AppError::InvalidRequest(
            "use only one client authentication method",
        )),
        (Some((client_id, client_secret)), None) => {
            // A client_id in the body is allowed but must agree with the header.
            if params.get("client_id").is_some_and(|id| id != client_id) {
                return Err(AppError::InvalidClient);
            }
            Ok(ClientCredentials {
                client_id,
                client_secret: Some(client_secret),
            })
        }
        (None, client_secret) => {
            let client_id = params.take("client_id").ok_or(AppError::InvalidClient)?;
            Ok(ClientCredentials {
                client_id,
                client_secret,
            })
        }
    }
}

/// Verifies credentials and returns the authenticated client.
///
/// Every failure is the same `invalid_client` error, so the response does not
/// reveal whether a `client_id` exists.
pub async fn authenticate(
    db: &DatabaseConnection,
    credentials: &ClientCredentials,
) -> Result<OAuthClient, AppError> {
    let client = db::clients::find_by_client_id(db, &credentials.client_id)
        .await?
        .filter(OAuthClient::is_active);

    let authenticated = match (&client, &credentials.client_secret) {
        (None, _) => false,
        // Confidential client with a secret: compare hashes in constant time.
        (Some(client), Some(secret)) => client.client_secret_hash.as_ref().is_some_and(|stored| {
            constant_time_eq(hash_token(secret).as_bytes(), stored.as_str().as_bytes())
        }),
        // No secret presented: only acceptable for public clients.
        (Some(client), None) => !client.is_confidential(),
    };

    match client {
        Some(client) if authenticated => Ok(client),
        _ => {
            tracing::warn!(
                target: "audit",
                event = "client_authentication_failed",
                client_id = %credentials.client_id
            );
            Err(AppError::InvalidClient)
        }
    }
}

/// Case-insensitive check of an HTTP auth scheme ("Basic", "Bearer").
pub fn has_scheme(header: &str, scheme: &str) -> bool {
    header
        .split_once(' ')
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

/// Parses `Basic base64(client_id:client_secret)`.
///
/// RFC 6749 §2.3.1 requires both parts to be form-urlencoded *before* they
/// are base64 encoded, so we decode that layer too.
pub fn parse_basic_authorization(header: &str) -> Option<(String, String)> {
    let (scheme, encoded) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    let (id, secret) = (form_urldecode(id), form_urldecode(secret));
    (!id.is_empty()).then_some((id, secret))
}

/// Decodes one application/x-www-form-urlencoded value (`+` → space, `%XX`).
fn form_urldecode(value: &str) -> String {
    // Reuse the url crate's decoder by parsing a one-pair form "v=<value>".
    // A raw `&` would start a new pair, so it is escaped first.
    let input = format!("v={}", value.replace('&', "%26"));
    url::form_urlencoded::parse(input.as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(items: &[(&str, &str)]) -> Params {
        Params::from_pairs(
            items
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn redirect_uri_registration_rules() {
        assert!(validate_redirect_uri_for_registration("https://app.example.com/callback").is_ok());
        assert!(validate_redirect_uri_for_registration("http://localhost:8080/cb").is_ok());
        assert!(validate_redirect_uri_for_registration("http://127.0.0.1/cb").is_ok());

        assert!(validate_redirect_uri_for_registration("http://app.example.com/cb").is_err());
        assert!(validate_redirect_uri_for_registration("https://app.example.com/cb#frag").is_err());
        assert!(validate_redirect_uri_for_registration("/relative").is_err());
        assert!(validate_redirect_uri_for_registration("javascript:alert(1)").is_err());
        assert!(
            validate_redirect_uri_for_registration("https://user:pw@app.example.com/cb").is_err()
        );
    }

    #[test]
    fn redirect_uri_matching_is_exact() {
        let client = OAuthClient {
            id: Uuid::now_v7(),
            client_id: "c".into(),
            client_secret_hash: None,
            name: "n".into(),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            allowed_scopes: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            disabled_at: None,
        };

        assert!(client.has_redirect_uri("https://app.example.com/callback"));
        // Everything a prefix/contains check would wrongly accept:
        for attempt in [
            "https://app.example.com/callback/../evil",
            "https://app.example.com/callback?x=1",
            "https://app.example.com/callbackx",
            "https://app.example.com/callback.evil.com",
            "https://APP.example.com/callback",
            "https://app.example.com/callback/",
        ] {
            assert!(
                !client.has_redirect_uri(attempt),
                "{attempt} must not match"
            );
        }
    }

    #[test]
    fn parses_basic_authorization_with_form_encoding() {
        // "my client:s3cr+t%" form-encoded is "my+client:s3cr%2Bt%25".
        let header = format!("basic {}", STANDARD.encode("my+client:s3cr%2Bt%25"));
        assert_eq!(
            parse_basic_authorization(&header),
            Some(("my client".into(), "s3cr+t%".into()))
        );
        assert_eq!(parse_basic_authorization("Basic !!!notbase64"), None);
        assert_eq!(parse_basic_authorization("Bearer abc"), None);
    }

    #[test]
    fn two_authentication_methods_are_rejected() {
        let header = format!("Basic {}", STANDARD.encode("id:secret"));
        let result = extract_credentials(Some(&header), &params(&[("client_secret", "secret")]));
        assert!(matches!(result, Err(AppError::InvalidRequest(_))));
    }

    #[test]
    fn public_client_credentials_have_no_secret() {
        let creds = extract_credentials(None, &params(&[("client_id", "abc")])).unwrap();
        assert_eq!(creds.client_id, "abc");
        assert!(creds.client_secret.is_none());
    }

    #[test]
    fn missing_client_id_is_invalid_client() {
        assert!(matches!(
            extract_credentials(None, &params(&[])),
            Err(AppError::InvalidClient)
        ));
    }
}
