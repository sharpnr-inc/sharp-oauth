//! The authorization endpoint: `GET|POST /oauth/authorize`.
//!
//! This is where a user, sent here by a third-party app, signs in and
//! approves access. The output is a short-lived **authorization code**
//! delivered to the app's redirect URI.
//!
//! ## Validation order matters
//!
//! Errors in an authorization request are normally reported back to the
//! client by redirecting to its `redirect_uri` with `?error=...`. But we may
//! only redirect after proving the redirect URI is legitimate. Otherwise an
//! attacker could craft a bad request whose "error redirect" sends the user
//! to a phishing site (an *open redirector*). So [`validate`] runs in two
//! phases (RFC 6749 §4.1.2.1):
//!
//! 1. `client_id` and `redirect_uri`. Failures here are shown to the user as
//!    an error page ([`AuthorizationError::Unsafe`]).
//! 2. Everything else. Failures are redirected back to the client
//!    ([`AuthorizationError::Redirect`]).
//!
//! ## What the code is bound to
//!
//! The stored code remembers the client, user, exact redirect URI, scopes,
//! PKCE challenge, nonce and authentication time. The token endpoint refuses
//! to redeem it unless the redeeming request matches.

use chrono::{DateTime, Duration, Utc};
use sea_orm::DatabaseConnection;
use url::Url;
use uuid::Uuid;

use crate::{
    AppState,
    db::{self, entities::SecretHash, scopes::ScopeDescription},
    error::AppError,
    identity::{session::Session, user::User},
    oauth::{client::OAuthClient, consent, params::Params, pkce, scope::ScopeSet},
    secret::{generate_token, hash_token},
};

/// Authorization codes live for one minute. The client is expected to redeem
/// them immediately; RFC 6749 recommends a maximum of ten minutes.
pub const AUTHORIZATION_CODE_TTL: Duration = Duration::seconds(60);

const MAX_NONCE_LEN: usize = 512;
const MAX_STATE_LEN: usize = 2048;

/// A one-time authorization code.
///
/// The SeaORM model for `oauth_authorization_codes`
/// ([`crate::db::entities::oauth_authorization_codes`]). `code_hash` is a
/// [`SecretHash`], so `{:?}` prints `<redacted>`.
pub use crate::db::entities::oauth_authorization_codes::Model as AuthorizationCode;

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

/// The raw parameters of an authorization request, not yet validated.
///
/// Every field is optional here; [`validate`] decides what is required.
#[derive(Debug, Clone, Default)]
pub struct AuthorizationRequest {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    /// OIDC request objects (`request`, `request_uri`) are not supported. We
    /// only record their presence so we can reject them explicitly instead
    /// of silently ignoring security-relevant parameters.
    pub has_request_object: bool,
    pub has_request_uri: bool,
}

impl AuthorizationRequest {
    pub fn from_params(params: &Params) -> Self {
        Self {
            client_id: params.take("client_id"),
            redirect_uri: params.take("redirect_uri"),
            response_type: params.take("response_type"),
            response_mode: params.take("response_mode"),
            scope: params.take("scope"),
            state: params.take("state"),
            code_challenge: params.take("code_challenge"),
            code_challenge_method: params.take("code_challenge_method"),
            nonce: params.take("nonce"),
            prompt: params.take("prompt"),
            max_age: params.take("max_age"),
            has_request_object: params.get("request").is_some(),
            has_request_uri: params.get("request_uri").is_some(),
        }
    }

    /// The parameters as name/value pairs, for rebuilding the request as a
    /// URL (after sign-in) or as hidden form fields (on the consent page).
    pub fn to_pairs(&self) -> Vec<(&'static str, &str)> {
        [
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("response_type", &self.response_type),
            ("response_mode", &self.response_mode),
            ("scope", &self.scope),
            ("state", &self.state),
            ("code_challenge", &self.code_challenge),
            ("code_challenge_method", &self.code_challenge_method),
            ("nonce", &self.nonce),
            ("prompt", &self.prompt),
            ("max_age", &self.max_age),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.as_deref().map(|v| (name, v)))
        .collect()
    }

    /// `/oauth/authorize?...` for this request.
    pub fn to_path(&self) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(self.to_pairs())
            .finish();
        format!("/oauth/authorize?{query}")
    }

    /// A copy without the parameters that force re-authentication
    /// (`prompt=login`, `max_age`).
    ///
    /// Used as the "return here after sign-in" URL. The user is about to
    /// authenticate from scratch, which satisfies both parameters. Keeping
    /// them would send the user straight back to the sign-in page forever.
    pub fn without_reauthentication(&self) -> Self {
        let prompt = self.prompt.as_deref().map(|prompt| {
            prompt
                .split(' ')
                .filter(|value| *value != "login")
                .collect::<Vec<_>>()
                .join(" ")
        });
        Self {
            prompt: prompt.filter(|p| !p.is_empty()),
            max_age: None,
            ..self.clone()
        }
    }
}

/// The OIDC `prompt` parameter.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Prompt {
    /// Never show UI; fail with `login_required` / `consent_required` instead.
    pub none: bool,
    /// Force the user to enter their password again.
    pub login: bool,
    /// Show the consent screen even if consent was already given.
    pub consent: bool,
}

impl Prompt {
    fn parse(raw: Option<&str>) -> Result<Self, ()> {
        let mut prompt = Prompt::default();
        for value in raw.unwrap_or_default().split(' ').filter(|v| !v.is_empty()) {
            match value {
                "none" => prompt.none = true,
                "login" => prompt.login = true,
                "consent" => prompt.consent = true,
                // A user has exactly one Sharpnr account in a browser, so
                // there is never an account to select.
                "select_account" => {}
                _ => return Err(()),
            }
        }
        // OIDC Core §3.1.2.1: `none` must not be combined with other values.
        if prompt.none && (prompt.login || prompt.consent) {
            return Err(());
        }
        Ok(prompt)
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// An authorization request that passed every check.
#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    pub client: OAuthClient,
    pub redirect_uri: String,
    pub scope: ScopeSet,
    pub state: String,
    pub code_challenge: String,
    pub nonce: Option<String>,
    pub prompt: Prompt,
    pub max_age: Option<i64>,
}

impl ValidatedRequest {
    /// Builds an error that is redirected back to this client.
    pub fn error(&self, error: &'static str, description: &'static str) -> AuthorizationError {
        AuthorizationError::Redirect(ErrorRedirect {
            redirect_uri: self.redirect_uri.clone(),
            state: Some(self.state.clone()),
            error,
            description,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    /// The client or redirect URI could not be verified. Redirecting would be
    /// unsafe, so the message is shown to the user directly.
    #[error("{0}")]
    Unsafe(&'static str),

    /// A protocol error that is reported to the client via redirect.
    #[error("{}: {}", .0.error, .0.description)]
    Redirect(ErrorRedirect),

    #[error(transparent)]
    Internal(#[from] AppError),
}

impl From<sea_orm::DbErr> for AuthorizationError {
    fn from(err: sea_orm::DbErr) -> Self {
        AuthorizationError::Internal(err.into())
    }
}

/// An error response for the client (RFC 6749 §4.1.2.1).
#[derive(Debug, Clone)]
pub struct ErrorRedirect {
    pub redirect_uri: String,
    pub state: Option<String>,
    pub error: &'static str,
    pub description: &'static str,
}

impl ErrorRedirect {
    /// `redirect_uri?error=...&error_description=...&state=...&iss=...`
    pub fn to_url(&self, issuer: &str) -> Result<String, AppError> {
        let mut params = vec![
            ("error", self.error),
            ("error_description", self.description),
        ];
        if let Some(state) = &self.state {
            params.push(("state", state));
        }
        params.push(("iss", issuer));
        redirect_with_params(&self.redirect_uri, &params)
    }
}

/// Checks an authorization request against the client registry and protocol rules.
pub async fn validate(
    db: &DatabaseConnection,
    request: &AuthorizationRequest,
) -> Result<ValidatedRequest, AuthorizationError> {
    use AuthorizationError::Unsafe;

    // ---- Phase 1: establish that we may redirect at all ----------------

    let client_id = request
        .client_id
        .as_deref()
        .ok_or(Unsafe("The request is missing the client_id parameter."))?;
    let client = db::clients::find_by_client_id(db, client_id)
        .await?
        .filter(OAuthClient::is_active)
        .ok_or(Unsafe(
            "The application making this request is not registered with Sharpnr.",
        ))?;

    // Always required: OIDC requires it, and requiring it removes any
    // ambiguity about where the code is sent.
    let redirect_uri = request
        .redirect_uri
        .as_deref()
        .ok_or(Unsafe("The request is missing the redirect_uri parameter."))?;
    if !client.has_redirect_uri(redirect_uri) {
        return Err(Unsafe(
            "The redirect_uri does not match any URI registered for this application.",
        ));
    }

    // ---- Phase 2: errors from here on go back to the client ------------

    let fail = |error: &'static str, description: &'static str| {
        AuthorizationError::Redirect(ErrorRedirect {
            redirect_uri: redirect_uri.to_owned(),
            state: request.state.clone(),
            error,
            description,
        })
    };

    if request.has_request_object {
        return Err(fail(
            "request_not_supported",
            "request objects are not supported",
        ));
    }
    if request.has_request_uri {
        return Err(fail(
            "request_uri_not_supported",
            "request_uri is not supported",
        ));
    }

    match request.response_type.as_deref() {
        Some("code") => {}
        None => return Err(fail("invalid_request", "response_type is required")),
        Some(_) => {
            return Err(fail(
                "unsupported_response_type",
                "only response_type=code is supported",
            ));
        }
    }

    if request
        .response_mode
        .as_deref()
        .is_some_and(|mode| mode != "query")
    {
        return Err(fail(
            "invalid_request",
            "only response_mode=query is supported",
        ));
    }

    // `state` lets the client tie the callback to the request it started,
    // which defeats CSRF against its callback endpoint. Sharpnr policy is to
    // require it.
    let state = request
        .state
        .clone()
        .ok_or_else(|| fail("invalid_request", "state is required"))?;
    if state.len() > MAX_STATE_LEN {
        return Err(fail("invalid_request", "state is too long"));
    }

    let scope = request
        .scope
        .as_deref()
        .ok_or_else(|| fail("invalid_scope", "scope is required"))
        .and_then(|raw| {
            ScopeSet::parse(raw).map_err(|_| fail("invalid_scope", "scope is malformed"))
        })?;
    if !scope.is_subset_of(&client.allowed_scopes()) {
        return Err(fail(
            "invalid_scope",
            "the client is not allowed to request one or more of these scopes",
        ));
    }

    // PKCE is mandatory for every client, and only with S256.
    let code_challenge = request
        .code_challenge
        .clone()
        .ok_or_else(|| fail("invalid_request", "code_challenge is required (PKCE)"))?;
    if request.code_challenge_method.as_deref() != Some(pkce::S256) {
        return Err(fail(
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }
    if !pkce::is_valid_s256_challenge(&code_challenge) {
        return Err(fail("invalid_request", "code_challenge is malformed"));
    }

    if request
        .nonce
        .as_ref()
        .is_some_and(|nonce| nonce.len() > MAX_NONCE_LEN)
    {
        return Err(fail("invalid_request", "nonce is too long"));
    }

    let prompt = Prompt::parse(request.prompt.as_deref())
        .map_err(|_| fail("invalid_request", "prompt is invalid"))?;

    let max_age = request
        .max_age
        .as_deref()
        .map(|raw| raw.parse::<u32>().map(i64::from))
        .transpose()
        .map_err(|_| fail("invalid_request", "max_age must be a non-negative integer"))?;

    Ok(ValidatedRequest {
        redirect_uri: redirect_uri.to_owned(),
        client,
        scope,
        state,
        code_challenge,
        nonce: request.nonce.clone(),
        prompt,
        max_age,
    })
}

// ---------------------------------------------------------------------------
// Deciding what happens next
// ---------------------------------------------------------------------------

/// The outcome of an authorization request.
#[expect(
    clippy::large_enum_variant,
    reason = "created once per request and matched immediately; boxing would only add noise"
)]
pub enum NextStep {
    /// The user must sign in, then come back to `return_to`.
    SignIn { return_to: String },
    /// The signed-in user must approve (or deny) these scopes.
    AskConsent {
        request: ValidatedRequest,
        user: User,
        scopes: Vec<ScopeDescription>,
    },
    /// All done: send the browser to the client with a code.
    RedirectToClient(String),
}

/// Runs the authorization endpoint for a request and the current browser session.
pub async fn decide(
    state: &AppState,
    request: &AuthorizationRequest,
    signed_in: Option<(Session, User)>,
) -> Result<NextStep, AuthorizationError> {
    let validated = validate(&state.db, request).await?;
    let now = Utc::now();

    // 1. Authentication.
    let signed_in =
        signed_in.filter(|(session, _)| !needs_reauthentication(&validated, session, now));
    let Some((session, user)) = signed_in else {
        if validated.prompt.none {
            return Err(validated.error("login_required", "the user is not signed in"));
        }
        return Ok(NextStep::SignIn {
            return_to: request.without_reauthentication().to_path(),
        });
    };

    // 2. Consent.
    let granted = consent::granted_scopes(&state.db, user.id, validated.client.id).await?;
    let already_approved = granted.is_some_and(|granted| validated.scope.is_subset_of(&granted));

    if already_approved && !validated.prompt.consent {
        let url = issue_code(state, &validated, &user, &session).await?;
        return Ok(NextStep::RedirectToClient(url));
    }
    if validated.prompt.none {
        return Err(validated.error("consent_required", "the user has not approved these scopes"));
    }

    let scopes = db::scopes::find_by_names(&state.db, &validated.scope.to_vec()).await?;
    Ok(NextStep::AskConsent {
        request: validated,
        user,
        scopes,
    })
}

/// Handles the user's answer on the consent screen.
///
/// The request is validated again from scratch: the hidden form fields came
/// back from the browser and must not be trusted just because we rendered
/// them.
pub async fn complete_consent(
    state: &AppState,
    request: &AuthorizationRequest,
    approved: bool,
    session: &Session,
    user: &User,
) -> Result<String, AuthorizationError> {
    let validated = validate(&state.db, request).await?;

    if !approved {
        tracing::info!(
            target: "audit",
            event = "consent_denied",
            user_id = %user.id,
            client_id = %validated.client.client_id
        );
        return Err(validated.error("access_denied", "the user denied the request"));
    }

    consent::grant(&state.db, user.id, validated.client.id, &validated.scope).await?;
    Ok(issue_code(state, &validated, user, session).await?)
}

/// True if the session is too old for this request, or the client demanded
/// a fresh sign-in.
fn needs_reauthentication(
    request: &ValidatedRequest,
    session: &Session,
    now: DateTime<Utc>,
) -> bool {
    let too_old = request
        .max_age
        .is_some_and(|max_age| (now - session.created_at).num_seconds() > max_age);
    request.prompt.login || too_old
}

/// Creates and stores a one-time authorization code, returning the redirect URL.
async fn issue_code(
    state: &AppState,
    request: &ValidatedRequest,
    user: &User,
    session: &Session,
) -> Result<String, AppError> {
    let code = generate_token();
    let now = Utc::now();
    let record = AuthorizationCode {
        id: Uuid::now_v7(),
        code_hash: SecretHash::from(hash_token(&code)),
        client_id: request.client.id,
        user_id: user.id,
        redirect_uri: request.redirect_uri.clone(),
        scope: request.scope.to_string(),
        code_challenge: request.code_challenge.clone(),
        code_challenge_method: pkce::S256.to_owned(),
        nonce: request.nonce.clone(),
        auth_time: session.created_at,
        expires_at: now + AUTHORIZATION_CODE_TTL,
        created_at: now,
        used_at: None,
    };
    db::authorization_codes::insert(&state.db, &record).await?;

    tracing::info!(
        target: "audit",
        event = "authorization_code_issued",
        user_id = %user.id,
        client_id = %request.client.client_id,
        scope = %request.scope
    );

    // RFC 9207: `iss` tells the client which server produced this response,
    // defending against "mix-up" attacks when it talks to several providers.
    redirect_with_params(
        &request.redirect_uri,
        &[
            ("code", &code),
            ("state", &request.state),
            ("iss", &state.config.issuer),
        ],
    )
}

/// Appends query parameters to a redirect URI, preserving any existing query.
fn redirect_with_params(redirect_uri: &str, params: &[(&str, &str)]) -> Result<String, AppError> {
    let mut url = Url::parse(redirect_uri).map_err(|_| {
        AppError::Internal(anyhow::anyhow!(
            "registered redirect_uri is not a valid URL"
        ))
    })?;
    url.query_pairs_mut().extend_pairs(params);
    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_parsing() {
        assert_eq!(Prompt::parse(None), Ok(Prompt::default()));
        assert_eq!(
            Prompt::parse(Some("login consent")),
            Ok(Prompt {
                none: false,
                login: true,
                consent: true
            })
        );
        assert!(Prompt::parse(Some("none login")).is_err());
        assert!(Prompt::parse(Some("bogus")).is_err());
    }

    #[test]
    fn return_to_url_drops_reauthentication_parameters_only() {
        let request = AuthorizationRequest {
            client_id: Some("abc".into()),
            state: Some("s t&x".into()),
            prompt: Some("login consent".into()),
            max_age: Some("0".into()),
            ..Default::default()
        };
        let path = request.without_reauthentication().to_path();
        assert_eq!(
            path,
            "/oauth/authorize?client_id=abc&state=s+t%26x&prompt=consent"
        );
    }

    #[test]
    fn redirect_preserves_existing_query_and_encodes_values() {
        let url = redirect_with_params(
            "https://app.example.com/cb?tenant=7",
            &[("code", "a b"), ("state", "x&y")],
        )
        .unwrap();
        assert_eq!(
            url,
            "https://app.example.com/cb?tenant=7&code=a+b&state=x%26y"
        );
    }

    #[test]
    fn max_age_forces_reauthentication_for_old_sessions() {
        let now = Utc::now();
        let session = Session {
            id: Uuid::now_v7(),
            user_id: Uuid::now_v7(),
            session_token_hash: crate::db::entities::SecretHash::from("hash".to_owned()),
            revoked_at: None,
            expires_at: now + Duration::days(1),
            created_at: now - Duration::seconds(120),
        };
        let mut request = ValidatedRequest {
            client: OAuthClient {
                id: Uuid::now_v7(),
                client_id: "c".into(),
                client_secret_hash: None,
                name: "n".into(),
                redirect_uris: vec![],
                allowed_scopes: vec![],
                created_at: now,
                updated_at: now,
                disabled_at: None,
            },
            redirect_uri: "https://x".into(),
            scope: ScopeSet::parse("openid").unwrap(),
            state: "s".into(),
            code_challenge: "c".into(),
            nonce: None,
            prompt: Prompt::default(),
            max_age: Some(300),
        };
        assert!(!needs_reauthentication(&request, &session, now));

        request.max_age = Some(60);
        assert!(needs_reauthentication(&request, &session, now));

        request.max_age = None;
        request.prompt.login = true;
        assert!(needs_reauthentication(&request, &session, now));
    }
}
