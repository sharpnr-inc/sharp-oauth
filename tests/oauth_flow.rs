//! Integration tests: the OAuth 2.0 Authorization Code flow with PKCE,
//! refresh-token rotation and revocation, including the negative/security
//! cases from the project plan.

mod common;

use axum::http::StatusCode;
use common::{
    Browser, REDIRECT_URI, TestApp, authorize_and_approve, authorize_uri, exchange_code, new_pkce,
    query_param,
};
use jsonwebtoken::{DecodingKey, Validation, jwk::JwkSet};
use sharp_oauth::oidc::id_token::IdTokenClaims;
use sqlx::PgPool;

const ALL_SCOPES: &str = "openid profile email offline_access";

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[sqlx::test]
async fn complete_flow_sign_in_consent_code_tokens_userinfo(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client(ALL_SCOPES, true).await;
    let client_id = client.client.client_id.clone();
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);
    let pkce = new_pkce();

    // 1. Not signed in: authorize sends the browser to the sign-in page.
    let uri = authorize_uri(&client_id, ALL_SCOPES, &pkce, &[]);
    let response = browser.get(&uri).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let return_to = query_param(response.location(), "return_to").unwrap();
    assert!(return_to.starts_with("/oauth/authorize?"));

    // 2. Sign in, which returns to the authorization request.
    let signed_in = browser.sign_in("user@example.com", Some(&return_to)).await;
    assert_eq!(signed_in.location(), return_to);

    // 3. Consent page lists what the app wants.
    let consent = browser.get(&return_to).await;
    assert_eq!(consent.status, StatusCode::OK);
    assert!(consent.body.contains("Example App"));
    assert!(consent.body.contains("See your email address"));

    // 4. Approve: redirected to the client with code, state and iss.
    let approved = browser
        .submit(&consent, "/oauth/consent", &[("decision", "approve")])
        .await;
    assert_eq!(approved.status, StatusCode::SEE_OTHER);
    let callback = approved.location();
    assert!(callback.starts_with(REDIRECT_URI));
    assert_eq!(query_param(callback, "state").as_deref(), Some("state-123"));
    assert_eq!(
        query_param(callback, "iss").as_deref(),
        Some(common::ISSUER)
    );
    let code = query_param(callback, "code").unwrap();

    // The raw code is not stored.
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_authorization_codes WHERE code_hash = $1")
            .bind(&code)
            .fetch_one(app.db())
            .await
            .unwrap();
    assert_eq!(stored, 0);

    // 5. Exchange the code with the PKCE verifier.
    let tokens = exchange_code(&app, &client, &code, &pkce.verifier).await;
    assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
    assert_eq!(tokens.headers["cache-control"], "no-store");
    let tokens = tokens.json();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 900);
    assert_eq!(tokens["scope"], "email offline_access openid profile");
    let access_token = tokens["access_token"].as_str().unwrap();
    let id_token = tokens["id_token"].as_str().unwrap();
    assert!(tokens["refresh_token"].is_string());

    // 6. Validate the ID token exactly as a client would: using JWKS.
    let jwks: JwkSet = serde_json::from_str(&app.get("/.well-known/jwks.json").await.body).unwrap();
    let kid = jsonwebtoken::decode_header(id_token).unwrap().kid.unwrap();
    let key = DecodingKey::from_jwk(jwks.find(&kid).unwrap()).unwrap();
    let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&[common::ISSUER]);
    validation.set_audience(&[&client_id]);
    let claims = jsonwebtoken::decode::<IdTokenClaims>(id_token, &key, &validation)
        .unwrap()
        .claims;
    assert_eq!(claims.nonce.as_deref(), Some("nonce-456"));
    let user_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users")
        .fetch_one(app.db())
        .await
        .unwrap();
    assert_eq!(claims.sub, user_id.to_string());

    // 7. UserInfo with the access token.
    let userinfo = app.get_with_bearer("/oauth/userinfo", access_token).await;
    assert_eq!(userinfo.status, StatusCode::OK, "{}", userinfo.body);
    let userinfo = userinfo.json();
    assert_eq!(userinfo["sub"], user_id.to_string());
    assert_eq!(userinfo["email"], "user@example.com");
    assert_eq!(userinfo["name"], "Test User");
}

#[sqlx::test]
async fn second_authorization_skips_consent(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client(ALL_SCOPES, true).await;
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("user@example.com", None).await;

    let pkce = new_pkce();
    let uri = authorize_uri(&client.client.client_id, "openid email", &pkce, &[]);
    authorize_and_approve(&mut browser, &uri).await;

    // Same or fewer scopes: straight back to the client.
    let uri = authorize_uri(&client.client.client_id, "openid", &pkce, &[]);
    let response = browser.get(&uri).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert!(response.location().starts_with(REDIRECT_URI));

    // More scopes: ask again.
    let uri = authorize_uri(&client.client.client_id, "openid email profile", &pkce, &[]);
    assert_eq!(browser.get(&uri).await.status, StatusCode::OK);

    // prompt=consent forces the screen even when already approved.
    let uri = authorize_uri(
        &client.client.client_id,
        "openid",
        &pkce,
        &[("prompt", "consent")],
    );
    assert_eq!(browser.get(&uri).await.status, StatusCode::OK);
}

#[sqlx::test]
async fn public_client_uses_pkce_without_secret(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("openid", false).await;
    assert!(client.client_secret.is_none());
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("user@example.com", None).await;

    let pkce = new_pkce();
    let code = authorize_and_approve(
        &mut browser,
        &authorize_uri(&client.client.client_id, "openid", &pkce, &[]),
    )
    .await;

    let response = app
        .client_post(
            "/oauth/token",
            None,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client.client.client_id),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", &pkce.verifier),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let tokens = response.json();
    assert!(tokens["id_token"].is_string());
    // No offline_access, so no refresh token.
    assert!(tokens.get("refresh_token").is_none());
}

#[sqlx::test]
async fn no_id_token_without_openid_scope(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("email", true).await;
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("user@example.com", None).await;

    let pkce = new_pkce();
    let code = authorize_and_approve(
        &mut browser,
        &authorize_uri(&client.client.client_id, "email", &pkce, &[]),
    )
    .await;
    let tokens = exchange_code(&app, &client, &code, &pkce.verifier)
        .await
        .json();
    assert!(tokens["access_token"].is_string());
    assert!(tokens.get("id_token").is_none());
}

// ---------------------------------------------------------------------------
// Authorization endpoint: errors that must NOT redirect
// ---------------------------------------------------------------------------

#[sqlx::test]
async fn unknown_client_shows_error_page_instead_of_redirecting(pool: PgPool) {
    let app = TestApp::new(pool);
    let pkce = new_pkce();
    let response = app
        .get(&authorize_uri("sharp_client_nope", "openid", &pkce, &[]))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.headers.get("location").is_none());
}

#[sqlx::test]
async fn unregistered_redirect_uri_shows_error_page(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("openid", true).await;
    let pkce = new_pkce();

    for evil in [
        "https://evil.example/callback",
        "https://client.example/callback/../../evil",
        "https://client.example/callback?extra=1",
        "https://client.example/callbackx",
    ] {
        let uri = authorize_uri(
            &client.client.client_id,
            "openid",
            &pkce,
            &[("redirect_uri", evil)],
        );
        let response = app.get(&uri).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{evil}");
        assert!(
            response.headers.get("location").is_none(),
            "must not redirect to {evil}"
        );
    }
}

#[sqlx::test]
async fn repeated_parameters_are_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("openid", true).await;
    let pkce = new_pkce();
    let uri = format!(
        "{}&redirect_uri=https%3A%2F%2Fevil.example",
        authorize_uri(&client.client.client_id, "openid", &pkce, &[])
    );
    let response = app.get(&uri).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert!(response.headers.get("location").is_none());
}

// ---------------------------------------------------------------------------
// Authorization endpoint: errors redirected to the client
// ---------------------------------------------------------------------------

/// Runs an authorization request for a signed-in user and returns the
/// `error` and `error_description` from the redirect.
async fn authorize_error(
    app: &TestApp,
    scopes: &str,
    overrides: &[(&str, &str)],
) -> (String, String) {
    let client = app.register_client(scopes, true).await;
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(app);
    browser.sign_in("user@example.com", None).await;

    let uri = authorize_uri(&client.client.client_id, "openid", &new_pkce(), overrides);
    let response = browser.get(&uri).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER, "{}", response.body);
    let location = response.location();
    assert!(location.starts_with(REDIRECT_URI), "{location}");
    (
        query_param(location, "error").unwrap_or_else(|| panic!("no error in {location}")),
        query_param(location, "error_description").unwrap_or_default(),
    )
}

#[sqlx::test]
async fn missing_pkce_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let (error, description) = authorize_error(
        &app,
        "openid",
        &[("code_challenge", ""), ("code_challenge_method", "")],
    )
    .await;
    assert_eq!(error, "invalid_request");
    assert!(description.contains("code_challenge"));
}

#[sqlx::test]
async fn plain_pkce_method_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let (error, description) =
        authorize_error(&app, "openid", &[("code_challenge_method", "plain")]).await;
    assert_eq!(error, "invalid_request");
    assert!(description.contains("S256"));
}

#[sqlx::test]
async fn scope_not_allowed_for_client_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let (error, _) = authorize_error(&app, "openid", &[("scope", "openid email")]).await;
    assert_eq!(error, "invalid_scope");
}

#[sqlx::test]
async fn missing_state_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let (error, description) = authorize_error(&app, "openid", &[("state", "")]).await;
    assert_eq!(error, "invalid_request");
    assert!(description.contains("state"));
}

#[sqlx::test]
async fn unsupported_response_type_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let (error, _) = authorize_error(&app, "openid", &[("response_type", "token")]).await;
    assert_eq!(error, "unsupported_response_type");
}

#[sqlx::test]
async fn request_objects_are_rejected_not_ignored(pool: PgPool) {
    let app = TestApp::new(pool);
    let (error, _) =
        authorize_error(&app, "openid", &[("request", "eyJhbGciOiJub25lIn0.e30.")]).await;
    assert_eq!(error, "request_not_supported");
}

#[sqlx::test]
async fn prompt_none_without_session_returns_login_required(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("openid", true).await;
    let uri = authorize_uri(
        &client.client.client_id,
        "openid",
        &new_pkce(),
        &[("prompt", "none")],
    );
    let response = app.get(&uri).await;
    assert_eq!(
        query_param(response.location(), "error").as_deref(),
        Some("login_required")
    );
    assert_eq!(
        query_param(response.location(), "state").as_deref(),
        Some("state-123")
    );
}

#[sqlx::test]
async fn prompt_none_without_consent_returns_consent_required(pool: PgPool) {
    let app = TestApp::new(pool);
    let (error, _) = authorize_error(&app, "openid", &[("prompt", "none")]).await;
    assert_eq!(error, "consent_required");
}

#[sqlx::test]
async fn prompt_login_forces_a_fresh_sign_in(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("openid", true).await;
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("user@example.com", None).await;

    let uri = authorize_uri(
        &client.client.client_id,
        "openid",
        &new_pkce(),
        &[("prompt", "login")],
    );
    let response = browser.get(&uri).await;
    assert!(
        response.location().starts_with("/signin?"),
        "signed-in user must re-authenticate"
    );

    // After signing in again we continue without looping back to /signin.
    let return_to = query_param(response.location(), "return_to").unwrap();
    assert!(!return_to.contains("prompt=login"));
    browser.sign_in("user@example.com", Some(&return_to)).await;
    assert_eq!(browser.get(&return_to).await.status, StatusCode::OK); // consent page
}

#[sqlx::test]
async fn denied_consent_redirects_with_access_denied(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("openid", true).await;
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("user@example.com", None).await;

    let consent = browser
        .get(&authorize_uri(
            &client.client.client_id,
            "openid",
            &new_pkce(),
            &[],
        ))
        .await;
    let denied = browser
        .submit(&consent, "/oauth/consent", &[("decision", "deny")])
        .await;
    assert_eq!(
        query_param(denied.location(), "error").as_deref(),
        Some("access_denied")
    );
    assert!(query_param(denied.location(), "code").is_none());
}

#[sqlx::test]
async fn consent_without_csrf_token_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("openid", true).await;
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("user@example.com", None).await;

    let consent = browser
        .get(&authorize_uri(
            &client.client.client_id,
            "openid",
            &new_pkce(),
            &[],
        ))
        .await;
    // A cross-site page could replay every hidden field except the CSRF token.
    let forged: Vec<(String, String)> = consent
        .hidden_fields()
        .into_iter()
        .filter(|(n, _)| n != "csrf_token")
        .collect();
    let mut form: Vec<(&str, &str)> = forged
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    form.push(("decision", "approve"));

    let response = browser.post_form("/oauth/consent", &form).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response.headers.get("location").is_none());
}

// ---------------------------------------------------------------------------
// Token endpoint: authorization_code grant
// ---------------------------------------------------------------------------

/// Signs in, approves and returns (app client, code, verifier).
async fn obtain_code(
    app: &TestApp,
    scopes: &str,
) -> (sharp_oauth::oauth::client::RegisteredClient, String, String) {
    let client = app.register_client(scopes, true).await;
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(app);
    browser.sign_in("user@example.com", None).await;
    let pkce = new_pkce();
    let code = authorize_and_approve(
        &mut browser,
        &authorize_uri(&client.client.client_id, scopes, &pkce, &[]),
    )
    .await;
    (client, code, pkce.verifier)
}

#[sqlx::test]
async fn reused_code_is_rejected_and_revokes_issued_refresh_tokens(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, ALL_SCOPES).await;

    let first = exchange_code(&app, &client, &code, &verifier).await;
    assert_eq!(first.status, StatusCode::OK);
    let refresh_token = first.json()["refresh_token"].as_str().unwrap().to_owned();

    let second = exchange_code(&app, &client, &code, &verifier).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert_eq!(second.json()["error"], "invalid_grant");

    // The replay revoked the refresh token from the first exchange.
    let refreshed = app
        .client_post(
            "/oauth/token",
            Some((
                &client.client.client_id,
                client.client_secret.as_deref().unwrap(),
            )),
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
            ],
        )
        .await;
    assert_eq!(refreshed.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn wrong_pkce_verifier_is_rejected_and_burns_the_code(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, "openid").await;

    let wrong = exchange_code(&app, &client, &code, &new_pkce().verifier).await;
    assert_eq!(wrong.json()["error"], "invalid_grant");

    // The attacker's failed guess consumed the code for good.
    let right = exchange_code(&app, &client, &code, &verifier).await;
    assert_eq!(right.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn missing_code_verifier_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, _) = obtain_code(&app, "openid").await;
    let response = app
        .client_post(
            "/oauth/token",
            Some((
                &client.client.client_id,
                client.client_secret.as_deref().unwrap(),
            )),
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
            ],
        )
        .await;
    assert_eq!(response.json()["error"], "invalid_request");
}

#[sqlx::test]
async fn expired_code_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, "openid").await;
    sqlx::query("UPDATE oauth_authorization_codes SET expires_at = now() - interval '1 second'")
        .execute(app.db())
        .await
        .unwrap();

    let response = exchange_code(&app, &client, &code, &verifier).await;
    assert_eq!(response.json()["error"], "invalid_grant");
    assert!(
        response.json()["error_description"]
            .as_str()
            .unwrap()
            .contains("expired")
    );
}

#[sqlx::test]
async fn invalid_code_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("openid", true).await;
    let response = exchange_code(&app, &client, "made-up-code", &new_pkce().verifier).await;
    assert_eq!(response.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn redirect_uri_must_match_at_token_endpoint(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, "openid").await;
    let response = app
        .client_post(
            "/oauth/token",
            Some((
                &client.client.client_id,
                client.client_secret.as_deref().unwrap(),
            )),
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://client.example/other"),
                ("code_verifier", &verifier),
            ],
        )
        .await;
    assert_eq!(response.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn wrong_client_secret_is_invalid_client(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, "openid").await;
    let response = app
        .client_post(
            "/oauth/token",
            Some((&client.client.client_id, "sharp_secret_wrong")),
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", &verifier),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.json()["error"], "invalid_client");
    assert!(response.headers.contains_key("www-authenticate"));

    // Client authentication failed before the code was touched, so the
    // real client can still redeem it.
    assert_eq!(
        exchange_code(&app, &client, &code, &verifier).await.status,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn confidential_client_must_authenticate(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, "openid").await;
    // Pretending to be a public client by sending only client_id.
    let response = app
        .client_post(
            "/oauth/token",
            None,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client.client.client_id),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", &verifier),
            ],
        )
        .await;
    assert_eq!(response.json()["error"], "invalid_client");
}

#[sqlx::test]
async fn code_cannot_be_redeemed_by_another_client(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_victim, code, verifier) = obtain_code(&app, "openid").await;
    let attacker = app.register_client("openid", true).await;

    let response = exchange_code(&app, &attacker, &code, &verifier).await;
    assert_eq!(response.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn client_secret_post_authentication_works(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, "openid").await;
    let response = app
        .client_post(
            "/oauth/token",
            None,
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &client.client.client_id),
                ("client_secret", client.client_secret.as_deref().unwrap()),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", &verifier),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
}

#[sqlx::test]
async fn unsupported_grant_type_and_bad_content_type(pool: PgPool) {
    let app = TestApp::new(pool);
    let client = app.register_client("openid", true).await;
    let secret = client.client_secret.as_deref().unwrap();

    let response = app
        .client_post(
            "/oauth/token",
            Some((&client.client.client_id, secret)),
            &[("grant_type", "password")],
        )
        .await;
    assert_eq!(response.json()["error"], "unsupported_grant_type");

    let request = axum::http::Request::post("/oauth/token")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            r#"{"grant_type":"authorization_code"}"#,
        ))
        .unwrap();
    assert_eq!(app.send(request).await.json()["error"], "invalid_request");
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

async fn refresh(
    app: &TestApp,
    client: &sharp_oauth::oauth::client::RegisteredClient,
    token: &str,
    extra: &[(&str, &str)],
) -> common::TestResponse {
    let mut form = vec![("grant_type", "refresh_token"), ("refresh_token", token)];
    form.extend_from_slice(extra);
    app.client_post(
        "/oauth/token",
        Some((
            &client.client.client_id,
            client.client_secret.as_deref().unwrap(),
        )),
        &form,
    )
    .await
}

#[sqlx::test]
async fn refresh_token_rotation_and_replay_detection(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, ALL_SCOPES).await;
    let rt1 = exchange_code(&app, &client, &code, &verifier).await.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();

    // Using RT1 returns new tokens, including a different refresh token RT2.
    let response = refresh(&app, &client, &rt1, &[]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let body = response.json();
    let rt2 = body["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(rt1, rt2);
    assert!(body["access_token"].is_string());
    assert!(body["id_token"].is_string());

    // RT2 works once and yields RT3.
    let rt3 = refresh(&app, &client, &rt2, &[]).await.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();

    // Someone replays RT1. It is rejected...
    let replay = refresh(&app, &client, &rt1, &[]).await;
    assert_eq!(replay.json()["error"], "invalid_grant");

    // ...and the whole family is revoked, so the latest token RT3 is dead too.
    let after = refresh(&app, &client, &rt3, &[]).await;
    assert_eq!(after.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn refresh_token_is_bound_to_its_client(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, ALL_SCOPES).await;
    let rt = exchange_code(&app, &client, &code, &verifier).await.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let other = app.register_client(ALL_SCOPES, true).await;
    assert_eq!(
        refresh(&app, &other, &rt, &[]).await.json()["error"],
        "invalid_grant"
    );

    // The attempt by another client did not revoke the real client's token.
    assert_eq!(
        refresh(&app, &client, &rt, &[]).await.status,
        StatusCode::OK
    );
}

#[sqlx::test]
async fn expired_refresh_token_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, ALL_SCOPES).await;
    let rt = exchange_code(&app, &client, &code, &verifier).await.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    sqlx::query("UPDATE oauth_refresh_tokens SET expires_at = now() - interval '1 second'")
        .execute(app.db())
        .await
        .unwrap();

    let response = refresh(&app, &client, &rt, &[]).await;
    assert_eq!(response.json()["error"], "invalid_grant");
}

#[sqlx::test]
async fn refresh_can_narrow_but_not_widen_scope(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, "openid offline_access").await;
    let rt = exchange_code(&app, &client, &code, &verifier).await.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let widened = refresh(
        &app,
        &client,
        &rt,
        &[("scope", "openid offline_access email")],
    )
    .await;
    assert_eq!(widened.json()["error"], "invalid_scope");

    let narrowed = refresh(&app, &client, &rt, &[("scope", "offline_access")])
        .await
        .json();
    assert_eq!(narrowed["scope"], "offline_access");
    assert!(narrowed.get("id_token").is_none());

    // The rotated token keeps the original grant.
    let next = narrowed["refresh_token"].as_str().unwrap();
    assert_eq!(
        refresh(&app, &client, next, &[]).await.json()["scope"],
        "offline_access openid"
    );
}

#[sqlx::test]
async fn revocation_endpoint_revokes_refresh_token_family(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, ALL_SCOPES).await;
    let rt = exchange_code(&app, &client, &code, &verifier).await.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret = client.client_secret.as_deref().unwrap();

    let response = app
        .client_post(
            "/oauth/revoke",
            Some((&client.client.client_id, secret)),
            &[("token", &rt)],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        refresh(&app, &client, &rt, &[]).await.json()["error"],
        "invalid_grant"
    );

    // Unknown tokens are not an error (RFC 7009 §2.2).
    let unknown = app
        .client_post(
            "/oauth/revoke",
            Some((&client.client.client_id, secret)),
            &[("token", "nope")],
        )
        .await;
    assert_eq!(unknown.status, StatusCode::OK);
}

#[sqlx::test]
async fn revocation_requires_client_authentication(pool: PgPool) {
    let app = TestApp::new(pool);
    let (client, code, verifier) = obtain_code(&app, ALL_SCOPES).await;
    let rt = exchange_code(&app, &client, &code, &verifier).await.json()["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = app
        .client_post(
            "/oauth/revoke",
            Some((&client.client.client_id, "wrong")),
            &[("token", &rt)],
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    // Another client cannot revoke it either.
    let other = app.register_client(ALL_SCOPES, true).await;
    let response = app
        .client_post(
            "/oauth/revoke",
            Some((
                &other.client.client_id,
                other.client_secret.as_deref().unwrap(),
            )),
            &[("token", &rt)],
        )
        .await;
    assert_eq!(response.json()["error"], "unauthorized_client");
    assert_eq!(
        refresh(&app, &client, &rt, &[]).await.status,
        StatusCode::OK
    );
}
