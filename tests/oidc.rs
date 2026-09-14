//! Integration tests: discovery, JWKS and UserInfo.

mod common;

use axum::http::StatusCode;
use chrono::Utc;
use common::{ISSUER, TestApp};
use sharp_oauth::{
    oauth::scope::ScopeSet,
    oidc::id_token::{self, IdTokenClaims},
    token::access::{self, AccessTokenClaims},
};
use sqlx::PgPool;

#[sqlx::test]
async fn discovery_document_advertises_what_is_implemented(pool: PgPool) {
    let app = TestApp::new(pool);
    let response = app.get("/.well-known/openid-configuration").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers["access-control-allow-origin"], "*");
    let doc = response.json();

    assert_eq!(doc["issuer"], ISSUER);
    assert_eq!(
        doc["authorization_endpoint"],
        format!("{ISSUER}/oauth/authorize")
    );
    assert_eq!(doc["token_endpoint"], format!("{ISSUER}/oauth/token"));
    assert_eq!(doc["jwks_uri"], format!("{ISSUER}/.well-known/jwks.json"));
    assert_eq!(doc["response_types_supported"], serde_json::json!(["code"]));
    assert_eq!(
        doc["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert_eq!(
        doc["id_token_signing_alg_values_supported"],
        serde_json::json!(["RS256"])
    );
    assert_eq!(doc["request_uri_parameter_supported"], false);
    assert_eq!(
        doc["scopes_supported"],
        serde_json::json!(["email", "offline_access", "openid", "profile"])
    );
}

#[sqlx::test]
async fn jwks_publishes_public_key_only(pool: PgPool) {
    let app = TestApp::new(pool);
    let jwks = app.get("/.well-known/jwks.json").await.json();
    let key = &jwks["keys"][0];
    assert_eq!(key["kid"], "test-key");
    assert_eq!(key["kty"], "RSA");
    assert!(key["n"].is_string());
    assert!(
        key.get("d").is_none(),
        "private exponent must never be published"
    );
}

async fn access_token_for(app: &TestApp, scope: &str) -> String {
    let user = app.create_user("user@example.com").await;
    let now = Utc::now();
    let claims = AccessTokenClaims::new(
        ISSUER,
        user.id,
        "sharp_client_x",
        &ScopeSet::parse(scope).unwrap(),
        now,
        now,
    );
    access::issue(&app.state.signing_keys, &claims).unwrap()
}

#[sqlx::test]
async fn userinfo_without_token_is_401_without_error_code(pool: PgPool) {
    let app = TestApp::new(pool);
    let response = app.get("/oauth/userinfo").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers["www-authenticate"],
        "Bearer realm=\"sharp-oauth\""
    );
}

#[sqlx::test]
async fn userinfo_rejects_garbage_token(pool: PgPool) {
    let app = TestApp::new(pool);
    let response = app.get_with_bearer("/oauth/userinfo", "not-a-jwt").await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(
        response.headers["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );
}

#[sqlx::test]
async fn userinfo_returns_claims_for_granted_scopes_only(pool: PgPool) {
    let app = TestApp::new(pool);
    let token = access_token_for(&app, "openid email").await;
    let claims = app.get_with_bearer("/oauth/userinfo", &token).await.json();
    assert_eq!(claims["email"], "user@example.com");
    assert!(
        claims.get("name").is_none(),
        "profile scope was not granted"
    );
}

#[sqlx::test]
async fn userinfo_requires_openid_scope(pool: PgPool) {
    let app = TestApp::new(pool);
    let token = access_token_for(&app, "email").await;
    let response = app.get_with_bearer("/oauth/userinfo", &token).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(
        response.headers["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("insufficient_scope")
    );
}

#[sqlx::test]
async fn id_token_cannot_be_used_as_access_token(pool: PgPool) {
    let app = TestApp::new(pool);
    let user = app.create_user("user@example.com").await;
    let now = Utc::now();
    // Make the audience equal the issuer, so only the `typ` check can catch it.
    let claims = IdTokenClaims::new(ISSUER, user.id, ISSUER, now, None, now);
    let token = id_token::issue(&app.state.signing_keys, &claims).unwrap();

    let response = app.get_with_bearer("/oauth/userinfo", &token).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn expired_access_token_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    let user = app.create_user("user@example.com").await;
    let long_ago = Utc::now() - chrono::Duration::hours(1);
    let claims = AccessTokenClaims::new(
        ISSUER,
        user.id,
        "c",
        &ScopeSet::parse("openid").unwrap(),
        long_ago,
        long_ago,
    );
    let token = access::issue(&app.state.signing_keys, &claims).unwrap();

    let response = app.get_with_bearer("/oauth/userinfo", &token).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn cors_preflight_is_answered_for_api_endpoints(pool: PgPool) {
    let app = TestApp::new(pool);
    let request = axum::http::Request::builder()
        .method("OPTIONS")
        .uri("/oauth/userinfo")
        .header("origin", "https://spa.example")
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "authorization")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.send(request).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers["access-control-allow-origin"], "*");
}
