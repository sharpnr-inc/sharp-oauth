//! Integration tests: health, sign-up, sign-in, sessions and logout.

mod common;

use axum::http::StatusCode;
use common::{Browser, PASSWORD, TestApp};
use sqlx::PgPool;

#[sqlx::test]
async fn health_endpoint_responds(pool: PgPool) {
    let app = TestApp::new(pool);
    let response = app.get("/health").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "sharp-oauth is alive");
}

#[sqlx::test]
async fn security_headers_are_present(pool: PgPool) {
    let app = TestApp::new(pool);
    let response = app.get("/signin").await;
    assert_eq!(response.headers["x-frame-options"], "DENY");
    assert!(
        response.headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(response.headers["cache-control"], "no-store");
}

#[sqlx::test]
async fn sign_up_creates_account_and_session(pool: PgPool) {
    let app = TestApp::new(pool);
    let mut browser = Browser::new(&app);

    let page = browser.get("/signup").await;
    let response = browser
        .submit(
            &page,
            "/signup",
            &[
                ("email", "New@Example.com"),
                ("password", PASSWORD),
                ("display_name", "New"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    assert_eq!(response.location(), "/");
    assert!(browser.cookies.contains_key("sharp_session"));

    let home = browser.get("/").await;
    assert!(
        home.body.contains("new@example.com"),
        "email should be normalised: {}",
        home.body
    );

    // The password is stored as an Argon2id hash, never in plaintext.
    let hash: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE email = 'new@example.com'")
            .fetch_one(app.db())
            .await
            .unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(!hash.contains(PASSWORD));
}

#[sqlx::test]
async fn duplicate_email_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("taken@example.com").await;
    let mut browser = Browser::new(&app);

    let page = browser.get("/signup").await;
    let response = browser
        .submit(
            &page,
            "/signup",
            &[("email", "TAKEN@example.com"), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response.body.contains("already exists"));
}

#[sqlx::test]
async fn sign_in_logout_and_session_invalidation(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);

    let response = browser.sign_in("user@example.com", None).await;
    assert_eq!(response.status, StatusCode::SEE_OTHER);
    let session_cookie = browser.cookies["sharp_session"].clone();
    assert!(browser.get("/").await.body.contains("signed in as"));

    // The raw session token is not stored in the database.
    let raw_stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM user_sessions WHERE session_token_hash = $1")
            .bind(&session_cookie)
            .fetch_one(app.db())
            .await
            .unwrap();
    assert_eq!(raw_stored, 0);

    let home = browser.get("/").await;
    let logout = browser.submit(&home, "/logout", &[]).await;
    assert_eq!(logout.status, StatusCode::SEE_OTHER);
    assert!(!browser.cookies.contains_key("sharp_session"));

    // Re-using the old cookie after logout must not work: the session was
    // revoked server-side, not just deleted from the browser.
    browser
        .cookies
        .insert("sharp_session".into(), session_cookie);
    assert!(browser.get("/").await.body.contains("not signed in"));
}

#[sqlx::test]
async fn wrong_password_and_unknown_email_look_identical(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);

    let page = browser.get("/signin").await;
    let wrong_password = browser
        .submit(
            &page,
            "/signin",
            &[("email", "user@example.com"), ("password", "nope-nope")],
        )
        .await;
    let unknown_email = browser
        .submit(
            &page,
            "/signin",
            &[("email", "ghost@example.com"), ("password", "nope-nope")],
        )
        .await;

    assert_eq!(wrong_password.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_email.status, StatusCode::UNAUTHORIZED);
    assert!(wrong_password.body.contains("Invalid email or password."));
    assert!(unknown_email.body.contains("Invalid email or password."));
    assert!(!browser.cookies.contains_key("sharp_session"));
}

#[sqlx::test]
async fn sign_in_without_csrf_token_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);

    // Simulates a cross-site form post: no CSRF cookie / field.
    let response = browser
        .post_form(
            "/signin",
            &[("email", "user@example.com"), ("password", PASSWORD)],
        )
        .await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(!browser.cookies.contains_key("sharp_session"));
}

#[sqlx::test]
async fn sign_in_does_not_redirect_off_site(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("user@example.com").await;
    let mut browser = Browser::new(&app);

    for evil in [
        "https://evil.example/phish",
        "//evil.example",
        "/\\evil.example",
    ] {
        let response = browser.sign_in("user@example.com", Some(evil)).await;
        assert_eq!(
            response.location(),
            "/",
            "return_to {evil:?} must be ignored"
        );
    }
}
