//! Integration tests: the developer portal (`/developer/apps`).

mod common;

use axum::http::StatusCode;
use common::{Browser, REDIRECT_URI, TestApp, TestResponse, authorize_uri, new_pkce, query_param};
use sqlx::PgPool;

/// The text of `<code id="{id}" ...>…</code>` on a page.
fn code_by_id(page: &TestResponse, id: &str) -> Option<String> {
    let start = page.body.find(&format!("<code id=\"{id}\""))?;
    let rest = &page.body[start..];
    let rest = &rest[rest.find('>')? + 1..];
    Some(rest[..rest.find("</code>")?].trim().to_owned())
}

/// Opens the "new application" page and submits its form.
async fn create_app(browser: &mut Browser<'_>, extra: &[(&str, &str)]) -> TestResponse {
    let page = browser.get("/developer/apps/new").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    browser.submit(&page, "/developer/apps", extra).await
}

const CONFIDENTIAL_APP: &[(&str, &str)] = &[
    ("name", "My App"),
    ("client_type", "confidential"),
    ("redirect_uris", REDIRECT_URI),
    ("scope", "openid"),
    ("scope", "email"),
];

#[sqlx::test]
async fn portal_requires_sign_in(pool: PgPool) {
    let app = TestApp::new(pool);
    for path in ["/developer/apps", "/developer/apps/new"] {
        let response = app.get(path).await;
        assert_eq!(response.status, StatusCode::SEE_OTHER);
        assert_eq!(
            query_param(response.location(), "return_to").as_deref(),
            Some(path)
        );
    }
}

#[sqlx::test]
async fn created_app_shows_secret_once_and_works_for_sign_in(pool: PgPool) {
    let app = TestApp::new(pool);
    let owner = app.create_user("dev@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("dev@example.com", None).await;

    let created = create_app(&mut browser, CONFIDENTIAL_APP).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let client_id = code_by_id(&created, "client-id").expect("client id on page");
    let secret = code_by_id(&created, "client-secret").expect("secret on page");
    assert!(client_id.starts_with("sharp_client_"));
    assert!(secret.starts_with("sharp_secret_"));

    // Stored with its owner, and the secret only as a hash.
    let (owner_id, secret_hash): (Option<uuid::Uuid>, String) = sqlx::query_as(
        "SELECT owner_user_id, client_secret_hash FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&client_id)
    .fetch_one(app.db())
    .await
    .unwrap();
    assert_eq!(owner_id, Some(owner.id));
    assert!(!secret_hash.contains(&secret));

    // The list shows it; the app page no longer shows the secret.
    let list = browser.get("/developer/apps").await;
    assert!(list.body.contains(&client_id), "{}", list.body);
    let page = browser.get(&format!("/developer/apps/{client_id}")).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(code_by_id(&page, "client-secret").is_none());
    assert!(!page.body.contains(&secret));

    // The credentials from the page complete a real authorization code flow.
    let pkce = new_pkce();
    let code = common::authorize_and_approve(
        &mut browser,
        &authorize_uri(&client_id, "openid email", &pkce, &[]),
    )
    .await;
    let tokens = app
        .client_post(
            "/oauth/token",
            Some((&client_id, &secret)),
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT_URI),
                ("code_verifier", &pkce.verifier),
            ],
        )
        .await;
    assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
    assert!(tokens.json()["id_token"].is_string());
}

#[sqlx::test]
async fn public_app_has_no_secret(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("dev@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("dev@example.com", None).await;

    let created = create_app(
        &mut browser,
        &[
            ("name", "My SPA"),
            ("client_type", "public"),
            ("redirect_uris", "http://localhost:5173/callback"),
            ("scope", "openid"),
        ],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert!(code_by_id(&created, "client-secret").is_none());
    let client_id = code_by_id(&created, "client-id").unwrap();

    let hash: Option<String> =
        sqlx::query_scalar("SELECT client_secret_hash FROM oauth_clients WHERE client_id = $1")
            .bind(&client_id)
            .fetch_one(app.db())
            .await
            .unwrap();
    assert!(hash.is_none());
}

#[sqlx::test]
async fn invalid_app_is_rejected_and_form_is_kept(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("dev@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("dev@example.com", None).await;

    let response = create_app(
        &mut browser,
        &[
            ("name", "Kept Name"),
            ("redirect_uris", "http://app.example.com/cb"),
            ("scope", "openid"),
        ],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        response.body.contains("must use https"),
        "{}",
        response.body
    );
    assert!(
        response.body.contains(r#"value="Kept Name""#),
        "{}",
        response.body
    );

    let no_scopes = create_app(
        &mut browser,
        &[("name", "App"), ("redirect_uris", REDIRECT_URI)],
    )
    .await;
    assert_eq!(no_scopes.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(no_scopes.body.contains("Choose at least one scope"));

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_clients")
        .fetch_one(app.db())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test]
async fn create_without_csrf_token_is_forbidden(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("dev@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("dev@example.com", None).await;

    let response = browser.post_form("/developer/apps", CONFIDENTIAL_APP).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn other_users_cannot_see_or_change_an_app(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("owner@example.com").await;
    app.create_user("other@example.com").await;

    let mut owner = Browser::new(&app);
    owner.sign_in("owner@example.com", None).await;
    let created = create_app(&mut owner, CONFIDENTIAL_APP).await;
    let client_id = code_by_id(&created, "client-id").unwrap();

    let mut other = Browser::new(&app);
    other.sign_in("other@example.com", None).await;
    assert!(!other.get("/developer/apps").await.body.contains(&client_id));

    let page_path = format!("/developer/apps/{client_id}");
    assert_eq!(other.get(&page_path).await.status, StatusCode::NOT_FOUND);

    // Use a real CSRF token of the other user's own, so only ownership is tested.
    let own_page = other.get("/developer/apps/new").await;
    for (path, extra) in [
        (
            page_path.clone(),
            vec![
                ("name", "Hijacked"),
                ("redirect_uris", REDIRECT_URI),
                ("scope", "openid"),
            ],
        ),
        (format!("{page_path}/secret"), vec![]),
        (format!("{page_path}/delete"), vec![("confirm", "yes")]),
    ] {
        let response = other.submit(&own_page, &path, &extra).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{path}");
    }

    let name: String = sqlx::query_scalar("SELECT name FROM oauth_clients WHERE client_id = $1")
        .bind(&client_id)
        .fetch_one(app.db())
        .await
        .unwrap();
    assert_eq!(name, "My App");
}

#[sqlx::test]
async fn owner_can_edit_rotate_and_delete(pool: PgPool) {
    let app = TestApp::new(pool);
    app.create_user("dev@example.com").await;
    let mut browser = Browser::new(&app);
    browser.sign_in("dev@example.com", None).await;

    let created = create_app(&mut browser, CONFIDENTIAL_APP).await;
    let client_id = code_by_id(&created, "client-id").unwrap();
    let old_secret = code_by_id(&created, "client-secret").unwrap();
    let page_path = format!("/developer/apps/{client_id}");

    // Edit.
    let page = browser.get(&page_path).await;
    let saved = browser
        .submit(
            &page,
            &page_path,
            &[
                ("name", "Renamed"),
                (
                    "redirect_uris",
                    "https://new.example/cb\nhttp://localhost:4000/cb",
                ),
                ("scope", "openid"),
                ("scope", "profile"),
            ],
        )
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    assert_eq!(saved.location(), format!("{page_path}?notice=saved"));
    let (name, uris, scopes): (String, Vec<String>, Vec<String>) = sqlx::query_as(
        "SELECT name, redirect_uris, allowed_scopes FROM oauth_clients WHERE client_id = $1",
    )
    .bind(&client_id)
    .fetch_one(app.db())
    .await
    .unwrap();
    assert_eq!(name, "Renamed");
    assert_eq!(uris, ["https://new.example/cb", "http://localhost:4000/cb"]);
    assert_eq!(scopes, ["openid", "profile"]);

    // Rotate: the old secret stops working, the new one works.
    let page = browser.get(&page_path).await;
    let rotated = browser
        .submit(&page, &format!("{page_path}/secret"), &[])
        .await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let new_secret = code_by_id(&rotated, "client-secret").unwrap();
    assert_ne!(new_secret, old_secret);
    let revoke = |secret: String| {
        let (app, client_id) = (&app, client_id.clone());
        async move {
            app.client_post(
                "/oauth/revoke",
                Some((&client_id, &secret)),
                &[("token", "not-a-real-token")],
            )
            .await
            .status
        }
    };
    assert_eq!(revoke(old_secret).await, StatusCode::UNAUTHORIZED);
    assert_eq!(revoke(new_secret).await, StatusCode::OK);

    // Delete needs the confirmation box.
    let page = browser.get(&page_path).await;
    let unconfirmed = browser
        .submit(&page, &format!("{page_path}/delete"), &[])
        .await;
    assert_eq!(unconfirmed.status, StatusCode::UNPROCESSABLE_ENTITY);

    let deleted = browser
        .submit(&page, &format!("{page_path}/delete"), &[("confirm", "yes")])
        .await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER);
    assert_eq!(deleted.location(), "/developer/apps?notice=deleted");
    assert_eq!(browser.get(&page_path).await.status, StatusCode::NOT_FOUND);
}
