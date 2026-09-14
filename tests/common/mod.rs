//! Shared helpers for the integration tests.
//!
//! Each test gets a fresh PostgreSQL database from `#[sqlx::test]` (created
//! from `DATABASE_URL`, migrated, and dropped afterwards). Requests go
//! straight into the Axum router with `tower::ServiceExt::oneshot`, so no
//! port is opened, but every middleware, extractor and SQL query runs for real.

#![allow(dead_code)] // Not every test file uses every helper.

use std::{collections::HashMap, sync::OnceLock};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use sharp_oauth::{
    AppState, app,
    config::Config,
    identity::user::{self, NewAccount, User},
    oauth::{
        client::{self, NewClient, RegisteredClient},
        pkce,
        scope::ScopeSet,
    },
    secret::generate_token,
    token::signing::{SigningKeys, generate_rsa_private_key_pem},
};
use sqlx::PgPool;
use tower::ServiceExt;

pub const ISSUER: &str = "http://localhost:3000";
pub const REDIRECT_URI: &str = "https://client.example/callback";
pub const PASSWORD: &str = "correct horse battery staple";

/// One RSA key per test binary; generating one per test would be slow.
fn test_key_pem() -> &'static str {
    static PEM: OnceLock<String> = OnceLock::new();
    PEM.get_or_init(|| generate_rsa_private_key_pem().expect("generate test key"))
}

pub struct TestApp {
    pub state: AppState,
    router: Router,
}

impl TestApp {
    pub fn new(pool: PgPool) -> Self {
        let keys = SigningKeys::from_pems(
            vec![("test-key".into(), test_key_pem().as_bytes().to_vec())],
            None,
        )
        .expect("load test key");
        let config = Config {
            database_url: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            issuer: ISSUER.into(),
            signing_keys_dir: "keys".into(),
            signing_active_kid: None,
        };
        let state = AppState::new(config, pool, keys);
        Self {
            router: app(state.clone()),
            state,
        }
    }

    pub fn db(&self) -> &PgPool {
        &self.state.db
    }

    pub async fn send(&self, request: Request<Body>) -> TestResponse {
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("router is infallible");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        TestResponse {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    pub async fn get(&self, uri: &str) -> TestResponse {
        self.send(Request::get(uri).body(Body::empty()).unwrap())
            .await
    }

    /// `POST /oauth/token` (or any form endpoint) as a client application.
    pub async fn client_post(
        &self,
        uri: &str,
        basic_auth: Option<(&str, &str)>,
        form: &[(&str, &str)],
    ) -> TestResponse {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some((id, secret)) = basic_auth {
            request = request.header(
                header::AUTHORIZATION,
                format!("Basic {}", STANDARD.encode(format!("{id}:{secret}"))),
            );
        }
        self.send(request.body(Body::from(encode_form(form))).unwrap())
            .await
    }

    pub async fn get_with_bearer(&self, uri: &str, token: &str) -> TestResponse {
        let request = Request::get(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        self.send(request).await
    }

    pub async fn create_user(&self, email: &str) -> User {
        user::sign_up(
            self.db(),
            NewAccount {
                email: email.into(),
                password: PASSWORD.into(),
                display_name: Some("Test User".into()),
            },
        )
        .await
        .expect("create user")
    }

    pub async fn register_client(&self, scopes: &str, confidential: bool) -> RegisteredClient {
        client::register(
            self.db(),
            NewClient {
                name: "Example App".into(),
                redirect_uris: vec![REDIRECT_URI.into()],
                scopes: ScopeSet::parse(scopes).unwrap(),
                confidential,
            },
        )
        .await
        .expect("register client")
    }
}

pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl TestResponse {
    pub fn location(&self) -> &str {
        self.headers
            .get(header::LOCATION)
            .unwrap_or_else(|| {
                panic!(
                    "expected a redirect, got {} with body {}",
                    self.status, self.body
                )
            })
            .to_str()
            .unwrap()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.body))
    }

    /// All `<input type="hidden">` fields of the page, HTML-unescaped.
    pub fn hidden_fields(&self) -> Vec<(String, String)> {
        let marker = "<input type=\"hidden\" name=\"";
        self.body
            .match_indices(marker)
            .map(|(start, _)| {
                let rest = &self.body[start + marker.len()..];
                let (name, rest) = rest.split_once("\" value=\"").unwrap();
                let (value, _) = rest.split_once('"').unwrap();
                (html_unescape(name), html_unescape(value))
            })
            .collect()
    }

    pub fn hidden_field(&self, name: &str) -> Option<String> {
        self.hidden_fields()
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }
}

/// A minimal browser: remembers cookies between requests.
pub struct Browser<'a> {
    app: &'a TestApp,
    pub cookies: HashMap<String, String>,
}

impl<'a> Browser<'a> {
    pub fn new(app: &'a TestApp) -> Self {
        Self {
            app,
            cookies: HashMap::new(),
        }
    }

    pub async fn get(&mut self, uri: &str) -> TestResponse {
        let request = Request::get(uri).header(header::COOKIE, self.cookie_header());
        let response = self.app.send(request.body(Body::empty()).unwrap()).await;
        self.store_cookies(&response.headers);
        response
    }

    pub async fn post_form(&mut self, uri: &str, form: &[(&str, &str)]) -> TestResponse {
        let request = Request::post(uri)
            .header(header::COOKIE, self.cookie_header())
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        let response = self
            .app
            .send(request.body(Body::from(encode_form(form))).unwrap())
            .await;
        self.store_cookies(&response.headers);
        response
    }

    /// Submits the form on `page` with its hidden fields plus `extra`.
    pub async fn submit(
        &mut self,
        page: &TestResponse,
        action: &str,
        extra: &[(&str, &str)],
    ) -> TestResponse {
        let hidden = page.hidden_fields();
        let mut form: Vec<(&str, &str)> = hidden
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        form.extend_from_slice(extra);
        self.post_form(action, &form).await
    }

    /// Signs in through the real sign-in page. Returns the redirect response.
    pub async fn sign_in(&mut self, email: &str, return_to: Option<&str>) -> TestResponse {
        let uri = match return_to {
            Some(path) => format!("/signin?{}", encode_form(&[("return_to", path)])),
            None => "/signin".into(),
        };
        let page = self.get(&uri).await;
        assert_eq!(page.status, StatusCode::OK);
        self.submit(
            &page,
            "/signin",
            &[("email", email), ("password", PASSWORD)],
        )
        .await
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn store_cookies(&mut self, headers: &HeaderMap) {
        for value in headers.get_all(header::SET_COOKIE) {
            let value = value.to_str().unwrap();
            let (pair, attributes) = value.split_once(';').unwrap_or((value, ""));
            let (name, cookie_value) = pair.split_once('=').unwrap();
            if cookie_value.is_empty() || attributes.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies
                    .insert(name.to_owned(), cookie_value.to_owned());
            }
        }
    }
}

/// A PKCE verifier and its S256 challenge.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

pub fn new_pkce() -> Pkce {
    let verifier = generate_token();
    let challenge = pkce::s256_challenge(&verifier);
    Pkce {
        verifier,
        challenge,
    }
}

/// Builds `/oauth/authorize?...`. Pairs in `overrides` replace or add
/// parameters; an empty value removes the parameter.
pub fn authorize_uri(
    client_id: &str,
    scope: &str,
    pkce: &Pkce,
    overrides: &[(&str, &str)],
) -> String {
    let mut params: Vec<(String, String)> = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("scope", scope),
        ("state", "state-123"),
        ("code_challenge", pkce.challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("nonce", "nonce-456"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();

    for (name, value) in overrides {
        params.retain(|(k, _)| k != name);
        if !value.is_empty() {
            params.push((name.to_string(), value.to_string()));
        }
    }
    let pairs: Vec<(&str, &str)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    format!("/oauth/authorize?{}", encode_form(&pairs))
}

pub fn encode_form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// Reads a query parameter from an absolute or relative URL.
pub fn query_param(location: &str, name: &str) -> Option<String> {
    let url = url::Url::parse(location)
        .or_else(|_| url::Url::parse(&format!("http://relative{location}")))
        .unwrap();
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn html_unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Runs the browser part of the flow for a signed-in browser: authorize,
/// approve consent if asked, and return the authorization code.
pub async fn authorize_and_approve(browser: &mut Browser<'_>, uri: &str) -> String {
    let response = browser.get(uri).await;
    let callback = if response.status == StatusCode::OK {
        // Consent page.
        let approved = browser
            .submit(&response, "/oauth/consent", &[("decision", "approve")])
            .await;
        assert_eq!(
            approved.status,
            StatusCode::SEE_OTHER,
            "consent failed: {}",
            approved.body
        );
        approved.location().to_owned()
    } else {
        assert_eq!(
            response.status,
            StatusCode::SEE_OTHER,
            "authorize failed: {}",
            response.body
        );
        response.location().to_owned()
    };
    assert!(
        callback.starts_with(REDIRECT_URI),
        "unexpected redirect {callback}"
    );
    query_param(&callback, "code").unwrap_or_else(|| panic!("no code in {callback}"))
}

/// Exchanges a code at the token endpoint with client_secret_basic.
pub async fn exchange_code(
    app: &TestApp,
    client: &RegisteredClient,
    code: &str,
    verifier: &str,
) -> TestResponse {
    app.client_post(
        "/oauth/token",
        Some((
            &client.client.client_id,
            client.client_secret.as_deref().unwrap(),
        )),
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier),
        ],
    )
    .await
}
