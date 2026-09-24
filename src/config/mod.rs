//! Application configuration.
//!
//! All settings come from environment variables (a local `.env` file is loaded
//! by `main.rs` in development). See `.env.example` for a template.
//!
//! | Variable             | Required | Default      | Meaning                                  |
//! |----------------------|----------|--------------|------------------------------------------|
//! | `DATABASE_URL`       | yes      | –            | PostgreSQL connection string             |
//! | `HOST`               | no       | `127.0.0.1`  | Interface to listen on                   |
//! | `PORT`               | no       | `3000`       | Port to listen on                        |
//! | `ISSUER_URL`         | yes      | –            | Public base URL, e.g. `https://auth.sharpnr.com` |
//! | `SIGNING_KEYS_DIR`   | no       | `keys`       | Directory with RSA private keys (`*.pem`) |
//! | `SIGNING_ACTIVE_KID` | no       | newest key   | Key ID used to sign new tokens           |
//! | `RUST_LOG`           | no       | `info`       | Log filter, e.g. `debug,sqlx=warn`       |

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use url::Url;

/// Runtime configuration.
///
/// `Debug` is intentionally not derived: `database_url` may contain a password
/// and we never want it to end up in a log line by accident.
#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
    /// The OIDC issuer identifier, without a trailing slash.
    ///
    /// This exact string appears as the `iss` claim in every token and in the
    /// discovery document. Clients compare it byte-for-byte, so it must be
    /// stable and must match the public URL of the server.
    pub issuer: String,
    pub signing_keys_dir: PathBuf,
    pub signing_active_kid: Option<String>,
}

impl Config {
    /// Reads configuration from the process environment.
    pub fn from_env() -> Result<Self> {
        let database_url = required("DATABASE_URL")?;
        let host = optional("HOST").unwrap_or_else(|| "127.0.0.1".to_owned());
        let port = match optional("PORT") {
            Some(port) => port
                .parse()
                .context("PORT must be a number between 0 and 65535")?,
            None => 3000,
        };
        let issuer = normalize_issuer(&required("ISSUER_URL")?)?;

        Ok(Self {
            database_url,
            host,
            port,
            issuer,
            signing_keys_dir: Self::signing_keys_dir_from_env(),
            signing_active_kid: optional("SIGNING_ACTIVE_KID"),
        })
    }

    /// The key directory on its own, for commands that do not need a database.
    pub fn signing_keys_dir_from_env() -> PathBuf {
        optional("SIGNING_KEYS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("keys"))
    }

    /// Whether cookies should carry the `Secure` attribute.
    ///
    /// Derived from the issuer: when the public URL is HTTPS, browsers must
    /// never send our session cookie over plain HTTP. For `http://localhost`
    /// development we have to allow it or the cookie would never be sent.
    pub fn secure_cookies(&self) -> bool {
        self.issuer.starts_with("https://")
    }

    /// Builds an absolute URL for a path on this server, e.g. `/oauth/token`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.issuer, path)
    }
}

/// Validates `ISSUER_URL` and strips a trailing slash.
///
/// OpenID Connect Discovery requires the issuer to be an `https` URL with no
/// query or fragment. We additionally allow `http://localhost` (and loopback
/// IPs) so the server can be developed without TLS.
pub fn normalize_issuer(raw: &str) -> Result<String> {
    let url = Url::parse(raw).context("ISSUER_URL must be an absolute URL")?;

    if url.query().is_some() || url.fragment().is_some() {
        bail!("ISSUER_URL must not contain a query string or fragment");
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(&url) => {}
        _ => bail!("ISSUER_URL must use https (http is only allowed for localhost)"),
    }

    Ok(raw.trim_end_matches('/').to_owned())
}

/// True for `localhost`, `127.0.0.1` and `[::1]`.
pub fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn required(name: &str) -> Result<String> {
    optional(name).with_context(|| format!("environment variable {name} is required"))
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_trailing_slash_is_removed() {
        assert_eq!(
            normalize_issuer("https://auth.sharpnr.com/").unwrap(),
            "https://auth.sharpnr.com"
        );
    }

    #[test]
    fn http_issuer_is_only_allowed_for_loopback() {
        assert!(normalize_issuer("http://localhost:3000").is_ok());
        assert!(normalize_issuer("http://127.0.0.1:3000").is_ok());
        assert!(normalize_issuer("http://auth.sharpnr.com").is_err());
    }

    #[test]
    fn issuer_with_query_or_fragment_is_rejected() {
        assert!(normalize_issuer("https://auth.sharpnr.com/?a=b").is_err());
        assert!(normalize_issuer("https://auth.sharpnr.com/#x").is_err());
    }
}
