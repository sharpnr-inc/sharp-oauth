//! The `sharp-oauth` binary.
//!
//! ```text
//! sharp-oauth [serve]                      Run the server (default)
//! sharp-oauth generate-signing-key         Create a new RSA key in SIGNING_KEYS_DIR
//! sharp-oauth create-client                Register an OAuth client
//!     --name <NAME>
//!     --redirect-uri <URI>                 (repeat for several)
//!     --scopes "<SCOPE> <SCOPE> ..."       e.g. "openid profile email offline_access"
//!     [--public]                           no client secret (SPA / mobile / desktop)
//! ```
//!
//! With Cargo, put the arguments after `--`:
//! `cargo run -- create-client --name "Demo" ...`

use std::path::Path;

use anyhow::{Context, Result, bail};
use sharp_oauth::{
    AppState, app,
    config::Config,
    db,
    oauth::{
        client::{self, NewClient},
        scope::ScopeSet,
    },
    token::signing::{self, SigningKeys},
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // A missing .env file is fine; real deployments set variables directly.
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("RUST_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("serve") => serve().await,
        Some("generate-signing-key") => generate_signing_key(),
        Some("create-client") => create_client(&args[1..]).await,
        Some(other) => bail!(
            "unknown command {other:?}; expected serve, generate-signing-key or create-client"
        ),
    }
}

async fn serve() -> Result<()> {
    let config = Config::from_env()?;

    let signing_keys = SigningKeys::load_from_dir(
        &config.signing_keys_dir,
        config.signing_active_kid.as_deref(),
    )?;
    tracing::info!(
        active_kid = signing_keys.active_kid(),
        "signing keys loaded"
    );

    let pool = db::connect(&config.database_url).await?;
    db::migrate(&pool).await?;
    tracing::info!("database migrations applied");

    let address = format!("{}:{}", config.host, config.port);
    let issuer = config.issuer.clone();
    let state = AppState::new(config, pool, signing_keys);

    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .with_context(|| format!("cannot listen on {address}"))?;
    tracing::info!(%address, %issuer, "sharp-oauth is listening");

    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")
}

/// Resolves on Ctrl+C so in-flight requests can finish before exit.
async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("shutting down");
}

fn generate_signing_key() -> Result<()> {
    let dir = Config::signing_keys_dir_from_env();
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;

    let kid = signing::new_kid();
    let path = dir.join(format!("{kid}.pem"));
    let pem = signing::generate_rsa_private_key_pem()?;
    write_private_file(&path, pem.as_bytes())?;

    println!("Created signing key {kid}");
    println!("  file: {}", path.display());
    println!("It becomes the active key the next time the server starts.");
    Ok(())
}

/// Writes a file readable only by the current user (mode 0600 on Unix).
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(contents)?;
    Ok(())
}

async fn create_client(args: &[String]) -> Result<()> {
    let mut name = None;
    let mut redirect_uris = Vec::new();
    let mut scopes = None;
    let mut public = false;

    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let mut value = || args.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--name" => name = Some(value()?.clone()),
            "--redirect-uri" => redirect_uris.push(value()?.clone()),
            "--scopes" => scopes = Some(value()?.clone()),
            "--public" => public = true,
            other => bail!("unknown option {other:?}"),
        }
    }

    let name = name.context("--name is required")?;
    let scopes = ScopeSet::parse(&scopes.context("--scopes is required")?)
        .context("--scopes must be a space-separated list")?;

    let config = Config::from_env()?;
    let pool = db::connect(&config.database_url).await?;
    db::migrate(&pool).await?;

    let registered = client::register(
        &pool,
        NewClient {
            name,
            redirect_uris,
            scopes,
            confidential: !public,
        },
    )
    .await?;

    let c = &registered.client;
    println!("Registered client \"{}\"", c.name);
    println!("  client_id:      {}", c.client_id);
    match &registered.client_secret {
        Some(secret) => {
            println!("  client_secret:  {secret}");
            println!("  (store the secret now; it cannot be shown again)");
        }
        None => println!("  type:           public (no secret, PKCE only)"),
    }
    println!("  redirect_uris:  {}", c.redirect_uris.join(", "));
    println!("  scopes:         {}", c.allowed_scopes.join(" "));
    Ok(())
}
