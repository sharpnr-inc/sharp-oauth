//! The `sharp-oauth` binary.
//!
//! ```text
//! sharp-oauth [serve]                      Run the server (default)
//! sharp-oauth generate-signing-key         Create a new RSA key in SIGNING_KEYS_DIR
//!     [--if-missing]                       only if the directory has no keys yet
//! sharp-oauth healthcheck                  Exit 0 if GET /health succeeds (for containers)
//! sharp-oauth create-client                Register an OAuth client
//!     --name <NAME>
//!     --redirect-uri <URI>                 (repeat for several)
//!     --scopes "<SCOPE> <SCOPE> ..."       e.g. "openid profile email offline_access"
//!     [--public]                           no client secret (SPA / mobile / desktop)
//! ```
//!
//! With Cargo, put the arguments after `--`:
//! `cargo run -- create-client --name "Demo" ...`

use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use sharp_oauth::{
    AppState, app,
    config::Config,
    oauth::services::{
        client::{self, NewClient},
        scope::ScopeSet,
    },
    pkg::jwt_manager::{self, SigningKeys},
    shared::database,
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
        Some("generate-signing-key") => generate_signing_key(&args[1..]),
        Some("create-client") => create_client(&args[1..]).await,
        Some("healthcheck") => healthcheck(),
        Some(other) => bail!(
            "unknown command {other:?}; expected serve, generate-signing-key, create-client or healthcheck"
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

    let pool = database::connect(&config.database_url).await?;
    database::migrate(&pool).await?;
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

/// Resolves on Ctrl+C or SIGTERM so in-flight requests can finish before exit.
///
/// SIGTERM matters in containers: `docker stop` and Kubernetes send it, and a
/// process running as PID 1 that does not handle it is killed after a timeout.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}

fn generate_signing_key(args: &[String]) -> Result<()> {
    let if_missing = match args {
        [] => false,
        [flag] if flag == "--if-missing" => true,
        _ => bail!("usage: generate-signing-key [--if-missing]"),
    };

    let dir = Config::signing_keys_dir_from_env();
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;

    // `--if-missing` makes this safe to run on every container start: it
    // creates the first key once and never rotates keys by accident.
    if if_missing && has_pem_file(&dir)? {
        println!(
            "Signing key already present in {}; nothing to do.",
            dir.display()
        );
        return Ok(());
    }

    let kid = jwt_manager::new_kid();
    let path = dir.join(format!("{kid}.pem"));
    let pem = jwt_manager::generate_rsa_private_key_pem()?;
    write_private_file(&path, pem.as_bytes())?;

    println!("Created signing key {kid}");
    println!("  file: {}", path.display());
    println!("It becomes the active key the next time the server starts.");
    Ok(())
}

fn has_pem_file(dir: &Path) -> Result<bool> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        if entry?.path().extension().and_then(|ext| ext.to_str()) == Some("pem") {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Calls `GET /health` on the local server and fails unless it answers 200.
///
/// Exists so container health checks work without shipping `curl` in the
/// runtime image. It only reads `PORT` (not the full config), so it needs no
/// database credentials.
fn healthcheck() -> Result<()> {
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_owned());
    let address = format!("127.0.0.1:{port}");

    let mut stream =
        TcpStream::connect(&address).with_context(|| format!("cannot connect to {address}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    if response.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        bail!(
            "unhealthy: {}",
            response.lines().next().unwrap_or("empty response")
        )
    }
}

/// Writes a file readable only by the current user (mode 0600 on Unix).
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
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
    let pool = database::connect(&config.database_url).await?;
    database::migrate(&pool).await?;

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
