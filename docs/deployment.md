# Running in containers

Sharp-OAuth ships as a single container image. It needs two things from the
outside: a **PostgreSQL database** and a **directory of signing keys**.

## Files

| File            | Purpose                                                            |
|-----------------|--------------------------------------------------------------------|
| `Dockerfile`    | Two-stage build: compile with the Rust image, run on `debian:trixie-slim` as a non-root user |
| `.dockerignore` | Keeps `.env`, `keys/`, `target/` and `.git/` out of the build context |
| `compose.yaml`  | Local stack: PostgreSQL + a one-shot key generator + the server    |

## Local stack with Docker Compose

```bash
docker compose up --build -d          # build and start in the background
docker compose logs -f sharp-oauth    # follow logs
curl http://localhost:3000/health     # → sharp-oauth is alive
```

What happens on `up`:

```text
db (postgres:18)  ──healthy──┐
                             ├──▶ sharp-oauth (serve, runs migrations, listens on :3000)
signing-key (one-shot) ──done┘
```

1. `db` starts and waits until `pg_isready` passes.
2. `signing-key` runs `sharp-oauth generate-signing-key --if-missing`. On the
   first start it creates an RSA key in the `signing-keys` volume; on later
   starts it sees a key and exits without doing anything.
3. `sharp-oauth` starts, applies migrations and serves on port 3000
   (published on `127.0.0.1` only).

### Register a client

The image's entrypoint is the `sharp-oauth` CLI, so any subcommand works with
`docker compose run`:

```bash
docker compose run --rm sharp-oauth create-client \
    --name "Demo App" \
    --redirect-uri http://localhost:4000/callback \
    --scopes "openid profile email offline_access"
```

Then the demo script works exactly as with `cargo run`:

```bash
CLIENT_ID=sharp_client_... CLIENT_SECRET=sharp_secret_... scripts/demo-flow.sh
```

### Port 3000 already in use?

If `cargo run` (or anything else) is using 3000:

```bash
SHARP_OAUTH_PORT=3100 docker compose up -d
curl http://localhost:3100/health
ISSUER_URL=http://localhost:3100 CLIENT_ID=... CLIENT_SECRET=... scripts/demo-flow.sh
```

`ISSUER_URL` follows `SHARP_OAUTH_PORT` automatically, because the issuer must
be the URL clients actually use.

### Useful commands

| Command | What it does |
|---|---|
| `docker compose ps` | Status and health of each service |
| `docker compose run --rm sharp-oauth generate-signing-key` | Add a new key (key rotation); restart to load it |
| `docker compose restart sharp-oauth` | Reload keys/config |
| `docker compose exec db psql -U sharp_oauth` | Database shell |
| `docker compose down` | Stop. Database and keys are kept in volumes |
| `docker compose down -v` | Stop and **delete** the database and signing keys |

## The image

```bash
docker build -t sharp-oauth .
```

* **Build stage** compiles dependencies in their own layer (rebuilt only when
  `Cargo.toml`/`Cargo.lock` change), then the application. Migrations are
  compiled into the binary.
* **Runtime stage** contains only the binary. It runs as UID `10001`
  (`sharp-oauth`), not root. No compiler, source code or secrets are in it.
* `HEALTHCHECK` runs `sharp-oauth healthcheck`, which calls `GET /health`
  locally, so the image does not need `curl`.
* The server handles `SIGTERM`, so `docker stop` lets in-flight requests finish.

### Configuration inside the container

| Variable | Image default | Notes |
|---|---|---|
| `DATABASE_URL` | none (required) | |
| `ISSUER_URL` | none (required) | The public URL, e.g. `https://auth.sharpnr.com` |
| `HOST` | `0.0.0.0` | Must not be `127.0.0.1` in a container, or nothing outside can connect |
| `PORT` | `3000` | |
| `SIGNING_KEYS_DIR` | `/var/lib/sharp-oauth/keys` | A volume |
| `SIGNING_ACTIVE_KID` | newest key | |
| `RUST_LOG` | `info,sqlx=warn` | |

### Running the image without Compose

```bash
docker volume create sharp-oauth-keys
docker run --rm -v sharp-oauth-keys:/var/lib/sharp-oauth/keys sharp-oauth generate-signing-key --if-missing

docker run -d --name sharp-oauth \
    -p 127.0.0.1:3000:3000 \
    -v sharp-oauth-keys:/var/lib/sharp-oauth/keys \
    -e DATABASE_URL=postgres://user:password@db-host:5432/sharp_oauth \
    -e ISSUER_URL=https://auth.sharpnr.com \
    sharp-oauth
```

If you mount a host directory instead of a volume, it must be readable by UID
10001: `chown 10001 ./keys && chmod 700 ./keys`.

## Before running this in production

`compose.yaml` is a development setup. For a real deployment:

1. **TLS in front.** Put a reverse proxy or load balancer terminating HTTPS in
   front of the container and set `ISSUER_URL=https://…`. That also turns on
   `Secure` cookies. Sharp-OAuth refuses a non-localhost `http` issuer.
2. **Real database credentials.** Use a managed PostgreSQL or at least a
   strong `POSTGRES_PASSWORD`, passed as a secret, never committed.
3. **Signing keys from a secret manager.** Mount them read-only at
   `SIGNING_KEYS_DIR` instead of generating them in a volume, and back them up.
   Losing the key invalidates all issued tokens; leaking it lets anyone forge them.
4. **Pin the image** by digest or version tag rather than `:dev`.
5. **Keep the base images updated.** Rebuild regularly so Debian security
   fixes are picked up, and scan the image (e.g. `docker scout cves sharp-oauth:dev`).
6. **Multiple replicas are fine.** All state is in PostgreSQL; every replica
   needs the same keys and the same `ISSUER_URL`. Note that migrations run on
   startup, so start one replica first when deploying a schema change.
7. **Rate limiting** is not built in yet (plan phase 10). Add it at the proxy.
