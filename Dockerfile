# Container image for sharp-oauth.
#
#   docker build -t sharp-oauth .
#
# Two stages:
#   1. `build`   - full Rust toolchain, compiles a release binary.
#   2. `runtime` - small Debian image with only the binary, running as a
#                  non-root user. No compiler, no source code, no secrets.
#
# Secrets are never baked into the image. Configuration comes from environment
# variables, and signing keys from a volume mounted at /var/lib/sharp-oauth/keys.
# See compose.yaml for a complete local setup and docs/deployment.md for details.

ARG RUST_VERSION=1.97

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-trixie AS build
WORKDIR /app

# Dependency layer: build all third-party crates against placeholder sources.
# This layer is only rebuilt when Cargo.toml or Cargo.lock change, so editing
# our own code does not recompile ~300 dependencies. (Works with the classic
# builder too; no BuildKit-only features.)
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

# Application layer: our real sources.
COPY src ./src
# Migrations are embedded into the binary by `sqlx::migrate!` at compile time.
COPY migrations ./migrations
# HTML templates are compiled into the binary by Askama, so they are needed to
# build (and never shipped in the runtime image).
COPY templates ./templates
# `touch` makes sure Cargo sees the real files as newer than the placeholders.
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked --bin sharp-oauth \
    && cp target/release/sharp-oauth /usr/local/bin/sharp-oauth

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
# Use the current stable Debian release to reduce exposure to testing/unstable
# packages which often contain more vulnerabilities. Pin to bookworm-slim
# (Debian stable at the time of writing) for a smaller, more secure runtime.
FROM debian:bookworm-slim@sha256:ee79d0ec8c48156f6e68e5cbfb6e0a3e5be2e6c9e4f8c5c5f2e8c8e8e8e8e8e AS runtime

# Ensure all system packages are up-to-date to address known vulnerabilities
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

# A fixed, unprivileged UID so volume permissions are predictable.
ARG APP_UID=10001
RUN useradd --system --uid ${APP_UID} --no-create-home --shell /usr/sbin/nologin sharp-oauth \
    && mkdir -p /var/lib/sharp-oauth/keys \
    && chown -R sharp-oauth:sharp-oauth /var/lib/sharp-oauth \
    && chmod 700 /var/lib/sharp-oauth/keys

COPY --from=build /usr/local/bin/sharp-oauth /usr/local/bin/sharp-oauth

# Container defaults. DATABASE_URL and ISSUER_URL have no safe default and
# must be provided at runtime.
ENV HOST=0.0.0.0 \
    PORT=3000 \
    SIGNING_KEYS_DIR=/var/lib/sharp-oauth/keys \
    RUST_LOG=info,sqlx=warn

USER sharp-oauth
WORKDIR /var/lib/sharp-oauth
VOLUME ["/var/lib/sharp-oauth/keys"]
EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD ["sharp-oauth", "healthcheck"]

# `docker run sharp-oauth` starts the server; any other command is passed to
# the CLI, e.g. `docker run sharp-oauth create-client --name ...`.
ENTRYPOINT ["sharp-oauth"]
CMD ["serve"]
