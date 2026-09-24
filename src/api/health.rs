//! `GET /health`

pub async fn health() -> &'static str {
    "sharp-oauth is alive"
}
