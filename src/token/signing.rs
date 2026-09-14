//! JWT signing keys, key rotation and JWKS.
//!
//! ## Where keys come from
//!
//! Keys are RSA private keys in PEM files inside `SIGNING_KEYS_DIR`
//! (default `keys/`). The file name without `.pem` is the key ID (`kid`):
//!
//! ```text
//! keys/
//! ├── 20260101T000000-a1b2c3.pem   ← older key, still published
//! └── 20260914T120000-d4e5f6.pem   ← newest key, signs new tokens
//! ```
//!
//! Private keys are never in source code or Git (`keys/` is git-ignored).
//! In production, mount this directory from a secret manager. Locally,
//! create a key with `cargo run -- generate-signing-key`.
//!
//! ## Why RS256
//!
//! OpenID Connect requires providers to support RS256, so every OIDC client
//! library can verify it. It is asymmetric: we sign with the private key and
//! anyone can verify with the public key, which is exactly what JWKS publishes.
//!
//! ## Key rotation without breaking tokens
//!
//! Every token header carries the `kid` of the key that signed it, and JWKS
//! lists *all* loaded public keys. To rotate:
//!
//! 1. Add a new key file. It is published in JWKS at the next restart.
//! 2. Once verifiers have had time to refresh JWKS, make it active. The
//!    newest file name is active by default, or set `SIGNING_ACTIVE_KID`.
//! 3. After the longest token lifetime (15 minutes) has passed, delete the
//!    old key file. Tokens it signed have all expired by then.

use std::path::Path;

use anyhow::{Context, Result, bail};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation,
    jwk::{Jwk, JwkSet, PublicKeyUse},
};
use serde::{Serialize, de::DeserializeOwned};

/// The only algorithm we sign with and accept.
pub const ALGORITHM: Algorithm = Algorithm::RS256;

/// [`ALGORITHM`] as it appears in JWT headers and the discovery document.
pub const ALGORITHM_NAME: &str = "RS256";

/// One RSA key pair.
struct SigningKey {
    kid: String,
    encoding: EncodingKey,
    decoding: DecodingKey,
    /// The public half, in JWK form, as published at the JWKS endpoint.
    public_jwk: Jwk,
}

/// All loaded keys, and which one signs new tokens.
pub struct SigningKeys {
    keys: Vec<SigningKey>,
    active: usize,
}

/// Why a JWT was rejected. The details are for logs and tests only; callers
/// should report every case to clients as simply "invalid token".
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("token header has no kid or an unknown kid")]
    UnknownKey,
    #[error("token has the wrong type (typ header)")]
    WrongType,
    #[error("token is invalid: {0}")]
    Invalid(#[from] jsonwebtoken::errors::Error),
}

impl SigningKeys {
    /// Loads every `*.pem` file in `dir`.
    pub fn load_from_dir(dir: &Path, active_kid: Option<&str>) -> Result<Self> {
        let entries = std::fs::read_dir(dir).with_context(|| {
            format!(
                "cannot read signing key directory {}; create a key with `cargo run -- generate-signing-key`",
                dir.display()
            )
        })?;

        let mut pems = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("pem") {
                continue;
            }
            let kid = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .context("key file name is not valid UTF-8")?
                .to_owned();
            let pem =
                std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            pems.push((kid, pem));
        }

        if pems.is_empty() {
            bail!(
                "no signing keys found in {}; create one with `cargo run -- generate-signing-key`",
                dir.display()
            );
        }
        Self::from_pems(pems, active_kid)
    }

    /// Builds the key set from `(kid, PEM bytes)` pairs.
    ///
    /// Without `active_kid`, the lexicographically greatest kid signs. The
    /// generated kids start with a timestamp, so that is the newest key.
    pub fn from_pems(mut pems: Vec<(String, Vec<u8>)>, active_kid: Option<&str>) -> Result<Self> {
        pems.sort_by(|a, b| a.0.cmp(&b.0));

        let mut keys = Vec::with_capacity(pems.len());
        for (kid, pem) in pems {
            if kid.is_empty()
                || !kid
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            {
                bail!("invalid key id {kid:?}: use only letters, digits, '-', '_' and '.'");
            }
            let encoding = EncodingKey::from_rsa_pem(&pem)
                .with_context(|| format!("key {kid} is not an RSA private key in PEM format"))?;

            let mut public_jwk = Jwk::from_encoding_key(&encoding, ALGORITHM)
                .with_context(|| format!("cannot derive the public key for {kid}"))?;
            public_jwk.common.key_id = Some(kid.clone());
            public_jwk.common.public_key_use = Some(PublicKeyUse::Signature);

            let decoding = DecodingKey::from_jwk(&public_jwk)
                .with_context(|| format!("cannot build a verification key for {kid}"))?;

            keys.push(SigningKey {
                kid,
                encoding,
                decoding,
                public_jwk,
            });
        }

        let active = match active_kid {
            Some(wanted) => keys
                .iter()
                .position(|key| key.kid == wanted)
                .with_context(|| {
                    format!("SIGNING_ACTIVE_KID={wanted} does not match any loaded key")
                })?,
            None => keys
                .len()
                .checked_sub(1)
                .context("at least one signing key is required")?,
        };

        Ok(Self { keys, active })
    }

    /// The kid of the key that signs new tokens.
    pub fn active_kid(&self) -> &str {
        &self.keys[self.active].kid
    }

    /// Signs `claims` with the active key. `typ` goes into the JWT header
    /// (`at+jwt` for access tokens, `JWT` for ID tokens).
    pub fn sign<T: Serialize>(&self, typ: &str, claims: &T) -> Result<String> {
        let key = &self.keys[self.active];
        let mut header = Header::new(ALGORITHM);
        header.typ = Some(typ.to_owned());
        header.kid = Some(key.kid.clone());
        jsonwebtoken::encode(&header, claims, &key.encoding).context("failed to sign JWT")
    }

    /// Verifies a JWT's signature, header type and registered claims.
    ///
    /// `validation` carries the expected issuer and audience. Its algorithm
    /// list is forced to RS256 here, so a token claiming `alg: none` or
    /// `alg: HS256` is always rejected (the classic JWT "algorithm
    /// confusion" attack).
    pub fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        expected_typ: &str,
        mut validation: Validation,
    ) -> Result<T, VerifyError> {
        let header = jsonwebtoken::decode_header(token)?;

        // The `typ` check stops one kind of token being used as another,
        // e.g. an ID token presented as an access token.
        if !header
            .typ
            .as_deref()
            .is_some_and(|typ| typ.eq_ignore_ascii_case(expected_typ))
        {
            return Err(VerifyError::WrongType);
        }

        let kid = header.kid.ok_or(VerifyError::UnknownKey)?;
        let key = self
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or(VerifyError::UnknownKey)?;

        validation.algorithms = vec![ALGORITHM];
        let data = jsonwebtoken::decode::<T>(token, &key.decoding, &validation)?;
        Ok(data.claims)
    }

    /// The public keys, as served at `/.well-known/jwks.json`.
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: self.keys.iter().map(|key| key.public_jwk.clone()).collect(),
        }
    }
}

/// Generates a new 2048-bit RSA private key as PKCS#8 PEM.
pub fn generate_rsa_private_key_pem() -> Result<String> {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};

    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
        .context("RSA key generation failed")?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode RSA key as PEM")?;
    Ok(pem.to_string())
}

/// A new key ID: UTC timestamp plus a random suffix, e.g. `20260914T120000-d4e5f6`.
///
/// The timestamp prefix makes "sort by name" equal "sort by age".
pub fn new_kid() -> String {
    let suffix = &crate::secret::generate_token()[..8];
    format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S"),
        suffix.replace(['-', '_'], "x")
    )
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Claims {
        iss: String,
        aud: String,
        exp: i64,
    }

    fn claims() -> Claims {
        Claims {
            iss: "https://auth.sharpnr.com".into(),
            aud: "api".into(),
            exp: chrono::Utc::now().timestamp() + 60,
        }
    }

    fn validation() -> Validation {
        let mut v = Validation::new(ALGORITHM);
        v.set_issuer(&["https://auth.sharpnr.com"]);
        v.set_audience(&["api"]);
        v
    }

    fn keys(kids: &[&str]) -> SigningKeys {
        let pems = kids
            .iter()
            .map(|kid| {
                (
                    kid.to_string(),
                    generate_rsa_private_key_pem().unwrap().into_bytes(),
                )
            })
            .collect();
        SigningKeys::from_pems(pems, None).unwrap()
    }

    #[test]
    fn sign_and_verify_round_trip_with_kid() {
        let keys = keys(&["k1"]);
        let token = keys.sign("at+jwt", &claims()).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("k1"));
        assert_eq!(header.alg, Algorithm::RS256);

        let verified: Claims = keys.verify(&token, "at+jwt", validation()).unwrap();
        assert_eq!(verified.iss, "https://auth.sharpnr.com");
        assert_eq!(verified.aud, "api");
    }

    #[test]
    fn wrong_typ_is_rejected() {
        let keys = keys(&["k1"]);
        let token = keys.sign("JWT", &claims()).unwrap();
        let result = keys.verify::<Claims>(&token, "at+jwt", validation());
        assert!(matches!(result, Err(VerifyError::WrongType)));
    }

    #[test]
    fn tampered_token_is_rejected() {
        let keys = keys(&["k1"]);
        let token = keys.sign("at+jwt", &claims()).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged_payload = crate::secret::base64url(
            br#"{"iss":"https://auth.sharpnr.com","aud":"api","exp":9999999999}"#,
        );
        parts[1] = &forged_payload;
        let result = keys.verify::<Claims>(&parts.join("."), "at+jwt", validation());
        assert!(matches!(result, Err(VerifyError::Invalid(_))));
    }

    #[test]
    fn rotation_newest_key_signs_and_old_tokens_still_verify() {
        let old_pem = generate_rsa_private_key_pem().unwrap().into_bytes();
        let new_pem = generate_rsa_private_key_pem().unwrap().into_bytes();

        // Before rotation: only the old key exists and signs a token.
        let before =
            SigningKeys::from_pems(vec![("2026-01".into(), old_pem.clone())], None).unwrap();
        let old_token = before.sign("at+jwt", &claims()).unwrap();

        // After rotation: a newer key is added next to the old one.
        let after = SigningKeys::from_pems(
            vec![("2026-01".into(), old_pem), ("2026-09".into(), new_pem)],
            None,
        )
        .unwrap();
        assert_eq!(after.active_kid(), "2026-09");
        assert_eq!(after.jwks().keys.len(), 2);

        // Tokens signed before the rotation remain valid...
        assert!(
            after
                .verify::<Claims>(&old_token, "at+jwt", validation())
                .is_ok()
        );
        // ...and new tokens carry the new kid.
        let new_token = after.sign("at+jwt", &claims()).unwrap();
        let header = jsonwebtoken::decode_header(&new_token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("2026-09"));
    }

    #[test]
    fn same_kid_with_different_key_does_not_verify() {
        // The kid only selects a key; the signature must still check out.
        let signer = keys(&["k1"]);
        let impostor = keys(&["k1"]);
        let token = signer.sign("at+jwt", &claims()).unwrap();
        assert!(
            impostor
                .verify::<Claims>(&token, "at+jwt", validation())
                .is_err()
        );
    }

    #[test]
    fn jwks_contains_only_public_parameters() {
        let keys = keys(&["k1"]);
        let json = serde_json::to_value(keys.jwks()).unwrap();
        let key = &json["keys"][0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["kid"], "k1");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["alg"], "RS256");
        // Private RSA parameters must never appear.
        for private in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(key.get(private).is_none(), "JWKS leaked {private}");
        }
    }

    #[test]
    fn unknown_active_kid_is_an_error() {
        let pem = generate_rsa_private_key_pem().unwrap().into_bytes();
        assert!(SigningKeys::from_pems(vec![("a".into(), pem)], Some("b")).is_err());
    }
}
