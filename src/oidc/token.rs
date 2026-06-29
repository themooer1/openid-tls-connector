use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;

/// Claims inserted into an OIDC ID Token.
///
/// See <https://openid.net/specs/openid-connect-core-1_0.html#IDToken>.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
}

/// Claims inserted into a self-signed OAuth2 access token (JWT).
///
/// `aud` is the issuer itself, since the only resource server consuming this
/// token in v1 is the issuer's own `/userinfo` endpoint. `client_id` records
/// which OAuth2 client requested the token.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub scope: Vec<String>,
    pub groups: Vec<String>,
    pub client_id: String,
}

/// A single JSON Web Key (RFC 7517) entry for the JWKS endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

/// JWKS document returned by the `jwks_uri` discovery endpoint.
#[derive(Debug, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("JWT signing/verification failed: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("RSA key error: {0}")]
    Rsa(String),
}

impl From<rsa::pkcs8::Error> for JwtError {
    fn from(err: rsa::pkcs8::Error) -> Self {
        JwtError::Rsa(err.to_string())
    }
}

impl From<rsa::pkcs1::Error> for JwtError {
    fn from(err: rsa::pkcs1::Error) -> Self {
        JwtError::Rsa(err.to_string())
    }
}

impl From<rsa::Error> for JwtError {
    fn from(err: rsa::Error) -> Self {
        JwtError::Rsa(err.to_string())
    }
}

/// Issues and verifies RS256 JWTs (ID tokens and access tokens).
///
/// Holds a single RSA keypair. The `kid` is derived from the public key so
/// that the JWKS endpoint and JWT headers agree.
pub struct JwtIssuer {
    issuer: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    kid: String,
    jwk: Jwk,
}

impl JwtIssuer {
    /// Construct from a PKCS#8 PEM-encoded RSA private key.
    pub fn from_pem(pem: &str, issuer: String) -> Result<Self, JwtError> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)?;
        Self::from_private_key(private_key, issuer)
    }

    /// Generate a fresh 2048-bit RSA keypair (used by tests and bootstrap).
    pub fn generate(issuer: String) -> Result<Self, JwtError> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        Self::from_private_key(private_key, issuer)
    }

    fn from_private_key(private_key: RsaPrivateKey, issuer: String) -> Result<Self, JwtError> {
        let public_key = private_key.to_public_key();

        // jsonwebtoken's `from_rsa_der` expects the PKCS#1 RSAPublicKey DER
        // (not the SPKI-wrapped form returned by `to_public_key_der`).
        let pkcs1_der = public_key.to_pkcs1_der()?;

        // `kid` is a stable hash of the public key so JWT header and JWKS agree.
        let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&sha2::Sha256::digest(pkcs1_der.as_bytes())[..16]);

        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(public_key.n().to_bytes_be());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(public_key.e().to_bytes_be());

        let jwk = Jwk {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            kid: kid.clone(),
            alg: "RS256".to_string(),
            n,
            e,
        };

        let pem = private_key.to_pkcs8_pem(LineEnding::LF)?;
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())?;
        let decoding_key = DecodingKey::from_rsa_der(pkcs1_der.as_bytes());

        Ok(Self {
            issuer,
            encoding_key,
            decoding_key,
            kid,
            jwk,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Issue an OIDC ID token. `audience` is the OAuth2 `client_id`.
    pub fn issue_id_token(
        &self,
        subject: &str,
        audience: &str,
        groups: &[String],
        nonce: Option<&str>,
        ttl: Duration,
    ) -> Result<String, JwtError> {
        let now = Self::now();
        let claims = IdTokenClaims {
            iss: self.issuer.clone(),
            sub: subject.to_string(),
            aud: audience.to_string(),
            exp: now + ttl.as_secs(),
            iat: now,
            nonce: nonce.map(|s| s.to_string()),
            groups: Some(groups.to_vec()),
        };

        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        Ok(encode(&header, &claims, &self.encoding_key)?)
    }

    /// Issue a self-signed access token. `audience` is the issuer (the resource
    /// server that will consume this token is the issuer's own `/userinfo`).
    pub fn issue_access_token(
        &self,
        subject: &str,
        client_id: &str,
        groups: &[String],
        scope: &[String],
        jti: &str,
        ttl: Duration,
    ) -> Result<String, JwtError> {
        let now = Self::now();
        let claims = AccessTokenClaims {
            iss: self.issuer.clone(),
            sub: subject.to_string(),
            aud: self.issuer.clone(),
            exp: now + ttl.as_secs(),
            iat: now,
            jti: jti.to_string(),
            scope: scope.to_vec(),
            groups: groups.to_vec(),
            client_id: client_id.to_string(),
        };

        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        Ok(encode(&header, &claims, &self.encoding_key)?)
    }

    /// Verify an access token's signature and standard claims, returning the
    /// parsed claims on success.
    pub fn verify_access_token(
        &self,
        token: &str,
    ) -> Result<AccessTokenClaims, JwtError> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.issuer]);
        // Small leeway to tolerate clock skew between issuer and verifier.
        validation.leeway = 5;

        let token_data = decode::<AccessTokenClaims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    /// Verify an ID token's signature and standard claims. The `expected_audience`
    /// is the OAuth2 client_id that the token was issued to.
    pub fn verify_id_token(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<IdTokenClaims, JwtError> {
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[expected_audience]);
        validation.leeway = 5;

        let token_data = decode::<IdTokenClaims>(token, &self.decoding_key, &validation)?;
        Ok(token_data.claims)
    }

    pub fn get_jwks(&self) -> Jwks {
        Jwks {
            keys: vec![self.jwk.clone()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ISSUER: &str = "https://test.example.com";

    fn test_issuer() -> JwtIssuer {
        JwtIssuer::generate(TEST_ISSUER.to_string()).unwrap()
    }

    #[test]
    fn test_issue_and_verify_access_token() {
        let issuer = test_issuer();
        let token = issuer
            .issue_access_token(
                "alice",
                "client1",
                &["users".to_string()],
                &["openid".to_string()],
                "jti-123",
                Duration::from_secs(3600),
            )
            .unwrap();

        let claims = issuer.verify_access_token(&token).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.client_id, "client1");
        assert_eq!(claims.jti, "jti-123");
        assert_eq!(claims.groups, vec!["users".to_string()]);
        assert_eq!(claims.scope, vec!["openid".to_string()]);
        assert_eq!(claims.iss, TEST_ISSUER);
        assert_eq!(claims.aud, TEST_ISSUER);
    }

    #[test]
    fn test_issue_and_verify_id_token() {
        let issuer = test_issuer();
        let token = issuer
            .issue_id_token(
                "alice",
                "client1",
                &["users".to_string()],
                Some("nonce123"),
                Duration::from_secs(3600),
            )
            .unwrap();

        let claims = issuer.verify_id_token(&token, "client1").unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.aud, "client1");
        assert_eq!(claims.iss, TEST_ISSUER);
        assert_eq!(claims.nonce, Some("nonce123".to_string()));
        assert_eq!(claims.groups, Some(vec!["users".to_string()]));
    }

    #[test]
    fn test_id_token_without_nonce() {
        let issuer = test_issuer();
        let token = issuer
            .issue_id_token("bob", "spa", &[], None, Duration::from_secs(60))
            .unwrap();

        let claims = issuer.verify_id_token(&token, "spa").unwrap();
        assert!(claims.nonce.is_none());
    }

    #[test]
    fn test_id_token_wrong_audience_rejected() {
        let issuer = test_issuer();
        let token = issuer
            .issue_id_token("bob", "spa", &[], None, Duration::from_secs(60))
            .unwrap();

        assert!(issuer.verify_id_token(&token, "other-client").is_err());
    }

    #[test]
    fn test_jwks_contains_key() {
        let issuer = test_issuer();
        let jwks = issuer.get_jwks();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].alg, "RS256");
        assert_eq!(jwks.keys[0].use_, "sig");
        assert_eq!(jwks.keys[0].kid, issuer.kid());
    }

    #[test]
    fn test_expired_token_fails_verification() {
        let issuer = test_issuer();
        let token = issuer
            .issue_access_token("alice", "client1", &[], &[], "jti", Duration::from_secs(1))
            .unwrap();
        // Leeway is 5s, so sleep past exp + leeway.
        std::thread::sleep(Duration::from_secs(7));
        let result = issuer.verify_access_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_token_fails_verification() {
        let issuer = test_issuer();
        let token = issuer
            .issue_access_token("alice", "client1", &[], &[], "jti", Duration::from_secs(3600))
            .unwrap();

        // Flip the last character of the signature.
        let mut parts: Vec<&str> = token.split('.').collect();
        let sig = parts[2].to_string();
        let mut bytes: Vec<char> = sig.chars().collect();
        let last = bytes.pop().unwrap();
        bytes.push(if last == 'A' { 'B' } else { 'A' });
        let tampered_sig: String = bytes.iter().collect();
        parts[2] = tampered_sig.as_str();
        let tampered = parts.join(".");

        assert!(issuer.verify_access_token(&tampered).is_err());
    }

    #[test]
    fn test_from_pem_round_trip() {
        // Generate a key, export to PEM, reload via from_pem, and verify both
        // issuers verify each other's tokens (same key).
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let original = JwtIssuer::from_pem(&pem, TEST_ISSUER.to_string()).unwrap();
        let reloaded = JwtIssuer::from_pem(&pem, TEST_ISSUER.to_string()).unwrap();

        let token = original
            .issue_access_token("alice", "client1", &[], &[], "jti", Duration::from_secs(60))
            .unwrap();
        reloaded.verify_access_token(&token).unwrap();
    }
}
