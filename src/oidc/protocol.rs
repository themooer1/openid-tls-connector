use std::str::FromStr;
use std::time::{Duration, SystemTime};

use thiserror::Error;

use super::client::ClientRegistry;
use super::code::{AuthorizationCode, CodeChallengeMethod};
use super::storage::TokenStore;
use super::token::JwtIssuer;
use crate::oidc::code::{AuthorizationCodeVerificationError, MacKey, TokenRequestError};

/// Errors returned by the OIDC flow. The `error_code` of each variant matches
/// the RFC 6749 / OIDC error strings so they can be serialized directly into
/// the OAuth2 error response body.
#[derive(Debug, Error)]
pub enum OIDCError {
    #[error("The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed: {0}")]
    InvalidRequest(String),

    #[error("The client is not authorized to request an authorization code using this method: {0}")]
    UnauthorizedClient(String),

    #[error("The resource owner or authorization server denied the request: {0}")]
    AccessDenied(String),

    #[error("The authorization server does not support obtaining an authorization code using this method: {0}")]
    UnsupportedResponseType(String),

    #[error("The requested scope is invalid, unknown, or malformed: {0}")]
    InvalidScope(String),

    #[error("The provided authorization grant or refresh token is invalid, expired, revoked, or was issued to another client: {0}")]
    InvalidGrant(String),

    #[error("Client authentication failed: {0}")]
    InvalidClient(String),

    #[error("The authorization server encountered an unexpected condition that prevented it from fulfilling the request: {0}")]
    ServerError(String),

    #[error("The authorization server is currently unable to handle the request due to temporary overloading or maintenance: {0}")]
    TemporarilyUnavailable(String),
}

impl OIDCError {
    /// RFC 6749 error string used in the `error` field of an OAuth2 error response.
    pub fn error_code(&self) -> &'static str {
        match self {
            OIDCError::InvalidRequest(_) => "invalid_request",
            OIDCError::UnauthorizedClient(_) => "unauthorized_client",
            OIDCError::AccessDenied(_) => "access_denied",
            OIDCError::UnsupportedResponseType(_) => "unsupported_response_type",
            OIDCError::InvalidScope(_) => "invalid_scope",
            OIDCError::InvalidGrant(_) => "invalid_grant",
            OIDCError::InvalidClient(_) => "invalid_client",
            OIDCError::ServerError(_) => "server_error",
            OIDCError::TemporarilyUnavailable(_) => "temporarily_unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    Code,
}

impl FromStr for ResponseType {
    type Err = OIDCError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "code" => Ok(ResponseType::Code),
            _ => Err(OIDCError::UnsupportedResponseType(format!(
                "Unsupported response_type: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
}

impl FromStr for GrantType {
    type Err = OIDCError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            _ => Err(OIDCError::InvalidRequest(format!(
                "Unsupported grant_type: {s}"
            ))),
        }
    }
}

/// RFC 6749 token endpoint response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub id_token: String,
    pub scope: Option<String>,
}

/// Input parameters for an authorization request (the `/authorize` flow).
///
/// `code_challenge` is optional: PKCE (RFC 7636) is an extension, not a
/// requirement of the base OIDC spec. If `Some`, the token endpoint will
/// require a matching `code_verifier`. If `None`, no PKCE verification is
/// performed.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: Option<&'a str>,
    pub code_challenge_method: CodeChallengeMethod,
    pub subject: &'a str,
    pub nonce: Option<&'a str>,
    pub groups: Vec<String>,
    pub scope: Vec<String>,
}

/// Input parameters for a token request (the `/token` flow).
///
/// `code_verifier` is optional: it's only required when the corresponding
/// `/authorize` request sent a `code_challenge`. If the stored code has no
/// challenge, the verifier is ignored.
#[derive(Debug, Clone)]
pub struct AccessTokenRequest<'a> {
    pub grant_type: GrantType,
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub code: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: Option<&'a str>,
}

/// Collaborators needed to issue tokens at the `/token` endpoint. Grouped to
/// keep `access_token_request`'s argument list short.
pub struct TokenIssueContext<'a> {
    pub clients: &'a ClientRegistry,
    pub jwt_issuer: &'a JwtIssuer,
    pub token_store: &'a dyn TokenStore,
    pub id_token_ttl: Duration,
    pub access_token_ttl: Duration,
}

/// Implements the OIDC Authorization Code + PKCE flow.
///
/// The authorization code is a signed, stateless token (BLAKE3 MAC over CBOR);
/// the token endpoint verifies the signature, freshness, PKCE, client
/// identity, and that the code has not been replayed before issuing JWTs.
pub struct OIDCAuthCodePKCEFlow {
    code_max_age: Duration,
    hmac_key: MacKey,
}

impl OIDCAuthCodePKCEFlow {
    pub fn new(code_max_age: Duration, hmac_key: MacKey) -> Self {
        Self {
            code_max_age,
            hmac_key,
        }
    }

    /// Build and sign an authorization code for the given request. Returns
    /// both the structured code and its signed, base64-encoded form (the value
    /// placed in the `code` query parameter of the redirect).
    pub fn authorization_request(
        &self,
        req: AuthorizationRequest<'_>,
    ) -> Result<(AuthorizationCode, String), OIDCError> {
        let code = AuthorizationCode {
            client_id: req.client_id.to_string(),
            redirect_uri: req.redirect_uri.to_string(),
            code_challenge: req.code_challenge.map(|s| s.to_string()),
            code_challenge_method: req.code_challenge_method,
            timestamp: SystemTime::now(),
            subject: req.subject.to_string(),
            nonce: req.nonce.map(|s| s.to_string()),
            groups: req.groups,
            scope: req.scope,
        };

        let encoded = code.sign_and_encode(&self.hmac_key);
        Ok((code, encoded))
    }

    /// Redeem a signed authorization code for ID and access tokens.
    ///
    /// Performs, in order:
    /// 1. Decode + verify the code's signature and freshness.
    /// 2. Validate client_id, redirect_uri, and PKCE verifier against the code.
    /// 3. Authenticate the client (public clients pass; confidential clients
    ///    must supply the correct secret).
    /// 4. Atomically consume the code so it cannot be replayed.
    /// 5. Issue RS256 ID and access tokens and record the access token for
    ///    `/userinfo` lookup and revocation.
    pub fn access_token_request(
        &self,
        req: AccessTokenRequest<'_>,
        ctx: &TokenIssueContext<'_>,
    ) -> Result<TokenResponse, OIDCError> {
        match req.grant_type {
            GrantType::AuthorizationCode => {
                let auth_code = AuthorizationCode::decode_and_verify(
                    req.code,
                    &self.hmac_key,
                    self.code_max_age,
                )
                .map_err(map_code_verification_error)?;

                auth_code
                    .validate_token_request(req.client_id, req.redirect_uri, req.code_verifier)
                    .map_err(map_token_request_error)?;

                if !ctx
                    .clients
                    .validate_redirect_uri(req.client_id, req.redirect_uri)
                {
                    return Err(OIDCError::InvalidGrant(
                        "Invalid redirect_uri for this client".to_string(),
                    ));
                }

                match ctx.clients.validate_client_secret(req.client_id, req.client_secret) {
                    super::client::AuthResult::Allow => {}
                    super::client::AuthResult::Deny => {
                        return Err(OIDCError::InvalidClient(
                            "Client authentication failed".to_string(),
                        ));
                    }
                }

                // Atomically consume the code to prevent replay. The hash is
                // used as the key rather than the raw code so the store doesn't
                // hold the full bearer token.
                let code_hash = code_replay_key(req.code);
                if !ctx.token_store.consume_code(&code_hash) {
                    return Err(OIDCError::InvalidGrant(
                        "Authorization code has already been used".to_string(),
                    ));
                }

                let jti = random_jti();

                let id_token = ctx
                    .jwt_issuer
                    .issue_id_token(
                        &auth_code.subject,
                        req.client_id,
                        &auth_code.groups,
                        auth_code.nonce.as_deref(),
                        ctx.id_token_ttl,
                    )
                    .map_err(|e| OIDCError::ServerError(e.to_string()))?;

                let access_token = ctx
                    .jwt_issuer
                    .issue_access_token(
                        &auth_code.subject,
                        req.client_id,
                        &auth_code.groups,
                        &auth_code.scope,
                        &jti,
                        ctx.access_token_ttl,
                    )
                    .map_err(|e| OIDCError::ServerError(e.to_string()))?;

                ctx.token_store.issue(
                    jti,
                    auth_code.subject.clone(),
                    req.client_id.to_string(),
                    auth_code.scope.clone(),
                    auth_code.groups.clone(),
                    SystemTime::now() + ctx.access_token_ttl,
                );

                Ok(TokenResponse {
                    access_token,
                    token_type: "Bearer".to_string(),
                    expires_in: ctx.access_token_ttl.as_secs(),
                    id_token,
                    scope: Some(auth_code.scope.join(" ")),
                })
            }
        }
    }
}

fn map_code_verification_error(err: AuthorizationCodeVerificationError) -> OIDCError {
    use AuthorizationCodeVerificationError::*;
    match err {
        InvalidTimestamp(_) => OIDCError::InvalidGrant("Authorization code has expired".to_string()),
        InvalidSignature => OIDCError::InvalidGrant("Authorization code is invalid".to_string()),
        InvalidBase64Encoding(_) | InvalidSignedDataContainerEncoding(_) => {
            OIDCError::InvalidGrant("Authorization code is malformed".to_string())
        }
    }
}

fn map_token_request_error(err: TokenRequestError) -> OIDCError {
    use TokenRequestError::*;
    match err {
        InvalidClientId | InvalidRedirectUri | InvalidPKCE => {
            OIDCError::InvalidGrant(err.to_string())
        }
    }
}

/// Derive a stable, opaque key for replay-tracking a signed authorization code.
/// BLAKE3 is already a dependency and gives a fast, fixed-size digest.
fn code_replay_key(code: &str) -> String {
    use base64::Engine;
    let digest = blake3::hash(code.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_bytes())
}

/// Generate a random RFC 4122 v4 UUID string for use as a JWT `jti`.
fn random_jti() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    // Set version (4) and variant (RFC 4122) bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::client::{ClientConfig, ClientRegistry};
    use crate::oidc::storage::InMemoryTokenStore;
    use crate::oidc::token::JwtIssuer;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    const ISSUER: &str = "https://test.example.com";
    const CLIENT_ID: &str = "client1";
    const REDIRECT_URI: &str = "https://app.example/cb";

    fn test_key() -> MacKey {
        [42u8; 32]
    }

    fn test_flow() -> OIDCAuthCodePKCEFlow {
        OIDCAuthCodePKCEFlow::new(Duration::from_secs(300), test_key())
    }

    fn s256_challenge(verifier: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier))
    }

    fn test_clients() -> ClientRegistry {
        ClientRegistry::new(vec![
            ClientConfig {
                client_id: CLIENT_ID.to_string(),
                client_secret: None,
                redirect_uris: vec![REDIRECT_URI.to_string()],
                groups: vec!["users".to_string()],
            },
            ClientConfig {
                client_id: "confidential".to_string(),
                client_secret: Some("s3cr3t".to_string()),
                redirect_uris: vec![REDIRECT_URI.to_string()],
                groups: vec![],
            },
        ])
        .unwrap()
    }

    fn test_ctx<'a>(clients: &'a ClientRegistry, jwt: &'a JwtIssuer, store: &'a InMemoryTokenStore) -> TokenIssueContext<'a> {
        TokenIssueContext {
            clients,
            jwt_issuer: jwt,
            token_store: store,
            id_token_ttl: Duration::from_secs(3600),
            access_token_ttl: Duration::from_secs(3600),
        }
    }

    fn issue_code(flow: &OIDCAuthCodePKCEFlow, verifier: &str) -> String {
        let challenge = s256_challenge(verifier);
        let (_, encoded) = flow
            .authorization_request(AuthorizationRequest {
                client_id: CLIENT_ID,
                redirect_uri: REDIRECT_URI,
                code_challenge: Some(&challenge),
                code_challenge_method: CodeChallengeMethod::S256,
                subject: "alice",
                nonce: Some("nonce-xyz"),
                groups: vec!["users".to_string()],
                scope: vec!["openid".to_string()],
            })
            .unwrap();
        encoded
    }

    #[test]
    fn test_authorization_request_fields() {
        let flow = test_flow();
        let challenge = s256_challenge("verifier");
        let (code, encoded) = flow
            .authorization_request(AuthorizationRequest {
                client_id: CLIENT_ID,
                redirect_uri: REDIRECT_URI,
                code_challenge: Some(&challenge),
                code_challenge_method: CodeChallengeMethod::S256,
                subject: "alice",
                nonce: Some("nonce-1"),
                groups: vec!["g1".to_string()],
                scope: vec!["openid".to_string()],
            })
            .unwrap();

        assert_eq!(code.client_id, CLIENT_ID);
        assert_eq!(code.redirect_uri, REDIRECT_URI);
        assert_eq!(code.subject, "alice");
        assert_eq!(code.nonce, Some("nonce-1".to_string()));
        assert_eq!(code.groups, vec!["g1".to_string()]);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_access_token_request_succeeds() {
        let flow = test_flow();
        let jwt = JwtIssuer::generate(ISSUER.to_string()).unwrap();
        let store = InMemoryTokenStore::new();
        let clients = test_clients();
        let ctx = test_ctx(&clients, &jwt, &store);

        let verifier = "my-verifier";
        let code = issue_code(&flow, verifier);

        let response = flow
            .access_token_request(
                AccessTokenRequest {
                    grant_type: GrantType::AuthorizationCode,
                    client_id: CLIENT_ID,
                    client_secret: None,
                    code: &code,
                    redirect_uri: REDIRECT_URI,
                    code_verifier: Some(verifier),
                },
                &ctx,
            )
            .unwrap();

        assert_eq!(response.token_type, "Bearer");
        assert!(!response.access_token.is_empty());
        assert!(!response.id_token.is_empty());
        assert_eq!(response.expires_in, 3600);

        let id_claims = jwt.verify_id_token(&response.id_token, CLIENT_ID).unwrap();
        assert_eq!(id_claims.sub, "alice");
        assert_eq!(id_claims.nonce, Some("nonce-xyz".to_string()));

        let access_claims = jwt.verify_access_token(&response.access_token).unwrap();
        assert_eq!(access_claims.sub, "alice");
        assert_eq!(access_claims.client_id, CLIENT_ID);
    }

    #[test]
    fn test_access_token_request_wrong_verifier() {
        let flow = test_flow();
        let jwt = JwtIssuer::generate(ISSUER.to_string()).unwrap();
        let store = InMemoryTokenStore::new();
        let clients = test_clients();
        let ctx = test_ctx(&clients, &jwt, &store);

        let code = issue_code(&flow, "correct-verifier");

        let result = flow.access_token_request(
            AccessTokenRequest {
                grant_type: GrantType::AuthorizationCode,
                client_id: CLIENT_ID,
                client_secret: None,
                code: &code,
                redirect_uri: REDIRECT_URI,
                code_verifier: Some("wrong-verifier"),
            },
            &ctx,
        );

        assert!(matches!(result, Err(OIDCError::InvalidGrant(_))));
    }

    #[test]
    fn test_access_token_request_wrong_client() {
        let flow = test_flow();
        let jwt = JwtIssuer::generate(ISSUER.to_string()).unwrap();
        let store = InMemoryTokenStore::new();
        let clients = test_clients();
        let ctx = test_ctx(&clients, &jwt, &store);

        let code = issue_code(&flow, "verifier");

        let result = flow.access_token_request(
            AccessTokenRequest {
                grant_type: GrantType::AuthorizationCode,
                client_id: "other-client",
                client_secret: None,
                code: &code,
                redirect_uri: REDIRECT_URI,
                code_verifier: Some("verifier"),
            },
            &ctx,
        );

        assert!(matches!(result, Err(OIDCError::InvalidGrant(_))));
    }

    #[test]
    fn test_access_token_request_expired_code() {
        let flow = OIDCAuthCodePKCEFlow::new(Duration::ZERO, test_key());
        let jwt = JwtIssuer::generate(ISSUER.to_string()).unwrap();
        let store = InMemoryTokenStore::new();
        let clients = test_clients();
        let ctx = test_ctx(&clients, &jwt, &store);

        let verifier = "v";
        let code = issue_code(&flow, verifier);
        std::thread::sleep(Duration::from_millis(10));

        let result = flow.access_token_request(
            AccessTokenRequest {
                grant_type: GrantType::AuthorizationCode,
                client_id: CLIENT_ID,
                client_secret: None,
                code: &code,
                redirect_uri: REDIRECT_URI,
                code_verifier: Some(verifier),
            },
            &ctx,
        );

        assert!(matches!(result, Err(OIDCError::InvalidGrant(_))));
    }

    #[test]
    fn test_access_token_request_replay_rejected() {
        let flow = test_flow();
        let jwt = JwtIssuer::generate(ISSUER.to_string()).unwrap();
        let store = InMemoryTokenStore::new();
        let clients = test_clients();
        let ctx = test_ctx(&clients, &jwt, &store);

        let verifier = "v";
        let code = issue_code(&flow, verifier);

        let req = AccessTokenRequest {
            grant_type: GrantType::AuthorizationCode,
            client_id: CLIENT_ID,
            client_secret: None,
            code: &code,
            redirect_uri: REDIRECT_URI,
            code_verifier: Some(verifier),
        };

        // First redemption succeeds.
        flow.access_token_request(req.clone(), &ctx).unwrap();
        // Second redemption (replay) is rejected.
        let result = flow.access_token_request(req, &ctx);
        assert!(matches!(result, Err(OIDCError::InvalidGrant(_))));
    }

    #[test]
    fn test_confidential_client_requires_secret() {
        let flow = test_flow();
        let jwt = JwtIssuer::generate(ISSUER.to_string()).unwrap();
        let store = InMemoryTokenStore::new();
        let clients = test_clients();
        let ctx = test_ctx(&clients, &jwt, &store);

        let verifier = "v";
        let challenge = s256_challenge(verifier);
        let (_, code) = flow
            .authorization_request(AuthorizationRequest {
                client_id: "confidential",
                redirect_uri: REDIRECT_URI,
                code_challenge: Some(&challenge),
                code_challenge_method: CodeChallengeMethod::S256,
                subject: "bob",
                nonce: None,
                groups: vec![],
                scope: vec!["openid".to_string()],
            })
            .unwrap();

        // No secret → rejected.
        let result = flow.access_token_request(
            AccessTokenRequest {
                grant_type: GrantType::AuthorizationCode,
                client_id: "confidential",
                client_secret: None,
                code: &code,
                redirect_uri: REDIRECT_URI,
                code_verifier: Some(verifier),
            },
            &ctx,
        );
        assert!(matches!(result, Err(OIDCError::InvalidClient(_))));

        // Wrong secret → rejected.
        let result = flow.access_token_request(
            AccessTokenRequest {
                grant_type: GrantType::AuthorizationCode,
                client_id: "confidential",
                client_secret: Some("wrong"),
                code: &code,
                redirect_uri: REDIRECT_URI,
                code_verifier: Some(verifier),
            },
            &ctx,
        );
        assert!(matches!(result, Err(OIDCError::InvalidClient(_))));
    }

    #[test]
    fn test_confidential_client_with_correct_secret_succeeds() {
        let flow = test_flow();
        let jwt = JwtIssuer::generate(ISSUER.to_string()).unwrap();
        let store = InMemoryTokenStore::new();
        let clients = test_clients();
        let ctx = test_ctx(&clients, &jwt, &store);

        let verifier = "v";
        let challenge = s256_challenge(verifier);
        let (_, code) = flow
            .authorization_request(AuthorizationRequest {
                client_id: "confidential",
                redirect_uri: REDIRECT_URI,
                code_challenge: Some(&challenge),
                code_challenge_method: CodeChallengeMethod::S256,
                subject: "bob",
                nonce: None,
                groups: vec![],
                scope: vec!["openid".to_string()],
            })
            .unwrap();

        let response = flow
            .access_token_request(
                AccessTokenRequest {
                    grant_type: GrantType::AuthorizationCode,
                    client_id: "confidential",
                    client_secret: Some("s3cr3t"),
                    code: &code,
                    redirect_uri: REDIRECT_URI,
                    code_verifier: Some(verifier),
                },
                &ctx,
            )
            .unwrap();

        assert!(!response.access_token.is_empty());
    }

    #[test]
    fn test_response_type_from_str() {
        assert_eq!(ResponseType::from_str("code").unwrap(), ResponseType::Code);
        assert!(ResponseType::from_str("token").is_err());
    }

    #[test]
    fn test_grant_type_from_str() {
        assert_eq!(
            GrantType::from_str("authorization_code").unwrap(),
            GrantType::AuthorizationCode,
        );
        assert!(GrantType::from_str("client_credentials").is_err());
    }
}
