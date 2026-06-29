use std::sync::Arc;
use std::time::Duration;

use openid_tls_connector::oidc::client::{ClientConfig, ClientRegistry};
use openid_tls_connector::oidc::code::MacKey;
use openid_tls_connector::oidc::discovery::DiscoveryManager;
use openid_tls_connector::oidc::endpoints::OIDCEndpointPaths;
use openid_tls_connector::oidc::protocol::OIDCAuthCodePKCEFlow;
use openid_tls_connector::oidc::router::{AppState, oidc_router};
use openid_tls_connector::oidc::storage::InMemoryTokenStore;
use openid_tls_connector::oidc::token::JwtIssuer;
use openid_tls_connector::users::UserManager;

use axum::Router;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub const TEST_MAC_KEY: MacKey = [42u8; 32];
pub const TEST_ISSUER: &str = "https://auth.example.com";
pub const TEST_CLIENT_ID: &str = "spa";
pub const TEST_REDIRECT_URI: &str = "https://app.example/cb";
pub const TEST_DN_HEADER: &str = "X-Client-Cert-Subject";
pub const TEST_USER_DN: &str = "CN=test-user,OU=eng,O=acme";
pub const TEST_CODE_MAX_AGE_SECS: u64 = 300;

/// A known PKCE pair (RFC 7636 Appendix B verifier + its S256 challenge).
pub fn test_pkce_pair() -> (String, String) {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier));
    (challenge, verifier.to_string())
}

pub fn test_clients() -> Vec<ClientConfig> {
    vec![
        ClientConfig {
            client_id: TEST_CLIENT_ID.to_string(),
            client_secret: None,
            redirect_uris: vec![TEST_REDIRECT_URI.to_string()],
            groups: vec!["spa-users".to_string()],
        },
        ClientConfig {
            client_id: "confidential".to_string(),
            client_secret: Some("s3cr3t".to_string()),
            redirect_uris: vec![TEST_REDIRECT_URI.to_string()],
            groups: vec!["api-callers".to_string()],
        },
    ]
}

pub fn build_test_state() -> AppState {
    let jwt_issuer = JwtIssuer::generate(TEST_ISSUER.to_string()).unwrap();

    let endpoints = OIDCEndpointPaths::default();
    let issuer_url = url::Url::parse(TEST_ISSUER).unwrap();
    let discovery_manager = DiscoveryManager::new(&issuer_url, &endpoints);

    AppState {
        flow: Arc::new(OIDCAuthCodePKCEFlow::new(
            Duration::from_secs(TEST_CODE_MAX_AGE_SECS),
            TEST_MAC_KEY,
        )),
        jwt_issuer: Arc::new(jwt_issuer),
        clients: Arc::new(ClientRegistry::new(test_clients()).unwrap()),
        token_store: Arc::new(InMemoryTokenStore::new()),
        user_manager: Arc::new(UserManager::new("CN".to_string())),
        discovery_manager: Arc::new(discovery_manager),
        user_header: TEST_DN_HEADER.to_string(),
        id_token_ttl: Duration::from_secs(3600),
        access_token_ttl: Duration::from_secs(3600),
        default_groups: vec!["everyone".to_string(), "authenticated".to_string()],
    }
}

pub fn build_test_router() -> Router {
    let state = build_test_state();
    oidc_router(state)
}

/// Decode the payload (middle segment) of a JWT as a JSON `Value` without
/// verifying the signature. Used in tests to assert claim values; signature
/// verification is tested separately via `JwtIssuer::verify_*`.
pub fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    serde_json::from_slice(&payload).unwrap()
}

/// Extract a query parameter from a `?key=value&key2=value2` string.
pub fn extract_param(url: &str, param: &str) -> String {
    let query = url.split('?').nth(1).unwrap_or("");
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if parts.next().unwrap() == param {
            return urlencoding::decode(parts.next().unwrap_or(""))
                .unwrap()
                .to_string();
        }
    }
    panic!("Parameter {param} not found in {url}");
}
