use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use openid_tls_connector::oidc::client::{ClientConfig, ClientRegistry};
use openid_tls_connector::oidc::discovery::DiscoveryManager;
use openid_tls_connector::oidc::endpoints::OIDCEndpointPaths;
use openid_tls_connector::oidc::protocol::OIDCAuthCodePKCEFlow;
use openid_tls_connector::oidc::router::{oidc_router, AppState};
use openid_tls_connector::oidc::storage::InMemoryTokenStore;
use openid_tls_connector::oidc::token::JwtIssuer;
use openid_tls_connector::users::UserManager;

mod config;
use config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let config = Config::load(PathBuf::from(&config_path).as_path())?;

    let hmac_key_bytes = hex_to_32_bytes(&config.code_hmac_key)
        .expect("code_hmac_key must be 64 hex characters (32 bytes)");

    let signing_key_pem = std::fs::read_to_string(&config.signing_key_path)
        .expect("Failed to read signing key PEM file");

    let jwt_issuer = JwtIssuer::from_pem(&signing_key_pem, config.issuer.clone())
        .expect("Failed to initialize JWT issuer");

    let clients = config
        .clients
        .iter()
        .map(|c| ClientConfig {
            client_id: c.client_id.clone(),
            client_secret: c.client_secret.clone(),
            redirect_uris: c.redirect_uris.clone(),
            groups: c.groups.clone(),
        })
        .collect();
    let client_registry = ClientRegistry::new(clients)?;

    let endpoints = OIDCEndpointPaths::default();

    let issuer_url = url::Url::parse(&config.issuer)?;
    let discovery_manager = DiscoveryManager::new(&issuer_url, &endpoints);

    let state = AppState {
        flow: Arc::new(OIDCAuthCodePKCEFlow::new(
            Duration::from_secs(config.code_max_age_seconds),
            hmac_key_bytes,
        )),
        jwt_issuer: Arc::new(jwt_issuer),
        clients: Arc::new(client_registry),
        token_store: Arc::new(InMemoryTokenStore::new()),
        user_manager: Arc::new(UserManager::new(config.dn_attribute)),
        discovery_manager: Arc::new(discovery_manager),
        user_header: config.user_header,
        id_token_ttl: Duration::from_secs(config.id_token_ttl_seconds),
        access_token_ttl: Duration::from_secs(config.access_token_ttl_seconds),
        default_groups: config.default_groups,
    };

    let app = oidc_router(state);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    println!("Listening on {}", config.listen_addr);
    axum::serve(listener, app).await?;

    Ok(())
}

fn hex_to_32_bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}
