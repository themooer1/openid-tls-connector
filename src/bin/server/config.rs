use serde::Deserialize;
use std::path::Path;

use openid_tls_connector::oidc::client::ClientConfig;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub issuer: String,
    pub listen_addr: String,
    pub code_max_age_seconds: u64,
    pub code_hmac_key: String,
    #[serde(default = "default_user_header")]
    pub user_header: String,
    #[serde(default = "default_dn_attribute")]
    pub dn_attribute: String,
    #[serde(default = "default_id_token_ttl")]
    pub id_token_ttl_seconds: u64,
    #[serde(default = "default_access_token_ttl")]
    pub access_token_ttl_seconds: u64,
    pub signing_key_path: String,
    #[serde(default)]
    pub clients: Vec<ClientConfig>,
    #[serde(default)]
    pub default_groups: Vec<String>,
}

fn default_user_header() -> String {
    "X-Client-Cert-Subject".to_string()
}

fn default_dn_attribute() -> String {
    "CN".to_string()
}

fn default_id_token_ttl() -> u64 {
    3600
}

fn default_access_token_ttl() -> u64 {
    3600
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
