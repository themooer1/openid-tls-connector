use super::endpoints::OIDCEndpointPaths;
use serde::Serialize;
use url::Url;

// Response for /.well-known/openid-configuration
#[derive(Clone, Serialize)]
struct OIDCDiscovery
{   
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>
}

fn discovery_info(issuer: &Url, config: &OIDCEndpointPaths) -> OIDCDiscovery {
    OIDCDiscovery {
        issuer: issuer.to_string(),
        authorization_endpoint: issuer.join(&config.authorization_endpoint).unwrap().to_string(),
        token_endpoint: issuer.join(&config.token_endpoint).unwrap().to_string(),
        userinfo_endpoint: issuer.join(&config.userinfo_endpoint).unwrap().to_string(),
        jwks_uri: issuer.join(&config.jwks_uri).unwrap().to_string(),
        scopes_supported: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        response_types_supported: vec!["code".to_string()]
    }
}

// Generates the OIDC discovery information
struct DiscoveryManager
{
   discovery: OIDCDiscovery, 
}

impl DiscoveryManager {
    fn new(issuer: &Url, config: &OIDCEndpointPaths) -> Self {
        DiscoveryManager { discovery: discovery_info(issuer, config) }
    }

    fn get_discovery_info<'a>(&'a self) -> &'a OIDCDiscovery {
        &self.discovery
    }
}