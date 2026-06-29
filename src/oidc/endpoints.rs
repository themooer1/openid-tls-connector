use serde::{Deserialize, Serialize};

/// Relative paths of the OIDC endpoints. These are joined with the issuer URL
/// to produce the absolute URLs advertised in the discovery document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OIDCEndpointPaths {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
}

impl Default for OIDCEndpointPaths {
    fn default() -> Self {
        Self {
            authorization_endpoint: "/authorize".to_string(),
            token_endpoint: "/token".to_string(),
            userinfo_endpoint: "/userinfo".to_string(),
            jwks_uri: "/jwks".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_paths() {
        let paths = OIDCEndpointPaths::default();
        assert_eq!(paths.authorization_endpoint, "/authorize");
        assert_eq!(paths.token_endpoint, "/token");
        assert_eq!(paths.userinfo_endpoint, "/userinfo");
        assert_eq!(paths.jwks_uri, "/jwks");
    }

    #[test]
    fn test_serde_round_trip() {
        let paths = OIDCEndpointPaths::default();
        let json = serde_json::to_string(&paths).unwrap();
        let back: OIDCEndpointPaths = serde_json::from_str(&json).unwrap();
        assert_eq!(back.authorization_endpoint, paths.authorization_endpoint);
        assert_eq!(back.jwks_uri, paths.jwks_uri);
    }
}
