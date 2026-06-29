use super::endpoints::OIDCEndpointPaths;
use serde::Serialize;
use url::Url;

/// OIDC discovery document returned at `/.well-known/openid-configuration`.
///
/// See <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>.
#[derive(Clone, Serialize)]
pub struct OIDCDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(rename = "code_challenge_methods_supported")]
    pub code_challenge_methods_supported: Vec<String>,
}

/// Build the discovery document from the issuer URL and endpoint paths.
///
/// The `issuer` field is normalized to not have a trailing slash (per OIDC
/// discovery spec, the issuer must exactly match the `iss` claim in tokens).
/// Endpoint URLs are produced by joining the relative paths onto the issuer.
pub fn discovery_info(issuer: &Url, paths: &OIDCEndpointPaths) -> OIDCDiscovery {
    // Normalize the issuer to a canonical form without a trailing slash so
    // that `iss` claims and the discovery `issuer` field match exactly.
    let canonical_issuer = canonicalize_issuer(issuer);
    let base = Url::parse(&canonical_issuer).unwrap_or_else(|_| issuer.clone());

    OIDCDiscovery {
        issuer: canonical_issuer.clone(),
        authorization_endpoint: base.join(&paths.authorization_endpoint).unwrap().to_string(),
        token_endpoint: base.join(&paths.token_endpoint).unwrap().to_string(),
        userinfo_endpoint: base.join(&paths.userinfo_endpoint).unwrap().to_string(),
        jwks_uri: base.join(&paths.jwks_uri).unwrap().to_string(),
        scopes_supported: vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec!["authorization_code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        code_challenge_methods_supported: vec!["S256".to_string(), "plain".to_string()],
    }
}

/// Strip a trailing slash from the path component of the issuer URL, so that
/// `https://auth.example.com/` becomes `https://auth.example.com`. Query and
/// fragment are preserved.
fn canonicalize_issuer(issuer: &Url) -> String {
    let mut s = issuer.to_string();
    if s.ends_with('/') {
        s.pop();
    }
    s
}

/// Caches the discovery document. The document is immutable after construction.
pub struct DiscoveryManager {
    discovery: OIDCDiscovery,
}

impl DiscoveryManager {
    pub fn new(issuer: &Url, paths: &OIDCEndpointPaths) -> Self {
        DiscoveryManager {
            discovery: discovery_info(issuer, paths),
        }
    }

    pub fn get_discovery_info(&self) -> &OIDCDiscovery {
        &self.discovery
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths() -> OIDCEndpointPaths {
        OIDCEndpointPaths::default()
    }

    #[test]
    fn test_discovery_info_urls_no_trailing_slash() {
        let issuer = Url::parse("https://auth.example.com").unwrap();
        let info = discovery_info(&issuer, &test_paths());
        assert_eq!(info.issuer, "https://auth.example.com");
        assert_eq!(
            info.authorization_endpoint,
            "https://auth.example.com/authorize"
        );
        assert_eq!(info.token_endpoint, "https://auth.example.com/token");
        assert_eq!(info.userinfo_endpoint, "https://auth.example.com/userinfo");
        assert_eq!(info.jwks_uri, "https://auth.example.com/jwks");
    }

    #[test]
    fn test_discovery_info_urls_with_trailing_slash() {
        let issuer = Url::parse("https://auth.example.com/").unwrap();
        let info = discovery_info(&issuer, &test_paths());
        // The trailing slash is stripped from the issuer but endpoint URLs
        // are still correct.
        assert_eq!(info.issuer, "https://auth.example.com");
        assert_eq!(
            info.authorization_endpoint,
            "https://auth.example.com/authorize"
        );
    }

    #[test]
    fn test_discovery_info_issuer_with_path() {
        let issuer = Url::parse("https://auth.example.com/oidc").unwrap();
        let info = discovery_info(&issuer, &test_paths());
        assert_eq!(info.issuer, "https://auth.example.com/oidc");
        assert_eq!(
            info.authorization_endpoint,
            "https://auth.example.com/authorize"
        );
    }

    #[test]
    fn test_discovery_info_supported_values() {
        let issuer = Url::parse("https://auth.example.com").unwrap();
        let info = discovery_info(&issuer, &test_paths());
        assert!(info.scopes_supported.contains(&"openid".to_string()));
        assert!(info
            .response_types_supported
            .contains(&"code".to_string()));
        assert!(info
            .grant_types_supported
            .contains(&"authorization_code".to_string()));
        assert!(info
            .id_token_signing_alg_values_supported
            .contains(&"RS256".to_string()));
        assert!(info
            .code_challenge_methods_supported
            .contains(&"S256".to_string()));
    }

    #[test]
    fn test_discovery_manager() {
        let issuer = Url::parse("https://auth.example.com").unwrap();
        let manager = DiscoveryManager::new(&issuer, &test_paths());
        let info = manager.get_discovery_info();
        assert_eq!(info.issuer, "https://auth.example.com");
    }

    #[test]
    fn test_discovery_json_serializes() {
        let issuer = Url::parse("https://auth.example.com").unwrap();
        let info = discovery_info(&issuer, &test_paths());
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["issuer"], "https://auth.example.com");
        assert_eq!(
            json["authorization_endpoint"],
            "https://auth.example.com/authorize"
        );
    }
}
