use thiserror::Error;

/// Result of authenticating a client at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Allow,
    Deny,
}

/// Configuration for a single OAuth2/OIDC client, loaded from TOML.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    /// `None` for public clients (PKCE-only). `Some(secret)` for confidential
    /// clients that must present the secret at the token endpoint.
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Registry of configured clients, used to validate `client_id`,
/// `redirect_uri`, and `client_secret` at both the authorize and token
/// endpoints.
#[derive(Debug, Clone)]
pub struct ClientRegistry {
    clients: Vec<ClientConfig>,
}

#[derive(Debug, Error)]
pub enum ClientRegistryError {
    #[error("duplicate client_id: {0}")]
    DuplicateClientId(String),
}

impl ClientRegistry {
    pub fn new(clients: Vec<ClientConfig>) -> Result<Self, ClientRegistryError> {
        // Reject duplicate client_ids at startup so the error is caught early
        // rather than producing non-deterministic lookup behavior.
        let mut seen = std::collections::HashSet::new();
        for c in &clients {
            if !seen.insert(&c.client_id) {
                return Err(ClientRegistryError::DuplicateClientId(c.client_id.clone()));
            }
        }
        Ok(Self { clients })
    }

    pub fn find_by_id(&self, client_id: &str) -> Option<&ClientConfig> {
        self.clients.iter().find(|c| c.client_id == client_id)
    }

    /// Verify that `redirect_uri` is registered for `client_id`.
    pub fn validate_redirect_uri(&self, client_id: &str, redirect_uri: &str) -> bool {
        self.find_by_id(client_id)
            .map(|c| c.redirect_uris.iter().any(|u| u == redirect_uri))
            .unwrap_or(false)
    }

    /// Authenticate a client at the token endpoint.
    ///
    /// Public clients (`client_secret == None` in config) are always allowed
    /// (PKCE provides client authentication in that case). Confidential clients
    /// must supply the correct secret via `presented_secret`.
    pub fn validate_client_secret(
        &self,
        client_id: &str,
        presented_secret: Option<&str>,
    ) -> AuthResult {
        match self.find_by_id(client_id) {
            Some(client) => match &client.client_secret {
                // Public client: no secret required.
                None => AuthResult::Allow,
                // Confidential client: the presented secret must match.
                Some(expected) => match presented_secret {
                    Some(given) if constant_time_eq(expected.as_bytes(), given.as_bytes()) => {
                        AuthResult::Allow
                    }
                    _ => AuthResult::Deny,
                },
            },
            None => AuthResult::Deny,
        }
    }
}

/// Constant-time comparison to avoid timing side channels on secret checks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ClientRegistry {
        ClientRegistry::new(vec![
            ClientConfig {
                client_id: "public-client".to_string(),
                client_secret: None,
                redirect_uris: vec!["https://app.example/cb".to_string()],
                groups: vec![],
            },
            ClientConfig {
                client_id: "confidential".to_string(),
                client_secret: Some("secret123".to_string()),
                redirect_uris: vec!["https://app.example/cb".to_string()],
                groups: vec![],
            },
        ])
        .unwrap()
    }

    #[test]
    fn test_find_by_id() {
        let reg = registry();
        assert!(reg.find_by_id("public-client").is_some());
        assert!(reg.find_by_id("unknown").is_none());
    }

    #[test]
    fn test_validate_redirect_uri() {
        let reg = registry();
        assert!(reg.validate_redirect_uri("public-client", "https://app.example/cb"));
        assert!(!reg.validate_redirect_uri("public-client", "https://evil.example/cb"));
        assert!(!reg.validate_redirect_uri("unknown", "https://app.example/cb"));
    }

    #[test]
    fn test_public_client_always_allowed() {
        let reg = registry();
        assert_eq!(
            reg.validate_client_secret("public-client", None),
            AuthResult::Allow
        );
        assert_eq!(
            reg.validate_client_secret("public-client", Some("anything")),
            AuthResult::Allow
        );
    }

    #[test]
    fn test_confidential_client_requires_correct_secret() {
        let reg = registry();
        assert_eq!(
            reg.validate_client_secret("confidential", None),
            AuthResult::Deny
        );
        assert_eq!(
            reg.validate_client_secret("confidential", Some("wrong")),
            AuthResult::Deny
        );
        assert_eq!(
            reg.validate_client_secret("confidential", Some("secret123")),
            AuthResult::Allow
        );
    }

    #[test]
    fn test_unknown_client_denied() {
        let reg = registry();
        assert_eq!(
            reg.validate_client_secret("unknown", None),
            AuthResult::Deny
        );
    }

    #[test]
    fn test_duplicate_client_id_rejected() {
        let result = ClientRegistry::new(vec![
            ClientConfig {
                client_id: "dup".to_string(),
                client_secret: None,
                redirect_uris: vec![],
                groups: vec![],
            },
            ClientConfig {
                client_id: "dup".to_string(),
                client_secret: None,
                redirect_uris: vec![],
                groups: vec![],
            },
        ]);
        assert!(result.is_err());
    }
}
