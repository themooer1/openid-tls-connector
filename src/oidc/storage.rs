use std::collections::HashMap;
use std::sync::RwLock;
use std::time::SystemTime;

/// Tracks an issued access token for `/userinfo` lookup, revocation, and
/// introspection. Keyed by the JWT `jti`.
#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub subject: String,
    pub client_id: String,
    pub scope: Vec<String>,
    pub groups: Vec<String>,
    pub expires_at: SystemTime,
    pub jti: String,
}

/// Persistence abstraction for the OIDC flow.
///
/// `TokenStore` has two responsibilities:
/// 1. Record issued access tokens (by `jti`) so `/userinfo` can look up
///    subject/groups without re-parsing the JWT, and so tokens can be revoked.
/// 2. Track consumed authorization codes so they cannot be replayed (RFC 6749
///    §4.1.2 requires one-time use).
pub trait TokenStore: Send + Sync {
    /// Record a newly issued access token.
    fn issue(
        &self,
        jti: String,
        subject: String,
        client_id: String,
        scope: Vec<String>,
        groups: Vec<String>,
        expires_at: SystemTime,
    );

    /// Look up an access token record by its `jti`. Returns `None` if the
    /// token was never issued or has been revoked.
    fn lookup(&self, jti: &str) -> Option<TokenRecord>;

    /// Revoke an access token by `jti`. Returns `true` if a record was removed.
    fn revoke(&self, jti: &str) -> bool;

    /// Atomically mark an authorization code as consumed.
    ///
    /// Returns `true` if this is the first time the code is consumed (the
    /// caller may proceed with token issuance). Returns `false` if the code
    /// has already been consumed (the caller must reject the replay).
    ///
    /// `code_key` is an opaque, stable identifier derived from the signed code
    /// (not the raw code itself) so the store does not retain the full bearer
    /// token.
    fn consume_code(&self, code_key: &str) -> bool;
}

/// In-memory `TokenStore` suitable for single-process deployments and tests.
pub struct InMemoryTokenStore {
    records: RwLock<HashMap<String, TokenRecord>>,
    consumed_codes: RwLock<HashMap<String, ()>>,
}

impl InMemoryTokenStore {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
            consumed_codes: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore for InMemoryTokenStore {
    fn issue(
        &self,
        jti: String,
        subject: String,
        client_id: String,
        scope: Vec<String>,
        groups: Vec<String>,
        expires_at: SystemTime,
    ) {
        let record = TokenRecord {
            subject,
            client_id,
            scope,
            groups,
            expires_at,
            jti: jti.clone(),
        };
        self.records.write().unwrap().insert(jti, record);
    }

    fn lookup(&self, jti: &str) -> Option<TokenRecord> {
        self.records.read().unwrap().get(jti).cloned()
    }

    fn revoke(&self, jti: &str) -> bool {
        self.records.write().unwrap().remove(jti).is_some()
    }

    fn consume_code(&self, code_key: &str) -> bool {
        let mut guard = self.consumed_codes.write().unwrap();
        // HashMap::insert returns None if the key was absent — i.e. first use.
        guard.insert(code_key.to_string(), ()).is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_record(jti: &str) -> TokenRecord {
        TokenRecord {
            subject: "alice".to_string(),
            client_id: "client1".to_string(),
            scope: vec!["openid".to_string()],
            groups: vec!["users".to_string()],
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            jti: jti.to_string(),
        }
    }

    #[test]
    fn test_issue_and_lookup() {
        let store = InMemoryTokenStore::new();
        let r = sample_record("jti-1");
        store.issue(
            r.jti.clone(),
            r.subject.clone(),
            r.client_id.clone(),
            r.scope.clone(),
            r.groups.clone(),
            r.expires_at,
        );
        let found = store.lookup("jti-1").unwrap();
        assert_eq!(found.subject, "alice");
        assert_eq!(found.client_id, "client1");
    }

    #[test]
    fn test_lookup_missing() {
        let store = InMemoryTokenStore::new();
        assert!(store.lookup("nope").is_none());
    }

    #[test]
    fn test_revoke() {
        let store = InMemoryTokenStore::new();
        let r = sample_record("jti-2");
        store.issue(
            r.jti.clone(),
            r.subject,
            r.client_id,
            r.scope,
            r.groups,
            r.expires_at,
        );
        assert!(store.revoke("jti-2"));
        assert!(store.lookup("jti-2").is_none());
        assert!(!store.revoke("jti-2"));
    }

    #[test]
    fn test_consume_code_first_use_succeeds() {
        let store = InMemoryTokenStore::new();
        assert!(store.consume_code("hash-abc"));
    }

    #[test]
    fn test_consume_code_replay_rejected() {
        let store = InMemoryTokenStore::new();
        assert!(store.consume_code("hash-abc"));
        assert!(!store.consume_code("hash-abc"));
    }
}
