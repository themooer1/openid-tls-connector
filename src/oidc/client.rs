use core::error::Error;
use core::result::Result;
use url::Url;

enum AuthResult {
    Allow,
    Deny,
}

// Authenticates OIDC clients and retrieves their redirect URIs.
trait ClientManager {
    async fn authenticate_client(&self, client_id: &str, client_secret: &str) -> AuthResult;
    async fn get_redirect_uri(&self, client_id: &str) -> Result<Url, Box<dyn Error>>;
}