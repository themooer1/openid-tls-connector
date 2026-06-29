use std::time::{Duration, SystemTime};

use super::pkce::verify_pkce;
use super::CodeChallengeMethod;

use super::signature::{AuthorizationCodeVerificationError, MacKey, SignedAuthorizationCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenRequestError {
    #[error("Authorization code not issued for this client.")]
    InvalidClientId,

    #[error("Authorization code not issued for this redirect URI.")]
    InvalidRedirectUri,

    #[error("Proof key did not match verifier.")]
    InvalidPKCE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: CodeChallengeMethod,
    pub timestamp: SystemTime,
    pub subject: String,
    pub nonce: Option<String>,
    pub groups: Vec<String>,
    pub scope: Vec<String>,
}

impl AuthorizationCode {
    // Encode self as a signed base64 string
    pub fn sign_and_encode(&self, hmac_key: &MacKey) -> String {
        SignedAuthorizationCode::sign_and_encode(self, hmac_key)
    }

    pub fn decode_and_verify(
        encoded: &str,
        hmac_key: &MacKey,
        max_age: Duration,
    ) -> Result<Self, AuthorizationCodeVerificationError> {
        SignedAuthorizationCode::decode_and_verify(encoded, hmac_key, max_age)
    }

    // Checks that a request to the token endpoint matches the authorization code being used and is valid
    pub fn validate_token_request(
        &self,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<(), TokenRequestError> {
        if self.client_id != client_id {
            return Err(TokenRequestError::InvalidClientId);
        }

        if self.redirect_uri != redirect_uri {
            return Err(TokenRequestError::InvalidRedirectUri);
        }

        if !verify_pkce(self.code_challenge_method, &self.code_challenge, code_verifier) {
            return Err(TokenRequestError::InvalidPKCE);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    fn make_code(challenge: &str, method: CodeChallengeMethod) -> AuthorizationCode {
        AuthorizationCode {
            client_id: "client1".to_string(),
            redirect_uri: "https://app.example/cb".to_string(),
            code_challenge: challenge.to_string(),
            code_challenge_method: method,
            timestamp: SystemTime::now(),
            subject: "user1".to_string(),
            nonce: None,
            groups: vec![],
            scope: vec!["openid".to_string()],
        }
    }

    fn s256_challenge(verifier: &str) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier))
    }

    #[test]
    fn test_validate_matching_request() {
        let verifier = "test-verifier";
        let challenge = s256_challenge(verifier);
        let code = make_code(&challenge, CodeChallengeMethod::S256);
        assert!(code
            .validate_token_request("client1", "https://app.example/cb", verifier)
            .is_ok());
    }

    #[test]
    fn test_validate_wrong_client() {
        let verifier = "test-verifier";
        let challenge = s256_challenge(verifier);
        let code = make_code(&challenge, CodeChallengeMethod::S256);
        assert!(matches!(
            code.validate_token_request("wrong-client", "https://app.example/cb", verifier),
            Err(TokenRequestError::InvalidClientId)
        ));
    }

    #[test]
    fn test_validate_wrong_redirect() {
        let verifier = "test-verifier";
        let challenge = s256_challenge(verifier);
        let code = make_code(&challenge, CodeChallengeMethod::S256);
        assert!(matches!(
            code.validate_token_request("client1", "https://evil.example/cb", verifier),
            Err(TokenRequestError::InvalidRedirectUri)
        ));
    }

    #[test]
    fn test_validate_wrong_verifier() {
        let code = make_code("challenge", CodeChallengeMethod::Plain);
        assert!(matches!(
            code.validate_token_request("client1", "https://app.example/cb", "wrong-verifier"),
            Err(TokenRequestError::InvalidPKCE)
        ));
    }

    #[test]
    fn test_validate_plain_pkce() {
        let code = make_code("my-verifier", CodeChallengeMethod::Plain);
        assert!(code
            .validate_token_request("client1", "https://app.example/cb", "my-verifier")
            .is_ok());
    }
}
