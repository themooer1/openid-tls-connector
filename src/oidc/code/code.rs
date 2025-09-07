use std::{
    fmt::{Display, Formatter},
    time::{Duration, SystemTime},
};

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
}

impl AuthorizationCode {
    // Encode self as a signed base64 string
    pub fn sign_and_encode(&self, hmac_key: &MacKey) -> String {
        SignedAuthorizationCode::sign_and_encode(&self, hmac_key)
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
