use std::time::{Duration, SystemTime};

use super::signature::{AuthorizationCodeVerificationError, MacKey, SignedAuthorizationCode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
enum CodeChallengeMethod {
    Plain,
    S256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationCode {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: CodeChallengeMethod,
    timestamp: SystemTime,
}

impl AuthorizationCode {
    // Encode self as a signed base64 string
    fn sign_and_encode(&self, hmac_key: &MacKey) -> String {
        SignedAuthorizationCode::sign_and_encode(&self, hmac_key)
    }

    fn decode_and_verify(encoded: &str, hmac_key: &MacKey, max_age: Duration) -> Result<Self, AuthorizationCodeVerificationError> {
        SignedAuthorizationCode::decode_and_verify(encoded, hmac_key, max_age) 
    }
}