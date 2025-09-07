use std::fmt::{Display, Formatter};
use std::time::Duration;
use thiserror::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use ciborium::{from_reader, into_writer};
use serde::{Deserialize, Serialize};

use crate::oidc::code::{AuthorizationCodeVerificationError, MacKey, TokenRequestError};

use super::client::ClientManager;
use super::code::{AuthorizationCode, CodeChallengeMethod};

#[derive(Debug, Error)]
enum OIDCAccessDeniedError
{
    #[error(transparent)]
    InvalidAuthorizationCode(#[from] AuthorizationCodeVerificationError),

    #[error(transparent)]
    InvalidTokenRequest(#[from] TokenRequestError),
}

// Error responses defined by rfc6749 4.1.2.1 with descriptions of each error
// exactly as they are defined in the RFC.
#[derive(Debug, Error)]
enum OIDCError {
    #[error("The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.")]
    InvalidRequest(String),

    #[error("The client is not authorized to request an authorization code using this method.")]
    UnauthorizedClient(String),

    #[error("The resource owner or authorization server denied the request.")]
    AccessDenied(#[from] OIDCAccessDeniedError),

    #[error("The authorization server does not support obtaining an authorization code using this method.")]
    UnsupportedResponseType(String),

    #[error("The requested scope is invalid, unknown, malformed.")]
    InvalidScope(String),

    #[error("The authorization server encountered an unexpected condition that prevented it from fulfilling the request.")]
    ServerError(String),

    #[error("The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.")]
    TemporarilyUnavailable(String),
}

enum ResponseType {
    Code,
    Token,
}

enum GrantType {
    AuthorizationCode,
    Implicit,
    ClientCredentials,
    Password,
}

struct OIDCAuthCodePKCEFlow {
    code_max_age: Duration,
    hmac_key: MacKey,
}

impl OIDCAuthCodePKCEFlow {
    // Assuming the client has been authenticated, this function generates an authorization code which authorizes
    // the issuance of an access token for the provided scopes.
    // Should have already checked the the requested response type is "code" and the client is authorized.
    pub fn authorization_request(
        client_id: &str,
        redirect_uri: &str,
        scope: &[&str],
        state: &str,
        code_challenge: &str,
        code_challenge_method: CodeChallengeMethod,
    ) -> Result<AuthorizationCode, OIDCError> {
        // Implementation for handling authorization code flow
        AuthorizationCode {}
    }

    // Checks the authorization code and returns an access token.
    // Client authentication must have already happened.
    pub fn access_token_request(
        &self,
        grant_type: GrantType,
        client_id: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<String, OIDCError> {
        match grant_type {
            GrantType::AuthorizationCode => {
                // Implementation for handling access token request

                let code = 
                    AuthorizationCode::decode_and_verify(code, &self.hmac_key, self.code_max_age)
                        .map_err(|err| OIDCAccessDeniedError::InvalidAuthorizationCode(err))?;
                
                // Check that the token request matches the authorization code being used
                code
                    .validate_token_request(client_id, redirect_uri, code_verifier)
                    .map_err(|err| OIDCAccessDeniedError::InvalidTokenRequest(err))?;
                
                // Issue OIDC token for user encoded in code


                Ok("access_token".to_string())
            }
            // Return error for unsupported flows.
            _ => Err(OIDCError::InvalidRequest("Invalid grant type".to_string())),
        }
    }
}