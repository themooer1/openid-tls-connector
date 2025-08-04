use std::fmt::{Display, Formatter};

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use ciborium::{from_reader, into_writer};
use serde::{Deserialize, Serialize};

// Error responses defined by rfc6749 4.1.2.1 with descriptions of each error
// exactly as they are defined in the RFC.
enum OIDCError {
    // The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than
    // once, or is otherwise malformed.
    InvalidRequest(String), 

    // The client is not authorized to request an authorization code using this method.
    UnauthorizedClient(String),

    // The resource owner or authorization server denied the request.
    AccessDenied(String),

    // The authorization server does not support obtaining an authorization code using this method.
    UnsupportedResponseType(String),

    // The requested scope is invalid, unknown, malformed.
    InvalidScope(String),

    // The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
    ServerError(String),

    // The authorization server is currently unable to handle the request due to a temporary overloading or maintenance
    // of the server.
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



impl Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeChallengeMethod::Plain => f.write_str("plain"),
            CodeChallengeMethod::S256 => f.write_str("S256"),
        }
    }
}

struct OIDCAuthCodePKCEFlow {

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
        OIDCAuthorizationCode {}
    }

    // Checks the authorization code and returns an access token.
    // Client authentication must have already happened.
    pub fn access_token_request(
        grant_type: GrantType,
        client_id: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<String, OIDCError> {
        if grant_type != GrantType::AuthorizationCode {
            return Err(OIDCError::InvalidRequest("Invalid grant type".to_string()));
        }



        
        // Implementation for handling access token request
        Ok("access_token".to_string())
    }
}