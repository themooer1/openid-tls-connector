// Configures the relative paths to the OIDC endpoints, e.g., /authorize, /token, etc.
pub struct OIDCEndpointPaths
{   
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
}