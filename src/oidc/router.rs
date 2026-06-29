use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

use super::client::ClientRegistry;
use super::code::CodeChallengeMethod;
use super::discovery::DiscoveryManager;
use super::protocol::{
    AccessTokenRequest, AuthorizationRequest, GrantType, OIDCAuthCodePKCEFlow, OIDCError,
    ResponseType, TokenIssueContext, TokenResponse,
};
use super::storage::TokenStore;
use super::token::JwtIssuer;
use crate::users::{resolve_groups, UserManager};

/// Shared application state passed to all handlers via axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub flow: Arc<OIDCAuthCodePKCEFlow>,
    pub jwt_issuer: Arc<JwtIssuer>,
    pub clients: Arc<ClientRegistry>,
    pub token_store: Arc<dyn TokenStore>,
    pub user_manager: Arc<UserManager>,
    pub discovery_manager: Arc<DiscoveryManager>,
    pub user_header: String,
    pub id_token_ttl: Duration,
    pub access_token_ttl: Duration,
    pub default_groups: Vec<String>,
}

impl AppState {
    /// Build a `TokenIssueContext` borrowing the collaborators needed by the
    /// token endpoint.
    pub fn token_context(&self) -> TokenIssueContext<'_> {
        TokenIssueContext {
            clients: &self.clients,
            jwt_issuer: &self.jwt_issuer,
            token_store: self.token_store.as_ref(),
            id_token_ttl: self.id_token_ttl,
            access_token_ttl: self.access_token_ttl,
        }
    }
}

/// Query parameters for `GET /authorize` (RFC 6749 §4.1.1 + OIDC + PKCE).
///
/// `code_challenge` and `code_challenge_method` are optional: PKCE is an
/// extension (RFC 7636), not a requirement of the base OIDC spec, so a
/// confidential client may legitimately omit it. Public clients should
/// always send it, but this server does not currently distinguish public
/// from confidential clients at the authorize endpoint.
#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: Option<String>,
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

/// Form parameters for `POST /token` (RFC 6749 §4.1.3).
///
/// `code_verifier` is optional: it's only required when the corresponding
/// `/authorize` request sent a `code_challenge`. If no challenge was
/// stored on the code, the verifier is ignored.
#[derive(Debug, Deserialize)]
pub struct TokenParams {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub code_verifier: Option<String>,
    pub client_id: Option<String>,
    /// Required for confidential clients; ignored for public clients.
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// RFC 6749 error response body.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

/// Map an `OIDCError` to the appropriate HTTP status code per RFC 6749 §5.2.
fn status_for_error(err: &OIDCError) -> StatusCode {
    match err {
        OIDCError::AccessDenied(_) => StatusCode::FORBIDDEN,
        OIDCError::InvalidClient(_) => StatusCode::UNAUTHORIZED,
        OIDCError::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        OIDCError::TemporarilyUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        // All other OAuth2 errors are 400 Bad Request.
        _ => StatusCode::BAD_REQUEST,
    }
}

impl IntoResponse for OIDCError {
    fn into_response(self) -> Response {
        let body = ErrorResponse {
            error: self.error_code().to_string(),
            error_description: Some(self.to_string()),
        };
        (status_for_error(&self), Json(body)).into_response()
    }
}

/// Build the OIDC router with all endpoints.
pub fn oidc_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(discovery_handler),
        )
        .route("/authorize", get(authorize_handler))
        .route("/token", post(token_handler))
        .route("/userinfo", get(userinfo_handler))
        .route("/jwks", get(jwks_handler))
        .with_state(state)
}

async fn discovery_handler(
    State(state): State<AppState>,
) -> Json<super::discovery::OIDCDiscovery> {
    Json(state.discovery_manager.get_discovery_info().clone())
}

async fn authorize_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Redirect, OIDCError> {
    // Validate response_type early. A bad response_type is a client error,
    // not a redirect error.
    let _response_type = ResponseType::from_str(&params.response_type)?;

    // PKCE: if a code_challenge is present, parse the method. If absent,
    // PKCE is simply not used for this request (the code will be issued
    // without a challenge and the token endpoint won't require a verifier).
    let code_challenge_method = match params.code_challenge_method.as_deref() {
        Some("S256") => CodeChallengeMethod::S256,
        Some("plain") | None => CodeChallengeMethod::Plain,
        Some(other) => {
            return Err(OIDCError::InvalidRequest(format!(
                "Unsupported code_challenge_method: {other}"
            )));
        }
    };

    // Per RFC 6749 §3.1.2.6, if the client_id is unknown or the redirect_uri
    // does not match, the server MUST NOT redirect — it informs the user
    // directly. So we validate both before touching the redirect.
    let client = state.clients.find_by_id(&params.client_id).ok_or_else(|| {
        OIDCError::UnauthorizedClient(format!("Unknown client_id: {}", params.client_id))
    })?;

    if !state
        .clients
        .validate_redirect_uri(&params.client_id, &params.redirect_uri)
    {
        return Err(OIDCError::InvalidRequest(
            "Invalid redirect_uri for this client".to_string(),
        ));
    }

    // The user is authenticated by mTLS at the proxy layer. The proxy injects
    // the client cert subject DN into a header; if it's absent, we cannot
    // identify the user and must deny the request.
    let header_value = headers
        .get(&state.user_header)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            OIDCError::AccessDenied(format!("Missing required header: {}", state.user_header))
        })?;

    let user = state
        .user_manager
        .resolve(header_value)
        .map_err(|e| OIDCError::AccessDenied(format!("Failed to resolve user: {e}")))?;

    let groups = resolve_groups(&client.groups, &state.default_groups);

    let scope: Vec<String> = params
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
        .unwrap_or_default();

    let (_, encoded_code) = state.flow.authorization_request(AuthorizationRequest {
        client_id: &params.client_id,
        redirect_uri: &params.redirect_uri,
        code_challenge: params.code_challenge.as_deref(),
        code_challenge_method,
        subject: &user.subject,
        nonce: params.nonce.as_deref(),
        groups,
        scope,
    })?;

    // Build the redirect URL with proper query encoding.
    let mut redirect_url = Url::parse(&params.redirect_uri)
        .map_err(|e| OIDCError::ServerError(format!("Invalid redirect_uri: {e}")))?;
    redirect_url
        .query_pairs_mut()
        .append_pair("code", &encoded_code);
    if let Some(state_val) = &params.state {
        redirect_url.query_pairs_mut().append_pair("state", state_val);
    }

    Ok(Redirect::temporary(redirect_url.as_str()))
}

async fn token_handler(
    State(state): State<AppState>,
    Form(params): Form<TokenParams>,
) -> Result<Json<TokenResponse>, OIDCError> {
    let grant_type = GrantType::from_str(&params.grant_type)?;

    let client_id = params
        .client_id
        .as_deref()
        .ok_or_else(|| OIDCError::InvalidRequest("Missing client_id".to_string()))?;

    let response = state.flow.access_token_request(
        AccessTokenRequest {
            grant_type,
            client_id,
            client_secret: params.client_secret.as_deref(),
            code: &params.code,
            redirect_uri: &params.redirect_uri,
            code_verifier: params.code_verifier.as_deref(),
        },
        &state.token_context(),
    )?;

    Ok(Json(response))
}

async fn userinfo_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, Response> {
    let claims = verify_bearer_token(&state, &headers).map_err(|r| *r)?;

    let record = state
        .token_store
        .lookup(&claims.jti)
        .ok_or_else(|| unauthenticated_error("Token has been revoked or is unknown"))?;

    Ok(Json(serde_json::json!({
        "sub": record.subject,
        "groups": record.groups,
        "scope": record.scope,
        "client_id": record.client_id,
    })))
}

async fn jwks_handler(State(state): State<AppState>) -> Json<super::token::Jwks> {
    Json(state.jwt_issuer.get_jwks())
}

/// Extract and verify a bearer access token from the `Authorization` header.
/// Returns the parsed claims on success, or a ready 401 `Response` on failure.
fn verify_bearer_token(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<super::token::AccessTokenClaims, Box<Response>> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| unauthenticated_error("Missing Authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| unauthenticated_error("Authorization header must use Bearer scheme"))?;

    state
        .jwt_issuer
        .verify_access_token(token)
        .map_err(|_| Box::new(unauthenticated_error("Invalid or expired access token")))
}

/// Build a 401 response with a Bearer error body (RFC 6750 §3).
fn unauthenticated_error(description: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: "invalid_token".to_string(),
            error_description: Some(description.to_string()),
        }),
    )
        .into_response()
}
