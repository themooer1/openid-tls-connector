use axum::{routing::get, Json, Router};
use serde::Serialize;
use url::Url;


pub fn discovery_router() -> Router {
    Router::new()
        // OIDC Discovery Endpoints
        .route("/.well-known/openid-configuration", get(discovery_handler))
}

// fn oidc_provider_router() -> Router {
//     Router::new()
//         // OIDC Provider Endpoints
//         .route("/authorize", get(authorize_handler))
//         .route("/token", post(token_handler))
// }