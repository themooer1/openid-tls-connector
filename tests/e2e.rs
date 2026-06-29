mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use openid_tls_connector::oidc::code::CodeChallengeMethod;
use openid_tls_connector::oidc::protocol::{
    AccessTokenRequest, AuthorizationRequest, GrantType, OIDCError,
};
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Discovery & JWKS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_discovery_endpoint() {
    let router = build_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["issuer"], TEST_ISSUER);
    assert!(json["authorization_endpoint"]
        .as_str()
        .unwrap()
        .contains("/authorize"));
    assert!(json["token_endpoint"]
        .as_str()
        .unwrap()
        .contains("/token"));
    assert!(json["userinfo_endpoint"]
        .as_str()
        .unwrap()
        .contains("/userinfo"));
    assert!(json["jwks_uri"].as_str().unwrap().contains("/jwks"));
    assert!(json["code_challenge_methods_supported"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "S256"));
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let router = build_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["keys"].as_array().unwrap().len(), 1);
    assert_eq!(json["keys"][0]["kty"], "RSA");
    assert_eq!(json["keys"][0]["alg"], "RS256");
    assert!(!json["keys"][0]["kid"].as_str().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// /authorize handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_authorize_missing_params() {
    let router = build_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Missing required query params → 400.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_missing_header() {
    let (challenge, _verifier) = test_pkce_pair();
    let router = build_test_router();
    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=xyz&code_challenge={}&code_challenge_method=S256",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Missing mTLS DN header → 403 (access_denied).
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_authorize_success_with_pkce_s256() {
    let (challenge, _verifier) = test_pkce_pair();
    let router = build_test_router();
    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=xyz&code_challenge={}&code_challenge_method=S256",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with(TEST_REDIRECT_URI));
    assert!(location.contains("code="));
    assert!(location.contains("state=xyz"));
}

#[tokio::test]
async fn test_authorize_success_with_plain_pkce() {
    let verifier = "plain-verifier-value";
    let router = build_test_router();
    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=abc&code_challenge={}&code_challenge_method=plain",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(verifier),
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("code="));
    assert!(location.contains("state=abc"));
}

#[tokio::test]
async fn test_authorize_unknown_client() {
    let (challenge, _verifier) = test_pkce_pair();
    let router = build_test_router();
    let uri = format!(
        "/authorize?response_type=code&client_id=unknown&redirect_uri={}&scope=openid&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Unknown client → 400, no redirect.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_invalid_redirect_uri() {
    let (challenge, _verifier) = test_pkce_pair();
    let router = build_test_router();
    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&code_challenge={}&code_challenge_method=S256",
        TEST_CLIENT_ID,
        urlencoding::encode("https://evil.example/cb"),
        urlencoding::encode(&challenge),
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Mismatched redirect_uri → 400, no redirect (per RFC 6749 §3.1.2.6).
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_authorize_unsupported_response_type() {
    let (challenge, _verifier) = test_pkce_pair();
    let router = build_test_router();
    let uri = format!(
        "/authorize?response_type=token&client_id={}&redirect_uri={}&scope=openid&code_challenge={}&code_challenge_method=S256",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unsupported_response_type");
}

#[tokio::test]
async fn test_authorize_echoes_state() {
    let (challenge, _verifier) = test_pkce_pair();
    let router = build_test_router();
    let state_val = "random-state-12345";
    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state={}&code_challenge={}&code_challenge_method=S256",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        state_val,
        urlencoding::encode(&challenge),
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let extracted = extract_param(location, "state");
    assert_eq!(extracted, state_val);
}

// ---------------------------------------------------------------------------
// /token handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_token_invalid_grant_type() {
    let router = build_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=client_credentials&code=x&redirect_uri=x&code_verifier=x&client_id=x",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_token_missing_client_id() {
    let router = build_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=authorization_code&code=x&redirect_uri=x&code_verifier=x",
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_token_wrong_verifier_returns_invalid_grant() {
    let (challenge, _verifier) = test_pkce_pair();
    let router = build_test_router();

    // Authorize to get a code.
    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=st&code_challenge={}&code_challenge_method=S256",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = extract_param(location, "code");

    // Redeem with wrong verifier.
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier=wrong&client_id={}",
        urlencoding::encode(&code),
        urlencoding::encode(TEST_REDIRECT_URI),
        TEST_CLIENT_ID,
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn test_token_replayed_code_returns_invalid_grant() {
    let (challenge, verifier) = test_pkce_pair();
    let router = build_test_router();

    // Authorize.
    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=st&code_challenge={}&code_challenge_method=S256",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = extract_param(location, "code");

    let form_body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_id={}",
        urlencoding::encode(&code),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&verifier),
        TEST_CLIENT_ID,
    );

    // First redemption succeeds.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Replay: same code is rejected.
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn test_token_confidential_client_without_secret_rejected() {
    let (challenge, verifier) = test_pkce_pair();
    let router = build_test_router();

    // Authorize as the confidential client.
    let uri = format!(
        "/authorize?response_type=code&client_id=confidential&redirect_uri={}&scope=openid&state=st&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = extract_param(location, "code");

    // Redeem without client_secret → 401 (invalid_client).
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_id=confidential",
        urlencoding::encode(&code),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&verifier),
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_token_confidential_client_with_secret_succeeds() {
    let (challenge, verifier) = test_pkce_pair();
    let router = build_test_router();

    let uri = format!(
        "/authorize?response_type=code&client_id=confidential&redirect_uri={}&scope=openid&state=st&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = extract_param(location, "code");

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_id=confidential&client_secret=s3cr3t",
        urlencoding::encode(&code),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&verifier),
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(!json["access_token"].as_str().unwrap().is_empty());
    assert!(!json["id_token"].as_str().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// /userinfo handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_userinfo_missing_bearer() {
    let router = build_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_userinfo_invalid_bearer() {
    let router = build_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("Authorization", "Bearer invalid-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_userinfo_wrong_scheme() {
    let router = build_test_router();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("Authorization", "Basic abc123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Protocol-level flow tests (no HTTP, direct API calls)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_protocol_full_flow_s256() {
    let (challenge, verifier) = test_pkce_pair();
    let state = build_test_state();
    let ctx = state.token_context();

    let (_, code_encoded) = state
        .flow
        .authorization_request(AuthorizationRequest {
            client_id: TEST_CLIENT_ID,
            redirect_uri: TEST_REDIRECT_URI,
            code_challenge: Some(&challenge),
            code_challenge_method: CodeChallengeMethod::S256,
            subject: "test-user",
            nonce: Some("my-nonce"),
            groups: vec![
                "everyone".to_string(),
                "authenticated".to_string(),
                "spa-users".to_string(),
            ],
            scope: vec!["openid".to_string()],
        })
        .unwrap();

    let token_response = state
        .flow
        .access_token_request(
            AccessTokenRequest {
                grant_type: GrantType::AuthorizationCode,
                client_id: TEST_CLIENT_ID,
                client_secret: None,
                code: &code_encoded,
                redirect_uri: TEST_REDIRECT_URI,
                code_verifier: Some(&verifier),
            },
            &ctx,
        )
        .unwrap();

    assert_eq!(token_response.token_type, "Bearer");
    assert!(!token_response.access_token.is_empty());
    assert!(!token_response.id_token.is_empty());

    // Verify ID token claims.
    let id_claims = state
        .jwt_issuer
        .verify_id_token(&token_response.id_token, TEST_CLIENT_ID)
        .unwrap();
    assert_eq!(id_claims.sub, "test-user");
    assert_eq!(id_claims.aud, TEST_CLIENT_ID);
    assert_eq!(id_claims.iss, TEST_ISSUER);
    assert_eq!(id_claims.nonce, Some("my-nonce".to_string()));
    let groups = id_claims.groups.unwrap();
    assert!(groups.contains(&"everyone".to_string()));
    assert!(groups.contains(&"authenticated".to_string()));
    assert!(groups.contains(&"spa-users".to_string()));

    // Verify access token claims.
    let access_claims = state
        .jwt_issuer
        .verify_access_token(&token_response.access_token)
        .unwrap();
    assert_eq!(access_claims.sub, "test-user");
    assert_eq!(access_claims.client_id, TEST_CLIENT_ID);
    assert_eq!(access_claims.iss, TEST_ISSUER);
    assert_eq!(access_claims.aud, TEST_ISSUER);

    // Token record stored for userinfo.
    let record = state.token_store.lookup(&access_claims.jti).unwrap();
    assert_eq!(record.subject, "test-user");
    assert!(record.groups.contains(&"spa-users".to_string()));
}

#[tokio::test]
async fn test_protocol_full_flow_plain_pkce() {
    let verifier = "plain-test-verifier";
    let state = build_test_state();
    let ctx = state.token_context();

    let (_, code_encoded) = state
        .flow
        .authorization_request(AuthorizationRequest {
            client_id: TEST_CLIENT_ID,
            redirect_uri: TEST_REDIRECT_URI,
            code_challenge: Some(verifier),
            code_challenge_method: CodeChallengeMethod::Plain,
            subject: "test-user",
            nonce: None,
            groups: vec![
                "everyone".to_string(),
                "authenticated".to_string(),
                "spa-users".to_string(),
            ],
            scope: vec!["openid".to_string()],
        })
        .unwrap();

    let token_response = state
        .flow
        .access_token_request(
            AccessTokenRequest {
                grant_type: GrantType::AuthorizationCode,
                client_id: TEST_CLIENT_ID,
                client_secret: None,
                code: &code_encoded,
                redirect_uri: TEST_REDIRECT_URI,
                code_verifier: Some(verifier),
            },
            &ctx,
        )
        .unwrap();

    let id_claims = state
        .jwt_issuer
        .verify_id_token(&token_response.id_token, TEST_CLIENT_ID)
        .unwrap();
    assert_eq!(id_claims.sub, "test-user");
    assert!(id_claims.nonce.is_none());
}

#[tokio::test]
async fn test_protocol_wrong_verifier_fails() {
    let (challenge, _verifier) = test_pkce_pair();
    let state = build_test_state();
    let ctx = state.token_context();

    let (_, code_encoded) = state
        .flow
        .authorization_request(AuthorizationRequest {
            client_id: TEST_CLIENT_ID,
            redirect_uri: TEST_REDIRECT_URI,
            code_challenge: Some(&challenge),
            code_challenge_method: CodeChallengeMethod::S256,
            subject: "test-user",
            nonce: None,
            groups: vec![],
            scope: vec!["openid".to_string()],
        })
        .unwrap();

    let result = state.flow.access_token_request(
        AccessTokenRequest {
            grant_type: GrantType::AuthorizationCode,
            client_id: TEST_CLIENT_ID,
            client_secret: None,
            code: &code_encoded,
            redirect_uri: TEST_REDIRECT_URI,
            code_verifier: Some("wrong-verifier"),
        },
        &ctx,
    );

    assert!(matches!(result, Err(OIDCError::InvalidGrant(_))));
}

// ---------------------------------------------------------------------------
// Full HTTP end-to-end flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_full_http_flow_s256() {
    let (challenge, verifier) = test_pkce_pair();
    let router = build_test_router();

    // Step 1: Authorize via HTTP.
    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=mystate&code_challenge={}&code_challenge_method=S256&nonce=test-nonce",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = extract_param(location, "code");
    assert_eq!(extract_param(location, "state"), "mystate");

    // Step 2: Token exchange via HTTP.
    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_id={}",
        urlencoding::encode(&code),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&verifier),
        TEST_CLIENT_ID,
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let token_response: Value = serde_json::from_slice(&body).unwrap();
    let access_token = token_response["access_token"].as_str().unwrap();
    let id_token = token_response["id_token"].as_str().unwrap();
    let expires_in = token_response["expires_in"].as_u64().unwrap();
    assert!(!access_token.is_empty());
    assert!(!id_token.is_empty());
    assert_eq!(token_response["token_type"], "Bearer");
    assert!(expires_in > 0);

    // Verify the ID token's nonce and sub claims.
    let id_claims = decode_jwt_payload(id_token);
    assert_eq!(id_claims["sub"], "test-user");
    assert_eq!(id_claims["aud"], TEST_CLIENT_ID);
    assert_eq!(id_claims["iss"], TEST_ISSUER);
    assert_eq!(id_claims["nonce"], "test-nonce");
    let groups = id_claims["groups"].as_array().unwrap();
    assert!(groups.iter().any(|g| g == "spa-users"));
    assert!(groups.iter().any(|g| g == "everyone"));
    assert!(groups.iter().any(|g| g == "authenticated"));

    // Step 3: UserInfo via HTTP.
    let response = router
        .oneshot(
            Request::builder()
                .uri("/userinfo")
                .header("Authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let userinfo: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(userinfo["sub"], "test-user");
    let groups = userinfo["groups"].as_array().unwrap();
    assert!(groups.iter().any(|g| g == "spa-users"));
    assert_eq!(userinfo["client_id"], TEST_CLIENT_ID);
}

#[tokio::test]
async fn test_full_http_flow_plain_pkce() {
    let verifier = "plain-http-verifier";
    let router = build_test_router();

    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=ps&code_challenge={}&code_challenge_method=plain",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(verifier),
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(TEST_DN_HEADER, TEST_USER_DN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    let code = extract_param(location, "code");

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}&client_id={}",
        urlencoding::encode(&code),
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(verifier),
        TEST_CLIENT_ID,
    );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Negative HTTP flow: missing header at /authorize
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_full_http_missing_header_403() {
    let (challenge, _verifier) = test_pkce_pair();
    let router = build_test_router();
    let uri = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&code_challenge={}&code_challenge_method=S256",
        TEST_CLIENT_ID,
        urlencoding::encode(TEST_REDIRECT_URI),
        urlencoding::encode(&challenge),
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri(&uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
