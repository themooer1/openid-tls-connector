# Plan: Finishing `openid-tls-connector`

## Decisions (confirmed)

- **ID token signing**: RS256 (asymmetric). Signing key exposed via JWKS endpoint.
- **Access tokens**: self-signed JWTs (stateless, no token store needed for validation).
  - A `TokenStore` is still useful for revocation/introspection and for `/userinfo`
    to avoid re-parsing the JWT; keep a lightweight in-memory store keyed by the
    JWT `jti`, but validation of the JWT itself is by signature + `exp`.
- **TLS termination**: not in this process. Always behind a reverse proxy that
  populates a header with the client cert DN. The header name is configurable.
- **Header contents**: assumed to be an x509 DN string (RFC 4514 form, e.g.
  `CN=alice,OU=eng,O=acme`). A minimal hand-rolled DN parser is sufficient.
- **Config format**: TOML.

---

## Current state

The project is a Rust OIDC provider that authenticates users via mTLS client
certificate DN. The code/PKCE/timestamp primitives are solid
(`src/oidc/code/*`), but everything around them is stubbed, private, or broken.
`cargo check` currently fails.

### What works
- `src/oidc/code/code.rs` — `AuthorizationCode` with `sign_and_encode`,
  `decode_and_verify`, `validate_token_request`
- `src/oidc/code/signature.rs` — BLAKE3-keyed-hash + CBOR + base64 signed
  container, `MacKey`
- `src/oidc/code/pkce.rs` — `CodeChallengeMethod` + `verify_pkce` (Plain + S256)
- `src/oidc/code/timestamp.rs` — `TimestampedContainer` freshness check

### What's broken/missing
- `protocol.rs::authorization_request` is a non-compiling stub
  (`AuthorizationCode {}`)
- `protocol.rs::access_token_request` returns hardcoded `"access_token"` — no
  real token issuance
- `router.rs::discovery_router` references a non-existent `discovery_handler`;
  provider router is commented out
- `discovery.rs` — `OIDCDiscovery`, `discovery_info`, `DiscoveryManager` are all
  private, unusable from `router.rs`
- `endpoints.rs::OIDCEndpointPaths` doesn't derive serde traits
- `client.rs` — `AuthResult` variants are private; `ClientManager` not exported
- `session.rs`, `storage.rs`, `users/mod.rs` — empty files
- `bin/server.rs` — boilerplate with typo `oidc::routery::discovery_router`;
  `lib.rs` doesn't `pub mod oidc`
- `bin/config.rs` — only `use sha3::Sha3_256;`
- No config file format, no token issuance, no JWT signing, no tests

---

## Task 1 — Auto-complete OIDC PKCE code flow

Goal: a client hits `/authorize` with PKCE params; the server, having already
authenticated the user via mTLS, immediately issues a code and redirects. The
client redeems the code at `/token` for an ID/access token.

### 1.1 Visibility & plumbing fixes
- `src/lib.rs`: change `mod oidc; mod users;` → `pub mod oidc; pub mod users;`
- Make `OIDCDiscovery`, `DiscoveryManager`, `discovery_info`,
  `OIDCEndpointPaths` (with `Serialize`/`Deserialize`/`Clone`), `AuthResult`
  variants, `ClientManager`, `OIDCAuthCodePKCEFlow`, `OIDCError`,
  `ResponseType`, `GrantType` all `pub` as needed.
- Fix `bin/server.rs` import (`router` not `routery`) and remove leftover axum
  example handlers.

### 1.2 Implement `authorization_request` (src/oidc/protocol.rs)
- Construct and return a real `AuthorizationCode { client_id, redirect_uri,
  code_challenge, code_challenge_method, timestamp: SystemTime::now() }`.
- Take `MacKey`/`code_max_age` from `&self` (currently `authorization_request`
  is `pub fn` not `&self` — make it `&self` so it can sign).
- Return both the `AuthorizationCode` and its signed/encoded string
  (`sign_and_encode`).

### 1.3 Implement `access_token_request` (src/oidc/protocol.rs)
- After `decode_and_verify` + `validate_token_request`, issue:
  - **ID token** (RS256 JWT) — see 1.6
  - **Access token** (self-signed RS256 JWT) — see 1.6
- Return a proper
  `TokenResponse { access_token, token_type: "Bearer", expires_in, id_token, scope }`
  rather than `String`.

### 1.4 Wire the axum router (src/oidc/router.rs)
Build `oidc_router(state)` with:
- `GET /.well-known/openid-configuration` → discovery JSON
- `GET /authorize` → reads PKCE params, calls `authorization_request`, returns
  `302` redirect to `redirect_uri?code=...&state=...`
- `POST /token` (and `GET` per spec) → parses form body, calls
  `access_token_request`, returns JSON `TokenResponse`
- `GET /userinfo` → bearer-token lookup, returns user claims JSON
- `GET /jwks` → JWKS document (RSA public key for RS256 verification)
- Use `axum::extract::State` with an `AppState` holding: `MacKey`,
  `issuer: Url`, `OIDCEndpointPaths`, `UserManager`, `ClientManager`,
  `TokenStore`, signing key, config.

### 1.5 Token storage (src/oidc/storage.rs)
- `TokenStore` trait + in-memory impl keyed by JWT `jti`
  (`RwLock<HashMap<String, TokenRecord>>`).
- `TokenRecord { subject: String, client_id: String, scope: Vec<String>,
  groups: Vec<String>, expires_at: SystemTime, jti: String }`.
- `issue(...)`, `lookup(&self, jti) -> Option<TokenRecord>`, `revoke(...)`.
- `/userinfo` looks up by `jti` extracted from the bearer JWT (after signature
  verification) — avoids re-parsing/decoding claims in multiple places.

### 1.6 JWT issuance (new: src/oidc/token.rs)
- Add dependency `jsonwebtoken` (RS256).
- `JwtIssuer` holding an RSA keypair (PEM-loaded from config path, or generated
  for tests).
- **ID token** claims: `iss`, `sub`, `aud` (client_id), `exp`, `iat`, `nonce`
  (if supplied at /authorize), `groups` (from requirement 3).
- **Access token** claims: `iss`, `sub`, `aud` (issuer userinfo endpoint or
  client_id), `exp`, `iat`, `jti` (random), `scope`, `groups`, `client_id`.
- Expose the RSA public key as a `Jwk` for the JWKS endpoint
  (`kid` computed from the public key thumbprint).

### 1.7 Session module (src/oidc/session.rs)
- For this mTLS-auto-flow there's no interactive session, but `/authorize` may
  want to stash `nonce` to validate at `/token`. Recommended approach:
  **stateless** — embed `nonce` in the signed `AuthorizationCode` (Task 3.3
  schema bump). `session.rs` stays minimal or unused for v1.

### 1.8 Authorize handler behavior (the "automatic" part)
- Don't render a login/consent page. The user is already authenticated by mTLS
  at the TLS layer (handled by the proxy).
- Extract subject from the configured header (Task 2), resolve groups
  (Task 3), build `AuthorizationCode`, redirect. This is what makes the flow
  "automatic."

---

## Task 2 — User identification from a configurable header

The default header is `X-Client-Cert-Subject` and contains the x509 DN of the
mTLS client, but the header name is configurable.

### 2.1 Config (add to `bin/config.rs` + a `Config` struct)
- Define a `Config` struct (serde, TOML) with fields including:
  - `issuer: Url`
  - `listen_addr: String`
  - `code_max_age_seconds: u64`
  - `code_hmac_key: String` (hex/base64 of 32 bytes)
  - `user_header: String` (default `"X-Client-Cert-Subject"`)
  - `dn_attribute: String` (default `"CN"`) — which DN component to treat as
    username
  - `id_token_ttl_seconds: u64`
  - `access_token_ttl_seconds: u64`
  - `signing_key_path: String` (PEM file with RSA private key for RS256)
  - `clients: Vec<ClientConfig>`
  - `group_mappings: ...` (Task 3)
  - `default_groups: Vec<String>` (Task 3)
- Add `toml` + `serde` derive deps to `Cargo.toml`.

### 2.2 DN parsing (src/users/mod.rs)
- A `UserManager` (or `UserResolver`) that, given the raw header value (e.g.
  `CN=alice,OU=eng,O=acme`), parses the DN and extracts the configured
  attribute.
- Use a small DN parser — hand-rolled (RDN split on `,`, attr split on `=`) to
  avoid heavy deps. Document the subset supported (RFC 4514 string form, with
  escaped-comma caveat).
- Expose `UserManager::resolve(header_value: &str) -> Result<User, UserError>`.
- `User { subject: String, raw_dn: String }`.

### 2.3 Header extraction in handlers
- Axum extractor/middleware that reads `req.headers().get(&config.user_header)`,
  passes the resolved `User` into the `/authorize` handler via `State` or
  `Extension`.
- Decide policy when header absent: reject with `401` (recommended). Make it
  configurable later if needed.

### 2.4 mTLS termination assumption
- This server expects to sit behind an mTLS-terminating reverse proxy
  (nginx/envoy/traefik) that populates the configured header with the client
  cert subject DN. The Rust process itself does not terminate TLS.

---

## Task 3 — Group mappings (per-client + default)

### 3.1 Config shapes
```toml
default_groups = ["everyone", "authenticated"]

[[clients]]
client_id = "spa"
# public client (PKCE), no secret
redirect_uris = ["https://app.example/cb"]
groups = ["spa-users", "reporting-viewers"]

[[clients]]
client_id = "backend"
client_secret = "..."
redirect_uris = ["..."]
groups = ["api-callers"]
```

### 3.2 Group resolution (src/users/mod.rs or new src/groups.rs)
- `fn resolve_groups(client: &ClientConfig, default: &[String]) -> Vec<String>`
  → dedup default ∪ client.groups.
- Store resolved groups on the `AuthorizationCode` (add a `groups: Vec<String>`
  field — bump code schema) so `/token` is self-contained and `/userinfo` reads
  from the `TokenRecord`.
- Add `groups` claim to ID token, access token, and `/userinfo` response.

### 3.3 Schema impact
- `AuthorizationCode` gains `subject: String`, `nonce: Option<String>`,
  `groups: Vec<String>`, `scope: Vec<String>`. Update `validate_token_request`
  signature accordingly (or keep validation minimal and just carry the data
  through). Bump/verify CBOR round-trips with the new fields.

---

## Task 4 — Tests

Add `#[cfg(test)]` modules and a `tests/` integration directory. Use
`tower::ServiceExt` (`oneshot`) for handler tests without spawning a real
server — add `tower` to `[dev-dependencies]`.

### 4.1 Unit tests (per module)
- `code/pkce.rs`: known verifier→challenge vectors for S256 and Plain;
  mismatch returns false.
- `code/timestamp.rs`: fresh container extracts OK; aged container returns
  `NotFresh`; clock-skew case.
- `code/signature.rs`: sign→encode→decode round-trip; tampered bytes →
  `InvalidSignature`; wrong key → `InvalidSignature`; bad base64 →
  `InvalidBase64Encoding`; expired → `InvalidTimestamp`.
- `code/code.rs`: `validate_token_request` accepts matching
  client/redirect/verifier; rejects wrong client, wrong redirect, wrong
  verifier.
- `users/mod.rs`: DN parsing for CN extraction, missing attribute, multi-RDN
  order, escaped commas; group resolution (default only, client only, union,
  dedup).
- `protocol.rs`: `authorization_request` produces a code whose fields match
  inputs; `access_token_request` rejects expired code, wrong client, wrong
  PKCE, and succeeds on valid input (mock `TokenStore`).
- `discovery.rs`: discovery JSON contains correct endpoint URLs derived from
  issuer + paths.
- `token.rs`: JWT issuance produces verifiable RS256 JWTs with correct claims;
  expired token fails verification.

### 4.2 Handler-level tests (axum + tower::oneshot)
- `GET /.well-known/openid-configuration` returns 200 + valid JSON with
  required fields.
- `GET /authorize`:
  - missing required params → 400 with RFC 6749 error body
  - valid PKCE request + mTLS header present → 302 to redirect_uri with `code`
    and `state`
  - missing mTLS header → 401
- `POST /token`:
  - valid code/verifier → 200 JSON with `access_token`, `id_token`,
    `expires_in`
  - replayed code → 400
  - wrong verifier → 400 `invalid_grant`
- `GET /userinfo`:
  - valid bearer → 200 with `sub` and `groups`
  - missing/invalid bearer → 401

### 4.3 End-to-end test (tests/e2e.rs)
Drive the entire flow with a single test using a constructed `Router` (no
network):
1. Build `AppState` with a fixed `MacKey`, test issuer, one configured client,
   default + client groups, and a generated RSA signing key.
2. Synthesize an mTLS header value (`CN=test-user,...`).
3. `GET /authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid&state=xyz&code_challenge=...&code_challenge_method=S256`
   with the header → capture 302 Location.
4. Parse `code` and `state` from Location; assert `state` echoes; assert
   redirect_uri matches.
5. `POST /token` with `grant_type=authorization_code`, `code`, `redirect_uri`,
   `code_verifier`, `client_id` → parse `TokenResponse`.
6. Decode the returned `id_token` JWT header+payload (verify with the test
   public key) and assert `sub == "test-user"`, `aud == client_id`, `groups` is
   the union of default + client, `iss == issuer`.
7. `GET /userinfo` with `Authorization: Bearer <access_token>` → assert `sub`
   and `groups` match. Verify the access token JWT signature against the test
   public key.
8. Negative e2e: missing header at /authorize → 401; wrong verifier at /token
   → 400.

Add a second e2e variant for a plain (non-S256) PKCE challenge and for `nonce`
echo in the ID token.

### 4.4 Test infra
- Helper in `tests/common/mod.rs` (or `src/test_utils.rs` gated by
  `#[cfg(test)]` + `pub`) to build a configured `Router`, a known PKCE pair,
  and a DN-header value.
- Generate a test RSA signing key once (lazy static or `OnceLock`) so JWT
  tests are deterministic.

---

## Suggested implementation order

1. Fix visibility/compile errors (1.1) so `cargo check` passes.
2. Add `Config` + TOML loading (2.1) and `UserManager` + DN parsing (2.2) with
   unit tests (4.1).
3. Extend `AuthorizationCode` schema (3.3) and implement
   `authorization_request` (1.2) + tests.
4. Add `TokenStore` (1.5) and JWT signing (1.6).
5. Implement `access_token_request` (1.3) + tests.
6. Build the axum router + handlers (1.4, 1.8, 2.3) including `/authorize`,
   `/token`, `/userinfo`, discovery, jwks.
7. Implement group resolution (3.2) and wire into code/token/userinfo.
8. Replace `bin/server.rs` with a real `main` that loads config and serves the
   router.
9. Write handler tests (4.2) and e2e tests (4.3).
10. `cargo test` green; `cargo clippy -- -D warnings` clean.

---

## New dependencies to add

- `toml` (config parsing)
- `serde_json` (JSON bodies / JWT claims) — or rely on `axum::Json` re-export
- `jsonwebtoken` (RS256 ID + access tokens)
- `rand` (JWT `jti`, test key generation)
- `tower` (`[dev-dependencies]`, for `oneshot` tests)
- Optionally `axum-test` or `hyper` for full-HTTP e2e if `oneshot` proves
  limiting.
