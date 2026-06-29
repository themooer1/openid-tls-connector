# openid-tls-connector

An [OpenID Connect](https://openid.net/connect/) provider that authenticates
users via mutual TLS (mTLS) client certificates, designed to sit behind a
reverse proxy that terminates TLS and injects the client certificate subject
DN as an HTTP header.

There is no login page, no consent screen, and no password — the user is
authenticated at the TLS layer by the proxy. The server reads the client cert
DN from a configurable header, extracts the subject, and immediately issues
OIDC authorization codes, ID tokens, and access tokens.

## How It Works

```
┌──────────┐    mTLS     ┌──────────────┐    HTTP + header    ┌─────────────────────────┐
│  Client  │────────────▶│  Reverse     │───────────────────▶│  openid-tls-connector   │
│  (app)   │  cert+key   │  Proxy       │  X-Client-Cert-    │                         │
│          │             │  (nginx/env  │  Subject: CN=...   │  /authorize → code      │
│          │             │  oy/traefik) │                    │  /token     → tokens    │
│          │             │              │                    │  /userinfo  → claims    │
│          │◀───────────│              │◀───────────────────│  /jwks      → public key │
│          │  OIDC tokens│              │   OIDC response    │  /.well-known/...       │
└──────────┘             └──────────────┘                    └─────────────────────────┘
```

**Flow:**

1. Client sends an authorization request to `/authorize` with PKCE parameters,
   over a TLS connection that requires a client certificate.
2. The proxy terminates mTLS, verifies the client cert against its CA, and
   injects the cert's subject DN into the `X-Client-Cert-Subject` header.
3. The server parses the DN, extracts the configured attribute (default: `CN`)
   as the subject, resolves groups, and issues a signed authorization code.
4. The server redirects to the client's `redirect_uri` with the code.
5. The client redeems the code at `/token` (with PKCE verifier) for an ID
   token and access token (both RS256 JWTs).
6. The client calls `/userinfo` with the access token to get claims.

## Features

- **mTLS-based authentication** — no passwords, no login pages, no sessions.
- **OIDC Authorization Code + PKCE flow** — the standard web flow, with both
  S256 and plain PKCE challenge methods.
- **RS256 JWTs** — ID tokens and self-signed access tokens, with JWKS
  endpoint for key discovery.
- **Stateless authorization codes** — signed with BLAKE3-keyed-hash, no
  database needed for code issuance (replay protection via in-memory store).
- **Group mappings** — per-client groups plus server-wide default groups,
  included in ID tokens, access tokens, and `/userinfo` responses.
- **Configurable DN extraction** — pick which x509 DN attribute to use as
  the subject (default: `CN`).
- **Confidential and public clients** — supports both PKCE-only public
  clients and secret-based confidential clients with constant-time secret
  comparison.
- **Distroless container** — minimal attack surface, non-root, read-only
  filesystem.
- **Replay protection** — authorization codes are one-time use.
- **Proper OAuth2 error handling** — RFC 6749 error codes and HTTP status
  codes throughout.

## Quick Start

### Prerequisites

- Rust 1.85+ (edition 2024)
- An RSA private key for JWT signing

### Generate a Signing Key

```sh
openssl genpkey -algorithm RSA -out signing_key.pem -pkeyopt rsa_keygen_bits:2048
```

### Generate an HMAC Key

```sh
openssl rand -hex 32
```

### Create a Config File

```sh
cp config.example.toml config.toml
# Edit config.toml: set issuer, code_hmac_key, signing_key_path, clients
```

### Run

```sh
cargo run --bin server -- config.toml
# Listening on 127.0.0.1:8080
```

### Test with curl (simulating the proxy header)

```sh
# Discovery:
curl http://localhost:8080/.well-known/openid-configuration | jq .

# Authorize (simulating mTLS header injection):
curl -v "http://localhost:8080/authorize?response_type=code&client_id=spa&redirect_uri=https://app.example/cb&scope=openid&state=xyz&code_challenge=$(python3 -c 'import base64,hashlib; print(base64.urlsafe_b64encode(hashlib.sha256(b"test-verifier").digest()).decode().rstrip("="))')&code_challenge_method=S256" \
  -H "X-Client-Cert-Subject: CN=test-user,OU=eng,O=acme"
# → 302 redirect with code and state

# Token exchange:
curl -v -X POST http://localhost:8080/token \
  -d "grant_type=authorization_code&code=CODE&redirect_uri=https://app.example/cb&code_verifier=test-verifier&client_id=spa"
# → JSON with access_token, id_token

# Userinfo:
curl -v http://localhost:8080/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
# → JSON with sub, groups, scope, client_id
```

## Configuration Reference

The server reads a TOML config file (path passed as the first CLI argument,
defaults to `config.toml`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuer` | string | **required** | Canonical issuer URL. Must not have a trailing slash. Used as `iss` in tokens and in discovery. |
| `listen_addr` | string | **required** | Bind address (e.g. `0.0.0.0:8080`). |
| `code_max_age_seconds` | integer | **required** | Authorization code lifetime. Short (e.g. 300) is recommended. |
| `code_hmac_key` | string | **required** | 32-byte hex-encoded key (64 hex chars) for signing authorization codes. Generate with `openssl rand -hex 32`. |
| `user_header` | string | `X-Client-Cert-Subject` | HTTP header containing the client cert subject DN, injected by the proxy. |
| `dn_attribute` | string | `CN` | Which DN attribute to extract as the OIDC `sub` claim. |
| `id_token_ttl_seconds` | integer | `3600` | ID token lifetime. |
| `access_token_ttl_seconds` | integer | `3600` | Access token lifetime. |
| `signing_key_path` | string | **required** | Path to a PKCS#8 PEM-encoded RSA private key for RS256 JWT signing. |
| `default_groups` | string array | `[]` | Groups assigned to every authenticated user. |
| `[[clients]]` | table array | — | OAuth2/OIDC client definitions (see below). |

### Client Configuration

Each `[[clients]]` entry:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | yes | OAuth2 client identifier. |
| `client_secret` | string | no | Client secret for confidential clients. Omit for public (PKCE-only) clients. |
| `redirect_uris` | string array | yes | Allowed redirect URIs. |
| `groups` | string array | no | Groups specific to this client. Unioned with `default_groups`. |

### Example

```toml
issuer = "https://auth.example.com"
listen_addr = "0.0.0.0:8080"
code_max_age_seconds = 300
code_hmac_key = "a1b2c3d4..."  # openssl rand -hex 32
signing_key_path = "/app/secrets/signing_key.pem"
default_groups = ["everyone", "authenticated"]

[[clients]]
client_id = "spa"
redirect_uris = ["https://app.example.com/cb"]
groups = ["spa-users", "reporting-viewers"]

[[clients]]
client_id = "backend"
client_secret = "super-secret"
redirect_uris = ["https://api.example.com/callback"]
groups = ["api-callers"]
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/openid-configuration` | — | OIDC discovery document. |
| GET | `/authorize` | mTLS header | Authorization endpoint. Redirects with `code` and `state`. |
| POST | `/token` | — | Token endpoint. Returns `access_token`, `id_token`, `expires_in`. |
| GET | `/userinfo` | Bearer | Returns `sub`, `groups`, `scope`, `client_id`. |
| GET | `/jwks` | — | JWKS document with the RSA public key for RS256 verification. |

### ID Token Claims

| Claim | Description |
|-------|-------------|
| `iss` | Issuer URL from config. |
| `sub` | Subject extracted from the mTLS client cert DN. |
| `aud` | The `client_id` that requested the token. |
| `exp` | Expiration time (Unix timestamp). |
| `iat` | Issued-at time (Unix timestamp). |
| `nonce` | Echoed from the `/authorize` request if provided. |
| `groups` | Union of `default_groups` and the client's `groups`. |

### Access Token Claims

| Claim | Description |
|-------|-------------|
| `iss` | Issuer URL. |
| `sub` | Subject from the mTLS client cert DN. |
| `aud` | Issuer URL (the audience is the issuer's own `/userinfo`). |
| `exp` | Expiration time. |
| `iat` | Issued-at time. |
| `jti` | Unique token ID (UUID v4). |
| `scope` | Granted scopes. |
| `groups` | Granted groups. |
| `client_id` | The OAuth2 client that requested the token. |

## Docker

The included `Dockerfile` produces a distroless image:

```sh
docker build -t openid-tls-connector .
docker run -p 8080:8080 -v $(pwd)/config.toml:/app/secrets/config.toml:ro -v $(pwd)/signing_key.pem:/app/secrets/signing_key.pem:ro openid-tls-connector
```

The image:
- Is based on `gcr.io/distroless/cc-debian12:nonroot` (no shell, no package manager).
- Runs as non-root (UID 65534).
- Expects `config.toml` and `signing_key.pem` mounted at `/app/secrets/`.
- Exposes port 8080.

## Kubernetes

See [`deploy/README.md`](deploy/README.md) for a complete Kubernetes
deployment guide with manifests for:

- Namespace, Deployment (2 replicas), Service
- Ingress with nginx mTLS annotations and header injection
- NetworkPolicy restricting traffic to the ingress namespace
- PodDisruptionBudget for high availability
- Security-hardened pod spec (non-root, read-only FS, dropped capabilities)
- Kustomize base for `kubectl apply -k deploy/`

## Reverse Proxy Configuration

### nginx

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate     /etc/nginx/tls/server.crt;
    ssl_certificate_key /etc/nginx/tls/server.key;

    # mTLS: require client certificate
    ssl_client_certificate /etc/nginx/ca/client-ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 1;

    location / {
        proxy_pass http://openid-tls-connector:8080;

        # Inject the client cert subject DN
        proxy_set_header X-Client-Cert-Subject $ssl_client_s_dn;

        # Standard proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Traefik (static config)

```yaml
entryPoints:
  web-secure:
    address: ":443"
    http:
      tls:
        certResolver: letsencrypt
        domains: [main: "auth.example.com"]
        options: mtls@file

tls:
  options:
    mtls:
      clientAuth:
        caFiles: ["/etc/traefik/ca/client-ca.crt"]
        clientAuthType: RequireAndVerifyClientCert
```

Traefik exposes the client cert info via the `X-Forwarded-Ssl-Client-Cert`
header. Set `user_header = "X-Forwarded-Ssl-Client-Cert"` in `config.toml`
to use it.

## Security Considerations

1. **Header spoofing** — the server trusts the `X-Client-Cert-Subject` header.
   It MUST sit behind a reverse proxy that terminates mTLS and overwrites this
   header. Never expose the server directly to untrusted networks. The
   NetworkPolicy in the K8s manifests enforces this at the network level.

2. **Client CA** — the proxy must verify client certificates against a trusted
   CA. If the proxy does not verify, anyone can inject a fake DN header.

3. **HMAC key rotation** — the `code_hmac_key` is used to sign authorization
   codes. Rotating it invalidates all outstanding codes. There is no key
   rotation protocol in v1; rotate during a maintenance window.

4. **Signing key management** — the RSA signing key should be stored in a
   secret manager (Kubernetes Secret, Vault, etc.). The JWKS endpoint
   exposes only the public key.

5. **In-memory token store** — the `InMemoryTokenStore` loses all state on
   restart. Issued access tokens remain valid until their `exp` (verified by
   JWT signature), but revocation is not possible after restart. For
   multi-instance deployments, replace with a shared store (Redis, etc.).

6. **No refresh tokens** — v1 does not issue refresh tokens. Clients must
   re-authorize when tokens expire (which means a new mTLS request through
   the proxy).

## Development

### Build and Test

```sh
# Build:
cargo build

# Run all tests (unit + e2e):
cargo test

# Lint:
cargo clippy --all-targets -- -D warnings

# Run the server locally:
cargo run --bin server -- config.toml
```

### Project Structure

```
src/
  lib.rs                  # Library root (pub mod oidc, pub mod users)
  oidc/
    mod.rs                # OIDC module root
    client.rs             # ClientConfig, ClientRegistry, client auth
    code/
      authorization_code.rs  # AuthorizationCode, validate_token_request
      pkce.rs             # PKCE verification (S256, plain)
      signature.rs        # BLAKE3-MAC signed code container
      timestamp.rs        # Freshness check for signed codes
    discovery.rs          # OIDC discovery document
    endpoints.rs          # Endpoint path configuration
    protocol.rs           # OIDCAuthCodePKCEFlow (authorize + token logic)
    router.rs             # axum router and HTTP handlers
    storage.rs            # TokenStore trait + InMemoryTokenStore
    token.rs              # JwtIssuer (RS256 ID + access tokens, JWKS)
  users/
    mod.rs                # UserManager, DN parsing, group resolution
  bin/
    server/
      main.rs             # Server binary (loads config, starts axum)
      config.rs           # Config struct (TOML deserialization)
tests/
  common/mod.rs           # Test helpers (router builder, PKCE pair, etc.)
  e2e.rs                  # Integration tests (handler-level + full flow)
```

## License

Specify your license here.
