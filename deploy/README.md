# Kubernetes Deployment Guide

This guide covers deploying `openid-tls-connector` to a Kubernetes cluster
with mTLS termination at the ingress controller.

## Prerequisites

- A Kubernetes cluster (1.27+)
- `kubectl` configured to reach your cluster
- An ingress controller installed (nginx-ingress recommended)
- A client CA certificate for mTLS verification
- An RSA private key for JWT signing
- `openssl` for generating keys
- `kustomize` (or `kubectl` with built-in kustomize)

## Manifests Overview

| File | Purpose |
|------|---------|
| `namespace.yaml` | Creates the `openid-tls-connector` namespace. |
| `configmap.yaml` | Template config.toml (not mounted directly — use it to build your Secret). |
| `secret.yaml` | Secret containing the real `config.toml` and `signing_key.pem`. |
| `deployment.yaml` | 2-replica Deployment with probes, resource limits, security context. |
| `service.yaml` | ClusterIP Service on port 8080. |
| `ingress.yaml` | Ingress with nginx mTLS annotations and header injection. |
| `networkpolicy.yaml` | Restricts ingress to the ingress-nginx namespace. |
| `poddisruptionbudget.yaml` | Keeps at least 1 pod available during disruptions. |
| `kustomization.yaml` | Ties everything together for `kubectl apply -k`. |

## Step-by-Step Deployment

### 1. Build and Push the Container Image

```sh
# From the repository root:
docker build -t ghcr.io/your-org/openid-tls-connector:latest .

# Push to your registry:
docker push ghcr.io/your-org/openid-tls-connector:latest
```

Update the `image` field in `deployment.yaml` to match your registry path.

### 2. Generate the HMAC Key and Signing Key

```sh
# 32-byte HMAC key (hex-encoded, 64 characters):
openssl rand -hex 32
# → e.g. a1b2c3d4e5f6... (64 chars)

# RSA private key for RS256 JWT signing:
openssl genpkey -algorithm RSA -out signing_key.pem -pkeyopt rsa_keygen_bits:2048
```

### 3. Create the Config File

Copy the template from the ConfigMap and edit it with your values:

```sh
# Extract the template:
kubectl apply -f deploy/configmap.yaml  # creates the template ConfigMap

# Or just copy the config.toml from deploy/configmap.yaml into a local file
# and edit it. Key fields to set:
#   - issuer:            your external URL (no trailing slash)
#   - code_hmac_key:     the hex string from step 2
#   - signing_key_path:  /app/secrets/signing_key.pem (keep as-is)
#   - clients:           your OAuth2 client definitions
```

Save the edited config as `config.toml` locally.

### 4. Create the Secret

```sh
kubectl create namespace openid-tls-connector  # if not already created

kubectl create secret generic openid-tls-connector-secrets \
  --namespace=openid-tls-connector \
  --from-file=config.toml=./config.toml \
  --from-file=signing_key.pem=./signing_key.pem
```

Verify:

```sh
kubectl -n openid-tls-connector get secret openid-tls-connector-secrets
```

### 5. Create the Client CA Secret for mTLS

The ingress controller needs a CA certificate to verify client certificates:

```sh
# If you have your own CA that signs client certificates:
kubectl create secret generic client-ca \
  --namespace=ingress-nginx \
  --from-file=ca.crt=client-ca.crt
```

### 6. Create the TLS Secret for the Ingress

```sh
# Using cert-manager or a manually-created TLS certificate:
kubectl create secret tls auth-tls \
  --namespace=openid-tls-connector \
  --cert=auth.example.com.crt \
  --key=auth.example.com.key
```

### 7. Apply the Manifests

```sh
# Apply everything (except the secret, which you created manually):
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/service.yaml
kubectl apply -f deploy/ingress.yaml
kubectl apply -f deploy/networkpolicy.yaml
kubectl apply -f deploy/poddisruptionbudget.yaml

# Or use kustomize (applies all resources at once):
kubectl apply -k deploy/
```

### 8. Verify the Deployment

```sh
# Pods should be Running and Ready:
kubectl -n openid-tls-connector get pods

# Check the discovery endpoint via port-forward:
kubectl -n openid-tls-connector port-forward svc/openid-tls-connector 8080:8080
curl http://localhost:8080/.well-known/openid-configuration | jq .

# Check logs:
kubectl -n openid-tls-connector logs -l app.kubernetes.io/name=openid-tls-connector
```

### 9. Test the Full Flow with mTLS

```sh
# Authorize (with client cert):
curl -v --cert client.crt --key client.key \
  "https://auth.example.com/authorize?response_type=code&client_id=spa&redirect_uri=https://app.example.com/cb&scope=openid&state=test&code_challenge=CHALLENGE&code_challenge_method=S256"

# Token exchange:
curl -v --cert client.crt --key client.key \
  -X POST "https://auth.example.com/token" \
  -d "grant_type=authorization_code&code=CODE&redirect_uri=https://app.example.com/cb&code_verifier=VERIFIER&client_id=spa"

# Userinfo:
curl -v \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  "https://auth.example.com/userinfo"
```

## Ingress Controller Configuration

### nginx-ingress (Recommended)

The `ingress.yaml` manifest is pre-configured for nginx-ingress with these
key annotations:

```yaml
# Require client certificate verification:
nginx.ingress.kubernetes.io/auth-tls-secret: "ingress-nginx/client-ca"
nginx.ingress.kubernetes.io/auth-tls-verify-client: "on"
nginx.ingress.kubernetes.io/auth-tls-verify-depth: "1"

# Inject the client cert subject DN:
nginx.ingress.kubernetes.io/configuration-snippet: |
  proxy_set_header X-Client-Cert-Subject $ssl_client_s_dn;
```

`$ssl_client_s_dn` returns the DN in RFC 2253 format (e.g.
`CN=alice,OU=eng,O=acme`), which is what the server's DN parser expects.

### Traefik

For Traefik, create a TLSOption that requires client certificates, and use
middleware to pass the client cert info:

```yaml
apiVersion: traefik.io/v1alpha1
kind: TLSOption
metadata:
  name: mtls
  namespace: openid-tls-connector
spec:
  clientAuth:
    secretNames: [client-ca]
    clientAuthType: RequireAndVerifyClientCert
```

Traefik passes the client cert DN in the `X-Forwarded-Ssl-Client-Cert` header
(or you can configure a middleware to extract it). Set `user_header` in
`config.toml` accordingly.

## Security Hardening

The manifests include several security measures:

1. **Distroless container** — no shell, no package manager, minimal attack surface.
2. **Non-root user** — runs as UID 65534 (distroless `nonroot`).
3. **Read-only root filesystem** — only `/tmp` (emptyDir) is writable.
4. **Dropped capabilities** — all Linux capabilities dropped.
5. **Seccomp profile** — `RuntimeDefault` seccomp profile enforced.
6. **NetworkPolicy** — only the ingress-nginx namespace can reach the pods.
7. **PodDisruptionBudget** — at least 1 pod stays available during disruptions.
8. **Pod anti-affinity** — replicas prefer different nodes.
9. **Resource limits** — CPU and memory bounded.
10. **Secret-mounted config** — HMAC key and signing key in Kubernetes Secrets.

## Upgrading

```sh
# Build and push the new image:
docker build -t ghcr.io/your-org/openid-tls-connector:v1.2.3 .
docker push ghcr.io/your-org/openid-tls-connector:v1.2.3

# Update the deployment image:
kubectl -n openid-tls-connector set image deployment/openid-tls-connector \
  server=ghcr.io/your-org/openid-tls-connector:v1.2.3

# Or edit deployment.yaml and re-apply.
```

## Troubleshooting

### Pods fail to start

```sh
# Check events:
kubectl -n openid-tls-connector describe pod -l app.kubernetes.io/name=openid-tls-connector

# Common issues:
# - Secret not found: create it (step 4)
# - Config references wrong signing_key_path: must be /app/secrets/signing_key.pem
# - Image pull error: check image path and registry credentials
```

### Readiness probe fails

```sh
# The readiness probe hits /.well-known/openid-configuration.
# If it fails, the server isn't starting — check logs:
kubectl -n openid-tls-connector logs -l app.kubernetes.io/name=openid-tls-connector
```

### mTLS not working (403 at /authorize)

```sh
# Verify the ingress is receiving client certs:
kubectl -n ingress-nginx logs -l app.kubernetes.io/name=ingress-nginx | grep ssl_client

# Verify the header is being passed:
# Add a temporary debug header to the ingress or check server logs for
# "Missing required header: X-Client-Cert-Subject"
```

### Config changes not picked up

The config is read at startup only. After changing the Secret:

```sh
# Restart the pods to pick up the new config:
kubectl -n openid-tls-connector rollout restart deployment/openid-tls-connector

# Watch the rollout:
kubectl -n openid-tls-connector rollout status deployment/openid-tls-connector
```
