# openid-tls-connector — OIDC Conformance Suite Integration Tests

This directory runs the [OpenID Foundation conformance suite][cs]
(`oidcc-basic-certification-test-plan`) against the `openid-tls-connector`
provider to validate that the OIDC Authorization Code + PKCE flow works
end-to-end.

[cs]: https://gitlab.com/openid/conformance-suite

## What's here

```
integration_tests/
├── docker-compose.yml        # Brings up the whole stack
├── run.sh                    # Top-level orchestrator (build + up + test + down)
├── run-tests.sh              # Drives the suite's scripts/run-test-plan.py
├── conformance-config.json   # Test plan config (server, client, browser tasks)
├── expected-failures.json    # Failures we accept as known (starts empty)
├── expected-skips.json       # Skips we accept as known (starts empty)
├── oidc-provider/
│   ├── config.toml           # Provider config (issuer, clients, signing key path)
│   └── signing_key.pem       # RSA signing key for RS256 JWTs (test-only)
├── op-nginx/
│   ├── Dockerfile            # nginx + self-signed cert for `op-nginx`
│   └── nginx.conf            # Proxies to the provider, injects X-Client-Cert-Subject
└── conformance-suite/        # Vendored checkout of the OIDF conformance suite
```

## How it works

The provider under test (`openid-tls-connector`) is designed to sit behind a
reverse proxy that terminates mTLS and injects the client certificate subject
DN as a header. There is no login page and no consent screen — the user is
"auto-logged-in" by the TLS layer.

To replicate that in the integration tests without actually doing mTLS:

1. **`op-nginx`** is an nginx reverse proxy in front of the provider. It
   terminates TLS (with a self-signed cert — the conformance suite requires
   `https://` endpoints in the discovery document) and hard-codes the
   `X-Client-Cert-Subject: CN=test-user,OU=eng,O=acme` header on every
   request. From the provider's point of view this is indistinguishable
   from a real mTLS-terminating proxy presenting a verified client cert.

2. **`openid-provider`** is the Rust provider, built from the repo root
   `Dockerfile`, with its `config.toml` and `signing_key.pem` mounted in.

3. **`conformance-server`** is the OIDF conformance suite (prebuilt image
   from `registry.gitlab.com/openid/conformance-suite`). It plays the
   Relying Party for the auth-code+PKCE flow.

4. **`conformance-nginx`** is the suite's own HTTPS-terminating proxy
   (built from the vendored `conformance-suite/nginx` directory).

5. **`mongodb`** is the suite's backing store.

The conformance suite has a built-in headless browser driver
(`BrowserControl`, using Selenium's `HtmlUnitDriver`) that is driven by a
`"browser"` block in `conformance-config.json`. Because our provider has no
login/consent UI — `/authorize` immediately 302s back to the suite's
callback — the browser config only needs to wait for the
`submission_complete` marker on the callback page. **No Selenium,
ChromeDriver, or external browser is required.**

> Note: an earlier draft of these instructions referenced a
> `--browser-script` flag on `scripts/run-test-plan.py` and a separate
> `login_handler.py` Selenium script. That flag does not exist in the
> current conformance suite; the suite's built-in `"browser"` config block
> is the supported mechanism for automated browser interaction.

## Running the tests

```sh
# From the repo root:
./integration_tests/run.sh
```

This will:

1. `docker compose build` the local images (`op-nginx`, `openid-provider`,
   `conformance-nginx`).
2. `docker compose up -d` the whole stack.
3. Wait for the conformance suite's REST API and the provider's discovery
   endpoint to become reachable.
4. Run `oidcc-basic-certification-test-plan` against the provider via the
   suite's `scripts/run-test-plan.py`.
5. Tear the stack down on exit (unless `--leave-up` is passed).

The orchestrator exits non-zero if any test module produces an unexpected
failure (i.e. a failure not listed in `expected-failures.json`).

### Useful flags

```sh
./run.sh --no-build       # skip `docker compose build` (use cached images)
./run.sh --leave-up       # don't `docker compose down` on exit (faster iteration)
./run.sh --list           # just enumerate the available plans, don't run them
./run.sh --rerun 1        # rerun plan #1 from the last `--list`
```

### Inspecting results

While the stack is up (e.g. after `./run.sh --leave-up`), open

```
https://localhost:8443/plans.html
```

in a browser (accept the self-signed-cert warning) to see per-module
request/response logs, JWTs, and the exact point of any failure.

## Test configuration

`conformance-config.json` registers a static confidential client
(`conformance-client` / `conformance-secret`) against the provider. The
matching `[[clients]]` entries live in `oidc-provider/config.toml`. The
client's `redirect_uri` is the conformance suite's own callback endpoint as
reachable from inside the docker network:
`https://conformance-nginx:8443/test/a/localtest/callback` — the suite
constructs this by appending `/test/a/{alias}/callback` to its `base_url`
(`https://conformance-nginx:8443`).

The conformance suite's `--browser` block (in the JSON config, not a CLI
flag) matches the OIDC provider's `/authorize` URL and waits for the
`suite's callback page to render its `submission_complete` marker — that's
the signal that the auth-code redirect has been received and the suite is
about to exchange the code for tokens.

## Iterating on failures

When `run-test-plan.py` reports an unexpected failure, the per-module
`log-detail.html?log={id}` page (linked from the script's stdout and from
`plans.html`) shows the exact HTTP request/response, the JWT decoded, and
the condition that failed. Fix the underlying provider bug, rebuild the
`openid-provider` image (`docker compose build openid-provider`), and rerun
the failing plan with `./run.sh --no-build --rerun N` (where `N` is the
plan number from `--list`).

Genuine protocol gaps that we accept as known limitations of this minimal
provider (e.g. no refresh tokens, no request objects) go into
`expected-failures.json` or `expected-skips.json` so they don't fail the
run. Each entry should have a `comment` explaining why the gap is accepted.
