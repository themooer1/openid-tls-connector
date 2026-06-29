#!/usr/bin/env bash
#
# End-to-end orchestrator for the openid-tls-connector conformance suite
# integration tests.
#
#   1. Builds and starts the docker-compose stack (mongodb + conformance
#      suite + our OIDC provider behind an mTLS-header-injecting nginx).
#   2. Waits for the conformance suite's REST API to become ready.
#   3. Runs the OIDC Basic Certification Profile test plan against the
#      provider via the suite's scripts/run-test-plan.py.
#   4. Tears the stack down on exit.
#
# Usage:
#   ./run.sh                 # build + up + test + down
#   ./run.sh --no-build      # skip the docker build step
#   ./run.sh --leave-up      # don't docker-compose down on exit
#   ./run.sh --list          # pass --list to run-tests.sh (just enumerate plans)
#   ./run.sh --rerun 1       # rerun plan #1 from the last run
#
# Any args after the recognised flags are forwarded to run-tests.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD=1
LEAVE_UP=0
PASSTHROUGH=()
while [ $# -gt 0 ]; do
    case "$1" in
        --no-build)  BUILD=0; shift ;;
        --leave-up)  LEAVE_UP=1; shift ;;
        *)           PASSTHROUGH+=("$1"); shift ;;
    esac
done

COMPOSE=(docker compose --file docker-compose.yml)

cleanup() {
    if [ "${LEAVE_UP}" -eq 1 ]; then
        echo
        echo "Leaving the stack running (--leave-up). Stop it with:"
        echo "  ${COMPOSE[*]} down"
    else
        echo
        echo "Tearing down the docker-compose stack..."
        "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "==> Building and starting the docker-compose stack"
if [ "${BUILD}" -eq 1 ]; then
    "${COMPOSE[@]}" build --pull
fi
"${COMPOSE[@]}" up --detach

echo
echo "==> Waiting for the conformance suite REST API to become ready"
# The conformance-server takes ~60-90s to come up (Spring Boot + MongoDB
# indexing). Poll the /api/runner/available endpoint until it returns 200.
ready=0
for _ in $(seq 1 120); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' \
            "${CONFORMANCE_SERVER:-https://localhost:8443/}api/runner/available" \
            2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
        ready=1
        break
    fi
    sleep 2
done
if [ "$ready" -ne 1 ]; then
    echo "Conformance suite did not become ready in time."
    echo " ----- conformance-server logs (last 80 lines) ----- "
    "${COMPOSE[@]}" logs --tail=80 conformance-server || true
    exit 1
fi
echo "Conformance suite is ready."

echo
echo "==> Waiting for the OIDC provider's discovery endpoint"
ready=0
for _ in $(seq 1 60); do
    # The discovery endpoint is only reachable from inside the docker
    # network (op-nginx is not published to the host), so ask the
    # conformance-server's container to fetch it for us.
    code=$(docker exec "$("${COMPOSE[@]}" ps -q conformance-server)" \
            sh -c 'wget -q -O /dev/null --no-check-certificate \
                    https://op-nginx/.well-known/openid-configuration \
                    && echo 200 || echo $?' 2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
        ready=1
        break
    fi
    sleep 2
done
if [ "$ready" -ne 1 ]; then
    echo "OIDC provider discovery endpoint did not become reachable from the conformance-server container."
    echo " ----- openid-provider logs (last 40 lines) ----- "
    "${COMPOSE[@]}" logs --tail=40 openid-provider || true
    echo " ----- op-nginx logs (last 40 lines) ----- "
    "${COMPOSE[@]}" logs --tail=40 op-nginx || true
    exit 1
fi
echo "OIDC provider is reachable."

echo
echo "==> Running the conformance test plan"
"${SCRIPT_DIR}/run-tests.sh" "${PASSTHROUGH[@]}"
