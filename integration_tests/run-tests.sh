#!/usr/bin/env bash
#
# Run the OIDC conformance suite's Basic Certification Profile test plan
# against the openid-tls-connector provider. This is intended to be run
# after `run.sh` has brought the docker-compose stack up and the
# conformance-server is reachable.
#
# Usage:
#   ./run-tests.sh                # run the full oidcc-basic-certification-test-plan
#   ./run-tests.sh --list         # just list the plans and exit
#   ./run-tests.sh --rerun 1      # rerun plan #1 from the last run
#
# Exit code is non-zero if any test module has an unexpected failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUITE_DIR="${SCRIPT_DIR}/conformance-suite"

# The conformance suite's REST API lives behind its nginx proxy. From the
# host (where this script runs) the published port is 8443. The Python
# orchestrator talks to this URL.
export CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost:8443/}"
# The suite's REST API doesn't require a token in dev mode, but the
# orchestrator still wants the env var to exist (it's used as the URL base
# for plan-detail/log-detail links printed at the end).
export CONFORMANCE_SERVER_MTLS="${CONFORMANCE_SERVER_MTLS:-${CONFORMANCE_SERVER}}"
# Tell run-test-plan.py to skip the CONFORMANCE_TOKEN requirement (we run
# against a local dev-mode server, not the public certification.openid.net
# service). The suite's dev mode injects a dummy admin user into every
# request, which is exactly what we want for automated testing.
export CONFORMANCE_DEV_MODE="${CONFORMANCE_DEV_MODE:-1}"

# The conformance suite uses a self-signed cert; the orchestrator must not
# verify it. The Python wrapper takes this from CONFORMANCE_VERIFY_TLS.
export CONFORMANCE_VERIFY_TLS="${CONFORMANCE_VERIFY_TLS:-false}"

# Make sure the Python venv the orchestrator needs exists. The conformance
# suite ships a requirements.txt with `httpx` and `pyparsing`.
VENV="${SCRIPT_DIR}/.venv"
if [ ! -d "${VENV}" ]; then
    echo "Creating Python venv at ${VENV}"
    python3 -m venv "${VENV}"
    # shellcheck disable=SC1091
    "${VENV}/bin/pip" install --quiet --upgrade pip
    "${VENV}/bin/pip" install --quiet -r "${SUITE_DIR}/scripts/requirements.txt"
fi
# shellcheck disable=SC1091
source "${VENV}/bin/activate"

PYTHONPATH="${SUITE_DIR}/scripts${PYTHONPATH:+:${PYTHONPATH}}"
export PYTHONPATH

# Defaults: run the Basic Certification Profile plan with the static-client
# variant against our config. The `[client_registration=static_client]`
# variant matches the `alias`-based static client we registered in the
# provider config. (`dynamic_client` would require DCR, which we don't
# implement.)
PLAN_NAME="oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
CONFIG="${SCRIPT_DIR}/conformance-config.json"
EXPECTED_FAILURES="${SCRIPT_DIR}/expected-failures.json"
EXPECTED_SKIPS="${SCRIPT_DIR}/expected-skips.json"

# Forward any extra args (e.g. --list, --rerun N) to run-test-plan.py.
EXTRA_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --list|--rerun|--no-parallel|--verbose)
            EXTRA_ARGS+=("$1")
            shift
            # --rerun takes a value
            if [ "${EXTRA_ARGS[-1]}" = "--rerun" ] && [ $# -gt 0 ]; then
                EXTRA_ARGS+=("$1")
                shift
            fi
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# Always pass our expected-failures/skips files so that known
# (intentional) gaps in the provider don't fail the run. The files start
# empty and accumulate as we deliberately accept limitations.
ARGS=(
    "${PLAN_NAME}"
    "${CONFIG}"
    --expected-failures-file "${EXPECTED_FAILURES}"
    --expected-skips-file "${EXPECTED_SKIPS}"
    --export-dir "${SCRIPT_DIR}"
    --show-untested-test-modules server-oidc-provider
    --no-parallel
)

# Run the orchestrator. It returns non-zero if any test module fails
# unexpectedly.
exec python3 "${SUITE_DIR}/scripts/run-test-plan.py" "${ARGS[@]}" "${EXTRA_ARGS[@]}"
