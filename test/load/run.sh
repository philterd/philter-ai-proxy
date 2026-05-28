#!/usr/bin/env bash
#
# Convenience wrapper to run one of the k6 scenarios against the load-test
# stack brought up by docker-compose.load.yaml. Uses the `grafana/k6` image
# so no local k6 install is required.
#
# Usage:
#   ./test/load/run.sh openai                       # run scenarios/openai.js
#   VUS=50 DURATION=60s ./test/load/run.sh openai   # override defaults
#   ./test/load/run.sh                              # list available scenarios

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="${SCRIPT_DIR}/scenarios"
RESULTS_DIR="${SCRIPT_DIR}/results"
mkdir -p "${RESULTS_DIR}"

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <scenario-name>"
  echo
  echo "Available scenarios:"
  for f in "${SCENARIO_DIR}"/*.js; do
    base="$(basename "${f}" .js)"
    [[ "${base}" == "common" ]] && continue
    echo "  ${base}"
  done
  exit 1
fi

SCENARIO="$1"
SCRIPT="${SCENARIO_DIR}/${SCENARIO}.js"
if [[ ! -f "${SCRIPT}" ]]; then
  echo "error: scenario '${SCENARIO}' not found (${SCRIPT})" >&2
  exit 1
fi

# Detect the proxy and stub URLs. Inside Linux Docker, container ports are
# reachable via host.docker.internal on Docker Desktop, and via --network host
# on plain Linux. We use --network host for simplicity here.
PROXY_URL="${PROXY_URL:-https://localhost:8080}"
STUB_URL="${STUB_URL:-http://localhost:8090}"
VUS="${VUS:-10}"
DURATION="${DURATION:-30s}"
SUMMARY="${RESULTS_DIR}/${SCENARIO}.summary.json"

echo "Running scenario: ${SCENARIO}"
echo "  proxy:    ${PROXY_URL}"
echo "  stub:     ${STUB_URL}"
echo "  vus:      ${VUS}"
echo "  duration: ${DURATION}"
echo "  summary:  ${SUMMARY}"
echo

docker run --rm --network host \
  -e PROXY_URL="${PROXY_URL}" \
  -e STUB_URL="${STUB_URL}" \
  -e VUS="${VUS}" \
  -e DURATION="${DURATION}" \
  -v "${SCENARIO_DIR}:/scenarios:ro" \
  -v "${RESULTS_DIR}:/results" \
  grafana/k6:latest run \
  --summary-export "/results/${SCENARIO}.summary.json" \
  "/scenarios/${SCENARIO}.js"
