#!/bin/bash
# Runs the contract tests and removes the containers afterwards. The Ollama model is kept in a volume, so only
# the first run downloads it. Arguments are passed to pytest, such as -k anthropic.
set -e
cd "$(dirname "$0")"
trap 'docker compose down --remove-orphans > /dev/null 2>&1' EXIT
docker compose build
docker compose up -d ollama sim proxy
docker compose run --rm ollama-pull > /dev/null
docker compose run --rm --no-deps clients pytest -v -rA "$@"
