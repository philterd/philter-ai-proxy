#!/usr/bin/env bash
#
# Build and push a multi-arch (linux/amd64, linux/arm64) container image of
# philter-ai-proxy to Docker Hub at philterd/philter-ai-proxy.
#
# Tags:
#   - latest
#   - <version>, where <version> is either:
#       * the VERSION env var if set, or
#       * `git describe --tags --always --dirty`
#
# Usage:
#   ./docker-build-push.sh                     # build + push with derived version
#   VERSION=v1.2.3 ./docker-build-push.sh      # explicit version
#   ALLOW_DIRTY=1 ./docker-build-push.sh       # push even with -dirty in version
#   DRY_RUN=1 ./docker-build-push.sh           # print what would happen, don't push
#
# Prerequisites:
#   - docker buildx available (Docker Desktop ships with it; otherwise: docker buildx install)
#   - `docker login` to Docker Hub as a user that can push to philterd/philter-ai-proxy

set -euo pipefail

IMAGE="${IMAGE:-philterd/philter-ai-proxy}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

# Anchor at the script's directory (the repo root) so the script works from anywhere.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Determine version ------------------------------------------------------

if [[ -z "${VERSION:-}" ]]; then
  if ! command -v git >/dev/null 2>&1; then
    echo "error: git not found and VERSION not set" >&2
    exit 1
  fi
  VERSION="$(git describe --tags --always --dirty)"
fi

if [[ "${VERSION}" == *-dirty && "${ALLOW_DIRTY:-0}" != "1" ]]; then
  echo "error: refusing to push a -dirty version (${VERSION})" >&2
  echo "       commit your changes, or re-run with ALLOW_DIRTY=1 to override" >&2
  exit 1
fi

# --- Verify buildx ----------------------------------------------------------

if ! docker buildx version >/dev/null 2>&1; then
  echo "error: docker buildx is required for multi-arch builds" >&2
  echo "       install Docker Desktop or run: docker buildx install" >&2
  exit 1
fi

BUILDER="${BUILDER:-philter-ai-proxy-builder}"

# --- Plan -------------------------------------------------------------------

cat <<INFO
Image:     ${IMAGE}
Tags:      ${IMAGE}:${VERSION}, ${IMAGE}:latest
Platforms: ${PLATFORMS}
Builder:   ${BUILDER}
Dry run:   ${DRY_RUN:-0}
INFO

if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo "(dry run — exiting without building or pushing)"
  exit 0
fi

# Ensure a buildx builder is active. The default builder doesn't support
# multi-platform; we create or reuse a named one. Done after the dry-run
# bail-out so dry-run doesn't leave state on the host.
if ! docker buildx inspect "${BUILDER}" >/dev/null 2>&1; then
  echo "creating buildx builder: ${BUILDER}"
  docker buildx create --name "${BUILDER}" --use >/dev/null
else
  docker buildx use "${BUILDER}" >/dev/null
fi

# --- Build + push -----------------------------------------------------------

# `buildx build --push` does both in one step. Multi-arch images cannot be
# loaded into the local Docker daemon, so push is the only practical sink.
docker buildx build \
  --platform "${PLATFORMS}" \
  --tag "${IMAGE}:${VERSION}" \
  --tag "${IMAGE}:latest" \
  --push \
  .

echo "pushed ${IMAGE}:${VERSION} and ${IMAGE}:latest"
