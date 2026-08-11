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
#   SKIP_SCAN=1 ./docker-build-push.sh         # push without the vulnerability scan
#
# Prerequisites:
#   - docker buildx available (Docker Desktop ships with it; otherwise: docker buildx install)
#   - trivy on PATH (https://trivy.dev/latest/getting-started/installation/)
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
  echo "(dry run: exiting without building or pushing)"
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

# --- Scan -------------------------------------------------------------------

# GATES the push. A multi-arch image cannot be loaded into the local daemon, so
# scan a single-arch build of the same Dockerfile; the multi-arch build below
# reuses the cached layers. Suppress a specific finding in .trivyignore.
SCAN_TAG="philter-ai-proxy:scan-${VERSION}"

if [[ "${SKIP_SCAN:-0}" == "1" ]]; then
  echo "warning: skipping the vulnerability scan (SKIP_SCAN=1)" >&2
elif ! command -v trivy >/dev/null 2>&1; then
  echo "error: trivy not found on PATH" >&2
  echo "       install it (https://trivy.dev) or re-run with SKIP_SCAN=1" >&2
  exit 1
else
  echo "scanning for HIGH and CRITICAL vulnerabilities that have a fix available"
  docker buildx build --load --build-arg VERSION="${VERSION}" --tag "${SCAN_TAG}" .
  trap 'docker rmi -f "${SCAN_TAG}" >/dev/null 2>&1 || true' EXIT
  if ! trivy image \
    --scanners vuln \
    --ignore-unfixed \
    --severity HIGH,CRITICAL \
    --exit-code 1 \
    --no-progress \
    "${SCAN_TAG}"; then
    echo "error: refusing to push an image with fixable HIGH or CRITICAL vulnerabilities" >&2
    echo "       rebuild on a patched base, or record an exception in .trivyignore" >&2
    exit 1
  fi
fi

# --- Build + push -----------------------------------------------------------

# `buildx build --push` does both in one step. Multi-arch images cannot be
# loaded into the local Docker daemon, so push is the only practical sink.
docker buildx build \
  --platform "${PLATFORMS}" \
  --build-arg VERSION="${VERSION}" \
  --tag "${IMAGE}:${VERSION}" \
  --tag "${IMAGE}:latest" \
  --push \
  .

echo "pushed ${IMAGE}:${VERSION} and ${IMAGE}:latest"
