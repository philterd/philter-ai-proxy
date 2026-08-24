#!/bin/bash
set -e

# Pushes the images built by build-image.sh to Docker Hub and joins them into a
# single multi-architecture tag. It builds nothing.
#
# Run this by hand, from a machine holding the credential: nothing in CI pushes
# an image. Requires `docker login` as a user with push access to the
# repository, and trivy on PATH (https://trivy.dev) unless SKIP_SCAN=1.
#
# Usage:
#   ./push-image.sh                # push the :latest-<arch> tags
#   ./push-image.sh v1.2.3         # push the :v1.2.3-<arch> tags
#   DRY_RUN=1 ./push-image.sh      # scan and print the plan, push nothing
#   SKIP_SCAN=1 ./push-image.sh    # push without the vulnerability scan
#   ALLOW_DIRTY=1 ./push-image.sh  # push a version built from a dirty tree

VERSION=${1:-latest}
IMAGE=${IMAGE:-philterd/philter-ai-proxy}
ARCHES=${ARCHES:-"amd64 arm64"}

# A -dirty version came from a working tree that matches no commit, so nobody
# could reproduce the image later.
if [ "${VERSION}" != "${VERSION%-dirty}" ] && [ "${ALLOW_DIRTY:-0}" != "1" ]; then
    echo "error: refusing to push a -dirty version (${VERSION})" >&2
    echo "       commit your changes and rebuild, or re-run with ALLOW_DIRTY=1" >&2
    exit 1
fi

# Every image has to exist locally before anything is pushed, so a half-built
# set fails here rather than leaving one architecture published without the other.
for arch in $ARCHES; do
    docker image inspect "${IMAGE}:${VERSION}-${arch}" > /dev/null 2>&1 || {
        echo "error: ${IMAGE}:${VERSION}-${arch} is not in the local Docker daemon" >&2
        echo "       build it first: ./build-image.sh ${VERSION}" >&2
        exit 1
    }
done

# GATES the push. These are the exact images that will be pushed, so scan each
# one rather than a stand-in build. Suppress a specific finding in .trivyignore.
if [ "${SKIP_SCAN:-0}" = "1" ]; then
    echo "warning: skipping the vulnerability scan (SKIP_SCAN=1)" >&2
else
    command -v trivy > /dev/null 2>&1 || {
        echo "error: trivy not found on PATH" >&2
        echo "       install it (https://trivy.dev) or re-run with SKIP_SCAN=1" >&2
        exit 1
    }
    for arch in $ARCHES; do
        echo "scanning ${IMAGE}:${VERSION}-${arch} for HIGH and CRITICAL vulnerabilities that have a fix available"
        trivy image \
            --scanners vuln \
            --ignore-unfixed \
            --severity HIGH,CRITICAL \
            --exit-code 1 \
            --no-progress \
            "${IMAGE}:${VERSION}-${arch}" || {
            echo "error: refusing to push an image with fixable HIGH or CRITICAL vulnerabilities" >&2
            echo "       rebuild on a patched base, or record an exception in .trivyignore" >&2
            exit 1
        }
    done
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo
    echo "(dry run) would push:"
    for arch in $ARCHES; do
        echo "  ${IMAGE}:${VERSION}-${arch}"
    done
    echo "(dry run) would join them into ${IMAGE}:${VERSION}"
    exit 0
fi

for arch in $ARCHES; do
    docker push "${IMAGE}:${VERSION}-${arch}"
done

# Joins the pushed per-architecture images under one tag, in the registry.
sources=""
for arch in $ARCHES; do
    sources="${sources} ${IMAGE}:${VERSION}-${arch}"
done

docker buildx imagetools create -t "${IMAGE}:${VERSION}" ${sources}

echo
echo "Pushed ${IMAGE}:${VERSION} for ${ARCHES}"
