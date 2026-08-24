#!/bin/bash
set -e

# Builds the Philter AI Proxy Docker image for amd64 and arm64. Pushing it is a
# separate, manual step: see push-image.sh.
#
# Each architecture is built and loaded under its own tag, so both are here to
# run and test locally. A multi-architecture image cannot be loaded into the
# local Docker daemon, which is why the per-architecture tags exist at all.

VERSION=${1:-latest}
IMAGE=${IMAGE:-philterd/philter-ai-proxy}
ARCHES=${ARCHES:-"amd64 arm64"}

# The version stamped into the binary and reported by --version. A named version
# is used as-is; "latest" falls back to the git description.
STAMP="${VERSION}"
if [ "$VERSION" = "latest" ]; then
    STAMP=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
fi

# The default builder cannot cross-build, so use a container builder.
docker buildx inspect philter-ai-proxy-builder > /dev/null 2>&1 ||
    docker buildx create --name philter-ai-proxy-builder --driver docker-container > /dev/null

for arch in $ARCHES; do
    docker buildx build --builder philter-ai-proxy-builder \
        --platform "linux/${arch}" --load --build-arg "VERSION=${STAMP}" \
        -t "${IMAGE}:${VERSION}-${arch}" .
done

echo
for arch in $ARCHES; do
    echo "Built ${IMAGE}:${VERSION}-${arch} (version ${STAMP})"
done
echo "Push them with: ./push-image.sh ${VERSION}"
