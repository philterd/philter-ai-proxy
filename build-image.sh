#!/bin/bash
set -e

# Builds the Philter AI Proxy Docker image for amd64 and arm64. Pushing it is a
# separate, manual step: see push-image.sh.
#
# Each architecture is built and loaded under its own tag, so both are here to
# run and test locally. A multi-architecture image cannot be loaded into the
# local Docker daemon, which is why the per-architecture tags exist at all.
#
#   ./build-image.sh 2.0.0     builds philterd/philter-ai-proxy:2.0.0-amd64 and -arm64
#   ./build-image.sh           builds :latest-amd64 and :latest-arm64

VERSION=${1:-latest}
IMAGE=${IMAGE:-philterd/philter-ai-proxy}
ARCHES=${ARCHES:-"amd64 arm64"}

# The version the proxy reports (--version, /health) comes from pom.xml, so a named
# image tag must match it, or the image would report a different version than its tag.
POM_VERSION=$(sed -n '/<artifactId>philter-ai-proxy<\/artifactId>/,/<version>/s:.*<version>\(.*\)</version>.*:\1:p' pom.xml)
if [ "$VERSION" != "latest" ] && [ "$VERSION" != "$POM_VERSION" ]; then
    echo "error: tag ${VERSION} does not match the version in pom.xml (${POM_VERSION})" >&2
    echo "       set <version>${VERSION}</version> in pom.xml first" >&2
    exit 1
fi

# The default builder cannot cross-build, so use a container builder.
docker buildx inspect philter-ai-proxy-builder > /dev/null 2>&1 ||
    docker buildx create --name philter-ai-proxy-builder --driver docker-container > /dev/null

for arch in $ARCHES; do
    docker buildx build --builder philter-ai-proxy-builder \
        --platform "linux/${arch}" --load \
        -t "${IMAGE}:${VERSION}-${arch}" .
done

echo
for arch in $ARCHES; do
    echo "Built ${IMAGE}:${VERSION}-${arch} (version ${POM_VERSION})"
done
echo "Push them with: ./push-image.sh ${VERSION}"
