# Installation

## Prerequisites

- Go 1.21 or later
- [Philter](https://philterd.ai/philter/) instance running and accessible

## Building from Source

To build the proxy from source:

```bash
make build
```

This will create an executable named `philter-ai-proxy`.

## Running

The proxy requires a YAML configuration file. Copy and edit the example config:

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your Philter endpoint and provider settings
./philter-ai-proxy --config config.yaml
```

See [Configuration](configuration.md) for the full config reference.

## Docker

To build a local Docker image (single arch, no push):

```bash
make docker-build
```

### Publishing multi-arch images

The `docker-build-push.sh` script builds and pushes a multi-arch image (`linux/amd64`, `linux/arm64`) to Docker Hub at `philterd/philter-ai-proxy`. It uses `docker buildx`, which ships with Docker Desktop and is available in modern Docker Engine installs.

```bash
docker login                          # one-time, as a user with push access
make docker-push                      # build + push linux/amd64,linux/arm64
make docker-push-dry-run              # print the plan without touching buildx or the registry
```

Two tags are pushed: `latest` and a derived version tag.

- The version comes from `git describe --tags --always --dirty`, or `VERSION=` if set explicitly.
- A `-dirty` working tree is refused unless `ALLOW_DIRTY=1` is set, to prevent accidentally publishing an image that doesn't correspond to any committed state.

```bash
VERSION=v1.2.3 make docker-push       # explicit version tag
ALLOW_DIRTY=1 make docker-push        # override the dirty-tree guard
```

## Docker Compose

To start the proxy using Docker Compose:

```bash
docker-compose up --build
```

The default `docker-compose.yaml` mounts `config.example.yaml` as the config file. Edit it or replace it with your own config before running.

## Kubernetes

Two ways to deploy on Kubernetes:

- **Helm chart** at `deploy/helm/philter-ai-proxy/` - production-ready, with values for replicas, autoscaling (HPA), Pod Disruption Budgets, Ingress, Prometheus Operator `ServiceMonitor`, mTLS, and cert-manager-issued TLS.
- **Plain manifests** at `deploy/k8s/` - minimal Deployment + Service + Secret for users who don't want Helm.

A starter Grafana dashboard covering every emitted metric ships alongside at `deploy/grafana/philter-ai-proxy.json`.

The [Kubernetes Quickstart](kubernetes.md) walks through both paths end-to-end.

## Certificates

The proxy listens over TLS and requires a certificate and private key. You can generate a self-signed certificate for testing with the following command:

```bash
make cert
```
