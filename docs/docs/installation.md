# Installation

## Prerequisites

- Go 1.25 or later
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

### Checking the version

Use `--version` to print the build version and exit:

```bash
./philter-ai-proxy --version
# philter-ai-proxy v1.0.0 (commit a1b2c3d4e5f6, built with go1.25)
```

Release builds stamp the version via `-ldflags "-X main.version=<tag>"` (the `Makefile` and `Dockerfile` derive it from `git describe`). Plain `go build` binaries report `dev` plus the commit recorded by the Go toolchain. The same version is logged at startup.

### Validating a config file

Use `--validate-config` to load and validate a config without starting the proxy. Useful as a CI gate before a deploy reaches a running cluster, or as a pre-restart sanity check.

```bash
./philter-ai-proxy --validate-config --config config.yaml
```

Exit codes:

- `0` and `config OK: <path>` on stdout when the file loads, expands all `${ENV_VAR}` / `file:` secret references, and passes schema validation.
- `1` and `config invalid: <reason>` on stderr otherwise. The reason names the offending field (for example `config: listen.port 999999 is out of range (1-65535)`).
- `2` for unknown CLI flags.

`--config` may be omitted if `PHILTER_PROXY_CONFIG` is set in the environment.

## Docker

To build a local Docker image (single arch, no push):

```bash
make docker-build
```

### Building for both architectures

`build-image.sh` builds `linux/amd64` and `linux/arm64` images and loads each into the local Docker daemon under its own tag, so both are available to run and test before anything is published. It pushes nothing.

```bash
./build-image.sh                      # philterd/philter-ai-proxy:latest-amd64 and :latest-arm64
./build-image.sh v1.2.3               # philterd/philter-ai-proxy:v1.2.3-amd64 and :v1.2.3-arm64
make docker-build-multiarch           # same, using the Makefile's derived VERSION
```

A single multi-arch tag cannot be loaded into the local daemon, which is why the images carry per-architecture tags. `IMAGE=` overrides the repository name and `ARCHES=` the architecture list.

### Publishing multi-arch images

Publishing is two deliberate steps, run by hand from a machine holding the credential. Nothing in CI pushes an image.

`build-image.sh` produces the per-architecture images (above); `push-image.sh` pushes them to Docker Hub at [`philterd/philter-ai-proxy`](https://hub.docker.com/repository/docker/philterd/philter-ai-proxy) and joins them into one multi-arch tag with `docker buildx imagetools create`. `push-image.sh` builds nothing, so what gets published is exactly what you built and tested.

```bash
docker login                          # one-time, as a user with push access
./build-image.sh v1.2.3               # build linux/amd64 and linux/arm64
./push-image.sh v1.2.3                # scan, push, and join into philterd/philter-ai-proxy:v1.2.3
./push-image.sh                       # repeat for the :latest tag
```

The Makefile wraps both, using its derived `VERSION`:

```bash
make docker-build-multiarch
make docker-push
make docker-push-dry-run              # scan and print the plan, push nothing
```

The push is gated on a [Trivy](https://trivy.dev) scan of each image being pushed, so `trivy` must be on your PATH. A HIGH or CRITICAL vulnerability that has a fix available blocks the push; unfixable findings do not, since no rebuild resolves them. Rebuild on a patched base, or record an exception with a reason in `.trivyignore`. `SKIP_SCAN=1` bypasses the gate.

Each invocation publishes one tag, taken from the argument (default `latest`). A version built from a dirty working tree carries a `-dirty` suffix and is refused, to prevent publishing an image that corresponds to no committed state; `ALLOW_DIRTY=1` overrides that.

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

The proxy listens over TLS and needs a certificate before it will start. There is no default path and the container image ships no keypair, so one of the two options below is required.

**Production.** Point `listen.cert` and `listen.key` at your keypair:

```yaml
listen:
  cert: /etc/philter-proxy/tls/tls.crt
  key: /etc/philter-proxy/tls/tls.key
```

**Evaluation.** Set `listen.devSelfSignedCert: true` and the proxy generates a throwaway certificate at startup, in memory, different on every start. Clients must disable certificate verification to connect, so use it for local trials and tests only. This is what `config.example.yaml` ships with, and it is the line to remove first when moving to production.

A rotated certificate is picked up on restart; the proxy does not reload TLS material while running.

To generate a self-signed keypair on disk instead, for example to share one certificate across a local stack:

```bash
make cert
```

Starting with neither a keypair nor `devSelfSignedCert` fails immediately:

```
TLS certificate error: no TLS certificate configured: set listen.cert and listen.key
to your certificate and private key, or set listen.devSelfSignedCert: true to generate
a throwaway certificate for evaluation
```
