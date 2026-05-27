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

## Docker

To build a Docker image:

```bash
make docker-build
```

## Docker Compose

To start the proxy using Docker Compose:

```bash
docker-compose up --build
```

## Certificates

The proxy listens over TLS and requires a certificate and private key. You can generate a self-signed certificate for testing with the following command:

```bash
make cert
```
