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

To build a Docker image:

```bash
make docker-build
```

## Docker Compose

To start the proxy using Docker Compose:

```bash
docker-compose up --build
```

The default `docker-compose.yaml` mounts `config.example.yaml` as the config file. Edit it or replace it with your own config before running.

## Certificates

The proxy listens over TLS and requires a certificate and private key. You can generate a self-signed certificate for testing with the following command:

```bash
make cert
```
