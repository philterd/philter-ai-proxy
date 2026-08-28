# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

Nothing has been released yet. This is what the first release will contain.

- OpenAI, Azure OpenAI, Anthropic, Google Gemini, Google Vertex AI, Amazon Bedrock, and Ollama, plus any OpenAI-compatible backend, all with streaming support.
- Inbound redaction across chat, embeddings, Responses, moderations, image, audio, and completions endpoints, including tool calls. Optional outbound response scanning with `redact`, `block`, or `flag`. Per-route policies.
- API-key auth (hashed at rest) and mTLS, per-key scopes and policy binding, `${ENV_VAR}` and `file:` secret references, and inbound request hardening: body and header caps, slowloris and handshake timeouts, a TLS 1.2 floor, a bounded handshake ceiling, and a global concurrency cap.
- Philter retry and circuit breaker, per-provider transport timeouts.
- Structured JSON audit log carrying metadata only, Prometheus metrics, OpenTelemetry tracing, `/livez` and `/readyz` probes, an unauthenticated `/health` endpoint serving the standard Philterd health contract (`{"status":"UP","applicationVersion":"..."}`), `--validate-config`, and `--version`.
- A Helm chart, plain Kubernetes manifests, a starter Grafana dashboard, and a k6 load-test harness.
- Routing, failover, rate limiting, response caching, and token or spend accounting are deliberately out of scope. The proxy is designed to run alongside an AI gateway rather than replace one. See [Using with an AI Gateway](docs/docs/ai-gateway.md).
