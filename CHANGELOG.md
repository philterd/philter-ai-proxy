# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- Bound concurrent in-flight TLS handshakes (`listen.maxConcurrentTLSHandshakes`, default 16384) so a connection flood cannot spawn unbounded handshake goroutines.
- Added a `--version` flag; the build version is stamped via `-ldflags` (derived from `git describe` in the Makefile and Dockerfile) and logged at startup.

## [1.0.0] - 2026-06-08

First public release. Philter AI Proxy is a redacting reverse proxy that strips PII/PHI from LLM traffic via [Philter](https://github.com/philterd/philter) before it reaches the provider, and can optionally scan responses on the way back.

- OpenAI, Azure OpenAI, Anthropic, Google Gemini, Google Vertex AI, Amazon Bedrock, and Ollama, plus any OpenAI-compatible backend — all with streaming (SSE) support.
- Inbound redaction across chat, embeddings, Responses, moderations, image, audio, and completions endpoints (including tool calls); optional outbound response scanning; per-route policies.
- API-key auth (hashed at rest) and mTLS, per-key scopes, secret references for credentials, and inbound request hardening (size caps, slowloris/handshake timeouts, TLS 1.2 floor).
- Per-client rate limiting, per-key token quotas, usage export, and a response cache — each backed by memory or shared Redis.
- Philter retry/circuit breaker and per-provider transport timeouts.
- Structured JSON audit log and errors, Prometheus metrics, OpenTelemetry tracing, `/livez` and `/readyz` probes, `--validate-config`, a Helm chart and Kubernetes manifests, and a k6 load-test harness.
