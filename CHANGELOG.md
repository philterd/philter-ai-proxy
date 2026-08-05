# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

- Outbound scanning now fails closed on unscannable streaming responses (#29). Under `outbound.action: block`, a streaming response is rejected with `403` (`pii_blocked` / `outbound_stream_unscannable`) instead of being forwarded unscanned, which any client could trigger with `"stream": true`. **Behavior change** for existing `block` routes; set `outbound.allowUnscannedStreams: true` to restore pass-through. `redact` and `flag` are unchanged.
- Removed the per-key concurrency cap (`auth.apiKeys[].maxConcurrent`) and the `per_key` scope label. Per-client parallelism belongs to an AI gateway. The global `listen.maxConcurrentRequests` cap is unchanged.
- Removed the response cache (`cache`, the `X-Cache` header, `philter_proxy_cache_*`). Caching belongs to an AI gateway, and per-tenant cache keying carried cross-tenant risk. This drops the last Redis dependency, so the proxy now keeps no shared state.
- Removed rate limiting (`rateLimit`, its per-key override, the Redis backend, `philter_proxy_ratelimit_*`, and the `429` / `rate_limit_error` response). Rate limiting belongs to an AI gateway; `listen.maxConcurrentRequests` remains for overload protection.
- Removed config keys are ignored rather than rejected, with a startup warning naming each one. No config version bump is required. See [Using with an AI Gateway](docs/docs/ai-gateway.md).
- Bound concurrent in-flight TLS handshakes (`listen.maxConcurrentTLSHandshakes`, default 16384) so a connection flood cannot spawn unbounded handshake goroutines.
- Added a `--version` flag; the build version is stamped via `-ldflags` (derived from `git describe` in the Makefile and Dockerfile) and logged at startup.
- Token usage is now accounted for streaming responses too: the OpenAI and Anthropic streaming paths extract prompt/completion tokens from the final usage event (without buffering the stream), feeding the same audit-log fields and Prometheus counters as non-streaming responses.
- Amazon Bedrock ConverseStream (`/model/{id}/converse-stream`) is now supported: the inbound request is redacted as usual and the AWS binary event-stream response is forwarded to the client incrementally (no buffering), matching the streaming behavior of the other providers.
- Tightened `providers.openaiCompatible` name validation: a compat name may no longer contain a path separator (`/`, `\`) or collide with a built-in provider identifier (`openai`, `anthropic`, `gemini`, `ollama`, `bedrock`, `azure`, `vertex`) in addition to the existing reserved route prefixes — these become ambiguous URL prefixes and audit/scope labels. Existing configs using such names (uncommon) must rename the provider.
- Added an optional top-level config `version` field and a documented configuration backward-compatibility policy. Omitting `version` tracks the current schema (no change for existing configs); an unsupported value fails fast at startup with a clear error. See [Configuration Compatibility](docs/docs/configuration.md#configuration-compatibility).

## [1.0.0] - 2026-06-08

First public release. Philter AI Proxy is a redacting reverse proxy that strips PII/PHI from LLM traffic via [Philter](https://github.com/philterd/philter) before it reaches the provider, and can optionally scan responses on the way back.

- OpenAI, Azure OpenAI, Anthropic, Google Gemini, Google Vertex AI, Amazon Bedrock, and Ollama, plus any OpenAI-compatible backend — all with streaming (SSE) support.
- Inbound redaction across chat, embeddings, Responses, moderations, image, audio, and completions endpoints (including tool calls); optional outbound response scanning; per-route policies.
- API-key auth (hashed at rest) and mTLS, per-key scopes, secret references for credentials, and inbound request hardening (size caps, slowloris/handshake timeouts, TLS 1.2 floor).
- Per-client rate limiting and a response cache, each backed by memory or shared Redis.
- Philter retry/circuit breaker and per-provider transport timeouts.
- Cost control (token quotas, spend tracking, per-tenant billing) is deliberately out of scope; the proxy is designed to run alongside an AI gateway. See [Using with an AI Gateway](docs/docs/ai-gateway.md).
- Structured JSON audit log and errors, Prometheus metrics, OpenTelemetry tracing, `/livez` and `/readyz` probes, `--validate-config`, a Helm chart and Kubernetes manifests, and a k6 load-test harness.
