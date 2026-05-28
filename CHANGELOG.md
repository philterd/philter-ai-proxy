# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Max-concurrent-requests guard. `listen.maxConcurrentRequests` caps the total in-flight requests the proxy will process at once; `auth.apiKeys[].maxConcurrent` adds an optional per-key in-flight cap. When either cap is reached the proxy returns HTTP 503 with `Retry-After: 1` and increments `philter_proxy_concurrency_shed_total{scope}` (scope is `global` or `per_key`). Disabled by default for backwards compatibility. (#112)
- Per-client rate limiting with optional global backstop. When `rateLimit.enabled: true`, requests are limited by API key (when auth is enabled) or client IP address. Individual keys can override the default limit via `auth.apiKeys[].rateLimit`. A global backstop (`rateLimit.global`) caps total throughput across all clients. Clients that exceed their limit receive `HTTP 429` with a `Retry-After` header. Rate limiting is disabled by default. (#96)
- API key authentication and mTLS support. Authentication is disabled by default. When `auth.apiKeys` is configured, clients must present a valid key in the `x-philter-proxy-key` header (configurable); missing or invalid keys receive HTTP `401`. Each key can be bound to a Philter policy override. When `listen.clientCA` is set, the proxy requires and verifies a client TLS certificate on every connection. Both mechanisms can be used simultaneously. (#95)
- Token usage tracking: `prompt_tokens` and `completion_tokens` are extracted from non-streaming provider responses and included in the audit log and as Prometheus counters `philter_proxy_prompt_tokens_total` / `philter_proxy_completion_tokens_total` (labeled by `provider` and `model`). Covers all five providers (OpenAI, Anthropic, Gemini, Ollama, Bedrock) and OpenAI-compatible providers. (#42)
- Support for multiple OpenAI-compatible providers (Mistral, Cohere, vLLM, LM Studio, etc.) via `providers.openaiCompatible`. Each entry maps a short name to a target URL; clients send requests to `/{name}/v1/...` and the proxy strips the prefix before forwarding. Full PII redaction and audit logging apply. (#41)
- Amazon Bedrock Converse API support (`/model/{modelId}/converse`). The proxy signs requests with AWS Signature Version 4 using the standard AWS credential chain (instance profile, IRSA, env vars). Clients send plain JSON with no AWS credentials required. System prompts and all message content blocks are redacted through Philter before forwarding. Outbound scanning is supported. Enable by setting `providers.bedrock.region` in the config. (#101)
- Retry and circuit breaker for the Philter backend. Failed Philter calls are retried with exponential backoff (configurable attempts, initial delay, and max delay). A circuit breaker can be enabled to open after a configurable number of consecutive failures, with `block` (HTTP 503) or `passthrough` (forward unredacted with a warning) fallback. (#99)
- Outbound response scanning: LLM responses are optionally scanned through Philter before being returned to the client. Disabled by default; enabled per-route or globally via `outbound.enabled: true` in the config. Configurable `action`: `redact` (replace PII), `block` (return HTTP 403), or `flag` (pass through with a warning log). Streaming responses are passed through unchanged with a warning. Outbound scans reuse the same Philter context and document ID as the inbound request for correlation. (#92)

### Security

- Removed hardcoded `InsecureSkipVerify: true` from all outbound HTTP transports. TLS certificate verification is now enabled by default for both Philter backend and LLM provider connections. (#14)
- Added `PHILTER_TLS_VERIFY` and `PHILTER_CA_CERT` environment variables to configure TLS for the Philter backend connection (supports custom CA certificates for self-signed certs).
- Added `PROVIDER_TLS_VERIFY` environment variable to configure TLS for LLM provider connections.

### Added

- Prometheus metrics endpoint on a configurable port (`metrics.port`, default `9090`). Metrics: `philter_proxy_requests_total`, `philter_proxy_request_duration_seconds`, `philter_proxy_redaction_duration_seconds`, `philter_proxy_entities_redacted_total`, `philter_proxy_philter_errors_total`, `philter_proxy_upstream_errors_total`, `philter_proxy_active_requests`. All labeled by provider and/or policy. See [Monitoring](http://philterd.github.io/philter-ai-proxy/monitoring/) for PromQL examples and Grafana alerting rules.
- `/health` endpoint now checks Philter backend reachability and returns `{"status":"degraded","philter":"unreachable"}` with HTTP 503 when the backend is unavailable; returns `{"status":"ok","philter":"ok"}` when healthy.
- `Filter` function no longer calls `os.Exit` on failure — errors are propagated to callers and result in a `502` response to the client with `philter_proxy_philter_errors_total` incremented.
- Tool-use and function-calling redaction for all providers. OpenAI `role: tool` message content, OpenAI `tool_calls[].function.arguments` (parsed, redacted, re-serialized), Anthropic `tool_result` content blocks, and Gemini `functionResponse` parts are now all redacted before the request is forwarded. OpenAI `role: system` messages are also explicitly covered.
- YAML configuration file support via `--config` flag or `PHILTER_PROXY_CONFIG` environment variable. Supports per-route policy selection based on request headers, URL path, or model name, and per-provider target URLs. Environment variables still work as overrides. Config is validated at startup with clear error messages.
- Streaming (SSE) support for all four providers (OpenAI, Anthropic, Gemini, Ollama). Response chunks are forwarded to the client in real time without buffering.
- Structured audit logging (JSONL) for every proxy request, including request ID, provider, model, policy name, document ID, fields redacted, entity count, entity types detected, redaction latency, client IP, and HTTP status. Enabled by default.
- Added `PHILTER_LOGGING_ENABLED` environment variable (default: `true`) to control audit logging.
- Added `PHILTER_LOG_FILE` environment variable to write audit logs to a file in addition to stdout.
- All proxy output (audit entries, startup, shutdown, errors) is now structured JSON via `log/slog`.

### Changed

- **Configuration file is now required.** Environment-variable-only configuration has been removed. All settings are in the YAML config file, specified via `--config` flag or `PHILTER_PROXY_CONFIG` environment variable.
- Logging and shutdown timeout settings moved into the config file (`logging` and `listen.shutdownTimeout` sections).
- Per-provider TLS clients: each provider now has its own HTTP client with independent `tlsVerify` settings.
- Replaced `httputil.ReverseProxy` with a streaming-capable forwarding function that reads response chunks and flushes them to the client immediately. This enables real-time SSE pass-through for all providers.
- Switched from Philter's `/api/filter` endpoint to `/api/explain` endpoint, which returns entity types and counts in the response. This enables full audit logging of what was redacted.
- Graceful shutdown with connection draining on SIGTERM/SIGINT. In-flight requests are allowed to complete up to a configurable timeout before the process exits.
