# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Security

- Removed hardcoded `InsecureSkipVerify: true` from all outbound HTTP transports. TLS certificate verification is now enabled by default for both Philter backend and LLM provider connections. (#14)
- Added `PHILTER_TLS_VERIFY` and `PHILTER_CA_CERT` environment variables to configure TLS for the Philter backend connection (supports custom CA certificates for self-signed certs).
- Added `PROVIDER_TLS_VERIFY` environment variable to configure TLS for LLM provider connections.

### Added

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
