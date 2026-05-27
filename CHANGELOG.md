# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Security

- Removed hardcoded `InsecureSkipVerify: true` from all outbound HTTP transports. TLS certificate verification is now enabled by default for both Philter backend and LLM provider connections. (#14)
- Added `PHILTER_TLS_VERIFY` and `PHILTER_CA_CERT` environment variables to configure TLS for the Philter backend connection (supports custom CA certificates for self-signed certs).
- Added `PROVIDER_TLS_VERIFY` environment variable to configure TLS for LLM provider connections.

### Added

- Structured audit logging (JSONL) for every proxy request, including request ID, provider, model, policy name, document ID, fields redacted, entity count, entity types detected, redaction latency, client IP, and HTTP status. Enabled by default.
- Added `PHILTER_LOGGING_ENABLED` environment variable (default: `true`) to control audit logging.
- Added `PHILTER_LOG_FILE` environment variable to write audit logs to a file in addition to stdout.
- All proxy output (audit entries, startup, shutdown, errors) is now structured JSON via `log/slog`.

### Changed

- Switched from Philter's `/api/filter` endpoint to `/api/explain` endpoint, which returns entity types and counts in the response. This enables full audit logging of what was redacted.
- Graceful shutdown with connection draining on SIGTERM/SIGINT. In-flight requests are allowed to complete up to a configurable timeout before the process exits.
- Added `PHILTER_SHUTDOWN_TIMEOUT` environment variable (default: 30 seconds) to control the graceful shutdown drain period.
