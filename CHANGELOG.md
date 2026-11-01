# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - Unreleased

A rewrite in Java that redacts in-process with Phileas, with no Philter backend. 2.0 does not read 0.x configuration files.

- Redaction with Phileas inside the proxy. Person names are found with the `ph-eye-pii-en-small` PhEye model, included in the Docker image and run in-process. All the text of a request is redacted together, against one policy.
- Policies are native Phileas policies, stored in the proxy's SQLite database and managed with a Philter-compatible policy API under `/admin/api/policies`. A built-in `default` policy finds person names, SSNs, and email addresses. Policies may not name a PhEye service, generators, or files and environment variables the deployment has not allowed.
- API keys, always required, managed under `/admin/api/keys`: roles (`admin`, `proxy`), scopes on providers, models, and paths, and a bound policy. Keys are stored as SHA-256 hashes.
- Contexts keep replacements consistent across requests, stored in the database with the original values encrypted (AES-256-GCM).
- Providers: OpenAI (chat, Responses, completions, embeddings, moderations, image generation, speech), Azure OpenAI (with Entra ID), OpenAI-compatible providers, Anthropic, Gemini, Vertex AI, Ollama, and Bedrock Converse. Request fields the proxy does not redact are forwarded unchanged. Requests without a body, such as `GET /v1/models`, are forwarded.
- Response scanning (`redact`, `block`, `flag`) for every provider, including streamed responses, which are scanned as they arrive. Content parts, refusals, tool-call arguments, and reasoning text are scanned, and `logprobs` removed under `redact` and `block`. A response that cannot be scanned is refused rather than returned unscanned.
- HTTPS by default in the image with a self-signed certificate generated at startup; your own certificate and mutual TLS through `server.ssl.*`.
- An audit log of metadata only, in the database, on standard output, and optionally in a file; Prometheus metrics named `philter_proxy_*`; OpenTelemetry tracing with the trace ID in the audit log; `/livez`, `/readyz` (once the configured policies and their models are loaded), and `/health`.
- `--version` and `--validate-config`. The proxy refuses to start with an encryption key other than the one its database was created with.
- A Helm chart and plain manifests for a single replica with a persistent volume, a Grafana dashboard, and a k6 load-test harness.
- Routing, failover, rate limiting, response caching, and token or spend accounting remain out of scope. See [Using with an AI Gateway](docs/docs/ai-gateway.md).

## 0.2.0 and earlier

The Go versions, which sent each text to a Philter instance for redaction. Tagged `0.1.0` and `0.2.0`.
