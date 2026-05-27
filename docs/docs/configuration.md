# Configuration

The proxy is configured via a YAML configuration file. The config file is required and must be specified via `--config` flag or `PHILTER_PROXY_CONFIG` environment variable.

```bash
./philter-ai-proxy --config config.yaml
# or
PHILTER_PROXY_CONFIG=config.yaml ./philter-ai-proxy
```

## Example Configuration

```yaml
listen:
  port: 8080
  cert: cert.pem
  key: key.pem
  shutdownTimeout: 30

logging:
  enabled: true
  # file: /var/log/philter-ai-proxy/audit.log

philter:
  endpoint: https://philter.internal:8080
  tlsVerify: true
  # caCert: /etc/ssl/internal-ca.pem

providers:
  openai:
    target: https://api.openai.com
    # tlsVerify: true
  anthropic:
    target: https://api.anthropic.com
    # tlsVerify: true
  gemini:
    target: https://generativelanguage.googleapis.com
    # tlsVerify: true
  ollama:
    target: http://localhost:11434
    # tlsVerify: true

routes:
  - match:
      header: x-philter-policy
      value: hipaa
    policy: hipaa-safe-harbor
    context: healthcare-chatbot

  - match:
      path: /v1/chat/completions
      model: gpt-4
    policy: general-purpose
    context: internal-analytics

  - match:
      model: claude-sonnet-4-20250514
    policy: code-review-policy

defaults:
  policy: default
  context: none
```

## Configuration Reference

### `listen`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | int | `8080` | Port the proxy listens on |
| `cert` | string | `cert.pem` | Path to the TLS certificate file |
| `key` | string | `key.pem` | Path to the TLS private key file |
| `shutdownTimeout` | int | `30` | Seconds to wait for in-flight requests during graceful shutdown |

### `logging`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable structured audit logging |
| `file` | string | (none) | Path to an additional log output file. When set, logs are written to both stdout and this file. |

### `philter`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint` | string | `https://localhost:8080` | URL of the Philter instance |
| `tlsVerify` | bool | `true` | Enable TLS certificate verification for the Philter connection |
| `caCert` | string | (none) | Path to a custom CA certificate (PEM) for the Philter connection |

### `providers`

Each provider (`openai`, `anthropic`, `gemini`, `ollama`) accepts:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | (provider default) | Target URL for the provider |
| `tlsVerify` | bool | `true` | Enable TLS certificate verification for this provider |

Default provider targets:

- `openai`: `https://api.openai.com`
- `anthropic`: `https://api.anthropic.com`
- `gemini`: `https://generativelanguage.googleapis.com`
- `ollama`: `http://localhost:11434`

### `routes`

Routes control which **Philter redaction policy and context** are applied to each request. They do not control which LLM provider handles the request — provider routing is determined automatically by the URL path (see [API Reference](api.md) for path-to-provider mapping).

This means a single route can apply across all providers. For example, a route matching the header `x-philter-policy: hipaa` will use the HIPAA policy whether the request is going to OpenAI, Anthropic, Gemini, or Ollama.

Routes are evaluated in order; the first match wins. If no route matches, the `defaults` are used.

Each route has a `match` block with one or more criteria (all specified criteria must match):

| Criterion | Description |
|-----------|-------------|
| `header` + `value` | Matches when the request contains the specified header with the specified value |
| `path` | Matches when the request URL path equals this value |
| `model` | Matches when the model name in the request body equals this value |

Each route specifies:

| Field | Required | Description |
|-------|----------|-------------|
| `policy` | Yes | Philter policy name to use for redaction |
| `context` | No | Philter context to use (falls back to `defaults.context` if not set) |

### `defaults`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policy` | string | `default` | Philter policy used when no route matches |
| `context` | string | `none` | Philter context used when no route matches (or when a matched route has no context) |

## Audit Logging

Every proxy request produces a structured JSON log entry (JSONL) to stdout. All output from the proxy — audit entries, startup, shutdown, and errors — is structured JSON, making it safe to pipe directly into log aggregators.

### Log Schema

| Field | Type | Description |
|-------|------|-------------|
| `time` | string | ISO 8601 timestamp |
| `request_id` | string | Unique ID for request correlation |
| `direction` | string | Scan direction (`inbound`; `outbound` when response scanning is added) |
| `provider` | string | LLM provider (`openai`, `anthropic`, `gemini`, `ollama`) |
| `model` | string | Model name from the request body |
| `policy_name` | string | Philter policy used for redaction |
| `document_id` | string | Philter document ID (correlates with Philter's own logs) |
| `fields_redacted` | int | Number of text fields sent through Philter |
| `entity_count` | int | Total number of entities detected and redacted |
| `entity_types` | string[] | Distinct entity types detected (e.g., `["NER_ENTITY", "SSN"]`) |
| `redact_latency_ms` | int | Total time spent on Philter redaction calls (milliseconds) |
| `client_ip` | string | Client IP address (supports `X-Forwarded-For`) |
| `http_status` | int | HTTP status code of the upstream provider response |

### Example Log Entry

```json
{"time":"2026-01-15T10:30:00Z","level":"INFO","msg":"request","request_id":"a1b2c3d4","direction":"inbound","provider":"openai","model":"gpt-4","policy_name":"default","document_id":"doc-789","fields_redacted":2,"entity_count":3,"entity_types":["NER_ENTITY","SSN"],"redact_latency_ms":45,"client_ip":"10.0.0.1","http_status":200}
```

### SIEM Integration

The proxy outputs one JSON object per line (JSONL) to stdout, which is the standard format for container-based log collection. Common integrations:

- **Fluentd / Fluent Bit**: Use the `tail` input plugin pointed at the container's stdout, or the `forward` input with Docker's fluentd log driver. No parsing configuration is needed since the output is already JSON.
- **Promtail / Loki**: Configure a `docker` or `journal` source. Use the `json` pipeline stage to extract fields for label-based querying.
- **Splunk**: Use the Splunk Connect for Kubernetes or the HTTP Event Collector (HEC) with `sourcetype=_json`.
- **Elastic (Filebeat)**: Use the `container` or `log` input with `json.keys_under_root: true` and `json.add_error_key: true`.
- **AWS CloudWatch**: Container stdout is captured automatically with ECS or EKS. Use CloudWatch Logs Insights to query JSON fields directly.

For file-based collection (non-containerized deployments), set `logging.file` in the config and point your collector at that path.

## Streaming

The proxy supports streaming responses (`stream: true`) for all four providers:

- **OpenAI**: Server-Sent Events (SSE) with `data:` prefixed chunks
- **Anthropic**: SSE with `event:` / `data:` chunks
- **Gemini**: Chunked JSON via `streamGenerateContent`
- **Ollama**: Newline-delimited JSON (streaming is the default)

Streaming requires no additional configuration. Inbound prompt redaction works identically for streaming and non-streaming requests. Response chunks are forwarded to the client in real time without buffering.

## TLS Configuration

By default, TLS certificate verification is enabled for all outbound connections (both to the Philter backend and to LLM providers). This is the recommended configuration for production deployments.

### Philter Backend with Self-Signed Certificate

If your Philter instance uses a self-signed certificate or a certificate from an internal CA, provide the CA certificate in the config:

```yaml
philter:
  endpoint: https://philter.internal:8080
  caCert: /etc/ssl/internal-ca.pem
```

### Disabling TLS Verification (Development Only)

To disable TLS verification for the Philter backend:

```yaml
philter:
  tlsVerify: false
```

To disable TLS verification for a specific LLM provider:

```yaml
providers:
  ollama:
    target: https://ollama.internal:11434
    tlsVerify: false
```

**Warning:** Disabling TLS verification makes connections vulnerable to man-in-the-middle attacks. Only disable verification in trusted development environments.
