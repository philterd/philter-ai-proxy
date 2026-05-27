# Configuration

The proxy is configured via environment variables.

| Variable | Description | Default |
|----------|-------------|---------|
| `PHILTER_ENDPOINT` | The URL of your Philter instance. | `https://localhost:8080` |
| `PHILTER_CONTEXT` | The context used for Philter requests. | `none` |
| `PHILTER_DOCUMENT_ID` | The document ID used for Philter requests. If not set, a random UUID will be used for each request. | (random UUID) |
| `PHILTER_POLICY_NAME` | The policy name used for Philter requests. | `default` |
| `PHILTER_TLS_VERIFY` | Enable TLS certificate verification for the Philter backend connection. | `true` |
| `PHILTER_CA_CERT` | Path to a custom CA certificate (PEM) for the Philter backend connection. Useful when Philter uses a self-signed or internal CA certificate. | (none) |
| `PROVIDER_TLS_VERIFY` | Enable TLS certificate verification for LLM provider connections (OpenAI, Anthropic, Gemini, Ollama). | `true` |
| `PHILTER_PROXY_PORT` | The port the proxy will listen on. | `8080` |
| `PHILTER_PROXY_CERT_FILE` | Path to the TLS certificate file. | `cert.pem` |
| `PHILTER_PROXY_KEY_FILE` | Path to the TLS private key file. | `key.pem` |
| `PHILTER_SHUTDOWN_TIMEOUT` | Seconds to wait for in-flight requests to complete during graceful shutdown. | `30` |
| `PHILTER_LOGGING_ENABLED` | Enable structured audit logging for every proxy request. | `true` |
| `PHILTER_LOG_FILE` | Path to an additional log output file. When set, logs are written to both stdout and this file. | (none) |

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

### Configuration

To disable audit logging:

```bash
export PHILTER_LOGGING_ENABLED=false
```

To write logs to a file in addition to stdout:

```bash
export PHILTER_LOG_FILE=/var/log/philter-ai-proxy/audit.log
```

### SIEM Integration

The proxy outputs one JSON object per line (JSONL) to stdout, which is the standard format for container-based log collection. Common integrations:

- **Fluentd / Fluent Bit**: Use the `tail` input plugin pointed at the container's stdout, or the `forward` input with Docker's fluentd log driver. No parsing configuration is needed since the output is already JSON.
- **Promtail / Loki**: Configure a `docker` or `journal` source. Use the `json` pipeline stage to extract fields for label-based querying.
- **Splunk**: Use the Splunk Connect for Kubernetes or the HTTP Event Collector (HEC) with `sourcetype=_json`.
- **Elastic (Filebeat)**: Use the `container` or `log` input with `json.keys_under_root: true` and `json.add_error_key: true`.
- **AWS CloudWatch**: Container stdout is captured automatically with ECS or EKS. Use CloudWatch Logs Insights to query JSON fields directly.

For file-based collection (non-containerized deployments), set `PHILTER_LOG_FILE` and point your collector at that path.

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

If your Philter instance uses a self-signed certificate or a certificate from an internal CA, you can provide the CA certificate:

```bash
export PHILTER_CA_CERT=/etc/ssl/internal-ca.pem
```

### Disabling TLS Verification (Development Only)

To disable TLS verification for the Philter backend (e.g., during development):

```bash
export PHILTER_TLS_VERIFY=false
```

To disable TLS verification for LLM provider connections:

```bash
export PROVIDER_TLS_VERIFY=false
```

**Warning:** Disabling TLS verification makes connections vulnerable to man-in-the-middle attacks. Only disable verification in trusted development environments.

## Example

```bash
export PHILTER_ENDPOINT=https://your-philter-ip:8080
export PHILTER_PROXY_PORT=8080
./philter-ai-proxy
```
