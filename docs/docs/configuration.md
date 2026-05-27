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
  retry:
    maxAttempts: 3
    initialBackoffMs: 100
    maxBackoffMs: 2000
  # circuitBreaker:
  #   enabled: true
  #   threshold: 5
  #   timeoutSeconds: 30
  #   fallback: block

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

### `metrics`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable the Prometheus metrics endpoint |
| `port` | int | `9090` | Port for the metrics HTTP server (separate from the proxy TLS port) |

See [Monitoring](monitoring.md) for available metrics, PromQL examples, and Grafana dashboard setup.

### `philter`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint` | string | `https://localhost:8080` | URL of the Philter instance |
| `tlsVerify` | bool | `true` | Enable TLS certificate verification for the Philter connection |
| `caCert` | string | (none) | Path to a custom CA certificate (PEM) for the Philter connection |
| `retry` | object | see below | Retry settings for failed Philter calls |
| `circuitBreaker` | object | see below | Circuit breaker settings for the Philter connection |

#### `philter.retry`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `maxAttempts` | int | `3` | Total number of attempts (1 = no retry). Only transient errors (network errors, HTTP 5xx) are retried. |
| `initialBackoffMs` | int | `100` | Initial backoff delay in milliseconds before the first retry |
| `maxBackoffMs` | int | `2000` | Maximum backoff delay in milliseconds (backoff is capped at this value) |

#### `philter.circuitBreaker`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the circuit breaker for the Philter connection |
| `threshold` | int | `5` | Number of consecutive failures before the circuit opens |
| `timeoutSeconds` | int | `30` | Seconds the circuit remains open before allowing a probe request (half-open state) |
| `fallback` | string | `block` | Action when the circuit is open: `block` (return HTTP 503) or `passthrough` (forward the request unredacted with a warning log) |

### `providers`

Each of the standard providers (`openai`, `anthropic`, `gemini`, `ollama`) accepts:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | (provider default) | Target URL for the provider |
| `tlsVerify` | bool | `true` | Enable TLS certificate verification for this provider |

Default provider targets:

- `openai`: `https://api.openai.com`
- `anthropic`: `https://api.anthropic.com`
- `gemini`: `https://generativelanguage.googleapis.com`
- `ollama`: `http://localhost:11434`

### `providers.openaiCompatible`

Any number of additional OpenAI-compatible providers (Mistral, Cohere, vLLM, LM Studio, etc.) can be registered under `providers.openaiCompatible`. Each entry maps a short **name** to a target URL.

```yaml
providers:
  openaiCompatible:
    mistral:
      target: https://api.mistral.ai
    cohere:
      target: https://api.cohere.com
    vllm:
      target: http://vllm.internal:8000
```

Clients send requests to `/{name}/v1/...` — the proxy strips the prefix and forwards the remainder to the configured target using the same OpenAI handler logic. For example, a request to `/mistral/v1/chat/completions` is forwarded to `https://api.mistral.ai/v1/chat/completions`. The provider label in the audit log is set to the registered name.

Each entry accepts:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | — (required) | Base URL for this provider |
| `tlsVerify` | bool | `true` | Enable TLS certificate verification for this provider |

**Reserved names**: `v1`, `api`, `model`, and `health` conflict with built-in route prefixes and will be rejected at startup.

### `providers.bedrock`

Amazon Bedrock is an optional provider. It is enabled by setting `providers.bedrock.region`. When enabled, the proxy accepts requests matching `/model/{modelId}/converse` and forwards them to `https://bedrock-runtime.{region}.amazonaws.com` using AWS Signature Version 4 authentication.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `region` | string | (none — Bedrock disabled) | AWS region for the Bedrock runtime endpoint (e.g., `us-east-1`) |
| `roleArn` | string | (none) | ARN of an IAM role to assume for Bedrock calls (e.g., `arn:aws:iam::123456789012:role/BedrockRole`). When set, the proxy calls `sts:AssumeRole` using the host's base credentials and signs Bedrock requests with the resulting session credentials. |
| `tlsVerify` | bool | `true` | Enable TLS certificate verification for the Bedrock connection |

**Authentication**: The proxy uses the standard [AWS credential chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html). No AWS credentials need to be supplied by the client. The recommended deployment pattern is to attach an IAM role to the compute resource running the proxy (EC2 instance profile, ECS task role, Kubernetes service account with IRSA) and grant that role the `bedrock:InvokeModel` permission. Environment variable credentials (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) are also supported for development.

If the host credentials do not have Bedrock access directly (e.g., in a multi-account setup), set `roleArn` to an IAM role ARN that the proxy should assume. The proxy will call `sts:AssumeRole` with the host's base credentials and use the resulting session credentials to sign Bedrock requests. The host role must have `sts:AssumeRole` permission on the target role.

**Minimum IAM policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "bedrock:InvokeModel",
    "Resource": "arn:aws:bedrock:us-east-1::foundation-model/*"
  }]
}
```

**Supported models**: Any model available through the [Bedrock Converse API](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html) in the configured region, including Anthropic Claude, Amazon Titan, Meta Llama, Mistral, and Cohere models.

**Streaming**: The `converseStream` endpoint is not yet supported. Streaming support is planned for a future release.

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
| `outbound` | No | Outbound response scanning settings for this route (see below) |

### `defaults`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `policy` | string | `default` | Philter policy used when no route matches |
| `context` | string | `none` | Philter context used when no route matches (or when a matched route has no context) |
| `outbound` | object | (disabled) | Default outbound scanning settings (see below) |

### `outbound`

Outbound response scanning runs the LLM's response through Philter before it is returned to the client. It is **disabled by default** and must be explicitly enabled. When enabled, the same Philter policy, context, and document ID used for inbound redaction are reused, so Philter can correlate the request/response pair.

**Latency note:** outbound scanning buffers the full provider response before returning it, adding the round-trip latency of the Philter call. For latency-sensitive workloads, consider enabling outbound scanning only on routes where compliance requires it.

**Streaming note:** outbound scanning is skipped automatically when the provider returns a streaming response (`text/event-stream` or `application/x-ndjson`). The response is passed through to the client unchanged, and a warning is logged.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable outbound response scanning |
| `action` | string | `redact` | Action when PII is detected: `redact`, `block`, or `flag` |

**Actions:**

| Action | Behaviour |
|--------|-----------|
| `redact` | Detected PII is replaced with Philter's configured replacement token before the response is returned (default). |
| `block` | If any PII is detected, the response is suppressed and the client receives HTTP `403` with `{"error":{"message":"response blocked: PII detected","type":"pii_blocked"}}`. |
| `flag` | PII is detected and logged as a warning, but the original unmodified response is returned to the client. |

**Example — block responses containing PII for HIPAA routes:**

```yaml
routes:
  - match:
      header: x-philter-policy
      value: hipaa
    policy: hipaa-safe-harbor
    context: healthcare-chatbot
    outbound:
      enabled: true
      action: block

defaults:
  policy: default
  context: none
  outbound:
    enabled: false
```

## Audit Logging

Every proxy request produces a structured JSON log entry (JSONL) to stdout. All output from the proxy — audit entries, startup, shutdown, and errors — is structured JSON, making it safe to pipe directly into log aggregators.

### Log Schema

| Field | Type | Description |
|-------|------|-------------|
| `time` | string | ISO 8601 timestamp |
| `request_id` | string | Unique ID for request correlation |
| `direction` | string | Scan direction: `inbound` (request) or `outbound` (response, when outbound scanning is enabled) |
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
| `prompt_tokens` | int | Prompt (input) token count reported by the provider. Omitted for streaming responses and when the provider does not return usage data. |
| `completion_tokens` | int | Completion (output) token count reported by the provider. Omitted under the same conditions as `prompt_tokens`. |

### Example Log Entries

When outbound scanning is disabled (default), one entry is emitted per request:

```json
{"time":"2026-01-15T10:30:00Z","level":"INFO","msg":"request","request_id":"a1b2c3d4","direction":"inbound","provider":"openai","model":"gpt-4","policy_name":"default","document_id":"doc-789","fields_redacted":2,"entity_count":3,"entity_types":["NER_ENTITY","SSN"],"redact_latency_ms":45,"client_ip":"10.0.0.1","http_status":200,"prompt_tokens":312,"completion_tokens":87}
```

When outbound scanning is enabled, two entries are emitted per request — one for the inbound scan and one for the outbound scan. Both share the same `request_id` and `document_id` for correlation. Token counts appear on the inbound entry only:

```json
{"time":"2026-01-15T10:30:00Z","level":"INFO","msg":"request","request_id":"a1b2c3d4","direction":"outbound","provider":"openai","model":"gpt-4","policy_name":"default","document_id":"doc-789","fields_redacted":1,"entity_count":1,"entity_types":["NER_ENTITY"],"redact_latency_ms":12,"client_ip":"10.0.0.1","http_status":200}
{"time":"2026-01-15T10:30:00Z","level":"INFO","msg":"request","request_id":"a1b2c3d4","direction":"inbound","provider":"openai","model":"gpt-4","policy_name":"default","document_id":"doc-789","fields_redacted":2,"entity_count":3,"entity_types":["NER_ENTITY","SSN"],"redact_latency_ms":45,"client_ip":"10.0.0.1","http_status":200,"prompt_tokens":312,"completion_tokens":87}
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
