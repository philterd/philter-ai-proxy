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

## Configuration Compatibility

The configuration file carries an optional top-level schema version:

```yaml
version: 1   # optional; defaults to the current schema when omitted
```

**Backward-compatibility policy** (the config-schema counterpart of the stable [error-code contract](#error-responses)):

- **Additive changes ship in any release.** New optional fields with safe defaults may be added at any time. A config that is valid for version *N* keeps working on later releases of the same major version without edits.
- **`version` is optional and defaults to the current schema.** Omitting it is fully supported, so existing configs need no changes. Setting it explicitly (`version: 1`) lets you pin the schema your automation was written against and get a clear startup error if a future build no longer supports it.
- **No silent breaking changes.** Existing fields will not be removed, renamed, or have their meaning/defaults changed in a way that breaks a valid config across minor versions. Anything breaking is reserved for a major-version bump.
- **Unsupported version → clear startup failure.** If `version` is set to a value this build does not understand, the proxy exits at startup (and `--validate-config` returns non-zero) with `config: unsupported config version <n> (this build supports version <m>) ...` — it never silently ignores the field.

**Migration guidance.** When a breaking schema change is unavoidable, the schema version is incremented, the release notes document the field-by-field migration, and both the old and new versions are accepted for at least one minor release so deployments can migrate without downtime. Validate a config against the running build before rollout with:

```bash
./philter-ai-proxy --validate-config --config config.yaml
```

The current schema version is **1**.

## Configuration Reference

### `version`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | int | current schema (`1`) | Optional config schema version. Omit to track the current schema, or pin it (e.g. `1`) so an unsupported future schema fails fast at startup. See [Configuration Compatibility](#configuration-compatibility). |

### `listen`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `port` | int | `8080` | Port the proxy listens on |
| `cert` | string | `cert.pem` | Path to the TLS certificate file |
| `key` | string | `key.pem` | Path to the TLS private key file |
| `shutdownTimeout` | int | `30` | Seconds to wait for in-flight requests during graceful shutdown |
| `clientCA` | string | (none) | Path to a PEM CA certificate used to verify client certificates. When set, mTLS is enabled and the proxy requires a valid client certificate on every connection. See [mTLS](#mtls-mutual-tls) below. |
| `maxConcurrentRequests` | int | `0` (unlimited) | Maximum number of in-flight requests the proxy will process at once. Excess requests get HTTP 503 with `Retry-After: 1`. See [Concurrency Limits](#concurrency-limits) below. |
| `maxRequestBodyBytes` | int | `10485760` (10 MiB) | Maximum inbound request body size in bytes. Larger bodies are rejected with HTTP 413. See [Request Hardening](#request-hardening) below. |
| `maxHeaderBytes` | int | `1048576` (1 MiB) | Maximum total size of inbound request headers. |
| `readHeaderTimeoutMs` | int | `10000` (10s) | Time a client may take to send the request headers before the connection is dropped (slowloris mitigation). |
| `readTimeoutMs` | int | `0` (disabled) | Time to read the entire request including body. Bounds slow-body attacks; affects only request reads, never response streaming. Disabled by default so large/slow uploads aren't truncated. |
| `tlsHandshakeTimeoutMs` | int | `10000` (10s) | Time a client may take to complete the TLS handshake before the connection is dropped (slow-handshake slowloris mitigation). Independent of `readHeaderTimeoutMs`, which only starts ticking after the handshake completes. See [Request Hardening](#request-hardening) below. |
| `maxConcurrentTLSHandshakes` | int | `16384` | Ceiling on simultaneous in-flight TLS handshakes. Bounds handshake goroutine count under a connection flood; excess connections are dropped immediately and counted by `philter_proxy_tls_handshakes_shed_total`. Established connections are unaffected. See [Request Hardening](#request-hardening) below. |
| `trustedProxies` | string list | empty (XFF ignored) | CIDR ranges of upstream load balancers / reverse proxies whose `X-Forwarded-For` header should be honored. Empty (default) means XFF is **never** trusted -- the safe behavior when the proxy is exposed directly to the internet. Operators behind a trusted LB **must** populate this with the LB's source CIDR(s) to restore accurate per-IP rate limits and audit-log IPs. See [Trusted Proxies / X-Forwarded-For](#trusted-proxies--x-forwarded-for). |

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

### `tracing`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Initialise the OpenTelemetry SDK. With this off the proxy pays zero per-request tracing overhead. |
| `serviceName` | string | `philter-ai-proxy` | The OTel `service.name` resource attribute when `OTEL_SERVICE_NAME` is not set. |

OTLP exporter destination, protocol, headers, sampler, and other tuning are all configured via the standard OTel env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_TRACES_SAMPLER`, etc.). See [Monitoring -> Distributed Tracing](monitoring.md#distributed-tracing) for the full list and worked examples.

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
| `timeouts` | object | (see [Provider Timeouts](#provider-timeouts)) | Per-provider HTTP timeouts |

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

Clients send requests to `/{name}/v1/...` - the proxy strips the prefix and forwards the remainder to the configured target using the same OpenAI handler logic. For example, a request to `/mistral/v1/chat/completions` is forwarded to `https://api.mistral.ai/v1/chat/completions`. The provider label in the audit log is set to the registered name.

Each entry accepts:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | - (required) | Base URL for this provider |
| `tlsVerify` | bool | `true` | Enable TLS certificate verification for this provider |

**Reserved names**: `v1`, `api`, `model`, and `health` conflict with built-in route prefixes and will be rejected at startup.

### `providers.bedrock`

Amazon Bedrock is an optional provider. It is enabled by setting `providers.bedrock.region`. When enabled, the proxy accepts requests matching `/model/{modelId}/converse` and `/model/{modelId}/converse-stream` and forwards them to `https://bedrock-runtime.{region}.amazonaws.com` using AWS Signature Version 4 authentication. ConverseStream responses (AWS binary event-stream) are forwarded to the client incrementally without buffering.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `region` | string | (none - Bedrock disabled) | AWS region for the Bedrock runtime endpoint (e.g., `us-east-1`) |
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

### `providers.azure`

Azure OpenAI is an optional first-class provider. It is enabled by setting `providers.azure.target` to your resource endpoint. Azure uses deployment-based routing rather than OpenAI's model-in-body convention: the proxy routes any request whose path begins with `/openai/deployments/{deployment}/`, preserves the path and the `api-version` query parameter, and forwards it to the configured Azure endpoint. Request and response bodies are OpenAI-compatible, so **inbound redaction and token-usage accounting are identical to the OpenAI provider**.

!!! note "Redaction scope"
    Inbound redaction covers the text-bearing fields of all JSON endpoints the proxy understands — see the [Redacted Fields](api.md#redacted-fields) table for the full per-endpoint list. Multipart/binary uploads (file uploads, audio transcriptions, image edits) are **not supported**: the proxy expects a JSON body and rejects multipart requests with `400 invalid_request`.

```yaml
providers:
  azure:
    target: https://my-resource.openai.azure.com
    apiVersion: "2024-02-01"   # optional: injected when a request omits api-version
    entraID: false             # false (default) = pass the client's api-key header through
    # tlsVerify: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | string | (none - Azure disabled) | Azure OpenAI resource endpoint, e.g. `https://my-resource.openai.azure.com`. |
| `apiVersion` | string | (none) | Default `api-version` injected when a request doesn't supply one. Azure requires this parameter; setting it here lets clients that omit it still work. A client-supplied `api-version` always takes precedence. |
| `entraID` | bool | `false` | When `true`, the proxy authenticates to Azure with an Azure AD / Entra ID bearer token instead of passing the client's `api-key` through. |
| `tlsVerify` | bool | `true` | Enable TLS certificate verification for the Azure connection. |

**Authentication — two modes:**

- **`api-key` pass-through (default).** The client sends its Azure `api-key` header; the proxy forwards it unchanged (the same way it passes through `Authorization` for OpenAI). No proxy-side credentials are needed.
- **Entra ID (`entraID: true`).** The proxy acquires a token via the [default Azure credential chain](https://learn.microsoft.com/azure/developer/go/azure-sdk-authentication) — managed identity, workload identity, or environment credentials (`AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET`) — caches it until shortly before expiry, and sets it as the `Authorization: Bearer` header on outbound requests (scope `https://cognitiveservices.azure.com/.default`). The recommended production pattern is a workload identity / managed identity assigned the **Cognitive Services OpenAI User** role on the resource, so no secrets are handled by clients. A token-acquisition failure returns `502` (`provider_error` / `azure_auth_failed`).

**Client example** (api-key mode):
```bash
curl -k "https://localhost:8080/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01" \
  -H "api-key: $AZURE_OPENAI_KEY" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Hello"}]}'
```

Note Azure encodes the model in the deployment name (URL), so the request body's `model` field is optional; the audit log records whatever the body supplies. When the proxy is not configured for Azure, `/openai/deployments/...` requests return `404` (`not_found` / `azure_disabled`).

### `providers.vertex`

Vertex AI (Gemini on Google Cloud) is an optional first-class provider. It is enabled by setting `providers.vertex.project` (and typically `providers.vertex.location`). Vertex's API surface differs from the public Gemini API:

- **Regional endpoint.** Requests go to `https://{location}-aiplatform.googleapis.com` (e.g. `us-central1-aiplatform.googleapis.com`), not `generativelanguage.googleapis.com`. The proxy derives this from `location`, or you can override it with `endpoint`.
- **Resource-style paths.** `/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent` and the streaming variant `:streamGenerateContent`. The proxy routes any request whose path matches this shape; the path is preserved verbatim when forwarding (so `{project}` and `{location}` in the URL need not equal the configured values, useful if the proxy fronts multiple projects whose ADC is permitted).
- **OAuth2 / ADC authentication.** No `?key=` query parameter; the proxy acquires a Google access token via [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) and sets it as the `Authorization: Bearer` header on outbound requests. The cached token is refreshed shortly before expiry.

Request and response bodies are the same Gemini schema as the public provider, so **inbound redaction and outbound scanning are identical to the public Gemini provider**.

```yaml
providers:
  vertex:
    project: my-gcp-project
    location: us-central1
    # endpoint: https://override.example.com   # optional: override the default regional endpoint
    # tlsVerify: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `project` | string | (none - Vertex disabled) | GCP project ID. Setting this enables the Vertex provider. |
| `location` | string | (none) | Region used to build the default endpoint (e.g. `us-central1`). Required unless `endpoint` is set. |
| `endpoint` | string | derived from `location` | Override the target URL. Useful for VPC-SC private endpoints or local-emulator testing. |
| `tlsVerify` | bool | `true` | Enable TLS certificate verification for the Vertex connection. |
| `timeouts` | object | (proxy defaults) | Per-provider [HTTP timeouts](#provider-timeouts). |

**Authentication.** The proxy uses [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials) (workload identity, service-account key, the metadata server on GCE/GKE/Cloud Run, `gcloud auth application-default login`, etc.). The recommended production pattern is a workload identity bound to a service account with the **Vertex AI User** role on the project. The OAuth2 scope used is `https://www.googleapis.com/auth/cloud-platform`. A token-acquisition failure returns `502` (`provider_error` / `vertex_auth_failed`).

**Client example.**

```bash
curl -k "https://localhost:8080/v1/projects/my-gcp-project/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent" \
  -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
```

The client does not send any credentials -- the proxy attaches the bearer token.

**Streaming.** Vertex's `:streamGenerateContent` endpoint returns one of two shapes depending on the request:

- With `?alt=sse` -- Vertex emits a true SSE stream (`Content-Type: text/event-stream`). The proxy detects this and passes chunks through to the client as they arrive, without buffering.
- Without `?alt=sse` (default) -- Vertex returns a single `application/json` array containing all generation chunks. The proxy treats this as a regular non-streaming response: the body is buffered, redacted (when outbound scanning is on), and forwarded in one shot. This is correct behavior given the shape Vertex returns; it just is not "streaming" end-to-end.

If you want token-by-token streaming end to end, your client must add `?alt=sse` to the request URL; the proxy forwards query parameters verbatim.

**Audit log.** The model in a Vertex request is identified by the URL (`/models/{model}`), not the request body. The proxy extracts the model from the path and records it in the audit entry's `model` field; `provider` is `vertex`. When the proxy is not configured for Vertex, requests to `/v1/projects/.../models/...:generateContent` return `404` (`not_found` / `vertex_disabled`).

### `routes`

Routes control which **Philter redaction policy and context** are applied to each request. They do not control which LLM provider handles the request - provider routing is determined automatically by the URL path (see [API Reference](api.md) for path-to-provider mapping).

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

**Example - block responses containing PII for HIPAA routes:**

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

## Rate Limiting

Rate limiting is **disabled by default**. When enabled, the proxy enforces per-client request rate limits using the token bucket algorithm. The client identifier is the **API key** (when auth is enabled) or the **client IP address** (when auth is disabled).

### Configuration

```yaml
rateLimit:
  enabled: true
  requestsPerSecond: 10.0   # per-client sustained rate
  burst: 20                 # maximum burst size above the sustained rate
  global:                   # optional: hard cap across all clients combined
    requestsPerSecond: 100.0
    burst: 200
```

Per-key overrides are configured on the API key entry:

```yaml
auth:
  apiKeys:
    - key: standard-team-key
    - key: high-volume-service-key
      rateLimit:
        requestsPerSecond: 50.0   # this key gets a higher limit
        burst: 100
```

### `rateLimit` reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable rate limiting. When false all other fields are ignored. |
| `requestsPerSecond` | float | - (required when enabled) | Sustained per-client request rate (requests per second) |
| `burst` | int | - (required when enabled) | Maximum number of requests a client may send in a burst above the sustained rate. Must be ≥ 1. |
| `global.requestsPerSecond` | float | `0` (disabled) | Global sustained rate across all clients combined. `0` disables the global backstop. |
| `global.burst` | int | `0` (disabled) | Global burst size. Must be set alongside `global.requestsPerSecond` to enable the global limit. |
| `backend` | object | `memory` | Where token-bucket state lives. Use `redis` to share state across replicas. See [Shared state for multi-replica deployments](#shared-state-for-multi-replica-deployments). |

Per-key rate limit overrides (`auth.apiKeys[].rateLimit`) accept the same `requestsPerSecond` and `burst` fields and take precedence over the global defaults for that key.

### Shared state for multi-replica deployments

By default, token-bucket state lives in process memory (`backend.type: memory`). This is correct for a single replica, but **running N replicas behind a load balancer multiplies the effective limit by N** — each replica counts only the requests it sees. To enforce one consistent limit across all replicas, point the limiter at a shared Redis backend:

```yaml
rateLimit:
  enabled: true
  requestsPerSecond: 100.0
  burst: 200
  backend:
    type: redis              # default: memory
    failureMode: open        # "open" (default) or "closed" — see below
    redis:
      address: redis.internal:6379
      username: philter       # optional (Redis 6+ ACL)
      password: ${REDIS_PASSWORD}   # supports ${ENV_VAR} / file: references
      db: 0
      keyPrefix: "philter:rl:"      # optional namespace
      timeoutMs: 100                # per-call timeout
      tls:
        enabled: true
        caCert: /etc/ssl/redis-ca.pem        # optional custom CA
        cert: /etc/ssl/redis-client.pem      # optional client cert (mTLS)
        key: /etc/ssl/redis-client-key.pem
        # insecureSkipVerify: true           # development only
```

The Redis backend implements an **atomic token bucket** in a server-side Lua script (a single round-trip per decision) and uses the Redis server clock, so replicas with skewed clocks still agree. The same per-client and global buckets described above apply — they are simply stored in Redis instead of process memory.

**Failure mode when Redis is unreachable** (`backend.failureMode`):

| Mode | Behaviour when the backend errors or times out |
|------|------------------------------------------------|
| `open` (default) | **Fail open** — degrade to the local in-memory limiter so traffic keeps flowing, still bounded per-replica. Availability is preserved at the cost of temporarily enforcing per-replica rather than global limits. |
| `closed` | **Fail closed** — reject requests with `429` while the backend is down. Choose this when exceeding the limit is worse than dropping traffic. |

The local-memory limiter is always retained and is used as the fail-open fallback, so a Redis outage never takes the proxy down.

**Backend health is observable** via Prometheus metrics: `philter_proxy_ratelimit_backend_duration_seconds` (call latency, labeled by backend and `ok`/`error` result), `philter_proxy_ratelimit_backend_errors_total` (backend error count), and `philter_proxy_ratelimit_fallback_total` (decisions that fell back to local memory). See [Monitoring](monitoring.md).

#### `rateLimit.backend` reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | `memory` | `memory` (per-replica, in-process) or `redis` (shared across replicas). |
| `failureMode` | string | `open` | Behaviour when the redis backend is unreachable: `open` (fall back to local memory) or `closed` (reject). |
| `redis.address` | string | - (required for redis) | Redis endpoint, `host:port`. |
| `redis.username` | string | (none) | Redis ACL username (Redis 6+). |
| `redis.password` | string | (none) | Redis password. Accepts `${ENV_VAR}` / `file:` [secret references](#loading-secrets-from-environment-variables-and-files). |
| `redis.db` | int | `0` | Logical database number. |
| `redis.keyPrefix` | string | `philter:rl:` | Namespace prefix for the proxy's keys. |
| `redis.timeoutMs` | int | `100` | Per-call Redis timeout in milliseconds. On timeout the failure mode applies. |
| `redis.tls.enabled` | bool | `false` | Connect to Redis over TLS. |
| `redis.tls.caCert` | string | (system roots) | PEM CA bundle for verifying the Redis server certificate. |
| `redis.tls.cert` / `redis.tls.key` | string | (none) | Client certificate + key for mutual TLS to Redis. Both required together. |
| `redis.tls.insecureSkipVerify` | bool | `false` | Skip server certificate verification (development only). |

### Behaviour when the limit is exceeded

When a client exceeds its limit the proxy returns `HTTP 429 Too Many Requests` with:

- `Content-Type: application/json`
- `Retry-After: <seconds>` header indicating when the client may retry
- JSON body: `{"error":{"message":"rate limit exceeded","type":"rate_limit_error"}}`

A structured warning is logged with the client identifier:

```json
{"time":"...","level":"WARN","msg":"Rate limit exceeded","client":"api-key-or-ip"}
```

### Client identification

| Auth state | Client ID used |
|-----------|----------------|
| Auth enabled, valid key | The API key value |
| Auth disabled | Client IP address (supports `X-Forwarded-For`) |

The global backstop, when configured, is checked before the per-client limit and applies regardless of which client is making the request.

## Authentication

Authentication is **disabled by default**. The proxy accepts requests from any client with no credentials required. This is appropriate for simple deployments where network-level controls (firewall, VPC, service mesh) are sufficient. Enable authentication for environments where multiple teams or services share a proxy instance, or where access needs to be scoped per client.

### API Key Authentication

Configure a list of API keys in the `auth` section. Each key can optionally be bound to a specific Philter policy.

```yaml
auth:
  header: x-philter-proxy-key   # optional - this is the default
  apiKeys:
    - key: secret-key-for-team-a
    - key: secret-key-for-healthcare
      policy: hipaa-safe-harbor   # this key always uses the HIPAA policy
```

Clients include the key in the configured request header:

```bash
curl -k https://localhost:8080/v1/chat/completions \
  -H "x-philter-proxy-key: secret-key-for-team-a" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}'
```

**Behaviour:**

| Scenario | Result |
|----------|--------|
| Valid key, no policy binding | Request proceeds; policy resolved by route matching as normal |
| Valid key with policy binding | Request proceeds; the key's policy overrides the matched route policy |
| Missing header | `401 Unauthorized` with JSON error body |
| Invalid key value | `401 Unauthorized` with JSON error body |
| No keys configured | All requests pass (auth disabled) |

**The proxy's auth header is always stripped before forwarding.** The LLM provider never sees `x-philter-proxy-key`. The provider's own credentials (`Authorization: Bearer ...`, `x-api-key`, etc.) pass through unchanged.

#### `auth` reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `header` | string | `x-philter-proxy-key` | Request header the proxy reads the API key from |
| `apiKeys` | list | (none - auth disabled) | List of valid API keys |

#### `auth.apiKeys[]` entry

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `key` | string | Yes | The API key value. Accepts plaintext, a pre-hashed value (see [Hashing](#api-key-hashing)), or a `${ENV_VAR}` / `file:` secret reference (see [Loading secrets from environment variables and files](#loading-secrets-from-environment-variables-and-files)). |
| `id` | string | No | **Strongly recommended.** Stable opaque identifier used as the rate-limit / concurrency / quota / cache-tenant / audit-log `key_id`. Falls back to the legacy positional `key-N` when unset, which is fragile across `apiKeys` reorders. See [Per-key Stable Identifiers](#per-key-stable-identifiers). |
| `policy` | string | No | Philter policy to enforce for all requests authenticated with this key. Overrides route and default policy. |
| `rateLimit` | object | No | Per-key rate-limit override. See [Rate Limiting](#rate-limiting). |
| `maxConcurrent` | int | No | Per-key in-flight concurrency cap (0 = unlimited). Applied in addition to the global `listen.maxConcurrentRequests` cap. See [Concurrency Limits](#concurrency-limits). |
| `quota` | object | No | Per-key token-quota override (daily/monthly). See [Token Quotas](#token-quotas). |
| `scopes` | object | No | Per-key allow-lists for providers, models, and request paths. Empty / unset means full access (backwards compatible). See [Per-key Authorization](#per-key-authorization-scopes). |
| `adminRole` | string | No | Optional scoped admin role for this key. Currently the only value is `usage-read`, which lets this key call `GET /admin/usage` without the full admin token. Empty (default) means no admin access. See [Admin Roles](#admin-roles). |

#### Per-key Authorization (scopes)

By default, a configured API key may call **any** provider, model, and request path the proxy supports. Multi-tenant deployments often want to constrain individual keys: a tenant's key should only call the providers / models / endpoints that tenant is paying for, and nothing else.

`auth.apiKeys[].scopes` declares per-key allow-lists. **Empty or unset is full access** (the existing behavior); a non-empty list on any axis is deny-by-default for that axis.

```yaml
auth:
  apiKeys:
    - key: team-a-key
      scopes:
        providers: [openai, anthropic]   # team A can use OpenAI and Anthropic
        models: ["gpt-4*", "claude-3*"]  # only these model families
        paths: ["/v1/"]                  # everything under /v1/, nothing else
    - key: team-b-key
      scopes:
        providers: [bedrock]             # team B is Bedrock-only
        # models / paths empty -> any model / path on bedrock
    - key: legacy-key
      # no scopes block at all -> unrestricted (backwards compat)
```

| Field | Type | Default | Matching |
|---|---|---|---|
| `providers` | string list | empty (allow all) | Exact match against the resolved provider name: `openai`, `anthropic`, `gemini`, `ollama`, `azure`, `bedrock`, `vertex`, or a configured `openaiCompatible[].name`. A trailing `*` on an entry makes it a prefix match. |
| `models` | string list | empty (allow all) | Exact match against the request's `model` field, or trailing-`*` glob (e.g. `gpt-4*`). When set, requests with no model field are denied. |
| `paths` | string list | empty (allow all) | Prefix match against the request path **after** any `openaiCompatible[]` provider prefix has been stripped. |

A request must satisfy **every** non-empty axis (logical AND across axes; logical OR within each axis). Denied requests receive `HTTP 403` with one of:

| `error.type` | `error.code` | When |
|---|---|---|
| `forbidden` | `scope_denied_provider` | Resolved provider not in the key's `providers` allow-list. |
| `forbidden` | `scope_denied_model` | Request `model` not in the key's `models` allow-list (or no `model` set when the allow-list is configured). |
| `forbidden` | `scope_denied_path` | Request path not in any of the key's `paths` prefix entries. |

The denial is mirrored in the audit log: the `key_id`, `provider`, `model`, `error_type`, and `error_code` fields all appear on the inbound audit entry with `http_status: 403`, so a denied call is fully traceable by `request_id` without ever exposing the raw key. See [Error Responses](#error-responses) for the full client-error contract.

#### Admin Roles

The `GET /admin/usage` endpoint is gated by either:

1. **The full admin token** (`admin.token`), sent in the configured admin header (default `x-philter-admin-token`). This is the existing all-or-nothing credential and remains unchanged.
2. **An API key with `adminRole: usage-read`**, sent in the regular auth header (default `x-philter-proxy-key`). This is a scoped read-only role for billing or reporting clients that should be able to read usage but not act as a full admin or make LLM calls outside their own scopes.

```yaml
admin:
  enabled: true
  token: ${ADMIN_TOKEN}

auth:
  apiKeys:
    - key: ${BILLING_READER_KEY}
      adminRole: usage-read   # this key can read /admin/usage, nothing else admin-y
```

`adminRole` is independent of `scopes`: the role grants admin-API access only, while `scopes` restricts the proxy's normal LLM-call surface. A successful admin export logs `auth_mode=admin_token` or `auth_mode=api_key_usage_read` plus the opaque `key_id` for the latter, so operators can distinguish the two paths in audit trails.

#### API Key Hashing

API keys are **hashed at load** and never stored in memory as plaintext. The in-memory `keyStore` holds only hashes; verification uses constant-time comparison. This protects against accidental disclosure via heap dumps, debug prints, or core files.

Three input formats are accepted in the `key:` field:

| Format | Example | When to use |
|---|---|---|
| Plaintext | `key: SuperSecretAPIKey123` | Quickstart. The proxy hashes the value with SHA256 at load. The plaintext is in your YAML file, so keep the file out of source control. |
| `sha256$<64-hex>` | `key: sha256$e3b0c44...` | Production. Pre-hash externally, put the hash in YAML. The plaintext never sits in version control or the running config. |
| `bcrypt$<bcrypt-hash>` | `key: bcrypt$$2a$10$N9qo8...` | For users with existing bcrypt-based key management or compliance requirements. Slower (see latency table). |

**Why SHA256 by default.** API keys are typically high-entropy random tokens (32+ random bytes). The threat model for hashing-at-rest is "an attacker who reaches a memory dump should not be able to recover live credentials." Brute-forcing 256 bits of entropy is infeasible, so a fast hash with constant-time comparison provides adequate protection. The slow-hash family (bcrypt, argon2id) is designed for low-entropy human passwords; for random API keys it adds latency without commensurate security gain.

**Generating pre-hashed values.** For SHA256:

```bash
printf '%s' 'SuperSecretAPIKey123' | sha256sum | awk '{print "sha256$" $1}'
# sha256$2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
```

For bcrypt (using Python; any bcrypt CLI works):

```bash
python3 -c "import bcrypt; print('bcrypt$' + bcrypt.hashpw(b'SuperSecretAPIKey123', bcrypt.gensalt(10)).decode())"
# bcrypt$$2b$10$Hkpz7C0vQp...
```

**Per-request latency.** Approximate cost of one auth check on a modern x86 server. The proxy iterates all configured keys and verifies the supplied key against each; total latency scales with the number of configured entries.

| Format | Per-entry cost | 10 entries | Notes |
|---|---:|---:|---|
| `sha256` | ~1-2 µs | ~20 µs | Recommended default. Negligible for any realistic QPS. |
| `bcrypt` cost=4 | ~1-2 ms | ~10-20 ms | bcrypt minimum cost; faster than the default but still meaningful. |
| `bcrypt` cost=10 | ~60-100 ms | ~600 ms-1 s | bcrypt default cost. **Avoid at high QPS** - this will dominate your request latency. |
| `bcrypt` cost=12 | ~250-400 ms | several seconds | bcrypt's "recommended" password cost. Not appropriate for API keys. |

**Recommendations:**

- Default (SHA256): no tuning needed.
- bcrypt: pick the lowest cost your compliance requirements allow. cost=4 is appropriate for high-throughput API key use.

**Per-key features (rate-limit, concurrency).** The proxy assigns each `auth.apiKeys[]` entry an opaque stable identifier. Per-key rate-limit, per-key concurrency, the response-cache tenant prefix, the usage store, and audit-log `key_id` are all keyed by this identifier, so the raw API key never has to reach those subsystems. See [Per-key Stable Identifiers](#per-key-stable-identifiers) for the explicit `id:` field (strongly recommended) and the legacy positional fallback (`key-0`, `key-1`, ...).

#### Per-key Stable Identifiers

Each `auth.apiKeys[]` entry can declare an explicit `id:` field, which is used as its stable opaque identifier wherever the proxy needs one (rate-limit bucket, concurrency bucket, quota counter, cache tenant prefix, audit log `key_id`, usage export row):

```yaml
auth:
  apiKeys:
    - key: ${TEAM_A_KEY}
      id: team-a                 # explicit
    - key: ${TEAM_B_KEY}
      id: team-b
    - key: ${BILLING_READER_KEY}
      id: billing-reader
      adminRole: usage-read
```

When `id:` is omitted the proxy falls back to the legacy positional identifier (`key-0`, `key-1`, ... derived from the entry's position in the list). **Setting `id:` explicitly is strongly recommended** because the positional fallback is fragile: inserting a new entry at the top of the list, removing a middle entry, or even reordering for readability re-shuffles which key owns which historical state. With a response cache enabled, that re-shuffle is a real cross-tenant data leak -- the new `key-0` would inherit the old `key-0`'s cached responses.

Validation:

- Each explicit `id:` must be unique across `auth.apiKeys`.
- Explicit `id:` values must not start with the reserved prefix `key-` (which would collide with the legacy positional scheme).

Migrating from positional IDs: add `id:` to each entry, choosing a stable label (`team-a`, `billing-reader`, etc.). The transition is opt-in -- entries without `id:` continue to receive their positional identifier so existing rate-limit / quota / cache state is not invalidated mid-flight.

#### Loading secrets from environment variables and files

Storing API keys as plaintext in `config.yaml` means they end up in version control or baked into container images. To keep secrets out of the config file, the `key:` field accepts two reference syntaxes in addition to literal values:

| Syntax | Example | Resolves to |
|---|---|---|
| `${ENV_VAR}` | `key: ${TEAM_A_KEY}` | The value of the `TEAM_A_KEY` environment variable |
| `file:<path>` | `key: file:/run/secrets/team-a` | The contents of `/run/secrets/team-a` (trailing whitespace/newline trimmed) |
| literal | `key: secret-key-for-team-a` | Used verbatim (backwards-compatible) |

```yaml
auth:
  apiKeys:
    - key: ${TEAM_A_KEY}                  # from environment variable
    - key: file:/run/secrets/healthcare   # from a mounted file
      policy: hipaa-safe-harbor
    - key: secret-key-legacy              # plaintext literal still works
```

References are resolved **once, at config load**, before validation and hashing. The resolved value then flows through the same [hashing](#api-key-hashing) path as a literal — so a plaintext secret loaded from a file or env var is still SHA256-hashed in memory and never retained as plaintext beyond load.

This is the recommended way to integrate with external secret stores:

- **Kubernetes / Docker secrets** — mount the secret as a file and reference it with `file:/run/secrets/...`.
- **HashiCorp Vault, AWS Secrets Manager, etc.** — have your init container or entrypoint export the secret into an environment variable (e.g. `vault read`, `aws secretsmanager get-secret-value`) and reference it with `${VAR}`.

**Error handling.** If a referenced environment variable is unset or empty, or a referenced file is missing or empty, the proxy fails to start with a clear error that names the variable or path. **Validation and resolution errors never echo the secret value itself** — only the reference (env var name or file path), which is not sensitive.

This syntax is implemented by a generic resolver (`resolveSecret`) and is intended to apply to any future secret-bearing config field (such as provider auth headers), not just `auth.apiKeys[].key`.

#### Rotating API keys

Because secrets are resolved at config load, rotation follows the lifecycle of the underlying env var / file plus a config reload:

1. **Issue the new key** in your secret store (Vault, Secrets Manager, Kubernetes Secret, etc.).
2. **Add it alongside the old one** as a second `auth.apiKeys[]` entry so both are valid during the cutover window (zero-downtime). For example, mount the new secret at `file:/run/secrets/team-a-next` and add a second entry referencing it.
3. **Reload the proxy** so it re-resolves the references and picks up the new value:
     - The proxy currently re-reads its config (and therefore re-resolves `${ENV_VAR}` / `file:` references) **on process restart**. In Kubernetes, trigger a rolling restart (`kubectl rollout restart deployment/philter-ai-proxy`) — updated Secret/env values are picked up by the new pods with no dropped connections.
     - *(Planned: in-place reload on `SIGHUP` so a running process can re-resolve secrets without a restart. Until that ships, use a rolling restart.)*
4. **Migrate clients** to the new key.
5. **Remove the old entry** and revoke the old secret in your store, then reload again.

Because the value lives in the secret store rather than the YAML, rotation does not require editing and re-committing `config.yaml`.

### mTLS (Mutual TLS)

For service-to-service authentication in zero-trust environments, the proxy can require clients to present a valid TLS certificate signed by a configured CA. Set `listen.clientCA` to the path of the PEM-encoded CA certificate:

```yaml
listen:
  port: 8080
  cert: cert.pem
  key: key.pem
  clientCA: /etc/ssl/client-ca.pem
```

When `clientCA` is set, the proxy configures `RequireAndVerifyClientCert` on its TLS listener. Any connection without a valid client certificate is rejected at the TLS handshake level, before any HTTP processing occurs.

**mTLS and API key authentication are orthogonal** - either or both can be enabled simultaneously. A typical defence-in-depth configuration uses mTLS to authenticate the connection and API keys to scope policy access per team.

**Generating a test client certificate:**

```bash
# CA key and cert (one-time setup)
openssl req -newkey rsa:4096 -keyout ca.key -x509 -days 3650 -out ca.crt -subj "/CN=My Proxy CA"

# Client key and CSR
openssl req -newkey rsa:2048 -keyout client.key -out client.csr -subj "/CN=my-service"

# Sign the client cert with the CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

Set `listen.clientCA: ca.crt` in the proxy config, then pass `--cert client.crt --key client.key` to curl (or configure the equivalent in your HTTP client).

## Audit Logging

Every proxy request produces a structured JSON log entry (JSONL) to stdout. All output from the proxy - audit entries, startup, shutdown, and errors - is structured JSON, making it safe to pipe directly into log aggregators.

### Log Schema

| Field | Type | Description |
|-------|------|-------------|
| `time` | string | ISO 8601 timestamp |
| `request_id` | string | Unique ID for request correlation |
| `direction` | string | Scan direction: `inbound` (request) or `outbound` (response, when outbound scanning is enabled) |
| `provider` | string | LLM provider (`openai`, `anthropic`, `gemini`, `ollama`, `azure`, `bedrock`, `vertex`, or an `openaiCompatible[].name`) |
| `model` | string | Model name from the request body |
| `policy_name` | string | Philter policy used for redaction |
| `document_id` | string | Philter document ID (correlates with Philter's own logs) |
| `fields_redacted` | int | Number of text fields sent through Philter |
| `entity_count` | int | Total number of entities detected and redacted |
| `entity_types` | string[] | Distinct entity types detected (e.g., `["NER_ENTITY", "SSN"]`) |
| `redact_latency_ms` | int | Total time spent on Philter redaction calls (milliseconds) |
| `client_ip` | string | Client IP address (supports `X-Forwarded-For`) |
| `key_id` | string | Opaque stable identifier (`key-N`) of the authenticated API key, or empty when no key was authenticated. Never the raw key. Use this to correlate per-key authorization decisions (including [scope denials](#per-key-authorization-scopes)) end-to-end. |
| `http_status` | int | HTTP status code of the upstream provider response |
| `prompt_tokens` | int | Prompt (input) token count reported by the provider. Omitted for streaming responses and when the provider does not return usage data. |
| `completion_tokens` | int | Completion (output) token count reported by the provider. Omitted under the same conditions as `prompt_tokens`. |
| `error_type` | string | The `error.type` value the client received. Empty on 2xx responses. See [Error Responses](#error-responses). |
| `error_code` | string | The `error.code` value the client received. Empty on 2xx responses. See [Error Responses](#error-responses). |
| `trace_id` | string | W3C trace ID, when OpenTelemetry tracing is enabled and the request was sampled. Use it to cross-reference audit log entries with traces in your APM. See [Distributed Tracing](monitoring.md#distributed-tracing). |

### Example Log Entries

When outbound scanning is disabled (default), one entry is emitted per request:

```json
{"time":"2026-01-15T10:30:00Z","level":"INFO","msg":"request","request_id":"a1b2c3d4","direction":"inbound","provider":"openai","model":"gpt-4","policy_name":"default","document_id":"doc-789","fields_redacted":2,"entity_count":3,"entity_types":["NER_ENTITY","SSN"],"redact_latency_ms":45,"client_ip":"10.0.0.1","http_status":200,"prompt_tokens":312,"completion_tokens":87}
```

When outbound scanning is enabled, two entries are emitted per request - one for the inbound scan and one for the outbound scan. Both share the same `request_id` and `document_id` for correlation. Token counts appear on the inbound entry only:

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

## Provider Timeouts

Every outbound HTTP client the proxy creates (Philter, the four built-in LLM providers, every `openaiCompatible` entry, and Bedrock) honors a configurable set of transport-level timeouts. They protect the proxy from a hung upstream (stalled LLM, dropped TCP, slow-loris attack) by bounding the network phases of each call without breaking streaming responses.

```yaml
providers:
  openai:
    target: https://api.openai.com
    timeouts:
      connectMs: 5000          # TCP dial
      tlsHandshakeMs: 5000     # TLS handshake
      responseHeaderMs: 30000  # wait for upstream to start responding
      idleConnMs: 90000        # keep-alive idle eviction
```

The same `timeouts:` block is accepted under `philter:`, `providers.bedrock:`, and each `providers.openaiCompatible.*` entry.

### Fields and defaults

| Field | Default | What it bounds |
|---|---:|---|
| `connectMs` | 5000 | TCP dial (`net.Dialer.Timeout`) |
| `tlsHandshakeMs` | 5000 | TLS handshake (`http.Transport.TLSHandshakeTimeout`) |
| `responseHeaderMs` | 30000 | Wait for response headers (`http.Transport.ResponseHeaderTimeout`). This is the timeout that catches a hung LLM that never starts responding. |
| `idleConnMs` | 90000 | Idle keep-alive eviction (`http.Transport.IdleConnTimeout`) |

A value of `0` or an omitted field uses the default. All values are milliseconds.

### Streaming and timeouts

The proxy deliberately does **not** set an overall request deadline (`http.Client.Timeout`). All four timeouts above are *transport-phase* timeouts — once the upstream has sent response headers, the body can stream for as long as the upstream keeps producing data. This means:

- A hung LLM that accepts the connection but never starts streaming is killed by `responseHeaderMs` (default 30s).
- A long-running streaming completion that takes 5 minutes to finish writing the body is **not** killed by any timeout, and that is the intended behavior.

If you need a hard ceiling on streaming wall-clock time you must enforce it at the client, with an ingress-level connection timeout, or by adding cancellation logic to your application.

### When to tune

- **Faster `responseHeaderMs` for an in-cluster Philter.** The 30s default fits LLM round-trips; a same-cluster Philter typically responds in single-digit milliseconds, and a 1-2s `responseHeaderMs` will surface backend issues much faster.
- **Slower `responseHeaderMs` for slow models or reasoning APIs.** Some chain-of-thought / o1-style endpoints take 60+ seconds before the first token. Raise the default if you see spurious 502s on otherwise-healthy traffic.
- **Tighter `connectMs` for in-cluster providers.** Local services should connect in milliseconds; a tighter dial timeout helps shed traffic to dead pods faster than the default 5s.

## Concurrency Limits

The proxy can cap the number of requests it processes at any one time. When the cap is reached the proxy returns `503 Service Unavailable` with `Retry-After: 1` instead of queuing the request or running out of resources. Concurrency limits are **disabled by default** for backwards compatibility.

```yaml
listen:
  maxConcurrentRequests: 200   # global in-flight cap; 0 (default) = unlimited

auth:
  apiKeys:
    - key: noisy-tenant
      maxConcurrent: 20        # per-key in-flight cap; applied in addition to the global cap
```

The global and per-key caps **compose** - a request must acquire both. The per-key cap protects the shared pool from a single noisy tenant; the global cap protects the proxy as a whole.

!!! warning "Pair concurrency caps with `listen.readTimeoutMs` for hostile clients"
    The proxy acquires its concurrency slot *before* reading the request body, so a slow-body uploader holds the slot for the duration of its upload. With `listen.readTimeoutMs` disabled (the documented default for large/slow legitimate uploads), a single authenticated key whose value has been compromised can dribble bodies indefinitely and hold `maxConcurrent` slots; with multiple compromised keys the attacker can hold `keys × maxConcurrent` slots. When you configure `maxConcurrent` to defend against this class of abuse, also set `listen.readTimeoutMs` to a value that bounds reasonable upload time (e.g. 60000 for 60s). See [Request Hardening](#request-hardening).

### Behaviour when the limit is exceeded

When either cap is reached, the proxy returns:

- HTTP status `503 Service Unavailable`
- Headers: `Retry-After: 1`, `Content-Type: application/json`
- JSON body: `{"error":{"message":"concurrency limit exceeded","type":"capacity"}}`

The `Retry-After` value is fixed at 1 second because, unlike rate limits, there is no deterministic time at which a concurrency slot will free up.

A structured warning is logged with the scope (`global` or `per_key`) and the client identifier:

```json
{"time":"...","level":"WARN","msg":"Concurrency limit exceeded","scope":"per_key","client":"noisy-tenant"}
```

### Choosing a value

A defensible starting point:

```
maxConcurrentRequests = 2 × (target_rps × p95_provider_response_seconds)
```

The `2×` is headroom for tail latency and short bursts. Cross-check against:

- **Your LLM provider's concurrent-request quota.** Set the proxy cap no higher than what your account can actually serve - otherwise you push work into the provider's queue and lose the back-pressure signal here.
- **File descriptors.** Each in-flight request needs ~3 sockets (client + Philter + provider). Default `ulimit -n` of 1024 is exhausted around ~330 concurrent. Raise it before raising the cap.
- **Memory.** Each in-flight request holds one goroutine plus buffered request/response bodies (rough estimate: 50–200 KB per request). 1,000 concurrent ≈ 50–200 MB of proxy state.

See the [Monitoring](monitoring.md#concurrency) page for the metrics to watch and a PromQL recipe for computing utilization.

## Request Hardening

The proxy is network-facing, so it bounds the **size and duration of inbound client requests** in addition to the [concurrency](#concurrency-limits) (count) and [provider timeout](#provider-timeouts) (outbound) limits. These are configured under `listen` and applied with secure defaults when unset:

```yaml
listen:
  maxRequestBodyBytes: 10485760   # 10 MiB; larger bodies → HTTP 413
  maxHeaderBytes: 1048576         # 1 MiB
  readHeaderTimeoutMs: 10000      # 10s to send headers (slowloris mitigation)
  readTimeoutMs: 0                # 0 = disabled; whole-request (incl. body) read bound
  tlsHandshakeTimeoutMs: 10000    # 10s to complete the TLS handshake
  maxConcurrentTLSHandshakes: 16384  # ceiling on simultaneous in-flight handshakes
```

| Protection | Field | Default | Behaviour |
|---|---|---|---|
| **Body size** | `maxRequestBodyBytes` | 10 MiB | The body is wrapped in a hard limit; exceeding it returns `413 Too Large` (`payload_too_large` / `request_body_too_large`) and the connection is closed. Raise it if you send large multimodal (base64 image) requests. |
| **Header size** | `maxHeaderBytes` | 1 MiB | Caps total request header bytes (matches net/http's default). |
| **Slowloris (headers)** | `readHeaderTimeoutMs` | 10s | Bounds how long a client may take to send the request headers; a client that dribbles headers to hold the connection open is dropped. |
| **Slow body** | `readTimeoutMs` | disabled | Bounds reading the whole request (headers + body). Opt-in, because a too-low value would truncate large or slow legitimate uploads. It affects only request reads. |
| **Slowloris (handshake)** | `tlsHandshakeTimeoutMs` | 10s | Bounds how long a client may take to complete the TLS handshake. `readHeaderTimeoutMs` only starts ticking **after** the handshake completes, so a client that opens a TLS connection and then dribbles the handshake (or never finishes it) would otherwise tie up the connection indefinitely. Each accepted connection is gated by this deadline on its own goroutine, so one slow client cannot stall accepts of other clients. Once the handshake succeeds the deadline is cleared, so post-handshake reads and response streaming are unaffected. |
| **Handshake flood** | `maxConcurrentTLSHandshakes` | 16384 | Ceiling on the number of TLS handshakes in flight at once. `tlsHandshakeTimeoutMs` bounds the *duration* of each handshake but not how *many* run concurrently: under a TCP+ClientHello flood, every accepted connection would otherwise spawn a goroutine pinned for the full handshake timeout. When the ceiling is reached, new connections are dropped immediately (not queued) and counted by `philter_proxy_tls_handshakes_shed_total`. The slot is released the instant a handshake resolves — before the connection is handed to net/http — so this gates only the handshake phase and never throttles established connections. The default is far above any real workload; lower it only if you want a tighter bound on peak handshake memory. |

**Streaming is unaffected.** The proxy deliberately does **not** set a write timeout, so streamed responses can run arbitrarily long. `readTimeoutMs` bounds only the inbound request, never the response. The same header limits and timeouts are applied to the metrics server; the handshake timeout applies only to the TLS-terminating listener.

### Trusted Proxies / X-Forwarded-For

The proxy uses the apparent client IP for **per-IP rate limiting** (when authentication is disabled), for the **audit log's `client_ip` field**, and for operator-facing log lines such as the admin-endpoint access record.

By default, `r.RemoteAddr` -- the immediate TCP peer -- is used, and `X-Forwarded-For` is ignored. This is the safe behavior when the proxy is exposed directly to clients: any attacker could otherwise set XFF to a value of their choosing, evading per-IP rate limits and corrupting audit-log IPs.

When the proxy runs behind a trusted upstream (ALB, NLB, Nginx, Cloudflare, an Istio sidecar, etc.), `listen.trustedProxies` must list the CIDR ranges those upstreams connect from, so the proxy can recognize them and honor the XFF they set:

```yaml
listen:
  trustedProxies:
    - 10.0.0.0/8         # internal LB subnet
    - 172.16.0.0/12      # peered VPC
    - 192.168.1.0/24
```

Behavior:

- If `r.RemoteAddr`'s IP falls inside any configured CIDR, the **left-most** non-empty `X-Forwarded-For` entry is taken as the client IP.
- If the peer is not in any CIDR (or no CIDRs are configured at all), XFF is silently ignored and `r.RemoteAddr` is used.
- Each CIDR is validated at startup; a malformed entry fails the config.

This is a **behavioral change vs earlier releases**, which trusted XFF unconditionally. Deployments that legitimately relied on XFF (those running behind a real LB) need to add the LB's source CIDR(s) to restore the previous behavior.

These limits apply per request and are independent of the concurrency guard: concurrency bounds *how many* requests run at once, while these bound *how big* and *how slow* any single request may be.

## Token Quotas

Token quotas cap **cumulative token consumption** per API key over a calendar window, distinct from [rate limits](#rate-limiting) (which bound request *frequency*). Use them for hard cost ceilings and multi-tenant budgets. Quotas are **disabled by default**.

```yaml
quota:
  enabled: true
  default:                  # applies to keys without their own quota
    dailyTokens: 1000000    # 0 = unlimited
    monthlyTokens: 20000000
  backend:
    type: memory            # or "redis" to share counters across replicas
    # redis:
    #   address: redis.internal:6379
    #   password: ${REDIS_PASSWORD}

auth:
  apiKeys:
    - key: ${TEAM_A_KEY}
      quota:                # per-key override (takes precedence over default)
        dailyTokens: 50000
        monthlyTokens: 1000000
```

**How it works.** Each request's `prompt + completion` tokens (the same counts in the audit log and Prometheus token metrics) accrue against the key's current UTC **day** and **month** windows. A request is checked *before* it is forwarded: if the key has already reached either limit, the proxy returns `429 Too Many Requests` with a `Retry-After` header pointing at the **window reset** (next UTC midnight for daily, first of next UTC month for monthly — the longer window wins when both are exceeded). Windows reset automatically; there is no manual reset.

The error body uses type `quota_exceeded` with code `daily_quota_exceeded` or `monthly_quota_exceeded`.

**Notes.**

- Quotas apply only to authenticated keys (there is no key to bill otherwise).
- A request that has *started* is never interrupted mid-flight; the next request after a window is exhausted is the one rejected. Token counts are only known after the response, so a single request may push a key slightly past its limit before the next one is blocked.
- Cache hits (see below) still consume quota only if they reach the provider; a served cache hit consumes no new tokens.
- With `backend.type: memory`, counters are per-replica — use `redis` for a consistent quota across a multi-replica deployment. On a Redis error the check **fails open** (allows the request) so an infrastructure blip never hard-blocks traffic.

### `quota` reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable token quotas. |
| `default.dailyTokens` | int | `0` | Per-key daily token cap applied to keys without their own quota. `0` = unlimited. |
| `default.monthlyTokens` | int | `0` | Per-key monthly token cap. `0` = unlimited. |
| `backend.type` | string | `memory` | `memory` (per-replica) or `redis` (shared). Also stores usage for the [admin export](#usage-export-admin-api). |
| `backend.redis.*` | — | — | Same Redis fields as the [rate-limit backend](#shared-state-for-multi-replica-deployments) (address, password, db, keyPrefix, timeoutMs, tls). |

Per-key overrides live on `auth.apiKeys[].quota.{dailyTokens,monthlyTokens}`.

## Response Cache

The optional response cache returns a stored response for repeated prompts, skipping both Philter and the LLM provider to cut cost and latency. It is **disabled by default**.

```yaml
cache:
  enabled: true
  ttlSeconds: 300       # entry lifetime; default 300
  maxEntries: 1024      # in-memory cap (memory backend only); default 1024
  maxBodyBytes: 1048576 # responses larger than this are not cached; default 1 MiB
  backend:
    type: memory        # or "redis" to share the cache across replicas
    # redis:
    #   address: redis.internal:6379
```

**Cache key.** Entries are keyed on `(API key, model, sha256(request body))`. Because the tenant key is part of the key, **one tenant can never read another tenant's cached response**, and a different model or any change to the request body is a different entry. When auth is disabled, all clients share an `anon` namespace.

**What is cached.** Only **non-streaming** (`"stream": true` is excluded, as are Gemini `streamGenerateContent` and Bedrock `converse-stream` paths), **`POST`**, **2xx** responses up to `maxBodyBytes`. Larger or streaming responses pass through uncached. Responses carry an `X-Cache: HIT` or `X-Cache: MISS` header so clients and dashboards can see cache behavior. A hit is served without calling Philter or the provider.

**Backends.** `memory` is a per-replica LRU-ish cache bounded by `maxEntries`; `redis` shares entries across replicas (TTL enforced by Redis). A Redis read/write failure is treated as a miss and never fails the request.

### `cache` reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the response cache. |
| `ttlSeconds` | int | `300` | Lifetime of a cached entry. |
| `maxEntries` | int | `1024` | Maximum in-memory entries (memory backend only). |
| `maxBodyBytes` | int | `1048576` | Responses larger than this are not cached. |
| `backend.type` | string | `memory` | `memory` or `redis`. |
| `backend.redis.*` | — | — | Same Redis fields as the [rate-limit backend](#shared-state-for-multi-replica-deployments). |

Cache hit/miss counters are exported as `philter_proxy_cache_hits_total` / `philter_proxy_cache_misses_total`; see [Monitoring](monitoring.md).

## Usage Export (Admin API)

When enabled, `GET /admin/usage` returns per-key token usage for billing and quota inspection. It is **disabled by default** and protected by an admin token.

```yaml
admin:
  enabled: true
  token: ${PHILTER_ADMIN_TOKEN}   # required; accepts ${ENV_VAR} / file: references
  header: x-philter-admin-token   # optional; this is the default
```

Usage is tracked whenever `admin.enabled` **or** `quota.enabled` is set, using `quota.backend` for storage (so the export and quota enforcement read the same counters).

**Request.** Send the admin token in the configured header. JSON is returned by default; `?format=csv` returns CSV.

```bash
curl -k https://localhost:8080/admin/usage \
  -H "x-philter-admin-token: $PHILTER_ADMIN_TOKEN"

curl -k "https://localhost:8080/admin/usage?format=csv" \
  -H "x-philter-admin-token: $PHILTER_ADMIN_TOKEN"
```

**JSON response.** Per key: the current UTC day/month windows with their token sums, and lifetime prompt/completion totals.

```json
{
  "usage": [
    {
      "key_id": "key-0",
      "day": "2026-05-28", "day_tokens": 1500,
      "month": "2026-05", "month_tokens": 42000,
      "total_prompt_tokens": 38000, "total_completion_tokens": 12000
    }
  ]
}
```

Keys are identified by their stable opaque ID (`key-0`, `key-1`, …, by position in `auth.apiKeys`), never the raw key value — the same identifier used in logs and per-key rate-limit/concurrency buckets.

**Behaviour:**

| Scenario | Result |
|----------|--------|
| Valid admin token | `200` with JSON (or CSV) usage |
| Missing/invalid token | `401 Unauthorized` (constant-time comparison) |
| Non-GET method | `405 Method Not Allowed` |
| `admin.enabled: false` | `404 Not Found` |

Every access is logged: a successful export emits an `Admin usage exported` line (with client IP, format, and key count — never the token), and a failed-auth attempt emits an `Admin usage access denied` line.

**Hardening.** The endpoint exposes per-customer billing data, so:

- Use a **high-entropy** admin token (e.g. `openssl rand -hex 32`) supplied via a `${ENV_VAR}` / `file:` reference, not a literal in the YAML.
- The admin path is **not** subject to the request [rate limiter](#rate-limiting), so token guesses are not throttled by the proxy. Rely on the strong token and keep the endpoint behind network controls (firewall/VPC/service mesh) or `listen.clientCA` mTLS where possible. The `Admin usage access denied` log lines give you a brute-force signal to alert on.

### `admin` reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the `GET /admin/usage` endpoint. |
| `token` | string | (required when enabled) | Admin token. Accepts `${ENV_VAR}` / `file:` [secret references](#loading-secrets-from-environment-variables-and-files). |
| `header` | string | `x-philter-admin-token` | Header carrying the admin token. |

## Error Responses

Every error the proxy generates uses the same structured JSON shape and the same set of stable codes. Clients can parse these reliably to drive retry, alerting, and routing.

### Response shape

```json
{
  "error": {
    "message": "human-readable description",
    "type": "broad-category enum",
    "code": "specific-reason enum",
    "request_id": "uuid-or-X-Request-Id-from-caller"
  }
}
```

- `Content-Type: application/json` is set on every error.
- `X-Request-Id` is set on every response (success and error) with the same value as `error.request_id`.
- An inbound `X-Request-Id` request header is honored when present; otherwise a UUID is generated.

### Stable enum

The `(type, code)` set below is part of the proxy's public API. New codes may be added in any release. **Existing codes will not be removed or repurposed across minor versions.**

| Status | `type` | `code` | Trigger | `Retry-After` |
|---|---|---|---|---|
| 400 | `invalid_request` | `bad_json` | Request body is not valid JSON for the matched provider | - |
| 400 | `invalid_request` | `body_read` | Request body could not be read from the client connection | - |
| 400 | `invalid_request` | `path_not_canonical` | Request path contained `.` / `..` segments, redundant slashes, or a trailing slash. Real LLM clients construct canonical paths; the proxy refuses non-canonical paths up front to close a class of path-traversal-based scope bypass. | - |
| 413 | `payload_too_large` | `request_body_too_large` | Request body exceeded `listen.maxRequestBodyBytes` | - |
| 401 | `unauthorized` | `missing_api_key` | Auth enabled and no key in the configured header | - |
| 401 | `unauthorized` | `invalid_api_key` | Auth enabled and the supplied key was not recognised | - |
| 403 | `pii_blocked` | `outbound_blocked` | Outbound scanning is on with `action: block` and PII was found in the provider response | - |
| 403 | `forbidden` | `scope_denied_provider` | Resolved provider is not in the authenticated key's `auth.apiKeys[].scopes.providers` allow-list | - |
| 403 | `forbidden` | `scope_denied_model` | Request `model` is not in the key's `scopes.models` allow-list (or no `model` set when the allow-list is configured) | - |
| 403 | `forbidden` | `scope_denied_path` | Request path is not in any of the key's `scopes.paths` prefix entries | - |
| 404 | `not_found` | `bedrock_disabled` | A Bedrock path was requested but `providers.bedrock.region` is unset | - |
| 404 | `not_found` | `azure_disabled` | An Azure path (`/openai/deployments/...`) was requested but `providers.azure.target` is unset | - |
| 404 | `not_found` | `vertex_disabled` | A Vertex path (`/v1/projects/.../models/...:generateContent`) was requested but `providers.vertex.project` is unset | - |
| 502 | `provider_error` | `vertex_auth_failed` | The proxy could not acquire a Google ADC bearer token for Vertex | - |
| 404 | `not_found` | `admin_disabled` | `/admin/usage` was requested but `admin.enabled` is false | - |
| 401 | `unauthorized` | `invalid_admin_token` | `/admin/usage` requested with a missing or wrong admin token | - |
| 405 | `method_not_allowed` | `method_not_allowed` | `/admin/usage` requested with a non-GET method | - |
| 429 | `rate_limit_error` | `rate_limited` | Rate-limit token bucket exhausted for this client | seconds until refill |
| 429 | `quota_exceeded` | `daily_quota_exceeded` | Per-key daily token quota reached | seconds until next UTC midnight |
| 429 | `quota_exceeded` | `monthly_quota_exceeded` | Per-key monthly token quota reached | seconds until first of next UTC month |
| 500 | `internal_error` | `marshal_failed` | Re-serialising the redacted request body failed (should not occur in normal operation) | - |
| 500 | `internal_error` | `request_creation_failed` | `http.NewRequest` failed when building the upstream call (typically an invalid target URL) | - |
| 500 | `internal_error` | `bedrock_sign_failed` | AWS SigV4 signing failed (credentials cannot be retrieved) | - |
| 500 | `internal_error` | `usage_snapshot_failed` | `/admin/usage` could not read the usage store | - |
| 502 | `provider_error` | `unreachable` | Upstream LLM provider connection failed (DNS, dial, TLS) | - |
| 502 | `provider_error` | `azure_auth_failed` | Entra ID token acquisition failed for an Azure request (`providers.azure.entraID: true`) | - |
| 502 | `provider_error` | `response_read_failed` | Connected to the provider but failed to read the response body | - |
| 502 | `philter_error` | `request_failed` | Philter call failed (network or non-2xx response) and retries were exhausted | - |
| 503 | `capacity` | `concurrency_exceeded` | `listen.maxConcurrentRequests` or a per-key cap was hit | `1` |
| 503 | `circuit_open` | `philter_unavailable` | Philter circuit breaker is open with `fallback: block` | - |

**Errors forwarded from upstream LLM providers** are passed through unchanged and follow the provider's own error format, not the schema above. The codes here apply only to errors the proxy itself generates.

### Audit correlation

Every error response is mirrored in the audit log: the same `request_id`, `error_type`, and `error_code` fields appear on the inbound audit entry. To trace a single failed request end-to-end:

1. Grab the `X-Request-Id` header from the client's response.
2. Search audit logs for `request_id=<that value>`.
3. The matching entry's `error_type` and `error_code` will equal what the client saw.
