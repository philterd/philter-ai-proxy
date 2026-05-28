# Monitoring

The proxy exposes a Prometheus metrics endpoint on a dedicated port (default `9090`) so it can be firewalled separately from the proxy port. Metrics are enabled by default.

## Configuration

```yaml
metrics:
  enabled: true
  port: 9090
```

To disable metrics:

```yaml
metrics:
  enabled: false
```

## Scraping with Prometheus

Add the proxy as a scrape target in your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: philter-ai-proxy
    static_configs:
      - targets: ['your-proxy-host:9090']
```

## Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `philter_proxy_requests_total` | Counter | `provider`, `status_code`, `policy` | Total requests proxied |
| `philter_proxy_request_duration_seconds` | Histogram | `provider` | End-to-end request latency |
| `philter_proxy_redaction_duration_seconds` | Histogram | `provider`, `policy` | Time spent on Philter redaction calls |
| `philter_proxy_entities_redacted_total` | Counter | `entity_type`, `provider` | Total entities redacted |
| `philter_proxy_prompt_tokens_total` | Counter | `provider`, `model` | Total prompt (input) tokens reported by providers |
| `philter_proxy_completion_tokens_total` | Counter | `provider`, `model` | Total completion (output) tokens reported by providers |
| `philter_proxy_philter_errors_total` | Counter | - | Failed calls to the Philter backend |
| `philter_proxy_upstream_errors_total` | Counter | `provider`, `status_code` | Failed calls to LLM providers |
| `philter_proxy_active_requests` | Gauge | - | Currently in-flight requests (those holding a concurrency slot) |
| `philter_proxy_concurrency_limit` | Gauge | `scope` | Configured max-concurrent-requests ceiling. `0` means unlimited. |
| `philter_proxy_concurrency_shed_total` | Counter | `scope` | Requests rejected (HTTP 503) due to the concurrency guard |
| `philter_proxy_ratelimit_backend_duration_seconds` | Histogram | `backend`, `result` | Latency of rate-limit backend calls. `result` is `ok` or `error`. Only emitted when rate limiting is enabled. |
| `philter_proxy_ratelimit_backend_errors_total` | Counter | `backend` | Rate-limit backend errors (e.g. Redis unreachable/timeout) |
| `philter_proxy_ratelimit_fallback_total` | Counter | - | Decisions that fell back to the local in-memory limiter because the configured backend was unreachable (fail-open) |
| `philter_proxy_cache_hits_total` | Counter | - | Response-cache hits (served from cache, skipping Philter and the provider) |
| `philter_proxy_cache_misses_total` | Counter | - | Response-cache misses on cacheable requests |
| `philter_proxy_quota_rejections_total` | Counter | `window` | Requests rejected (HTTP 429) due to a token quota, by window (`daily`, `monthly`) |

Token counters are populated from each provider's native usage response field. They are not incremented for streaming responses, since token counts are not reliably available mid-stream.

### Label values

**`provider`**: `openai`, `anthropic`, `gemini`, `ollama`, `bedrock`, or the name of any configured OpenAI-compatible provider

**`entity_type`**: Philter entity type string, e.g. `NER_ENTITY`, `SSN`, `PHONE_NUMBER`, `EMAIL_ADDRESS`. The full list depends on your Philter policy configuration.

**`policy`**: The Philter policy name matched by the route, e.g. `default`, `hipaa-safe-harbor`.

**`scope`** (on concurrency metrics): `global` for the proxy-wide cap, `per_key` for per-API-key caps.

**`backend`** (on rate-limit metrics): `memory` or `redis`.

**`result`** (on `philter_proxy_ratelimit_backend_duration_seconds`): `ok` for a successful backend decision, `error` for a backend failure/timeout.

**`window`** (on `philter_proxy_quota_rejections_total`): `daily` or `monthly` — which token-quota window was exceeded.

## Health Endpoints

The proxy exposes three HTTP endpoints on the proxy port (not the metrics port) for use as load-balancer health checks and Kubernetes probes.

### `/livez` (liveness)

Always returns `200 OK` with body `{"status":"ok"}` as long as the process is running and the listener is accepting connections. **Does not probe Philter** - this is the endpoint to point a Kubernetes liveness probe at, so transient upstream blips don't trigger pod restarts.

### `/readyz` (readiness)

Returns `200 OK` with body `{"status":"ok"}` when the proxy is willing to accept traffic, or `503 Service Unavailable` with body `{"status":"not_ready","reason":"philter_circuit_open"}` when the Philter circuit breaker is open AND configured to block. In every other state (no breaker configured, breaker closed, breaker half-open, or breaker open with `fallback: passthrough`) the proxy is considered ready: individual requests may still fail but Kubernetes should NOT shed traffic from the pod.

**Does not probe Philter** - the breaker's existing state is the source of truth. This keeps readiness cheap and avoids adding load to a struggling Philter.

Use this as a Kubernetes readiness probe.

### `/health` (deprecated)

Retained for backwards compatibility. Returns `200 OK` with `{"status":"ok","philter":"ok"}` when Philter is reachable; `503` with `{"status":"degraded","philter":"unreachable"}` when not. Unlike `/readyz`, this endpoint makes an active outbound probe to Philter on every call (2-second timeout).

**Deprecated in favor of `/livez` and `/readyz`.** New deployments should use the split endpoints; treating Philter unreachability as a liveness failure causes Kubernetes to restart healthy pods during transient outages, which is precisely the failure mode the split was introduced to fix.

## Distributed Tracing

The proxy emits OpenTelemetry spans for every inbound request, with child spans for each call to Philter and each upstream LLM provider. Trace context is propagated to the upstream via the W3C `traceparent` header, so a request traversing the proxy can be viewed end-to-end in any APM (Jaeger, Honeycomb, Datadog, Grafana Tempo, etc.).

Tracing is **disabled by default**. With the SDK off the proxy pays zero per-request tracing overhead.

### Enabling tracing

Two things must be true for spans to start flowing:

1. Set `tracing.enabled: true` in the config (this initialises the OTel SDK).
2. Set the standard OTel env vars to point at your collector AND tell the SDK to actually sample. Even with `tracing.enabled: true` the default sampler is `always_off`, so spans are only emitted when the operator explicitly opts in via `OTEL_TRACES_SAMPLER`.

```yaml
tracing:
  enabled: true
  serviceName: philter-ai-proxy   # optional; defaults to "philter-ai-proxy"
```

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf   # or "grpc" for port 4317
export OTEL_TRACES_SAMPLER=parentbased_always_on   # see samplers below
```

### Recognised env vars

The proxy honours the standard OTel SDK env vars:

| Env var | Effect |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector URL. Required when tracing is enabled. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` (default) or `grpc`. |
| `OTEL_EXPORTER_OTLP_HEADERS` | Comma-separated `key=value` headers (e.g., auth tokens). |
| `OTEL_EXPORTER_OTLP_INSECURE` | `true` to skip TLS for gRPC exporters. |
| `OTEL_SERVICE_NAME` | Overrides `tracing.serviceName` when set. |
| `OTEL_RESOURCE_ATTRIBUTES` | Extra resource attributes, e.g. `deployment.environment=prod`. |
| `OTEL_TRACES_SAMPLER` | `always_off` (default), `always_on`, `parentbased_always_on`, `parentbased_always_off`, `traceidratio`, `parentbased_traceidratio`. |
| `OTEL_TRACES_SAMPLER_ARG` | Argument for ratio samplers, e.g. `0.1` for 10% sampling. |

### Spans the proxy emits

| Span | When |
|---|---|
| `proxy.request {METHOD} {PATH}` | Root span per inbound request, created by `otelhttp.NewHandler`. Honors an inbound `traceparent` header. |
| `philter.filter` | Each call to Philter's `/api/explain` (inbound redaction + outbound scan). |
| `provider.{name}` | Each call to an upstream provider (`openai`, `anthropic`, `gemini`, `ollama`, `bedrock`, or any configured `openaiCompatible` name). |

Child spans inherit the inbound trace ID so the whole request appears as one trace in your APM.

### Correlating trace IDs with audit logs

Every audit log entry includes a `trace_id` field when tracing is active and the request was sampled. Use it to jump from a slow audit-log entry to the full distributed trace in your APM, or vice versa:

```json
{"time":"...","msg":"request","request_id":"...","provider":"openai","http_status":200,"trace_id":"11112222333344445555666677778888",...}
```

When tracing is disabled or the request was not sampled, `trace_id` is omitted from the audit entry.

## Grafana Dashboard

A pre-built dashboard covering every metric in the table above is shipped at [`deploy/grafana/philter-ai-proxy.json`](https://github.com/philterd/philter-ai-proxy/blob/main/deploy/grafana/philter-ai-proxy.json). Import it via Grafana → **Dashboards** → **New** → **Import** and pick the Prometheus datasource that's scraping `philter_proxy_*`. The dashboard exposes a `datasource` template variable so the same JSON works across environments.

If you'd rather build your own, the recipes below are the queries the bundled dashboard uses.

### Recommended panels

**Request rate** (requests per second by provider):
```promql
sum by (provider) (rate(philter_proxy_requests_total[5m]))
```

**Error rate** (% of requests that failed):
```promql
sum(rate(philter_proxy_requests_total{status_code=~"5.."}[5m]))
  /
sum(rate(philter_proxy_requests_total[5m]))
```

**p95 request latency by provider**:
```promql
histogram_quantile(0.95, sum by (provider, le) (rate(philter_proxy_request_duration_seconds_bucket[5m])))
```

**p95 redaction latency by policy**:
```promql
histogram_quantile(0.95, sum by (policy, le) (rate(philter_proxy_redaction_duration_seconds_bucket[5m])))
```

**Entities redacted per minute by type**:
```promql
sum by (entity_type) (rate(philter_proxy_entities_redacted_total[1m])) * 60
```

**Token throughput by provider** (tokens per minute):
```promql
sum by (provider) (rate(philter_proxy_prompt_tokens_total[5m]) + rate(philter_proxy_completion_tokens_total[5m])) * 60
```

**Prompt vs. completion token split by model**:
```promql
sum by (model) (rate(philter_proxy_prompt_tokens_total[5m]))
sum by (model) (rate(philter_proxy_completion_tokens_total[5m]))
```

**Cumulative tokens by provider** (useful for cost attribution dashboards):
```promql
sum by (provider) (philter_proxy_prompt_tokens_total + philter_proxy_completion_tokens_total)
```

**Philter backend error rate**:
```promql
rate(philter_proxy_philter_errors_total[5m])
```

**Active in-flight requests**:
```promql
philter_proxy_active_requests
```

### Concurrency

**Utilization (% of the global concurrency ceiling currently in use)** - only meaningful when `listen.maxConcurrentRequests > 0`:
```promql
philter_proxy_active_requests
  / on() philter_proxy_concurrency_limit{scope="global"}
```

**Sustained shed rate by scope** (rejections/sec from the concurrency guard):
```promql
sum by (scope) (rate(philter_proxy_concurrency_shed_total[5m]))
```

If `scope="global"` is rising, you have a real capacity problem - **scale out horizontally first** rather than raising the cap. If only `scope="per_key"` is rising, talk to that tenant or raise their per-key cap; the global pool is fine.

### Alerting rules

```yaml
groups:
  - name: philter-ai-proxy
    rules:
      - alert: PhilterBackendDown
        expr: rate(philter_proxy_philter_errors_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Philter backend is returning errors"

      - alert: HighUpstreamErrorRate
        expr: |
          sum(rate(philter_proxy_upstream_errors_total[5m])) /
          sum(rate(philter_proxy_requests_total[5m])) > 0.05
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "More than 5% of upstream requests are failing"

      - alert: HighRedactionLatency
        expr: |
          histogram_quantile(0.95, sum by (le) (rate(philter_proxy_redaction_duration_seconds_bucket[5m]))) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Philter redaction p95 latency exceeds 1 second"

      - alert: ConcurrencyGuardShedding
        expr: rate(philter_proxy_concurrency_shed_total{scope="global"}[5m]) > 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Proxy is shedding requests at the global concurrency cap - scale out or raise listen.maxConcurrentRequests"
```
