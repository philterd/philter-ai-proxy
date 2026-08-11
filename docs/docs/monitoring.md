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
| `philter_proxy_philter_errors_total` | Counter | - | Failed calls to the Philter backend |
| `philter_proxy_upstream_errors_total` | Counter | `provider`, `status_code` | Failed calls to LLM providers |
| `philter_proxy_active_requests` | Gauge | - | Currently in-flight requests (those holding a concurrency slot) |
| `philter_proxy_concurrency_limit` | Gauge | `scope` | Configured max-concurrent-requests ceiling. `0` means unlimited. |
| `philter_proxy_concurrency_shed_total` | Counter | `scope` | Requests rejected (HTTP 503) due to the concurrency guard |
| `philter_proxy_tls_handshakes_shed_total` | Counter | - | Inbound TLS connections dropped because the `listen.maxConcurrentTLSHandshakes` ceiling was reached (connection-flood backstop) |

The proxy does not export token-usage metrics. Token accounting is an AI-gateway concern; see [Running Behind an AI Gateway](ai-gateway.md).

### Label values

**`provider`**: `openai`, `anthropic`, `gemini`, `ollama`, `bedrock`, or the name of any configured OpenAI-compatible provider

**`entity_type`**: Philter entity type string, e.g. `NER_ENTITY`, `SSN`, `PHONE_NUMBER`, `EMAIL_ADDRESS`. The full list depends on your Philter policy configuration.

**`policy`**: The Philter policy name matched by the route, e.g. `default`, `hipaa-safe-harbor`.

**`scope`** (on concurrency metrics): `global`, the proxy-wide cap.

Every label value is drawn from a fixed vocabulary. No label is client-supplied, and none carries message content. See [Is any sensitive data logged?](faq.md#is-any-sensitive-data-logged) for the full guarantee and how it is enforced.

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

If `scope="global"` is rising, you have a real capacity problem - **scale out horizontally first** rather than raising the cap.

### Alerting rules

```yaml
groups:
  - name: philter-ai-proxy
    rules:
      # The silent failure this proxy exists to prevent: traffic flowing,
      # 200s returning, and nothing being redacted. Every other alert here
      # stays green through it. `or vector(0)` is required because the
      # counter has no series at all until the first entity is redacted.
      - alert: RedactionDetectionStopped
        expr: |
          (sum(rate(philter_proxy_entities_redacted_total[30m])) or vector(0)) == 0
          and sum(rate(philter_proxy_requests_total[30m])) > 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Proxy is serving traffic but has redacted nothing for 30 minutes"
          description: "Check that the Philter policy is loaded and matches the traffic, and that any NER model the policy depends on is available."

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

`RedactionDetectionStopped` is a warning rather than a critical because a deployment whose traffic genuinely contains no PII will trip it. Tune the window to your traffic, or drop the rule if zero detections is normal for you. On a route where PII is expected on every request, raise it to critical: a policy that silently stops matching produces exactly this signal and nothing else does.
