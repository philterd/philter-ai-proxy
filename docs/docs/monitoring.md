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

Token counters are populated from each provider's native usage response field. They are not incremented for streaming responses, since token counts are not reliably available mid-stream.

### Label values

**`provider`**: `openai`, `anthropic`, `gemini`, `ollama`, `bedrock`, or the name of any configured OpenAI-compatible provider

**`entity_type`**: Philter entity type string, e.g. `NER_ENTITY`, `SSN`, `PHONE_NUMBER`, `EMAIL_ADDRESS`. The full list depends on your Philter policy configuration.

**`policy`**: The Philter policy name matched by the route, e.g. `default`, `hipaa-safe-harbor`.

**`scope`** (on concurrency metrics): `global` for the proxy-wide cap, `per_key` for per-API-key caps.

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
