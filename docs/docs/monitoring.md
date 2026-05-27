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
| `philter_proxy_philter_errors_total` | Counter | — | Failed calls to the Philter backend |
| `philter_proxy_upstream_errors_total` | Counter | `provider`, `status_code` | Failed calls to LLM providers |
| `philter_proxy_active_requests` | Gauge | — | Currently in-flight requests |

### Label values

**`provider`**: `openai`, `anthropic`, `gemini`, `ollama`

**`entity_type`**: Philter entity type string, e.g. `NER_ENTITY`, `SSN`, `PHONE_NUMBER`, `EMAIL_ADDRESS`. The full list depends on your Philter policy configuration.

**`policy`**: The Philter policy name matched by the route, e.g. `default`, `hipaa-safe-harbor`.

## Health Endpoint

`GET /health` (on the proxy port, not the metrics port) returns a JSON body indicating whether the Philter backend is reachable:

```json
{"status":"ok","philter":"ok"}
```

If Philter is unreachable, the endpoint returns HTTP `503` with:

```json
{"status":"degraded","philter":"unreachable"}
```

This is suitable for use as a Kubernetes liveness/readiness probe or a load-balancer health check. The check uses a 2-second timeout so it does not stall health polling loops.

## Grafana Dashboard

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
```
