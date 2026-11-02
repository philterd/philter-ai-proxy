# Monitoring

The proxy exposes Prometheus metrics, health endpoints, an audit log, and optional OpenTelemetry traces. None of them carries the text of a prompt or response.

## Metrics

Metrics are served for Prometheus at `/metrics` on the management port, `9090` (`management.server.port`), always over plain HTTP. Keep the port off the internet.

```yaml
scrape_configs:
  - job_name: philter-ai-proxy
    static_configs:
      - targets: ["philter-ai-proxy:9090"]
```

On Kubernetes, the Helm chart's `serviceMonitor.enabled` creates a Prometheus Operator ServiceMonitor.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `philter_proxy_requests_total` | counter | `provider`, `status`, `policy` | Requests handled, by the status returned to the client. |
| `philter_proxy_request_duration_seconds` | histogram | `provider` | Time to handle a request, including the provider's response. |
| `philter_proxy_redaction_duration_seconds` | histogram | `provider`, `policy` | Time spent redacting a request's text. |
| `philter_proxy_entities_redacted_total` | counter | `entity_type`, `provider` | Values found in requests, by filter type (for example `ssn`, `email-address`, `name`). |
| `philter_proxy_upstream_errors_total` | counter | `provider`, `status` | Provider responses with status 400 or above, and providers that could not be reached (`502`). |
| `philter_proxy_redaction_errors_total` | counter | `provider` | Requests refused, or streams ended, because redaction or scanning failed. |
| `philter_proxy_concurrency_shed_total` | counter | | Requests refused at `proxy.limits.max-concurrent-requests`. |
| `philter_proxy_active_requests` | gauge | | Requests in flight. |
| `philter_proxy_concurrency_limit` | gauge | | The configured concurrency limit; `0` is no limit. |

A counter appears once it has first counted something. The JVM, HTTP server, and process metrics that Spring Boot provides are served too.

## Health endpoints

All three are served on port 8080 without authentication.

| Endpoint | Answers 200 | Use it for |
|---|---|---|
| `/livez` | While the process runs | The liveness probe. |
| `/readyz` | Once the policies the configuration names (the default and each route's) and their models are loaded, and while the database is usable; `503` otherwise | The readiness probe. Loading the bundled model takes several seconds after start. |
| `/health` | While the database is usable; `503` otherwise | Monitoring. It answers with the standard Philterd health response, `{"status": "UP", "applicationVersion": "2.0.0"}`. |

## Audit log

Each request to a provider produces one audit entry, written:

- to the proxy's database, in the `audit_log` table;
- to standard output as one JSON line, through the `philter-ai-proxy.audit` logger;
- and to `proxy.audit.file` when it is set, as one JSON line, in a file created readable only by the proxy's user.

The database copy is kept until `proxy.audit.retention-days` removes it (off by default). The `model` field holds at most 256 characters of what the client sent.

```json
{"timestamp":"2026-11-01T14:02:11.482Z","request_id":"6f1c...","event":"proxy_request","provider":"openai","model":"gpt-4o-mini","policy_name":"default","key_id":"5f0c8a4e-...","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","client_ip":"203.0.113.50","http_status":200,"fields_redacted":1,"entity_count":2,"entity_types":{"email-address":1,"name":1},"redact_latency_ms":31,"duration_ms":842,"streamed":false}
```

| Field | Meaning |
|---|---|
| `request_id` | The `X-Request-Id` returned to the client. |
| `provider`, `model`, `policy_name`, `context` | What the request used. |
| `key_id` | The ID of the proxy key, never the key. |
| `trace_id` | The OpenTelemetry trace ID, when tracing is on and the request was sampled. |
| `client_ip` | The client's address; see `proxy.security.trusted-proxies`. |
| `http_status` | The status returned to the client. |
| `fields_redacted`, `entity_count`, `entity_types` | How many text fields had values replaced, and how many values of each type were found in the request. |
| `outbound_action`, `outbound_entity_count`, `outbound_entity_types` | With response scanning: the action, and what was found in the response. |
| `redact_latency_ms`, `duration_ms` | Time spent redacting the request, and handling it in all. |
| `streamed` | Whether the response was a stream. |
| `error_type`, `error_code` | For a refused or failed request, the error the client received. |

The admin API records its changes too: `policy_created`, `policy_replaced`, `policy_deleted`, `api_key_created`, and `api_key_deleted`, each with the acting key's ID.

Entries in the database are kept until you remove them.

## Distributed Tracing

The proxy can export OpenTelemetry traces over OTLP. Tracing is off by default.

```yaml
management:
  tracing:
    enabled: true
  opentelemetry:
    tracing:
      export:
        otlp:
          endpoint: http://otel-collector:4318/v1/traces
```

Or with environment variables: `MANAGEMENT_TRACING_ENABLED=true` and `MANAGEMENT_OPENTELEMETRY_TRACING_EXPORT_OTLP_ENDPOINT=http://otel-collector:4318/v1/traces`.

Every request is sampled by default (`management.tracing.sampling.probability: 1.0`); lower it for busy deployments. The service name is `philter-ai-proxy`. Each sampled request's trace ID is recorded in its audit entry as `trace_id`, so an audit entry can be found from a trace and the other way around.

## Grafana Dashboard

A dashboard for these metrics is at [`deploy/grafana/philter-ai-proxy.json`](https://github.com/philterd/philter-ai-proxy/blob/main/deploy/grafana/philter-ai-proxy.json). Import it with Grafana's **Dashboards**, **New**, **Import**, and choose the Prometheus data source that scrapes the proxy. Its `datasource` variable lets the same JSON work across environments.

### Alerting rules

```yaml
groups:
  - name: philter-ai-proxy
    rules:
      # Traffic flowing, 200s returning, and nothing being redacted. `or vector(0)` is needed because the
      # counter has no series until the first value is found.
      - alert: RedactionDetectionStopped
        expr: |
          (sum(rate(philter_proxy_entities_redacted_total[30m])) or vector(0)) == 0
          and sum(rate(philter_proxy_requests_total[30m])) > 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "The proxy is serving traffic but has found nothing to redact for 30 minutes"
          description: "Check that the policy in use matches the traffic and that the models it names are installed."

      - alert: RedactionErrors
        expr: rate(philter_proxy_redaction_errors_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Requests are being refused because redaction failed"

      - alert: HighUpstreamErrorRate
        expr: |
          sum(rate(philter_proxy_upstream_errors_total[5m])) /
          sum(rate(philter_proxy_requests_total[5m])) > 0.05
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "More than 5% of provider requests are failing"

      - alert: HighRedactionLatency
        expr: |
          histogram_quantile(0.95, sum by (le) (rate(philter_proxy_redaction_duration_seconds_bucket[5m]))) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Redaction p95 latency exceeds 1 second"

      - alert: ConcurrencyLimitShedding
        expr: rate(philter_proxy_concurrency_shed_total[5m]) > 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "The proxy is refusing requests at its concurrency limit"
```

`RedactionDetectionStopped` is a warning rather than critical, since traffic that genuinely contains no PII trips it. Tune the window to your traffic, or drop the rule if finding nothing is normal for you. On a route where PII is expected in every request, raise it to critical: a policy that silently stops matching produces this signal and nothing else.
