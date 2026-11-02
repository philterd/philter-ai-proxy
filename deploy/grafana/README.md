# Grafana dashboard

`philter-ai-proxy.json` is a starter Grafana dashboard covering the metrics emitted by the proxy. Compatible with Grafana 9+ and any Prometheus-format datasource.

## Import

1. Grafana → **Dashboards** → **New** → **Import**.
2. Upload `philter-ai-proxy.json` (or paste its contents).
3. When prompted, pick the Prometheus datasource that's scraping `philter_proxy_*` metrics.
4. **Import**.

The dashboard has two variables: `datasource`, so the same JSON can be imported into several environments, and `provider`, which filters the per-provider panels.

Panels are ordered so redaction comes first. Throughput, latency, and capacity follow: useful, but not specific to what this proxy does.

## Panels

| Panel | Metric(s) | Purpose |
|---|---|---|
| Entities redacted by type | `philter_proxy_entities_redacted_total` | Volume and mix of values the proxy redacts. The signal no other component in the stack can produce, and the one that goes quiet when redaction stops working. |
| Redaction errors | `philter_proxy_redaction_errors_total` | Requests refused because redaction or response scanning failed |
| Request rate by provider | `philter_proxy_requests_total` | Throughput, broken out by provider |
| Request latency (p50/p95/p99) | `philter_proxy_request_duration_seconds` | End-to-end latency, including redaction and the provider |
| 5xx error rate | `philter_proxy_requests_total{status=~"5.."}` | Share of requests answered with a 5xx |
| Active in-flight requests | `philter_proxy_active_requests` | Live concurrency |
| Concurrency utilization | `philter_proxy_active_requests / philter_proxy_concurrency_limit` | Share of the concurrency limit in use. The limit gauge is `0` when `proxy.limits.max-concurrent-requests` is negative (no limit), so the panel is meaningful only with a limit set. |
| Concurrency sheds | `philter_proxy_concurrency_shed_total` | Requests refused with 503 at the concurrency limit |
| Upstream LLM errors | `philter_proxy_upstream_errors_total` | Failed or error responses from providers, by provider and status |

## Customising

The dashboard is meant as a starting point. Common edits:

- Filter by environment label if you scrape multiple clusters: add an `environment` variable and append `{environment="$environment"}` to each query.
- Adjust the 5-minute `rate()` windows to match your scrape interval (default Prometheus scrape is 15 s; a `[1m]` window is fine if you scrape that often, otherwise stick to `[5m]`).
- For PromQL reference and alert recipes, see [Monitoring](https://philterd.github.io/philter-ai-proxy/monitoring/).
