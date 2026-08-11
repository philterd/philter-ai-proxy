# Grafana dashboard

`philter-ai-proxy.json` is a starter Grafana dashboard covering the metrics emitted by the proxy. Compatible with Grafana 9+ and any Prometheus-format datasource.

## Import

1. Grafana → **Dashboards** → **New** → **Import**.
2. Upload `philter-ai-proxy.json` (or paste its contents).
3. When prompted, pick the Prometheus datasource that's scraping `philter_proxy_*` metrics.
4. **Import**.

The dashboard exposes one variable, `datasource`, so the same JSON can be imported into multiple environments.

Panels are ordered so redaction comes first. Throughput, latency, and capacity follow: useful, but not specific to what this proxy does.

## Panels

| Panel | Metric(s) | Purpose |
|---|---|---|
| Entities redacted by type | `philter_proxy_entities_redacted_total` | Volume and mix of PII the proxy is catching. The signal no other component in the stack can produce, and the one that goes quiet when redaction silently stops working. |
| Philter backend errors | `philter_proxy_philter_errors_total` | Health of the redaction backend everything above depends on |
| Request rate by provider | `philter_proxy_requests_total` | Throughput overview, broken out by provider |
| Request latency (p50/p95/p99) | `philter_proxy_request_duration_seconds` | End-to-end latency budget, including Philter + LLM |
| Error rate | `philter_proxy_requests_total{status_code=~"5.."}` | % of requests returning 5xx |
| Active in-flight requests | `philter_proxy_active_requests` | Live concurrency |
| Concurrency utilization | `philter_proxy_active_requests / philter_proxy_concurrency_limit{scope="global"}` | % of the configured concurrency ceiling in use. Only meaningful when `listen.maxConcurrentRequests > 0`. |
| Concurrency sheds | `philter_proxy_concurrency_shed_total` | Requests rejected (503) by the capacity guard, by scope |
| Upstream LLM errors | `philter_proxy_upstream_errors_total` | Health of the LLM providers |

## Customising

The dashboard is meant as a starting point. Common edits:

- Filter by environment label if you scrape multiple clusters: add an `environment` variable and append `{environment="$environment"}` to each query.
- Adjust the 5-minute `rate()` windows to match your scrape interval (default Prometheus scrape is 15 s; a `[1m]` window is fine if you scrape that often, otherwise stick to `[5m]`).
- For PromQL reference and alert recipes, see [Monitoring](https://philterd.github.io/philter-ai-proxy/monitoring/).
