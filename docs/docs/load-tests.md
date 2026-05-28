# Load tests

A [k6](https://k6.io) harness lives at `test/load/` in the repo. It brings up a self-contained stack (Philter + a stub LLM provider + the proxy) via docker-compose and exercises five scenarios that together cover the proxy's hot paths: inbound redaction, outbound response scanning, streaming, and a no-proxy baseline for comparison.

See [`test/load/README.md`](https://github.com/philterd/philter-ai-proxy/blob/main/test/load/README.md) for run instructions.

## Reference baseline

Numbers measured on the reference instance below, 10 virtual users, 20-second runs, deliberate PII fixture in every request body (so redaction has work to do every iteration). Each row is a separate k6 run against the same warm stack.

| Scenario | iters | req/s | p50 (ms) | p95 (ms) | p99 (ms) | failures |
|---|---:|---:|---:|---:|---:|---:|
| `no-redaction` (direct to stub, baseline) | 798,147 | **39,907** | 0.17 | 0.37 | 0.68 | 0.000% |
| `openai` (proxy + inbound redaction) | 58,951 | **2,947** | 2.16 | 8.78 | 13.17 | 0.000% |
| `anthropic` (proxy + inbound redaction) | 14,610 | **729** | 8.36 | 41.67 | 66.03 | 0.000% |
| `openai-streaming` (proxy + inbound + SSE pass-through) | 13,933 | **696** | 4.85 | 60.50 | 101.98 | 0.000% |
| `outbound-scan` (proxy + inbound + outbound Philter scan) | 28,537 | **1,424** | 3.25 | 32.14 | 65.22 | 0.000% |

## Reading the table

The `no-redaction` row is a baseline. k6 hits the stub provider directly without traversing the proxy or Philter. Subtracting this row's latency from any of the others gives the **incremental cost of running the proxy and Philter for that flow**.

For the most common production case (`openai` inbound redaction):

- The proxy adds **~2 ms p50** and **~8.4 ms p95** of latency on top of the direct-to-stub baseline.
- Sustained throughput drops from ~40K req/s to **~2.9K req/s**. The bottleneck is the Philter container, not the proxy itself: with one Philter instance on the same machine, every request serializes through a single redaction call.
- For higher throughput, scale Philter horizontally and bring up additional proxy replicas (the proxy is stateless except for in-process rate-limit buckets and concurrency slots; see issue #110 for shared rate-limit state).

The `outbound-scan` row is **two** Philter round-trips per request (one inbound on the prompt, one outbound on the response). Throughput halves vs `openai` and p99 climbs from 13ms to 65ms - the price of scanning the LLM's reply for PII before it leaves the proxy.

The `anthropic` row is slower than `openai` despite running through the same proxy code. The difference is on the Philter side: the Anthropic fixture's polymorphic content shape (string-or-array of typed blocks) and Anthropic's request body shape produce a different Philter workload pattern under contention. The proxy's per-request overhead is comparable across providers; the throughput delta is in the redaction backend.

The `openai-streaming` row's p99 (~100ms) reflects the stub's chunk schedule (4 chunks at 10ms intervals = ~40ms minimum body time) plus contention; the proxy's per-request overhead in this scenario is dominated by waiting on the upstream stream, not by its own work.

## Reference instance

- **CPU:** Intel Core i5-11400 @ 2.60 GHz, 12 logical cores.
- **RAM:** 62 GiB total, ~52 GiB free.
- **OS:** Ubuntu 24.04.4 LTS.
- **Docker:** Engine 29.5.2.
- **Network:** all components on the same host, communicating via the docker-compose default bridge network.

All five components - Philter, stub provider, proxy, and the k6 container - ran on the same machine in this measurement, so they competed for CPU. In a real deployment Philter would typically be on a separate node sized for redaction throughput.

## How to reproduce

```bash
# From the repo root.
docker compose -f test/load/docker-compose.load.yaml up -d --build
for s in no-redaction openai anthropic openai-streaming outbound-scan; do
  VUS=10 DURATION=20s ./test/load/run.sh "$s"
done
docker compose -f test/load/docker-compose.load.yaml down -v
```

Per-scenario JSON summaries land under `test/load/results/<scenario>.summary.json`.

## CI

A scheduled GitHub Actions workflow (`.github/workflows/load-test.yml`) re-runs the same baseline weekly and on `workflow_dispatch`, uploading the summary JSONs as job artifacts. The numbers above are not auto-updated in this docs page when the CI workflow runs - they are a point-in-time reference. Open a PR to refresh the table when the baseline shifts materially.
