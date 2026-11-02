# Load tests

A [k6](https://k6.io) harness lives at `test/load/` in the repository. It brings up a stub LLM provider and the proxy built from the repository, with the default policy and its bundled person-name model, and runs five scenarios: inbound redaction for OpenAI and Anthropic, a streamed response, response scanning, and a baseline that skips the proxy.

## Reference baseline

Measured on the reference instance below on 2026-11-02: 10 virtual users, 20 seconds per scenario, the same prompt in every request (`The SSN on file is 123-45-6789. Summarize the case.`). The default policy runs the PhEye model over every prompt, and a context is configured, so each request also reads and writes the SQLite context store.

| Scenario | Iterations | req/s | p50 (ms) | p95 (ms) | p99 (ms) | Failures |
|---|---:|---:|---:|---:|---:|---:|
| `no-redaction` (direct to the stub, no proxy) | 741,701 | **37,084** | 0.2 | 0.4 | 0.6 | 0.000% |
| `openai` (inbound redaction) | 1,684 | **84** | 110.7 | 174.7 | 241.5 | 0.000% |
| `anthropic` (inbound redaction) | 1,746 | **87** | 104.9 | 170.4 | 270.1 | 0.000% |
| `openai-streaming` (inbound redaction, streamed response passed through) | 1,744 | **87** | 113.3 | 131.6 | 146.7 | 0.000% |
| `outbound-scan` (inbound redaction and response scanning) | 809 | **40** | 241.0 | 328.8 | 365.2 | 0.000% |

Before 2026-11-02 the stub answered `openai-streaming` without streaming, since it streamed only for a `?stream=1` query parameter; it now streams when the body asks, as providers do. The earlier figures for the other scenarios were within a few percent of these.

## Reading the table

The `no-redaction` row is the baseline: k6 calls the stub directly. The difference between it and another row is the cost of the proxy for that flow.

- **The model sets the throughput.** Running the PhEye person-name model on the CPU is most of each request's cost: about 110 ms at the median with 10 requests at a time, and about 85 requests a second on this machine. The rest of the proxy (authentication, routing, the context store, forwarding) is small beside it.
- **Response scanning redacts twice**, the prompt and the response, so `outbound-scan` runs at about half the throughput.
- **Providers cost the same.** OpenAI, Anthropic, and the streamed response run the same redaction, so their rows match.
- **A pattern-only policy is much faster.** A policy without a PhEye filter (SSNs, email addresses, phone numbers, and the like) skips the model.

For more throughput, give the proxy more CPU, or run more instances, each with its own database, behind your gateway. The model can also run on a GPU through ONNX Runtime's GPU build; the image ships the CPU build.

## Reference instance

- **CPU:** Intel Core i5-11400 @ 2.60 GHz, 12 logical cores.
- **RAM:** 62 GiB.
- **OS:** Ubuntu 24.04.5 LTS.
- **Docker:** Engine 29.9.2.
- **Network:** every component on the same host, over the docker-compose network.

The stub, the proxy, and the k6 container ran on the same machine, so they competed for CPU.

## How to reproduce

```bash
# From the repository root.
docker compose -f test/load/docker-compose.load.yaml up -d --build
for s in no-redaction openai anthropic openai-streaming outbound-scan; do
  VUS=10 DURATION=20s ./test/load/run.sh "$s"
done
docker compose -f test/load/docker-compose.load.yaml down -v
```

`run.sh` waits until the proxy is ready, creates a proxy key with the admin API, and runs the scenario. Each scenario's summary is written to `test/load/results/<scenario>.summary.json`. If ports 8080, 9090, or 8090 are taken on your machine, set `PROXY_PORT`, `METRICS_PORT`, or `STUB_PORT` for `docker compose`, and `PROXY_URL` (such as `https://localhost:18080`) for `run.sh`.

## CI

A scheduled GitHub Actions workflow (`.github/workflows/load-test.yml`) runs the scenarios weekly and on `workflow_dispatch`, and uploads the summaries as artifacts. The table above is a point-in-time reference and is not updated by the workflow.
