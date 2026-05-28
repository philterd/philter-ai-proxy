# Load tests

[k6](https://k6.io)-based load test harness for measuring throughput, latency, and behavior under sustained load. Designed to run against a self-contained docker-compose stack so you can produce numbers on a laptop and reproduce them in CI.

## Layout

```
test/load/
├── docker-compose.load.yaml   # Philter + stub LLM + proxy
├── config.load.yaml           # proxy config used by the stack
├── stub-provider/             # tiny Go HTTP server stubbing OpenAI + Anthropic
├── scenarios/                 # k6 JS scripts (one per scenario)
├── results/                   # k6 summary JSON dropped here (gitignored)
└── run.sh                     # wrapper that invokes the grafana/k6 image
```

## Quickstart

From the **repo root**:

```bash
# 1. Build the proxy image, bring up Philter + stub provider + proxy.
docker compose -f test/load/docker-compose.load.yaml up -d --build

# 2. Run a scenario (uses the grafana/k6 docker image; no local k6 needed).
./test/load/run.sh openai

# 3. Look at the per-iteration summary k6 prints, or the machine-readable
#    JSON under test/load/results/.

# 4. Tear down.
docker compose -f test/load/docker-compose.load.yaml down -v
```

The proxy listens on `https://localhost:8080` with a self-signed cert generated at image-build time; k6 scenarios skip TLS verification accordingly. Philter is reachable on `http://localhost:8081` and the stub provider on `http://localhost:8090` if you want to poke at them directly.

## Available scenarios

| Scenario | What it measures |
|---|---|
| `openai` | Full inbound redaction + non-streaming round-trip via `/v1/chat/completions`. |
| `anthropic` | Same shape via `/v1/messages`. |
| `openai-streaming` | Server-Sent Events round-trip via `/v1/chat/completions` with `stream:true`. Tests the proxy's streaming pass-through path. |
| `outbound-scan` | Inbound redaction + **outbound response scan** (`outbound.enabled: true`, `action: redact`). Triggered by the `x-loadtest-mode: outbound` header. Doubles the Philter round-trip per request. |
| `no-redaction` | Direct hit on the stub provider, bypassing the proxy entirely. The baseline you compare the other scenarios against. |

Run them by name:

```bash
./test/load/run.sh openai
./test/load/run.sh openai-streaming
./test/load/run.sh outbound-scan
```

`./test/load/run.sh` with no args lists the available scenarios.

## Knobs

Every scenario reads `VUS` and `DURATION` from the environment. Defaults are 10 virtual users for 30 seconds — enough to read p95/p99 reliably without burning the laptop. Override via env:

```bash
VUS=50 DURATION=2m ./test/load/run.sh openai
```

The proxy and stub URLs are also overridable via `PROXY_URL` and `STUB_URL` if you want to point the same scenarios at a remote deployment.

## Interpreting the output

k6 prints a per-iteration summary on stdout and writes a machine-readable JSON to `results/<scenario>.summary.json`. The numbers that matter:

- `http_req_duration` (p50, p95, p99) — end-to-end latency.
- `http_req_failed` (rate) — fraction of requests that did not return 2xx.
- `iterations` (count and rate) — requests/second sustained.

Each scenario declares thresholds for `http_req_duration` and `http_req_failed` that k6 enforces and prints as pass/fail. Crossing a threshold marks the run as failed (non-zero exit), which is what the CI workflow uses to gate the build.

## Comparing redaction-on vs redaction-off

Run the `openai` scenario (proxy + Philter) and the `no-redaction` scenario (direct to stub) with the same `VUS` and `DURATION`. The delta in p95/p99 latency is the cost of one inbound redaction pass; the delta in iterations/second is the throughput cost. See `docs/docs/load-tests.md` for an example report on a reference instance.

## Stub provider

The stub at `test/load/stub-provider/` is a 200-line Go HTTP server that returns canned OpenAI- and Anthropic-shape responses (JSON for non-streaming, SSE for streaming). Knobs via query string:

- `delay=200ms` — server-side latency before the response starts.
- `chunks=8` — number of SSE chunks for streaming endpoints.
- `chunk_delay=10ms` — delay between chunks.

The stub deliberately includes a fake SSN in its response body so the outbound-scan scenario has work to do for Philter.

## Pointing the scenarios at a real provider

For a real-world baseline, swap the stub for the upstream provider:

```yaml
# config.load.yaml
providers:
  openai:
    target: https://api.openai.com
```

…and supply a real API key on the k6 requests via env vars. **This will cost money** and is subject to provider rate limits — keep `VUS` modest. Most regression work should use the stub.

## CI

`.github/workflows/load-test.yml` runs a small baseline (10 VUs × 1 minute) on every push to `main` and on `workflow_dispatch`. Results are uploaded as job artifacts. The workflow does not currently fail PRs on regression — it surfaces numbers, not gates.
