# Philter AI Proxy

This project is a proxy for OpenAI, Azure OpenAI, Claude, Gemini, Ollama, and Amazon Bedrock that uses [Philter](https://philterd.ai/philter/) to remove PII, PHI, and other sensitive information from a [chat completion](https://platform.openai.com/docs/api-reference/chat), [messages](https://docs.anthropic.com/claude/reference/messages_post), [Gemini](https://ai.google.dev/api/rest/v1beta/models/generateContent), [Ollama](https://docs.ollama.com/api/generate), [Bedrock Converse](https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html), or [Azure OpenAI](https://learn.microsoft.com/azure/ai-services/openai/reference) request before sending the request to the respective API. If you don't have a running instance of Philter, you can launch one in your cloud at https://philterd.ai/philter/.

The proxy works by sending requests destined for OpenAI, Claude, Gemini, Ollama, or Amazon Bedrock first to Philter where the sensitive information is redacted per Philter's configuration. The redacted text is then sent to the API. For example, if you send the following text `How old is John Smith?`, the proxy and Philter will remove the text `John Smith` from the request. The redacted request sent to the API will be `How old is REDACTED?`

Outbound response scanning is also supported on an opt-in basis: LLM responses can be scanned through Philter before being returned to the client, guarding against hallucinated or training-data PII in responses. The behavior is configurable per route: redact detected PII, block the response entirely, or pass it through with a warning log.

View the [documentation](http://philterd.github.io/philter-ai-proxy).

## Scope

The proxy does redaction and the audit trail that goes with it. Two boundaries are deliberate:

- **It is not an AI gateway.** Routing, failover, token quotas, and per-tenant billing belong to a gateway such as LiteLLM, Portkey, or Kong AI Gateway. The proxy is designed to run alongside one, redacting on the last hop before traffic leaves your network. See [Using with an AI Gateway](https://philterd.github.io/philter-ai-proxy/ai-gateway/).
- **It handles text conversations only.** Multipart requests (file uploads, audio transcriptions, image edits) are rejected with `400 invalid_request` / `unsupported_content_type` and should be routed directly to the provider. Audio ([#40](https://github.com/philterd/philter-ai-proxy/issues/40)) and image edits ([#41](https://github.com/philterd/philter-ai-proxy/issues/41)) are tracked; file uploads will not be supported.

## Running the Proxy

Copy `config.example.yaml` to `config.yaml`, edit the values to match your environment, then run:

```
./philter-ai-proxy --config config.yaml
```

Or set the config path via environment variable:

```
PHILTER_PROXY_CONFIG=config.yaml ./philter-ai-proxy
```

To run with Docker Compose, update `config.yaml` (mounted into the container) and then:

```
docker compose build
docker compose up
```

### Kubernetes

A production-ready Helm chart lives at `deploy/helm/philter-ai-proxy/` and plain manifests at `deploy/k8s/`. A starter Grafana dashboard covering every emitted metric is at `deploy/grafana/philter-ai-proxy.json`.

```bash
# Quickstart with the chart (TLS cert pre-created as a Secret)
kubectl create secret tls philter-ai-proxy-tls --cert=tls.crt --key=tls.key
helm install proxy ./deploy/helm/philter-ai-proxy \
  --set tls.existingSecret.name=philter-ai-proxy-tls \
  --set config.philter.endpoint=http://philter.philter-system.svc.cluster.local:8080
```

The chart supports replicas, autoscaling (HPA), Pod Disruption Budgets, Ingress, Prometheus Operator `ServiceMonitor`, mTLS, and cert-manager-issued TLS. See [the Kubernetes Quickstart](https://philterd.github.io/philter-ai-proxy/kubernetes/) for the full walkthrough.

## Usage

To use this proxy, you can send a request to it like you would to OpenAI, Claude, Gemini, or Bedrock but change the hostname:

### OpenAI

```
curl https://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
  }'
```

### Claude

```
curl https://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
  }'
```

### Gemini

```
curl "https://localhost:8080/v1beta/models/gemini-1.5-flash:generateContent?key=$GEMINI_API_KEY" \
    -H 'Content-Type: application/json' \
    -X POST \
    -d '{
      "contents": [{
        "parts":[{"text": "Whose social security number is 123-45-6789"}]
      }]
    }'
```

### Ollama

```
curl https://localhost:8080/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3",
    "prompt": "Whose social security number is 123-45-6789",
    "stream": false
  }'
```

### OpenAI-Compatible Providers (Mistral, Cohere, vLLM, etc.)

Register any OpenAI-compatible provider under `providers.openaiCompatible` in `config.yaml`:

```yaml
providers:
  openaiCompatible:
    mistral:
      target: https://api.mistral.ai
```

Then send requests to `/{name}/v1/...`:

```
curl https://localhost:8080/mistral/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $MISTRAL_API_KEY" \
  -d '{
    "model": "mistral-small-latest",
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
  }'
```

### Amazon Bedrock

The proxy signs requests to Bedrock using AWS Signature Version 4 - no AWS credentials are required from the client. Set `providers.bedrock.region` in `config.yaml` to enable this provider.

```
curl https://localhost:8080/model/amazon.titan-text-express-v1/converse \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{"role": "user", "content": [{"text": "Whose social security number is 123-45-6789"}]}],
    "inferenceConfig": {"maxTokens": 512}
  }'
```

## Provider timeouts

Every outbound HTTP client (Philter, each LLM provider, and Bedrock) honors transport-level timeouts so a hung upstream cannot exhaust goroutines or file descriptors. Defaults: 5s connect, 5s TLS handshake, 30s response headers, 90s idle. None of these bound body-read time, so streaming responses can run as long as the upstream keeps producing data. Override per-provider in `config.yaml`:

```yaml
providers:
  openai:
    timeouts:
      responseHeaderMs: 60000   # raise for slow reasoning models
```

See [Configuration -> Provider Timeouts](https://philterd.github.io/philter-ai-proxy/configuration/#provider-timeouts) for the full reference.

## Capacity and concurrency

The proxy can cap the number of requests it processes at any one time. When the cap is reached the proxy responds with `503 Service Unavailable` and a `Retry-After: 1` header instead of queuing or running out of resources.

```yaml
listen:
  maxConcurrentRequests: 200   # global in-flight cap; 0 (default) = unlimited
```

This is a proxy-wide ceiling protecting the proxy and the Philter instance behind it. Per-client concurrency policy belongs to the AI gateway the proxy runs alongside.

### What an in-flight request holds

Each request in flight occupies, until the upstream LLM finishes responding:

- One goroutine (Go starts each at 2 KB and grows as needed; expect a few tens of KB under load).
- One outbound TCP connection to Philter (typically released in tens of milliseconds - only held during the redaction call).
- One outbound TCP connection to the LLM provider, held for the full LLM response time (often **5–60+ seconds** for streaming completions).
- The buffered request and response bodies - bounded by your max request size.

The LLM connection is the dominant cost. With long-tail LLM latency, a small request rate can produce a surprisingly large in-flight count: at 10 RPS with an average 8-second LLM response, steady-state concurrency is ~80.

### Choosing a starting value

A defensible starting point:

```
maxConcurrentRequests = 2 × (target_rps × p95_provider_response_seconds)
```

The `2×` is headroom for tail latency and short bursts. Cross-check against:

- **Your LLM provider's concurrent-request quota.** Set the proxy cap no higher than what your account can actually serve - otherwise you push work into the provider's queue and lose the back-pressure signal here.
- **File descriptors.** Each in-flight request needs ~3 sockets (client + Philter + provider). Default `ulimit -n` of 1024 is exhausted around ~330 concurrent. Raise it before raising the cap.
- **Memory.** Rough estimate: `goroutine + buffers ≈ 50–200 KB per request`. 1,000 concurrent ≈ 50–200 MB just for the proxy state, before request/response bodies.

### Tuning workflow

1. Deploy with a generous cap and `philter_proxy_concurrency_shed_total` set to zero.
2. Watch `philter_proxy_active_requests / philter_proxy_concurrency_limit{scope="global"}` for utilization. PromQL:
   ```
   philter_proxy_active_requests
     / on() philter_proxy_concurrency_limit{scope="global"}
   ```
3. If utilization stays below ~50% at peak, the cap is loose enough.
4. If utilization regularly approaches 1.0 and you see `philter_proxy_concurrency_shed_total{scope="global"}` rising, you have a real capacity problem - **scale out horizontally first** (add replicas) rather than raising the cap. Removing the cap to "fix" sheds turns a graceful 503 into goroutine/FD exhaustion.

### Metrics reference

| Metric | Type | Use |
| --- | --- | --- |
| `philter_proxy_active_requests` | gauge | Current in-flight requests holding a concurrency slot. |
| `philter_proxy_concurrency_limit{scope="global"}` | gauge | Configured global ceiling (0 = unlimited). |
| `philter_proxy_concurrency_shed_total{scope="global"}` | counter | Requests rejected with 503 because the global ceiling was reached. |

## License

Copyright 2023-2026 Philterd, LLC. "Philter" is a registered trademark of Philterd, LLC.

Licensed under the Apache License, version 2.
