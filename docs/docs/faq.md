# FAQ

### What is the Philter AI Proxy?

The Philter AI Proxy is a proxy for OpenAI, Azure OpenAI, Anthropic (Claude), Google Gemini (public API and Vertex AI), Ollama, and Amazon Bedrock that uses [Philter](https://philterd.ai/philter/) to remove PII, PHI, and other sensitive information from LLM requests before they are sent to the provider.

### Why should I use it?

By using the proxy, you ensure that sensitive information never leaves your environment and is not sent to the AI providers, helping you maintain compliance and protect privacy. Every request produces a structured audit log for compliance reporting.

### Which AI providers are supported?

The proxy supports:

* OpenAI
* Azure OpenAI
* Anthropic (Claude)
* Google Gemini
* Google Vertex AI
* Ollama
* Amazon Bedrock (Converse and ConverseStream APIs)
* Any OpenAI-compatible provider (Mistral, Cohere, vLLM, LM Studio, etc.) via `providers.openaiCompatible`

Both streaming and non-streaming requests are supported for all providers.

### Does it support streaming?

Yes. Streaming responses (SSE for OpenAI/Anthropic, chunked JSON for Gemini, NDJSON for Ollama) are forwarded to the client in real time without buffering. Inbound prompt redaction works identically for streaming and non-streaming requests.

Outbound response scanning can only inspect non-streaming responses. Under `action: redact` or `flag` the stream is forwarded unchanged and a warning is logged. Under `action: block` the proxy rejects the response with `403` instead of forwarding an unscanned body, so a client cannot bypass a configured block by requesting a stream.

### Can it redact file uploads, audio, or images?

No. The proxy handles text conversations only. It expects a JSON request body and rejects `multipart/form-data` with `400 invalid_request` / `unsupported_content_type`, so file uploads (`/v1/files`), audio transcriptions (`/v1/audio/transcriptions`), and image edits and variations are not proxied. Route those calls directly to the provider.

File uploads will not be supported: a batch file is many embedded requests, and redacting one upload would mean one Philter call per record inside a single synchronous request. Redact the file contents with Philter before uploading. Audio ([#40](https://github.com/philterd/philter-ai-proxy/issues/40)) and image edits ([#41](https://github.com/philterd/philter-ai-proxy/issues/41)) are tracked for support.

### Is any sensitive data logged?

No. The audit log contains only metadata (provider, model, entity types, counts, latency, etc.). No message content or filtered text is ever logged. Client IP addresses are included, which may be considered personal data under GDPR.

The same holds for the application log and for Prometheus metric labels, which are exported to anyone who can scrape `/metrics`. A regression test drives distinctively marked content through inbound redaction, all three outbound actions, a streaming response, and the error paths, then asserts the markers appear in none of the three. Adding a field to the audit entry fails that test until the field is declared as metadata, so the guarantee is enforced rather than maintained by convention.

### Do I need a Philter instance?

Yes, the proxy requires a running instance of Philter to perform the redaction. You can launch one in your cloud or on-premise. Visit [philterd.ai](https://philterd.ai/philter/) for more information.

### Can the proxy scan LLM responses for PII, not just requests?

Yes. Outbound response scanning is supported on an opt-in basis. When enabled, the proxy buffers the LLM's response, passes it through Philter, and returns the result to the client. The behavior when PII is detected is configurable: `redact` (replace PII tokens), `block` (return HTTP 403), or `flag` (pass through with a warning log).

Outbound scanning is disabled by default because it adds a Philter round-trip after the provider responds. Enable it only on routes where compliance requires it. See [Configuration](configuration.md#outbound) for details.

### Does outbound scanning add latency?

Yes. When outbound scanning is enabled, the proxy must buffer the full provider response and make an additional request to Philter before returning the response to the client. The added latency equals roughly one Philter round-trip (typically low-double-digit milliseconds on local deployments).

Streaming responses cannot be scanned. Under `redact` and `flag` they are forwarded immediately, so those requests carry no outbound latency overhead; under `block` they are rejected rather than forwarded.

### How do I configure the proxy?

The proxy is configured via a YAML configuration file. Please refer to the [Configuration](configuration.md) page for all available settings.

### Can I deploy the proxy to Kubernetes?

Yes. A production-ready Helm chart lives at `deploy/helm/philter-ai-proxy/` in the repo, and plain manifests for non-Helm users at `deploy/k8s/`. The chart supports replicas, autoscaling, Pod Disruption Budgets, optional Ingress, Prometheus Operator `ServiceMonitor`, mTLS, and TLS issuance via either an existing Secret or cert-manager. A starter Grafana dashboard at `deploy/grafana/philter-ai-proxy.json` covers every emitted metric. See the [Kubernetes Quickstart](kubernetes.md) for the full walkthrough.

### Is the proxy open source?

Yes, the Philter AI Proxy is licensed under the Apache License, version 2.

### Does the proxy support authentication?

Yes. API key authentication and mTLS are both supported, and both are disabled by default.

For API key authentication, configure one or more keys under `auth.apiKeys` in the config. Clients send the key in the `x-philter-proxy-key` header (configurable). Requests without a valid key receive HTTP `401`. Each key can optionally be bound to a specific Philter policy, which lets an admin issue a key to the healthcare team that always uses the HIPAA policy regardless of what the client requests. The proxy's auth header is always stripped before forwarding, so LLM providers never see it.

For zero-trust service-to-service authentication, set `listen.clientCA` to a CA certificate. The proxy will require and verify a client TLS certificate on every connection. API key auth and mTLS can be used simultaneously. See [Configuration](configuration.md#authentication) for details and examples.

### Where can I see throughput and latency numbers for the proxy?

A k6 load-test harness lives at [`test/load/`](https://github.com/philterd/philter-ai-proxy/tree/main/test/load) in the repo, with a self-contained docker-compose stack (Philter + a stub LLM provider + the proxy) and five scenarios covering inbound redaction, outbound response scanning, streaming, and a no-proxy baseline for comparison. A reference baseline measured on a single-host Intel i5-11400 - including the OpenAI proxy path at ~2,900 req/s p95=8.8ms, and outbound-scan at ~1,400 req/s p95=32ms - is published at [Load tests](load-tests.md). A scheduled GitHub Actions workflow re-runs the harness weekly and uploads summary JSONs as artifacts.

### Does the proxy support OpenTelemetry tracing?

Yes. With `tracing.enabled: true` in the config, the proxy emits OTLP spans: one root span per inbound request, child spans for each Philter call and each upstream LLM provider call. Trace context is propagated to the upstream via the W3C `traceparent` header, so end-to-end traces work across the proxy in any APM (Jaeger, Honeycomb, Datadog, Grafana Tempo, etc.). Exporter destination, protocol, headers, and sampler are configured via the standard OTel env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_TRACES_SAMPLER`, etc.).

Tracing is off by default. Even with `tracing.enabled: true` the default sampler is `always_off`, so spans only flow when an operator explicitly sets `OTEL_TRACES_SAMPLER`. The `trace_id` appears in audit log entries when a request is sampled so APM traces and audit lines can be cross-referenced by ID. See [Distributed Tracing](monitoring.md#distributed-tracing) for the full reference.

### What endpoints should I use for Kubernetes probes?

Point liveness at `/livez` and readiness at `/readyz`. `/livez` always returns 200 as long as the process is running, so transient Philter outages don't restart healthy pods. `/readyz` returns 503 only when the Philter circuit breaker is open with `fallback: block` - the proxy can't serve any traffic in that state. In every other state (no breaker, breaker closed, half-open, or open with `fallback: passthrough`) `/readyz` returns 200. The first-party Helm chart and plain manifests already use these endpoints. The legacy `/health` endpoint is retained for backwards compatibility but is deprecated; treating Philter unreachability as a liveness failure is the exact failure mode the split fixes. See [Monitoring -> Health Endpoints](monitoring.md#health-endpoints).

### Are API keys hashed at rest?

Yes. Keys are hashed when the config is loaded and never held in memory as plaintext. The `auth.apiKeys[].key` field accepts plaintext (auto-hashed with SHA256 at load), `sha256$<64-hex>` for a pre-hashed value, or `bcrypt$<bcrypt-hash>` for users with existing bcrypt key-management workflows. Verification uses constant-time comparison. For production, pre-hash externally so the plaintext never appears in your YAML, source control, or container images. See [API Key Hashing](configuration.md#api-key-hashing) for format details, latency per algorithm, and CLI recipes for generating pre-hashed values.

To keep the secret out of the config file entirely, the `key:` field also accepts `${ENV_VAR}` (read from an environment variable) and `file:/path/to/secret` (read from a mounted file) references, resolved at load and then hashed like any other value. This is the recommended way to integrate with environment-injected secrets, Kubernetes/Docker secrets, Vault, or AWS Secrets Manager. See [Loading secrets from environment variables and files](configuration.md#loading-secrets-from-environment-variables-and-files) and the [key-rotation procedure](configuration.md#rotating-api-keys).

### Can I cap token spend or get per-customer usage for billing?

Not in the proxy. Token quotas, usage export, and per-tenant billing are the job of an AI gateway, and the proxy is designed to run alongside one rather than duplicate it. See [Using with an AI Gateway](ai-gateway.md).

### Can I cache responses to repeated prompts?

Not in the proxy. Response caching is traffic management, which belongs to the AI gateway the proxy runs alongside. Caching in the proxy would also mean storing provider responses keyed by tenant, which adds a cross-tenant exposure risk to a component whose job is to reduce that risk. See [Using with an AI Gateway](ai-gateway.md).

### Do the proxy's replicas need shared state?

No. The proxy keeps no state that has to be shared between replicas, so you can scale it horizontally without a database, cache, or coordination service.

### Does the proxy rate limit requests?

No. Rate limiting, routing, failover, and spend controls belong to an AI gateway running alongside the proxy. See [Using with an AI Gateway](ai-gateway.md).

### Can I use the proxy with Mistral, Cohere, vLLM, or other OpenAI-compatible providers?

Yes. Register any OpenAI-compatible provider under `providers.openaiCompatible` in the config, giving it a short name and a target URL. Clients send requests to `/{name}/v1/...` (e.g., `/mistral/v1/chat/completions`); the proxy strips the prefix and forwards the standard OpenAI-format request to the configured target after running PII redaction. No changes are needed to route configuration - routes work the same way across all OpenAI-compatible providers. See [Configuration](configuration.md#providersopenaicompatible) for details.

### How does Bedrock authentication work?

The proxy handles AWS Signature Version 4 signing internally. The client sends a plain JSON request (no AWS credentials needed). The proxy signs the modified request using credentials from the standard AWS credential chain - environment variables, EC2 instance profile, ECS task role, or IRSA - before forwarding it to Bedrock. This means you never expose AWS credentials to API clients, and access control is enforced at the IAM level on the proxy's role.

### Does the proxy support streaming with Amazon Bedrock?

Yes. The `/model/{modelId}/converse-stream` endpoint is supported: the inbound request is redacted as usual and the AWS binary event-stream response is forwarded to the client incrementally (no buffering). As with the other providers, the streamed response body is passed through without outbound scanning. Non-streaming requests via the Converse API are also fully supported.

### What happens if Philter is temporarily unavailable?

By default, the proxy retries failed Philter calls up to 3 times with exponential backoff before returning an error to the client. Only transient errors (network timeouts, HTTP 5xx responses) are retried; 4xx errors are not.

For sustained Philter unavailability, enable the circuit breaker (`philter.circuitBreaker.enabled: true`). Once the configured failure threshold is reached, the circuit opens and subsequent requests either receive HTTP 503 immediately (`fallback: block`, the default) or are forwarded unredacted with a warning log (`fallback: passthrough`). After the configured timeout, the circuit allows a probe request through; if it succeeds, the circuit closes.

See [Configuration](configuration.md#philterretry) for retry and circuit breaker settings.

### Can I bound how many concurrent requests the proxy will handle?

Yes. Set `listen.maxConcurrentRequests` to cap the total number of in-flight requests across the whole proxy. It is off by default. When the cap is reached, the proxy returns HTTP `503` with `Retry-After: 1` and the JSON body `{"error":{"message":"concurrency limit exceeded","type":"capacity"}}` instead of queuing the request. Per-client concurrency policy belongs to your AI gateway; the proxy's cap exists to protect itself and Philter from overload. The two metrics to watch are `philter_proxy_active_requests` (current utilization) and `philter_proxy_concurrency_shed_total{scope}` (rejections by scope). See [Configuration](configuration.md#concurrency-limits) for sizing guidance and [Monitoring](monitoring.md#concurrency) for the PromQL utilization recipe.

### What format are the proxy's error responses in?

All errors the proxy generates itself are structured JSON with the shape:

```json
{"error":{"message":"...","type":"...","code":"...","request_id":"..."}}
```

`Content-Type: application/json` and an `X-Request-Id` header carrying the same `request_id` are always set. The `(type, code)` pair is a stable enum - codes will not be removed or repurposed across minor versions. The full table lives at [Configuration → Error Responses](configuration.md#error-responses).

To trace a failed request: grab the `X-Request-Id` header from the response, then search audit logs for `request_id=<that value>`. The audit entry's `error_type` and `error_code` will match what the client received.

Errors that originate from the upstream LLM provider are forwarded through unchanged and follow the provider's own format, not the schema above.

### Does the proxy track token usage?

No. Token counts appear in neither the audit log nor the metrics. They say nothing about redaction, which is what this proxy exists to do and what its audit trail is evidence of. Tracking them would mean carrying usage-parsing for every provider and streaming format the proxy supports, to produce a partial copy of data the provider already reports accurately.

Use your AI gateway's accounting, or the provider's own usage dashboard. See [Using with an AI Gateway](ai-gateway.md).

### Is commercial support available?

Yes, commercial support for the Philter AI Proxy and Philter is available from [Philterd](https://www.philterd.ai). Please [contact us](https://www.philterd.ai/contact/) for more information.
