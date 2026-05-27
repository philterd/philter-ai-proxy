# FAQ

### What is the Philter AI Proxy?

The Philter AI Proxy is a proxy for OpenAI, Anthropic (Claude), Google Gemini, Ollama, and Amazon Bedrock that uses [Philter](https://philterd.ai/philter/) to remove PII, PHI, and other sensitive information from LLM requests before they are sent to the provider.

### Why should I use it?

By using the proxy, you ensure that sensitive information never leaves your environment and is not sent to the AI providers, helping you maintain compliance and protect privacy. Every request produces a structured audit log for compliance reporting.

### Which AI providers are supported?

The proxy supports:

* OpenAI
* Anthropic (Claude)
* Google Gemini
* Ollama
* Amazon Bedrock (Converse API)
* Any OpenAI-compatible provider (Mistral, Cohere, vLLM, LM Studio, etc.) via `providers.openaiCompatible`

Both streaming and non-streaming requests are supported for all providers.

### Does it support streaming?

Yes. Streaming responses (SSE for OpenAI/Anthropic, chunked JSON for Gemini, NDJSON for Ollama) are forwarded to the client in real time without buffering. Inbound prompt redaction works identically for streaming and non-streaming requests.

Outbound response scanning is not applied to streaming responses — the stream is forwarded to the client unchanged and a warning is logged. Outbound scanning applies only to non-streaming responses.

### Is any sensitive data logged?

No. The audit log contains only metadata (provider, model, entity types, counts, latency, etc.). No message content or filtered text is ever logged. Client IP addresses are included, which may be considered personal data under GDPR.

### Do I need a Philter instance?

Yes, the proxy requires a running instance of Philter to perform the redaction. You can launch one in your cloud or on-premise. Visit [philterd.ai](https://philterd.ai/philter/) for more information.

### Can the proxy scan LLM responses for PII, not just requests?

Yes. Outbound response scanning is supported on an opt-in basis. When enabled, the proxy buffers the LLM's response, passes it through Philter, and returns the result to the client. The behavior when PII is detected is configurable: `redact` (replace PII tokens), `block` (return HTTP 403), or `flag` (pass through with a warning log).

Outbound scanning is disabled by default because it adds a Philter round-trip after the provider responds. Enable it only on routes where compliance requires it. See [Configuration](configuration.md#outbound) for details.

### Does outbound scanning add latency?

Yes. When outbound scanning is enabled, the proxy must buffer the full provider response and make an additional request to Philter before returning the response to the client. The added latency equals roughly one Philter round-trip (typically low-double-digit milliseconds on local deployments).

Streaming responses are not scanned — they are forwarded immediately — so streaming requests have no outbound latency overhead.

### How do I configure the proxy?

The proxy is configured via a YAML configuration file. Please refer to the [Configuration](configuration.md) page for all available settings.

### Is the proxy open source?

Yes, the Philter AI Proxy is licensed under the Apache License, version 2.

### Can I use the proxy with Mistral, Cohere, vLLM, or other OpenAI-compatible providers?

Yes. Register any OpenAI-compatible provider under `providers.openaiCompatible` in the config, giving it a short name and a target URL. Clients send requests to `/{name}/v1/...` (e.g., `/mistral/v1/chat/completions`); the proxy strips the prefix and forwards the standard OpenAI-format request to the configured target after running PII redaction. No changes are needed to route configuration — routes work the same way across all OpenAI-compatible providers. See [Configuration](configuration.md#providersopenaicompatible) for details.

### How does Bedrock authentication work?

The proxy handles AWS Signature Version 4 signing internally. The client sends a plain JSON request (no AWS credentials needed). The proxy signs the modified request using credentials from the standard AWS credential chain — environment variables, EC2 instance profile, ECS task role, or IRSA — before forwarding it to Bedrock. This means you never expose AWS credentials to API clients, and access control is enforced at the IAM level on the proxy's role.

### Does the proxy support streaming with Amazon Bedrock?

Not in the current release. The `converseStream` endpoint is planned for a future release. Non-streaming requests via the Converse API are fully supported.

### What happens if Philter is temporarily unavailable?

By default, the proxy retries failed Philter calls up to 3 times with exponential backoff before returning an error to the client. Only transient errors (network timeouts, HTTP 5xx responses) are retried; 4xx errors are not.

For sustained Philter unavailability, enable the circuit breaker (`philter.circuitBreaker.enabled: true`). Once the configured failure threshold is reached, the circuit opens and subsequent requests either receive HTTP 503 immediately (`fallback: block`, the default) or are forwarded unredacted with a warning log (`fallback: passthrough`). After the configured timeout, the circuit allows a probe request through; if it succeeds, the circuit closes.

See [Configuration](configuration.md#philterretrynew) for retry and circuit breaker settings.

### Is commercial support available?

Yes, commercial support for the Philter AI Proxy and Philter is available from [Philterd](https://www.philterd.ai). Please [contact us](https://www.philterd.ai/contact/) for more information.
