# FAQ

### What is the Philter AI Proxy?

A self-hosted proxy for LLM providers that removes PII, PHI, and other sensitive information from requests before they leave your network, and can scan responses on the way back. It runs [Phileas](https://github.com/philterd/phileas) in-process, with a PhEye model for person names included in the Docker image. See the [overview](index.md).

### Why should I use it?

It puts redaction in the network path, where applications cannot skip it, and keeps a record of what was found in each request. It is designed to reduce how much sensitive data reaches LLM providers and to support your compliance efforts. Detection is probabilistic and does not catch every instance, so validate the output against your own data.

### Which AI providers are supported?

* OpenAI
* Azure OpenAI
* Anthropic (Claude)
* Google Gemini
* Google Vertex AI
* Ollama
* Amazon Bedrock (Converse and ConverseStream)
* OpenAI-compatible providers (Mistral, vLLM, LM Studio, and others) configured under `proxy.providers.openai-compatible`

Streaming and non-streaming requests are supported for all of them. See [Usage](usage.md).

### Do I need a Philter instance?

No. Version 2.0 redacts in-process with Phileas, the library under Philter, and needs no other service. Earlier versions (0.x) sent each text to a Philter instance. Policies are the same format in both, so a Philter policy works in the proxy.

### Does it support streaming?

Yes, for every provider. Without response scanning, streamed responses are forwarded as they arrive. With response scanning, the proxy scans the stream as it arrives, holding back a little text so a value split across fragments is scanned whole. See [Streamed responses](api.md#streamed-responses).

### Can the proxy scan LLM responses for PII, not just requests?

Yes, turned on per route. It can redact what it finds, block the response, or return it unchanged and record what it found. See [Response Scanning](api.md#response-scanning-outbound).

### Does response scanning add latency?

Yes. A normal response is scanned after it arrives, which adds about the time it took to redact the request. A streamed response reaches the client a little later than it arrives, since text is held back until it can be scanned. Turn scanning on only for the routes that need it. See [Load tests](load-tests.md).

### Can it redact file uploads, audio, or images?

No. The proxy handles text conversations only. It expects a JSON request body and rejects `multipart/form-data` with `400 invalid_request` / `unsupported_content_type`, so file uploads (`/v1/files`), audio transcriptions (`/v1/audio/transcriptions`), and image edits and variations are not proxied. Route those calls directly to the provider.

The proxy does not parse multipart bodies, so image edits and file uploads will not be supported. Audio is the exception and is tracked in [#40](https://github.com/philterd/philter-ai-proxy/issues/40): its body is binary with no inbound text, so it can be forwarded untouched and the transcript scanned on the way back. See [Supported request types](api.md#supported-request-types).

The proxy redacts text only, and does not inspect what an image, recording, video, or file contains. By default it refuses a JSON request that carries one, such as an `image_url` or `input_audio` content part, with `400 invalid_request` / `media_not_allowed`. Set `media: forward` on a route (or in `proxy.defaults`) to forward those requests with the media unchanged and unredacted. Images and audio in responses are returned unscanned. Remove or redact media before the request reaches the proxy if it can contain sensitive data. See [Images, audio, and files are not redacted](api.md#images-audio-and-files-are-not-redacted).

### Is any sensitive data logged?

The audit log holds metadata only: provider, model, policy, counts of what was found by type, status, and timing. It never holds the text of a prompt or response. It does hold the client's IP address, which may be personal data under GDPR. Metric labels hold no text either.

What the proxy does store is in its database: the policies, hashed API keys, the audit log, and, for contexts, each original value and its replacement, both encrypted with the encryption key.

### How do I configure the proxy?

With `application.yaml` and environment variables. See [Configuration](configuration.md).

### Does the proxy support authentication?

Yes, always. Every request to a provider needs a proxy key in `x-philter-proxy-key`, and the admin API needs a key with the `admin` role. Keys can be limited to providers, models, and paths, and bound to a policy. See [API keys](api.md#api-keys). Mutual TLS is available too; see [Certificates](installation.md#certificates).

### Are API keys hashed at rest?

Yes. Keys are 32 random bytes, and only their SHA-256 hashes are stored. A key is shown once, when it is created.

### Can I run more than one instance?

Each instance needs its own database. The proxy keeps its policies, keys, contexts, and audit log in a SQLite file, and refuses to start on a file another instance is using. For more capacity, give the instance more CPU, or run several instances, each with its own database and keys, behind your gateway.

### Can I deploy the proxy to Kubernetes?

Yes, with the Helm chart or the plain manifests in the repository. See [Kubernetes](kubernetes.md).

### What endpoints should I use for Kubernetes probes?

`/livez` for liveness and `/readyz` for readiness. `/readyz` answers once the configured policies and their models are loaded. See [Health endpoints](monitoring.md#health-endpoints).

### Does the proxy support OpenTelemetry tracing?

Yes. It is off by default; turn it on and set an OTLP endpoint. Each sampled request's trace ID is recorded in its audit entry. See [Distributed Tracing](monitoring.md#distributed-tracing).

### Where can I see throughput and latency numbers?

See [Load tests](load-tests.md) for a reference baseline and how to reproduce it.

### Can I use the proxy with Mistral, vLLM, or other OpenAI-compatible providers?

Yes. Add each under `proxy.providers.openai-compatible` and call it at `/<name>/v1/...`. See [OpenAI-compatible providers](configuration.md#openai-compatible-providers).

### How does Bedrock authentication work?

The proxy signs each request with SigV4 using its own AWS credentials, from the AWS default chain, optionally assuming a role. Clients send no AWS credentials. See [Amazon Bedrock](configuration.md#amazon-bedrock).

### Does the proxy support streaming with Amazon Bedrock?

Yes. `/model/<model>/converse-stream` responses are forwarded, or scanned with response scanning on, in AWS's event stream format.

### Can I bound how many requests the proxy handles at once?

Yes, with `proxy.limits.max-concurrent-requests`. It is off by default. When the limit is reached, the proxy answers `503` with `Retry-After: 1` instead of queuing the request. Per-client limits belong to your AI gateway.

### What format are the proxy's error responses in?

```json
{"error":{"message":"...","type":"...","code":"...","request_id":"..."}}
```

`type` and `code` are stable. Every response carries an `X-Request-Id` header, and the audit entry for the request records the same ID and the error's `type` and `code`. Errors from the provider are returned unchanged, in the provider's format. See [Errors](api.md#errors).

### Can I cap token spend, cache responses, or rate limit?

No. Those belong to an AI gateway, which the proxy is designed to run alongside. The proxy does not track token usage at all. See [Using with an AI Gateway](ai-gateway.md).

### Can the proxy restore the original values in a response?

No. A response comes back with the replacements in it. Re-identification of values encrypted with `CRYPTO_REPLACE` is tracked in [#21](https://github.com/philterd/philter-ai-proxy/issues/21).

### Is the proxy open source?

Yes, under the Apache License 2.0. The source is at [github.com/philterd/philter-ai-proxy](https://github.com/philterd/philter-ai-proxy).

### Is commercial support available?

Yes, commercial support for Philter AI Proxy is available from [Philterd](https://www.philterd.ai). Please [contact us](https://www.philterd.ai/contact/) for more information.
