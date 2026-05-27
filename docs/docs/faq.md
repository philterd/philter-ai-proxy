# FAQ

### What is the Philter AI Proxy?

The Philter AI Proxy is a proxy for OpenAI, Anthropic (Claude), Google Gemini, and Ollama that uses [Philter](https://philterd.ai/philter/) to remove PII, PHI, and other sensitive information from LLM requests before they are sent to the provider.

### Why should I use it?

By using the proxy, you ensure that sensitive information never leaves your environment and is not sent to the AI providers, helping you maintain compliance and protect privacy. Every request produces a structured audit log for compliance reporting.

### Which AI providers are supported?

The proxy supports:

* OpenAI
* Anthropic (Claude)
* Google Gemini
* Ollama

Both streaming and non-streaming requests are supported for all providers.

### Does it support streaming?

Yes. Streaming responses (SSE for OpenAI/Anthropic, chunked JSON for Gemini, NDJSON for Ollama) are forwarded to the client in real time without buffering. Inbound prompt redaction works identically for streaming and non-streaming requests.

### Is any sensitive data logged?

No. The audit log contains only metadata (provider, model, entity types, counts, latency, etc.). No message content or filtered text is ever logged. Client IP addresses are included, which may be considered personal data under GDPR.

### Do I need a Philter instance?

Yes, the proxy requires a running instance of Philter to perform the redaction. You can launch one in your cloud or on-premise. Visit [philterd.ai](https://philterd.ai/philter/) for more information.

### How do I configure the proxy?

The proxy is configured via environment variables. Please refer to the [Configuration](configuration.md) page for a list of all available variables.

### Is the proxy open source?

Yes, the Philter AI Proxy is licensed under the Apache License, version 2.

### Is commercial support available?

Yes, commercial support for the Philter AI Proxy and Philter is available from [Philterd](https://www.philterd.ai). Please [contact us](https://www.philterd.ai/contact/) for more information.
