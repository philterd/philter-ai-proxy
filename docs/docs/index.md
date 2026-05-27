# Philter AI Proxy

This project is a proxy for OpenAI, Anthropic (Claude), Google Gemini, and Ollama that uses [Philter](https://philterd.ai/philter/) to remove PII, PHI, and other sensitive information from LLM requests before sending them to the provider. Both streaming and non-streaming requests are supported.

## How it Works

The proxy intercepts requests destined for an LLM provider and sends the text content to Philter, where sensitive information is redacted per Philter's policy configuration. The redacted text is then forwarded to the provider. Streaming responses (SSE, chunked JSON, NDJSON) are passed through to the client in real time without buffering.

For example, if you send the following text `How old is John Smith?`, the proxy and Philter will remove the text `John Smith` from the request. The redacted request sent to the API will be `How old is {{{REDACTED-entity}}}?`

Every request produces a structured JSON audit log entry with the provider, model, entity types detected, entity count, and other metadata for compliance and debugging. See [Configuration](configuration.md) for details.
