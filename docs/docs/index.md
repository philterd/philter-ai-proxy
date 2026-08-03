# Philter AI Proxy

This project is a proxy for OpenAI, Azure OpenAI, Anthropic (Claude), Google Gemini (public API and Vertex AI), Ollama, and Amazon Bedrock that uses [Philter](https://philterd.ai/philter/) to remove PII, PHI, and other sensitive information from LLM requests before sending them to the provider. Both streaming and non-streaming requests are supported.

## How it Works

The proxy intercepts requests destined for an LLM provider and sends all text-bearing fields to Philter, where sensitive information is redacted per Philter's policy configuration. The redacted request is then forwarded to the provider. Streaming responses (SSE, chunked JSON, NDJSON) are passed through to the client in real time without buffering.

For example, if you send the text `How old is John Smith?`, the proxy will remove `John Smith` before forwarding. The request sent to the provider becomes `How old is {{{REDACTED-entity}}}?`

Inbound redaction covers all message types, including agentic and tool-use workflows:

| Provider | Fields redacted |
|----------|-----------------|
| OpenAI | `messages[].content` (all roles: `user`, `system`, `tool`), `tool_calls[].function.arguments` (parsed as JSON, string values redacted, re-serialized) |
| Anthropic | `system`, `messages[].content` (`text` and `tool_result` blocks) |
| Gemini | `contents[].parts[].text`, `contents[].parts[].functionResponse.response` (recursive) |
| Ollama | `messages[].content`, `prompt`, `system` |

**Outbound response scanning** is also supported on an opt-in basis. When enabled, the LLM's response is scanned through Philter before it reaches the client, guarding against hallucinated or training-data PII in responses. The behaviour when PII is found is configurable: redact it, block the response entirely, or pass it through with a warning log. See [Configuration](configuration.md#outbound) for details.

Every request produces a structured JSON audit log entry with the provider, model, entity types detected, entity count, and other metadata for compliance and debugging. See [Configuration](configuration.md) for details.

## Deployment options

The proxy ships as a single Go binary. From there:

- **Local / VM** - run the binary directly with `--config config.yaml`. See [Installation](installation.md).
- **Docker** - a multi-arch image at `philterd/philter-ai-proxy`. See [Installation → Docker](installation.md#docker).
- **Kubernetes** - first-party Helm chart and plain manifests under `deploy/`, plus a starter Grafana dashboard. See [Kubernetes Quickstart](kubernetes.md).

## Scope

The proxy does redaction and the audit trail that goes with it. It deliberately does not do routing, failover, token quotas, or per-tenant billing; those belong to an AI gateway, and the proxy is designed to run alongside one. See [Using with an AI Gateway](ai-gateway.md).
