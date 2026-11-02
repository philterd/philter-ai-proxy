# Philter AI Proxy

Philter AI Proxy is a self-hosted proxy for OpenAI, Azure OpenAI, Anthropic (Claude), Google Gemini (public API and Vertex AI), Ollama, Amazon Bedrock, and OpenAI-compatible providers. It removes PII, PHI, and other sensitive information from LLM requests before they leave your network, and can scan the responses on the way back. Streaming and non-streaming requests are supported.

Redaction runs inside the proxy with [Phileas](https://github.com/philterd/phileas), the library under [Philter](https://philterd.ai/philter/). Policies are standard Phileas policies, so a policy works the same in the proxy and in Philter, except that the proxy refuses policies that name a PhEye service, generators, or files and environment variables the deployment has not allowed; see [What a policy may not do](policies.md#what-a-policy-may-not-do). The proxy needs no other service: person names are detected with a PhEye model that ships in the Docker image and runs in-process.

## How it Works

The proxy receives the request an application would send to the provider, redacts the text in it according to a policy, and forwards the redacted request with the application's own provider credentials (for Vertex AI, Amazon Bedrock, and Azure OpenAI with Entra ID, the proxy authenticates with its own). For example, the request text `How old is George Washington?` reaches the provider as `How old is {{{REDACTED-name}}}?`.

- **Inbound redaction** covers the text of every message, including system prompts, content parts, refusals, and tool-call arguments and results. See [Redacted Fields](api.md#redacted-fields).
- **Outbound scanning**, turned on per route, scans the provider's response before it reaches the application: redact what it finds, block the response, or pass it through and record what was found. Streamed responses are scanned as they arrive. See [Response Scanning](api.md#response-scanning-outbound).
- **Policies** are managed through an admin API with the paths of Philter's policy API, under `/admin`. See [Policies](policies.md).
- **Consistent pseudonymization**: a context keeps the replacement chosen for a value, so the same value is replaced the same way across requests. See [Contexts](policies.md#contexts).
- **An audit log** records each request's metadata (provider, model, policy, how many values of each type were found), never the text of a prompt or response. See [Monitoring](monitoring.md#audit-log).

Detection is probabilistic: the proxy reduces how much sensitive data reaches a provider, and it does not catch every instance. Validate its output against your own data and policies.

## Deployment options

- **Docker**: the `philterd/philter-ai-proxy` image, with the person-name model included. See [Installation](installation.md).
- **From source**: build with Maven and run the jar on Java 25. See [Installation](installation.md#building-from-source).

The proxy keeps its policies, API keys, contexts, and audit log in a SQLite file, so one instance serves each database file. See [FAQ](faq.md#can-i-run-more-than-one-instance).

## Scope

The proxy does redaction and the audit trail that goes with it. It deliberately does not do routing, failover, token quotas, or per-tenant billing; those belong to an AI gateway, and the proxy is designed to run alongside one. See [Using with an AI Gateway](ai-gateway.md).

It also handles **text conversations only**. The proxy accepts JSON request bodies and does not parse `multipart/form-data`, so file uploads, audio, and image edits are rejected with `400 invalid_request` / `unsupported_content_type`. Audio support is tracked in [#40](https://github.com/philterd/philter-ai-proxy/issues/40); image edits and file uploads are not planned. See [Supported request types](api.md#supported-request-types).

Only text is redacted. A JSON request carrying images, audio, video, or files (such as image and audio content parts) is refused by default, or forwarded with the media unchanged and uninspected when `media` is set to `forward`. Media in responses is returned unscanned. See [Images, audio, and files are not redacted](api.md#images-audio-and-files-are-not-redacted).
