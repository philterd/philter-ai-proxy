# Philter AI Proxy

A self-hosted proxy for OpenAI, Azure OpenAI, Anthropic (Claude), Google Gemini, Vertex AI, Ollama, Amazon Bedrock, and OpenAI-compatible providers that removes PII, PHI, and other sensitive information from LLM requests before they leave your network, and can scan the responses on the way back.

Redaction runs inside the proxy with [Phileas](https://github.com/philterd/phileas), the library under [Philter](https://philterd.ai/philter/). Policies are standard Phileas policies, managed through an admin API with the same paths as Philter's. The Docker image includes a PhEye model for finding person names, which runs in-process, so the proxy needs no other service.

For example, the request text `How old is George Washington?` reaches the provider as `How old is {{{REDACTED-name}}}?`. Responses can be scanned per route: redact what is found, block the response, or pass it through and record what was found. Streamed responses are scanned as they arrive. Each request produces an audit entry with its metadata, never the text.

Detection is probabilistic: the proxy is designed to reduce how much sensitive data reaches a provider, and it does not catch every instance. Validate its output against your own data.

View the [documentation](https://philterd.github.io/philter-ai-proxy).

## Scope

The proxy does redaction and the audit trail that goes with it. Three boundaries are deliberate:

- **It is not an AI gateway.** Routing, failover, token quotas, and per-tenant billing belong to a gateway such as LiteLLM, Portkey, or Kong AI Gateway. The proxy is designed to run alongside one, redacting on the last hop before traffic leaves your network. See [Using with an AI Gateway](https://philterd.github.io/philter-ai-proxy/ai-gateway/).
- **It handles text conversations only.** The proxy accepts JSON request bodies and does not parse `multipart/form-data`, so file uploads, audio, and image edits are rejected with `400 invalid_request` / `unsupported_content_type` and should be routed directly to the provider. Audio support is tracked in [#40](https://github.com/philterd/philter-ai-proxy/issues/40); image edits and file uploads are not planned.
- **It refuses what it cannot redact.** A request with a body to an endpoint the proxy does not know how to redact (such as `/v1/batches` or `/v1/threads/{id}/messages`) is refused with `400 invalid_request` / `unsupported_endpoint` unless `unsupported-endpoints: forward` is set for it.
- **It redacts text only.** A JSON request carrying images, audio, video, or files (such as image and audio content parts) is refused by default with `400 invalid_request` / `media_not_allowed`. Setting `media: forward` forwards such requests with the media unchanged and uninspected. Media in responses is returned unscanned. See [Images, audio, and files are not redacted](https://philterd.github.io/philter-ai-proxy/api/#images-audio-and-files-are-not-redacted).

## Running the Proxy

```bash
export ENCRYPTION_KEY="$(openssl rand -hex 32)"      # keep a copy: the database cannot be read without it
export BOOTSTRAP_API_KEY="$(openssl rand -hex 32)"

docker run -d --name philter-ai-proxy \
  -p 8080:8080 -p 127.0.0.1:9090:9090 \
  -v philter-ai-proxy-data:/var/lib/philter-ai-proxy \
  -e PHILTER_AI_PROXY_ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  -e PHILTER_AI_PROXY_BOOTSTRAP_API_KEY="$BOOTSTRAP_API_KEY" \
  philterd/philter-ai-proxy:2.0.0
```

Create a key for your application, then send it requests as you would send them to the provider, with the key in `x-philter-proxy-key`:

```bash
curl -k https://localhost:8080/admin/api/keys \
  -H "Authorization: Bearer $BOOTSTRAP_API_KEY" -H "Content-Type: application/json" \
  -d '{"name": "my-app", "roles": ["proxy"]}'

curl -k https://localhost:8080/v1/chat/completions \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789?"}]}'
```

The image serves HTTPS with a self-signed certificate it generates at startup, hence `-k`. See [Installation](https://philterd.github.io/philter-ai-proxy/installation/) for your own certificate, settings, and building from source, and [Kubernetes](https://philterd.github.io/philter-ai-proxy/kubernetes/) for the Helm chart.

## Building

The build needs Java 25.

```bash
./mvnw verify                 # build, run the tests, and check coverage
docker build -t philter-ai-proxy .
```

## Community

Users and developers are welcome in the [Philterd Slack workspace](https://philterd.ai/slack/). It's the place to ask questions, share feedback, and discuss contributions.

## License

Copyright 2023-2026 Philterd, LLC. "Philter" is a registered trademark of Philterd, LLC.

Licensed under the Apache License, version 2.
