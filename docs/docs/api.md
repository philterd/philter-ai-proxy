# API Reference

The Philter AI Proxy provides several endpoints to redact sensitive information before sending requests to AI providers. All endpoints support both streaming and non-streaming requests.

## Redacted Fields

The proxy inspects and redacts all text-bearing fields in the request body before forwarding. The table below lists exactly which fields are redacted per provider.

| Provider | Message type | Fields redacted |
|----------|-------------|-----------------|
| OpenAI / OpenAI-compatible | `role: user` | `content` (string) |
| OpenAI / OpenAI-compatible | `role: system` | `content` (string) |
| OpenAI / OpenAI-compatible | `role: tool` | `content` (string) |
| OpenAI / OpenAI-compatible | `role: assistant` with tool calls | `tool_calls[].function.arguments` — parsed as JSON, string values redacted, re-serialized |
| Anthropic | Top-level | `system` (string) |
| Anthropic | `text` content block | `text` |
| Anthropic | `tool_result` content block | `content` (string or nested `text` blocks) |
| Gemini | `text` part | `text` |
| Gemini | `functionResponse` part | `response` object — all string values redacted recursively |
| Ollama generate | — | `prompt`, `system` |
| Ollama chat | `role: *` | `content` |
| Bedrock Converse | Top-level | `system[].text` |
| Bedrock Converse | `messages[].content[]` | `text` |

Fields not in the table (e.g., model names, IDs, non-string values) are forwarded unchanged.

## Response Scanning (Outbound)

By default, provider responses are forwarded to the client without modification. When outbound scanning is enabled for a route, the proxy buffers the provider's response and passes each text field through Philter before returning it to the client.

### Response fields scanned per provider

| Provider | Response fields scanned |
|----------|------------------------|
| OpenAI / OpenAI-compatible | `choices[].message.content` |
| Anthropic | `content[].text` (where `type == "text"`) |
| Gemini | `candidates[].content.parts[].text` |
| Ollama generate | `response` |
| Ollama chat | `message.content` |
| Bedrock Converse | `output.message.content[].text` |

### Actions

The `outbound.action` setting controls what happens when PII is detected in a response:

| Action | HTTP status | Description |
|--------|------------|-------------|
| `redact` (default) | `200` | Detected PII is replaced with Philter's configured token before the response is returned |
| `block` | `403` | The response is suppressed entirely; the error body below is returned |
| `flag` | `200` | The original unmodified response is returned; a warning is written to the proxy log |

**Block error response** (`403 Forbidden`):
```json
{"error":{"message":"response blocked: PII detected","type":"pii_blocked"}}
```

### Streaming responses

Outbound scanning applies only to non-streaming responses. When the provider returns a streaming response (`Content-Type: text/event-stream` or `application/x-ndjson`), the proxy skips scanning, logs a warning, and forwards the stream to the client unchanged. Inbound prompt redaction is unaffected.

### Latency

Outbound scanning adds a full Philter round-trip after the provider responds. For latency-sensitive workloads, enable it only on routes where compliance requires it. See [Configuration](configuration.md#outbound) for configuration details.

## Route Detection

The proxy routes requests based on the URL path:

| Path pattern | Provider |
|---|---|
| `/v1/messages` | Anthropic |
| Path containing `generateContent` (case-insensitive) | Gemini |
| `/api/generate` | Ollama |
| `/api/chat` | Ollama |
| `/model/{modelId}/converse` | Amazon Bedrock |
| `/{name}/v1/...` | OpenAI-compatible (configured via `providers.openaiCompatible`) |
| `/health` | Health check (no proxying) |
| All other paths | OpenAI |

## Endpoints

### OpenAI Chat Completions

- **URL**: `/v1/chat/completions`
- **Method**: `POST`
- **Streaming**: Set `"stream": true` in the request body. Response is SSE (`text/event-stream`).
- **Example**:
  ```bash
  curl -k https://localhost:8080/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -d '{
      "model": "gpt-4",
      "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
    }'
  ```

### Anthropic Messages

- **URL**: `/v1/messages`
- **Method**: `POST`
- **Streaming**: Set `"stream": true` in the request body. Response is SSE (`text/event-stream`).
- **Example**:
  ```bash
  curl -k https://localhost:8080/v1/messages \
    -H "Content-Type: application/json" \
    -H "x-api-key: $ANTHROPIC_API_KEY" \
    -H "anthropic-version: 2023-06-01" \
    -d '{
      "model": "claude-sonnet-4-20250514",
      "max_tokens": 1024,
      "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
    }'
  ```

### Gemini Generate Content

- **URL**: `/v1beta/models/{model}:generateContent`
- **Method**: `POST`
- **Streaming**: Use `:streamGenerateContent` instead of `:generateContent`. Response is chunked JSON.
- **Note**: The Gemini API passes the API key as a URL query parameter (`?key=...`) rather than a header. The proxy forwards the query string to the provider but never logs API keys — sensitive query parameters are redacted from all log and error output.
- **Example**:
  ```bash
  curl -k "https://localhost:8080/v1beta/models/gemini-2.0-flash:generateContent?key=$GEMINI_API_KEY" \
      -H 'Content-Type: application/json' \
      -X POST \
      -d '{
        "contents": [{
          "parts":[{"text": "Whose social security number is 123-45-6789"}]
        }]
      }'
  ```

### Ollama Generate

- **URL**: `/api/generate`
- **Method**: `POST`
- **Streaming**: Ollama streams by default (NDJSON). Set `"stream": false` to receive a single response.
- **Example**:
  ```bash
  curl -k https://localhost:8080/api/generate \
    -H "Content-Type: application/json" \
    -d '{
      "model": "llama3",
      "prompt": "Whose social security number is 123-45-6789",
      "stream": false
    }'
  ```

### Ollama Chat

- **URL**: `/api/chat`
- **Method**: `POST`
- **Streaming**: Ollama streams by default (NDJSON). Set `"stream": false` to receive a single response.
- **Example**:
  ```bash
  curl -k https://localhost:8080/api/chat \
    -H "Content-Type: application/json" \
    -d '{
      "model": "llama3",
      "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}],
      "stream": false
    }'
  ```

### Amazon Bedrock Converse

- **URL**: `/model/{modelId}/converse`
- **Method**: `POST`
- **Authentication**: The proxy signs requests to Bedrock using AWS Signature Version 4 with credentials from the standard AWS credential chain (environment variables, `~/.aws/credentials`, EC2/ECS instance profile, IRSA). The client does **not** need to supply AWS credentials.
- **Streaming**: Not supported in the current release (`converseStream` is deferred).
- **Required configuration**: `providers.bedrock.region` must be set. See [Configuration](configuration.md#providersbedrock) for details.
- **Example**:
  ```bash
  curl -k https://localhost:8080/model/amazon.titan-text-express-v1/converse \
    -H "Content-Type: application/json" \
    -d '{
      "messages": [{"role": "user", "content": [{"text": "Whose SSN is 123-45-6789?"}]}],
      "inferenceConfig": {"maxTokens": 512}
    }'
  ```

### OpenAI-Compatible Providers

- **URL**: `/{name}/v1/chat/completions` (or any `/{name}/v1/...` path)
- **Method**: `POST`
- **Streaming**: Supported. Behaviour is identical to the OpenAI endpoint.
- **Required configuration**: The provider must be registered under `providers.openaiCompatible` in the config. See [Configuration](configuration.md#providersopenaicompatible) for details.
- **Example** (Mistral):
  ```bash
  curl -k https://localhost:8080/mistral/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $MISTRAL_API_KEY" \
    -d '{
      "model": "mistral-small-latest",
      "messages": [{"role": "user", "content": "Whose SSN is 123-45-6789?"}]
    }'
  ```

The proxy strips the `/{name}` prefix before forwarding, so the provider receives a standard OpenAI-format request. All PII redaction and audit logging applies normally; the `provider` field in the audit log is set to the registered name (e.g., `mistral`).

### Health Check

- **URL**: `/health`
- **Method**: `GET`
- **Description**: Returns the health status of the proxy.
- **Response**: `200 OK` with body `ok`.
- **Example**:
  ```bash
  curl -k https://localhost:8080/health
  ```
