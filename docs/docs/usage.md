# Usage

Send requests to the proxy exactly as you would to the provider, with the proxy's address in place of the provider's and your proxy key in the `x-philter-proxy-key` header. The provider's own credential travels as usual and is forwarded; the proxy key is not. Streaming (`"stream": true`) and non-streaming requests are supported.

The examples use the self-signed certificate the Docker image serves by default, so `curl` passes `-k`. `$PROXY_KEY` is a key with the `proxy` role; see [Create a key for your application](installation.md#create-a-key-for-your-application).

The proxy decides the provider from the path, as below. A path no provider claims goes to OpenAI.

| Provider | Paths |
|---|---|
| OpenAI | `/v1/...` |
| Azure OpenAI | `/openai/deployments/<deployment>/...` |
| OpenAI-compatible providers | `/<name>/v1/...`, for each name under `proxy.providers.openai-compatible` |
| Anthropic | `/v1/messages` |
| Gemini | paths containing `generateContent`, and `/v1beta/...` |
| Vertex AI | `/v1/projects/<project>/locations/<location>/publishers/google/models/<model>:generateContent` (and `:streamGenerateContent`) |
| Ollama | `/api/generate`, `/api/chat` |
| Amazon Bedrock | `/model/<model>/converse`, `/model/<model>/converse-stream` |

## OpenAI

```bash
curl -k https://localhost:8080/v1/chat/completions \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789?"}]
  }'
```

OpenAI receives `Whose social security number is {{{REDACTED-ssn}}}?`. Add `"stream": true` to stream the response.

The Responses API, legacy completions, embeddings, moderations, image generation, and speech are redacted too; see [Redacted Fields](api.md#redacted-fields). Requests without a body, such as `GET /v1/models`, are forwarded as they are.

From an SDK, set the base URL to the proxy and add the header:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://philter-ai-proxy.internal:8080/v1",
    default_headers={"x-philter-proxy-key": PROXY_KEY},
)
```

## Azure OpenAI

Configure `proxy.providers.azure.target` (see [Configuration](configuration.md#azure-openai)), then call the deployment path:

```bash
curl -k "https://localhost:8080/openai/deployments/my-gpt-4o/chat/completions?api-version=2024-10-21" \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "api-key: $AZURE_OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "Whose social security number is 123-45-6789?"}]}'
```

With `api-version` configured, requests that omit it get the configured one. With `entra-id: true`, the proxy authenticates with its own Entra ID token instead of the client's `api-key`.

## OpenAI-compatible providers

Each provider configured under `proxy.providers.openai-compatible` is reached at `/<name>/v1/...`. The proxy strips the name before forwarding:

```bash
curl -k https://localhost:8080/vllm/v1/chat/completions \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "qwen", "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789?"}]}'
```

## Anthropic (Claude)

```bash
curl -k https://localhost:8080/v1/messages \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-5",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789?"}]
  }'
```

Thinking blocks sent back in a conversation are forwarded unchanged: Anthropic verifies their signatures, so redacting them would make the request fail.

## Gemini

```bash
curl -k "https://localhost:8080/v1beta/models/gemini-2.5-flash:generateContent" \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "x-goog-api-key: $GEMINI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"contents": [{"parts": [{"text": "Whose social security number is 123-45-6789?"}]}]}'
```

The key can also go in the `key` query parameter, which is forwarded. The audit log does not record the path or query string.

For streaming, use `streamGenerateContent?alt=sse`. Without `alt=sse`, Gemini streams a JSON array; with response scanning on, the proxy reads that array whole before scanning it.

## Vertex AI

Configure `proxy.providers.vertex` (see [Configuration](configuration.md#vertex-ai)). The proxy authenticates with Google application default credentials, replacing any `Authorization` the client sends:

```bash
curl -k "https://localhost:8080/v1/projects/my-project/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent" \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"contents": [{"role": "user", "parts": [{"text": "Whose social security number is 123-45-6789?"}]}]}'
```

## Ollama

```bash
curl -k https://localhost:8080/api/chat \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "llama3.2", "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789?"}]}'
```

`/api/generate` redacts `prompt` and `system`. Ollama streams by default, as newline-delimited JSON; send `"stream": false` for one response.

## Amazon Bedrock

Configure `proxy.providers.bedrock.region` (see [Configuration](configuration.md#amazon-bedrock)). The proxy signs each request with its own AWS credentials, so the client sends no AWS headers, and only `Content-Type` and the signature are forwarded:

```bash
curl -k https://localhost:8080/model/anthropic.claude-3-5-haiku-20241022-v1:0/converse \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": [{"text": "Whose social security number is 123-45-6789?"}]}]}'
```

`/converse-stream` streams the response in AWS's event stream format.

## Tool Use and Function Calling

Tool calls and their results are redacted with the rest of the conversation:

- **OpenAI**: `tool_calls[].function.arguments` and legacy `function_call.arguments` are parsed as JSON, each string in them is redacted, and the JSON is written back. Tool results arrive as `role: tool` messages, whose content is redacted like any message.
- **Anthropic**: `tool_use` input (each string) and `tool_result` content (a string or text blocks).
- **Gemini and Vertex AI**: `functionCall.args` and `functionResponse.response` (each string, at any depth).
- **Ollama**: `tool_calls[].function.arguments` (each string).
- **Bedrock**: `toolUse.input` and `toolResult.content` (text and JSON).

Arguments that are not valid JSON are redacted as text.

## Response Scanning

Scanning provider responses is turned on per route; see [Configuration](configuration.md#routes). For example, to scan every response and redact what is found:

```yaml
proxy:
  defaults:
    outbound:
      enabled: true
      action: redact
```

Streamed responses are scanned as they arrive. See [Response Scanning](api.md#response-scanning-outbound) for what is scanned and how each action behaves.

## Health Check

```bash
curl -k https://localhost:8080/health
```

```json
{"status":"UP","applicationVersion":"2.0.0"}
```

See [Health endpoints](monitoring.md#health-endpoints) for `/livez` and `/readyz`.
