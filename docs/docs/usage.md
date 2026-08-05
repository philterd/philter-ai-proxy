# Usage

To use this proxy, send requests to it exactly as you would to the LLM provider, but change the hostname to your proxy's address. Both streaming (`"stream": true`) and non-streaming requests are supported.

## OpenAI

```bash
curl -k https://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
  }'
```

With streaming:

```bash
curl -k -N https://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}],
    "stream": true
  }'
```

## Anthropic (Claude)

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

## Gemini

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

**Note:** The Gemini API passes the API key as a URL query parameter rather than a header. The proxy forwards the query string to the provider but never logs API keys - sensitive query parameters are redacted from all log and error output.

For streaming, use the `streamGenerateContent` endpoint:

```bash
curl -k -N "https://localhost:8080/v1beta/models/gemini-2.0-flash:streamGenerateContent?key=$GEMINI_API_KEY" \
    -H 'Content-Type: application/json' \
    -X POST \
    -d '{
      "contents": [{
        "parts":[{"text": "Whose social security number is 123-45-6789"}]
      }]
    }'
```

## Ollama

### Chat

```bash
curl -k https://localhost:8080/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3",
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}],
    "stream": false
  }'
```

### Generate

```bash
curl -k https://localhost:8080/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3",
    "prompt": "Whose social security number is 123-45-6789",
    "stream": false
  }'
```

Ollama streams by default. Set `"stream": false` to receive a single response.

## Tool Use and Function Calling

The proxy redacts PII in tool-use workflows automatically - no additional configuration is required.

### OpenAI Tool Results

Tool result messages (`role: tool`) have their `content` field redacted:

```bash
curl -k https://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Look up customer 42"},
      {"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_customer", "arguments": "{\"id\": 42}"}}]},
      {"role": "tool", "tool_call_id": "call_1", "content": "Customer John Smith, SSN 123-45-6789, balance $4200"}
    ]
  }'
```

The `content` of the tool message is redacted before the full conversation is forwarded to OpenAI.

### OpenAI Function Call Arguments

When an assistant message contains `tool_calls`, the `function.arguments` JSON string is parsed, all string values are redacted, and the result is re-serialized before forwarding:

```json
{
  "role": "assistant",
  "tool_calls": [{
    "id": "call_abc",
    "type": "function",
    "function": {
      "name": "lookup_patient",
      "arguments": "{\"name\": \"John Smith\", \"dob\": \"1990-01-15\"}"
    }
  }]
}
```

The proxy sends `{"name":"REDACTED","dob":"REDACTED"}` to the provider.

### Anthropic Tool Results

`tool_result` content blocks are redacted alongside regular `text` blocks:

```bash
curl -k https://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "max_tokens": 1024,
    "messages": [{
      "role": "user",
      "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "Patient Jane Doe, MRN 8847291"}]
    }]
  }'
```

### Gemini Function Responses

`functionResponse` parts have their `response` object recursively redacted:

```bash
curl -k "https://localhost:8080/v1beta/models/gemini-2.0-flash:generateContent?key=$GEMINI_API_KEY" \
  -H 'Content-Type: application/json' \
  -X POST \
  -d '{
    "contents": [{
      "parts": [{"functionResponse": {"name": "get_patient", "response": {"result": "Patient John Smith, SSN 123-45-6789"}}}]
    }]
  }'
```

## Outbound Response Scanning

By default, the proxy only redacts inbound prompts. You can also scan LLM responses for PII before they reach your client by enabling outbound scanning in the config:

```yaml
defaults:
  policy: default
  outbound:
    enabled: true
    action: redact   # redact | block | flag
```

Or on a specific route only:

```yaml
routes:
  - match:
      header: x-philter-policy
      value: hipaa
    policy: hipaa-safe-harbor
    outbound:
      enabled: true
      action: block
```

**`redact`** - PII in the response is replaced before it reaches the client:

```bash
curl -k https://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "What is a common SSN format?"}]
  }'
```

If the model responds with `A common SSN looks like 123-45-6789`, the proxy scans the response through Philter and returns the redacted version: `A common SSN looks like {{{REDACTED-ssn}}}`.

**`block`** - If any PII is detected in the response, the proxy returns HTTP 403 instead of forwarding the response:

```json
{"error":{"message":"response blocked: PII detected","type":"pii_blocked"}}
```

**`flag`** - The original response is returned unchanged; a warning entry is written to the audit log if PII is found. Useful for monitoring without modifying responses.

**Streaming note:** Outbound scanning can only inspect non-streaming responses. Under `action: redact` or `flag`, streaming responses (`"stream": true`) are forwarded to the client unchanged. Under `action: block` the proxy rejects them with `403` rather than delivering an unscanned body, since otherwise any client could bypass the block by requesting a stream. Inbound prompt redaction is unaffected in every case.

## Health Check

To check the health of the proxy, send a GET request to the `/health` endpoint:

```bash
curl -k https://localhost:8080/health
```

The proxy will return an HTTP 200 OK status and the body `ok`.
