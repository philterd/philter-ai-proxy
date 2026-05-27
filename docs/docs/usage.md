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

**Note:** The Gemini API passes the API key as a URL query parameter rather than a header. The proxy forwards the query string to the provider but never logs API keys — sensitive query parameters are redacted from all log and error output.

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

## Health Check

To check the health of the proxy, send a GET request to the `/health` endpoint:

```bash
curl -k https://localhost:8080/health
```

The proxy will return an HTTP 200 OK status and the body `ok`.
