# Usage

To use this proxy, you can send a request to it like you would to OpenAI, Claude, or Gemini, but change the hostname to your proxy's address.

## OpenAI

```bash
curl https://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
  }'
```

## Claude

```bash
curl https://localhost:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
  }'
```

## Gemini

```bash
curl "https://localhost:8080/v1beta/models/gemini-1.5-flash:generateContent?key=$GEMINI_API_KEY" \
    -H 'Content-Type: application/json' \
    -X POST \
    -d '{
      "contents": [{
        "parts":[{"text": "Whose social security number is 123-45-6789"}]
      }]
    }'
```

## Health Check

To check the health of the proxy, send a GET request to the `/health` endpoint:

```bash
curl -k https://localhost:8080/health
```

The proxy will return an HTTP 200 OK status and the body `ok`.
