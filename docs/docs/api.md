# API Reference

The Philter AI Proxy provides several endpoints to redact sensitive information before sending requests to AI providers.

## Endpoints

### OpenAI Chat Completions

- **URL**: `/v1/chat/completions`
- **Method**: `POST`
- **Description**: Proxies requests to the OpenAI Chat Completions API.
- **Example**:
  ```bash
  curl https://localhost:8080/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -d '{
      "model": "gpt-3.5-turbo",
      "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
    }'
  ```

### Anthropic Messages

- **URL**: `/v1/messages`
- **Method**: `POST`
- **Description**: Proxies requests to the Anthropic Messages API.
- **Example**:
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

### Gemini Generate Content

- **URL**: `/v1beta/models/{model}:generateContent`
- **Method**: `POST`
- **Description**: Proxies requests to the Google Gemini Generate Content API.
- **Example**:
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

### Health Check

- **URL**: `/health`
- **Method**: `GET`
- **Description**: Returns the health status of the proxy.
- **Response**: `200 OK` with body `ok`.
- **Example**:
  ```bash
  curl -k https://localhost:8080/health
  ```
