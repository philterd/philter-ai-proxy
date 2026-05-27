# Philter AI Proxy

This project is a proxy for OpenAI, Claude, Gemini, and Ollama that uses [Philter](https://philterd.ai/philter/) to remove PII, PHI, and other sensitive information from a [chat completion](https://platform.openai.com/docs/api-reference/chat), [messages](https://docs.anthropic.com/claude/reference/messages_post), [Gemini](https://ai.google.dev/api/rest/v1beta/models/generateContent), or [Ollama](https://docs.ollama.com/api/generate) request before sending the request to the respective API. If you don't have a running instance of Philter, you can launch one in your cloud at https://philterd.ai/philter/.

The proxy works by sending requests destined for OpenAI, Claude, Gemini, or Ollama first to Philter where the sensitive information is redacted per Philter's configuration. The redacted text is then sent to the API. For example, if you send the following text `How old is John Smith?`, the proxy and Philter will remove the text `John Smith` from the request. The redacted request sent to the API will be `How old is REDACTED?`

Outbound response scanning is also supported on an opt-in basis: LLM responses can be scanned through Philter before being returned to the client, guarding against hallucinated or training-data PII in responses. The behavior is configurable per route: redact detected PII, block the response entirely, or pass it through with a warning log.

View the [documentation](http://philterd.github.io/philter-ai-proxy).

## Running the Proxy

Copy `config.example.yaml` to `config.yaml`, edit the values to match your environment, then run:

```
./philter-ai-proxy --config config.yaml
```

Or set the config path via environment variable:

```
PHILTER_PROXY_CONFIG=config.yaml ./philter-ai-proxy
```

To run with Docker Compose, update `config.yaml` (mounted into the container) and then:

```
docker compose build
docker compose up
```

## Usage

To use this proxy, you can send a request to it like you would to OpenAI, Claude, or Gemini but change the hostname:

### OpenAI

```
curl https://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Whose social security number is 123-45-6789"}]
  }'
```

### Claude

```
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

### Gemini

```
curl "https://localhost:8080/v1beta/models/gemini-1.5-flash:generateContent?key=$GEMINI_API_KEY" \
    -H 'Content-Type: application/json' \
    -X POST \
    -d '{
      "contents": [{
        "parts":[{"text": "Whose social security number is 123-45-6789"}]
      }]
    }'
```

### Ollama

```
curl https://localhost:8080/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3",
    "prompt": "Whose social security number is 123-45-6789",
    "stream": false
  }'
```

## License

Copyright 2023-2026 Philterd, LLC. "Philter" is a registered trademark of Philterd, LLC.

Licensed under the Apache License, version 2.
