# Contract tests

Each provider's official SDK talks to the proxy built from this repository, and the proxy talks to a simulator
that records every request. The tests check that what reached the "provider" was redacted, that the proxy key was
not forwarded, and that the SDK parsed the redacted response the proxy returned, buffered and streamed.

```bash
./run.sh                  # everything
./run.sh -k anthropic     # arguments go to pytest
```

The first run downloads the `qwen2.5:0.5b` and `all-minilm:22m` models (about 450 MB) into a Docker volume. Nothing reaches a real
provider; the credentials in `docker-compose.yaml` are invented.

| SDK | Provider | What answers |
|---|---|---|
| `openai` | OpenAI, and Azure OpenAI with `AzureOpenAI` | The simulator |
| `anthropic` | Anthropic | The simulator |
| `google-genai` | Gemini (Developer API) | The simulator |
| `boto3` | Bedrock Converse | The simulator, which checks the proxy's SigV4 signature with botocore |
| `ollama` | Ollama | A real Ollama server, through the simulator's recorder |
| `openai` | An OpenAI-compatible provider | Ollama's OpenAI-compatible API, through the recorder |

What this covers: the requests real SDKs send, and whether real SDKs accept what the proxy sends back. What it
does not: the simulator's responses are written from each provider's documentation, so a provider's actual
responses, and whether it accepts the proxy's requests, still need a check against the real service. Vertex AI and
Azure with Entra ID are not covered, since they need the proxy to hold a real cloud credential.

The SDK versions are pinned in `clients/requirements.txt`. Raise them deliberately, and run the tests when you do.
