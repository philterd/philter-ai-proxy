# Configuration

## How settings are given

The proxy is a Spring Boot application. Its settings come from, in increasing precedence:

1. The defaults in the image's `application.yaml`.
2. A file of your own, loaded with `SPRING_CONFIG_ADDITIONAL_LOCATION=file:/path/to/application.yaml`.
3. Environment variables.
4. Command-line options, such as `--proxy.defaults.policy=support`.

An environment variable's name is the setting's name in capitals, with `.` and `[]` as `_` and hyphens removed: `proxy.providers.openai.target` is `PROXY_PROVIDERS_OPENAI_TARGET`, `proxy.security.trusted-proxies` is `PROXY_SECURITY_TRUSTEDPROXIES`, and `proxy.routes[0].match.model` is `PROXY_ROUTES_0_MATCH_MODEL`.

Two settings also have shorter environment variables, used in the examples:

| Variable | Setting |
|---|---|
| `PHILTER_AI_PROXY_ENCRYPTION_KEY` | `proxy.security.encryption-key` |
| `PHILTER_AI_PROXY_BOOTSTRAP_API_KEY` | `proxy.security.bootstrap-api-key` |

`--validate-config` checks the settings without serving requests; see [Installation](installation.md#validating-the-configuration).

## Example

```yaml
proxy:
  providers:
    bedrock:
      region: us-east-1
    openai-compatible:
      vllm:
        target: http://vllm.internal:8000
  defaults:
    policy: default
  routes:
    # Scan responses for one model and keep replacements consistent across requests.
    - match:
        model: gpt-4o
      context: support-conversations
      outbound:
        enabled: true
        action: redact
    # A stricter policy for one team, chosen by a header their gateway sets.
    - match:
        header: x-team
        value: finance
      policy: finance
  limits:
    max-concurrent-requests: 200
  security:
    trusted-proxies:
      - 10.0.0.0/8
```

## Settings

### Security and storage

| Setting | Default | Meaning |
|---|---|---|
| `proxy.security.encryption-key` | (required) | Encrypts values stored at rest, such as the original values a context keeps. 32 random bytes as 64 hex characters or base64: `openssl rand -hex 32`. The proxy refuses to start with a key other than the one its database was created with. |
| `proxy.security.bootstrap-api-key` | | An admin key created on first start, while no API key exists. At least 32 characters. |
| `proxy.security.proxy-key-header` | `x-philter-proxy-key` | The request header that carries the proxy key on provider traffic. It is never forwarded. |
| `proxy.security.trusted-proxies` | none | Load balancers and proxies (IP addresses or CIDR ranges) whose `X-Forwarded-For` is believed for the client address in the audit log. The header is read from the right, skipping trusted proxies. |
| `proxy.storage.sqlite-path` | `/var/lib/philter-ai-proxy/philter-ai-proxy.db` | The SQLite database: policies, API keys, contexts, and the audit log. Created readable only by the proxy's user. One instance per file. |
| `proxy.audit.file` | | A file each audit entry is also appended to, as one JSON line. See [Audit log](monitoring.md#audit-log). |

### Policies and models

| Setting | Default | Meaning |
|---|---|---|
| `proxy.models.directory` | `/opt/philter-ai-proxy/models` | Local PhEye models, one per subdirectory. See [Models](policies.md#models). |
| `proxy.policy-files.directories` | none | Directories the files a policy names (such as dictionary files) must be inside. With none, a policy may name no file. |
| `proxy.policy-files.allowed-environment-variables` | none | Environment variables a policy may name as `env:NAME`, such as a key for `CRYPTO_REPLACE`. With none, a policy may name none. |

### Defaults and routes

| Setting | Default | Meaning |
|---|---|---|
| `proxy.defaults.policy` | `default` | The policy for a request no route matches. |
| `proxy.defaults.context` | none | The context for a request no route matches. See [Contexts](policies.md#contexts). |
| `proxy.defaults.outbound.enabled` | `false` | Whether responses to requests no route matches are scanned. |
| `proxy.defaults.outbound.action` | `redact` | `redact`, `block`, or `flag`. See [Actions](api.md#actions). |
| `proxy.routes` | none | Routes, in order; see [Routes](#routes). |

### Limits and streaming

| Setting | Default | Meaning |
|---|---|---|
| `proxy.limits.max-request-body-bytes` | `10485760` (10 MiB) | Larger request bodies are refused with `413`. |
| `proxy.limits.max-concurrent-requests` | `0` (no limit) | Requests handled at once; more are refused with `503` and `Retry-After: 1`. |
| `proxy.streaming.holdback-characters` | `256` | How much of a streamed response is held back so a value split across fragments is scanned whole. See [Streamed responses](api.md#streamed-responses). |

### Server and TLS

| Setting | Default | Meaning |
|---|---|---|
| `server.port` | `8080` | Provider traffic and the admin API. |
| `management.server.port` | `9090` | Prometheus metrics at `/metrics`, always plain HTTP. |
| `proxy.tls.dev-self-signed-cert` | `true` in the image, `false` otherwise | Serve HTTPS with a self-signed certificate generated at startup. A configured certificate takes precedence. |
| `server.ssl.certificate`, `server.ssl.certificate-private-key` | | Your certificate and key in PEM form, to serve HTTPS. |
| `server.ssl.enabled-protocols` | | Limit the TLS versions, such as `TLSv1.3,TLSv1.2`. Setting it turns TLS on. |
| `server.ssl.trust-certificate`, `server.ssl.client-auth` | | For mutual TLS: the PEM file of the CA that signs client certificates, and `need`. |
| `server.tomcat.connection-timeout` | `10s` | How long a connection may take to send its request. |
| `server.max-http-request-header-size` | `1MB` | Larger request headers are refused. |

The proxy does not limit how many TLS handshakes run at once. Put a load balancer or ingress in front of it to absorb a flood of handshakes or connections.

See [Monitoring](monitoring.md#distributed-tracing) for the tracing settings.

## Providers

| Provider | Setting | Enabled |
|---|---|---|
| OpenAI | `proxy.providers.openai` | By default, at `https://api.openai.com` |
| Anthropic | `proxy.providers.anthropic` | By default, at `https://api.anthropic.com` |
| Gemini | `proxy.providers.gemini` | By default, at `https://generativelanguage.googleapis.com` |
| Ollama | `proxy.providers.ollama` | By default, at `http://localhost:11434` |
| Azure OpenAI | `proxy.providers.azure` | When `target` is set |
| Vertex AI | `proxy.providers.vertex` | When `project` is set |
| Amazon Bedrock | `proxy.providers.bedrock` | When `region` is set |
| OpenAI-compatible | `proxy.providers.openai-compatible.<name>` | For each name with a `target` |

Every provider takes:

| Field | Default | Meaning |
|---|---|---|
| `target` | as above | The provider's base URL. |
| `connect-timeout-ms` | `5000` | How long to wait to connect. |
| `response-timeout-ms` | `120000` | How long to wait for the response to begin. A stream may then run as long as it lasts. |
| `ca-cert` | | A PEM file of certificate authorities to trust for this provider instead of the system's, such as for a self-hosted server with a private CA. |
| `disabled` | `false` | Turns off a provider that is on by default. A request for it is refused with `404`. |

Redirects from providers are not followed.

### Azure OpenAI

```yaml
proxy:
  providers:
    azure:
      target: https://my-resource.openai.azure.com
      api-version: 2024-10-21
      entra-id: false
```

`api-version` is added to requests that do not send one. With `entra-id: true`, the proxy authenticates with an Entra ID token from the default Azure credential chain (managed identity, workload identity, environment variables, and so on) instead of passing the client's `api-key` through.

### Vertex AI

```yaml
proxy:
  providers:
    vertex:
      project: my-project
      location: us-central1
```

Requests go to `https://<location>-aiplatform.googleapis.com` unless `target` is set. The proxy authenticates with Google application default credentials (a service account key named in `GOOGLE_APPLICATION_CREDENTIALS`, workload identity, or the metadata server), replacing any `Authorization` the client sends.

### Amazon Bedrock

```yaml
proxy:
  providers:
    bedrock:
      region: us-east-1
      role-arn: arn:aws:iam::123456789012:role/philter-ai-proxy
```

Requests go to `https://bedrock-runtime.<region>.amazonaws.com` unless `target` is set. The proxy signs each request with SigV4, with credentials from the AWS default chain (environment variables, a profile, web identity, or instance and container roles), assuming `role-arn` when it is set. Only `Content-Type` and the signature are forwarded; the client's headers are not.

### OpenAI-compatible providers

```yaml
proxy:
  providers:
    openai-compatible:
      vllm:
        target: http://vllm.internal:8000
      mistral:
        target: https://api.mistral.ai
```

Each is reached at `/<name>/v1/...` and redacted like OpenAI. A name is lowercase letters, digits, `-`, and `_`, and cannot be one the proxy's own paths use (`v1`, `v1beta`, `api`, `openai`, `model`, `admin`).

## Routes

A route chooses the policy, context, and response scanning for the requests it matches. The first route whose every set condition matches applies; a request no route matches uses `proxy.defaults`.

| Field | Meaning |
|---|---|
| `match.path` | The request path, exactly, after any OpenAI-compatible prefix is removed. |
| `match.model` | The model the request names, exactly. |
| `match.header`, `match.value` | A request header and the value it must have. |
| `policy` | The policy to apply. Without one, `proxy.defaults.policy`. |
| `context` | The context to keep replacements in. Without one, `proxy.defaults.context`. |
| `outbound.enabled`, `outbound.action` | Response scanning for the route. A route without `outbound` does not scan responses. |

A key created with a `policy` overrides the route's policy. See [Choosing the policy for a request](policies.md#choosing-the-policy-for-a-request).

```yaml
proxy:
  routes:
    - match:
        path: /v1/embeddings
      policy: embeddings
    - match:
        header: x-scan-responses
        value: "true"
      outbound:
        enabled: true
        action: block
```

A header match is only as trustworthy as whoever sets the header. When clients can set it themselves, they can choose their route; bind a policy to their keys instead.
