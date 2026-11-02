# Authentication

Two credentials are involved in every request, and they are separate:

1. **A proxy key** authenticates the client to the proxy. The proxy checks it, applies the key's roles and scopes, and never forwards it.
2. **A provider credential** authenticates the request to the LLM provider. Depending on the provider, it is the client's own key, passed through, or a credential the proxy holds for the whole deployment.

A proxy key never translates into a provider credential. The proxy has no user accounts: API keys are its only identities.

## Proxy keys

Every request to a provider needs a proxy key in the `x-philter-proxy-key` header (configurable with `proxy.security.proxy-key-header`). A request without one is refused with `401` `missing_api_key`, and one with an unknown key with `401` `invalid_api_key`. There is no anonymous access.

Keys are created and deleted through the [admin API](api.md#api-keys). Each key has:

- **A name**, such as `support-bot`. The audit log records the key's ID with each request, and with each admin action (creating or deleting a key or policy).
- **Roles.** `proxy` allows provider traffic; `admin` allows the admin API. A key can hold both, but separate keys are easier to scope and to rotate.
- **Scopes** (optional) on the providers, models, and paths the key may use. A request outside them is refused with `403`.
- **A bound policy** (optional), applied to every request with the key. A key with a bound policy also skips routes that match on a header, so its client cannot choose a route that forwards media or turns off response scanning. See [Routes](configuration.md#routes).

Keys created through the admin API are 32 random bytes, prefixed `pap_`. Every key, including the bootstrap key, is stored only as a SHA-256 hash. A key is shown once, when it is created. A deleted key stops working at once.

The admin API takes its key as `Authorization: Bearer <key>`, as Philter's clients send it, and needs the `admin` role.

### The first key

On first start, while no key exists, the proxy creates an `admin` key from `proxy.security.bootstrap-api-key` (`PHILTER_AI_PROXY_BOOTSTRAP_API_KEY`, at least 32 characters). The key's secret is the configured value itself, and the key is named `bootstrap`. Use it to create the keys your applications use. It is created only while the database holds no key. A shorter value stops the proxy at startup; with no value, the proxy starts without a key and logs a warning.

### Unauthenticated endpoints

`/livez`, `/readyz`, and `/health` on port 8080 answer without a key, for probes and load balancers. The metrics port (9090) is also unauthenticated; keep it off the internet.

## Provider credentials

| Provider | Credential sent to the provider |
|---|---|
| OpenAI, Anthropic, Gemini, Ollama, OpenAI-compatible providers | The client's own: `Authorization`, `x-api-key`, `x-goog-api-key`, or Gemini's `?key=`, forwarded unchanged |
| Azure OpenAI | The client's `api-key` or `Authorization`, forwarded unchanged. With `entra-id: true`, the proxy's Entra ID token instead |
| Vertex AI | The proxy's Google application default credentials, replacing any `Authorization` the client sends |
| Amazon Bedrock | The proxy's AWS credentials (SigV4, optionally assuming `role-arn`). No client credentials are forwarded; of the client's headers, only `X-Amzn-Bedrock-*` settings are |

When client headers are forwarded, the proxy removes the proxy key header, every header starting with `x-philter-`, hop-by-hop headers, `Accept-Encoding` (so the response can be scanned), `X-Request-Id`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `Forwarded`.

### Passed-through credentials

For the providers in the first two rows, the proxy stores no provider secrets. Each application sends its own provider key alongside its proxy key:

```bash
curl -k https://localhost:8080/v1/chat/completions \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Hello"}]}'
```

The proxy key decides whether the request is allowed and which policy applies; the provider key decides which provider account is used. The proxy does not choose or restrict the provider account.

### The proxy's own credentials

For Azure with Entra ID, Vertex AI, and Bedrock, the proxy uses one credential, configured for the deployment (see [Providers](configuration.md#providers)). Every key that may reach the provider uses it, so a proxy key alone grants access to the provider through that credential. Use the key's `providers` and `models` scopes to decide which clients may use it. A Vertex AI path that names a project or location other than the configured one is refused. With `unsupported-endpoints: reject`, the default, the credential is used only for the endpoints the proxy redacts: a request to any other endpoint of these providers is refused, with or without a body. A route with `unsupported-endpoints: forward` lets every key that matches it use the credential on that path.

### Keeping provider keys out of applications

The proxy cannot hold a provider key and add it for a client. If applications must not see provider keys, put an AI gateway that maps its own keys to provider credentials (such as LiteLLM or Portkey virtual keys) behind the proxy. See [Using with an AI Gateway](ai-gateway.md).

## Mutual TLS

The proxy can also require a client certificate signed by a CA you name, in addition to the proxy key. See [Certificates](installation.md#certificates) and, on Kubernetes, `mtls.enabled` in [Kubernetes](kubernetes.md#values).

## Recommendations

- Give each application its own `proxy` key, scoped to the providers, models, and paths it uses, so a leaked key reaches only that and can be deleted alone.
- Bind a policy to keys whose clients must not choose their route.
- Keep `admin` keys with administrators, one per person, so the audit log shows who made a change, and never in an application.
- Scope keys carefully for providers the proxy authenticates to itself (Azure with Entra ID, Vertex AI, Bedrock), since the key is the only credential the client needs.
