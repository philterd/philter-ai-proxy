# Using with an AI Gateway

Philter AI Proxy is a redaction proxy. It does not do routing, failover, model fallback, token quotas, spend tracking, or per-tenant billing. Those are the job of an AI gateway such as [LiteLLM](https://github.com/BerriAI/litellm), [Portkey](https://portkey.ai/), [Kong AI Gateway](https://konghq.com/products/kong-ai-gateway), or a cloud provider's own gateway.

The two are complementary. Run the gateway for traffic management and the proxy for redaction.

## Recommended topology

Put the proxy between the gateway and the provider, so redaction is the last thing that happens before data leaves your network:

```
client -> AI gateway -> Philter AI Proxy -> Philter -> LLM provider
                              |
                              +-> audit log
```

This ordering matters. Anything downstream of redaction cannot undo it, and no gateway plugin, retry path, or model-fallback rule can route around it. If the gateway is instead placed after the proxy, a fallback to a provider the proxy did not see, or a gateway-injected system prompt, can put unredacted text on the wire.

Configuration is a one-line change on the gateway: point its upstream base URL at the proxy instead of at the provider. The proxy speaks each provider's native wire protocol, so the gateway needs no other changes.

### LiteLLM

```yaml
model_list:
  - model_name: gpt-4
    litellm_params:
      model: openai/gpt-4
      api_base: https://philter-ai-proxy.internal:8080/v1
      api_key: os.environ/OPENAI_API_KEY
```

### Portkey

Set the provider's custom host on the virtual key or in the request config:

```json
{
  "provider": "openai",
  "custom_host": "https://philter-ai-proxy.internal:8080/v1"
}
```

### Kong AI Gateway

Override the upstream on the `ai-proxy` plugin:

```yaml
plugins:
  - name: ai-proxy
    config:
      route_type: llm/v1/chat
      model:
        provider: openai
        options:
          upstream_url: https://philter-ai-proxy.internal:8080/v1/chat/completions
```

## What to disable when behind a gateway

When the gateway is the trust boundary and the proxy is on a private network reachable only by the gateway, several proxy features become redundant. Turning them off avoids two systems enforcing overlapping limits with unclear precedence:

| Proxy feature | Behind a gateway |
|---|---|
| `auth.apiKeys` | Usually redundant. The gateway authenticates callers. Keep it on if the proxy is reachable by anything else. |
| `rateLimit` | Usually redundant. The gateway rate limits. Keep a global backstop if you want the proxy protected independently. |
| `listen.maxConcurrentRequests` | Keep. This protects the proxy and Philter from overload regardless of what sits in front. |
| `cache` | Disable if the gateway caches. Two caches in series waste memory and complicate invalidation. |
| Audit logging | Keep. This is the record of what was redacted, and no gateway produces it. |

If the proxy is exposed directly to clients in addition to the gateway, keep auth and rate limiting on. See [Configuration](configuration.md).

## When you do not need the proxy

If your gateway supports guardrail callbacks (LiteLLM, Portkey, and Kong all do), it can call [Philter](https://philterd.ai/philter/) directly and you can skip the proxy entirely. That is a legitimate setup and it is simpler when it fits.

The proxy is the better choice when you want redaction enforced at the network layer rather than as a feature of the gateway's configuration:

- **It cannot be toggled per request.** A guardrail hook is a gateway config that a developer with gateway access can disable, reorder, or bypass with a direct call. A proxy in the network path cannot be routed around.
- **It covers traffic the gateway does not.** Applications that call providers directly, SDKs pinned to a provider base URL, and anything that predates the gateway can be pointed at the proxy without touching the gateway.
- **It is the last hop.** Redaction happens after every gateway decision has been made, including retries and fallbacks.

For a compliance boundary you have to defend to an auditor, the network-layer version is easier to demonstrate. For convenience redaction inside an already-governed gateway, the callback is fine.

## Token accounting

The proxy does not enforce token budgets, but it does observe them. Per-request prompt and completion token counts appear in the audit log, and `philter_proxy_prompt_tokens_total` / `philter_proxy_completion_tokens_total` are exported for Prometheus, labeled by provider and model. See [Monitoring](monitoring.md).

Streamed responses from Gemini, Vertex, Ollama, and Bedrock do not carry usage in a shape the proxy parses, so their token counts are absent from the audit log. Use the gateway's accounting as the system of record for spend.
