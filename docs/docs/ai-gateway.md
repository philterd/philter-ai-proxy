# Using with an AI Gateway

Philter AI Proxy is a redaction proxy. It does not do routing, failover, model fallback, rate limiting, response caching, token quotas, spend tracking, or per-tenant billing. Those are the job of an AI gateway such as [LiteLLM](https://github.com/BerriAI/litellm), [Portkey](https://portkey.ai/), [Kong AI Gateway](https://konghq.com/products/kong-ai-gateway), or a cloud provider's own gateway.

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
| `auth.apiKeys` | Redundant as authentication, but keep it if you use per-key policy binding: the key's stable ID is what pins a caller to a Philter policy regardless of what the client requests. |
| `listen.maxConcurrentRequests` | Keep. This protects the proxy and Philter from overload regardless of what sits in front. |
| Audit logging | Keep. This is the record of what was redacted, and no gateway produces it. |

If the proxy is exposed directly to clients in addition to the gateway, keep auth on. See [Configuration](configuration.md).

## When you do not need the proxy

If your gateway supports guardrail callbacks (LiteLLM, Portkey, and Kong all do), it can call [Philter](https://philterd.ai/philter/) directly and you can skip the proxy entirely. That is a legitimate setup and it is simpler when it fits.

The proxy is the better choice when you want redaction enforced at the network layer rather than as a feature of the gateway's configuration:

- **It cannot be toggled per request.** A guardrail hook is a gateway config that a developer with gateway access can disable, reorder, or bypass with a direct call. A proxy in the network path cannot be routed around.
- **It covers traffic the gateway does not.** Applications that call providers directly, SDKs pinned to a provider base URL, and anything that predates the gateway can be pointed at the proxy without touching the gateway.
- **It is the last hop.** Redaction happens after every gateway decision has been made, including retries and fallbacks.

For a compliance boundary you have to defend to an auditor, the network-layer version is easier to demonstrate. For convenience redaction inside an already-governed gateway, the callback is fine.

## Token accounting

The proxy does not track token usage at all: not in the audit log, not as a metric. Token counts say nothing about redaction, and duplicating them here would mean carrying per-provider usage-parsing for every provider and streaming format the proxy supports, to produce a partial copy of what the gateway already records accurately.

Use the gateway's accounting as the system of record for spend, budgets, and per-tenant usage. If you run without a gateway, the provider's own usage dashboard is the source of truth.
