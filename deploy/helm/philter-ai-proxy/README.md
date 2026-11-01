# philter-ai-proxy Helm chart

Deploys [Philter AI Proxy](https://github.com/philterd/philter-ai-proxy), a self-hosted proxy that redacts PII and
PHI from LLM requests and responses.

The proxy runs as a single replica, recreated on update: it keeps policies, API keys, contexts, and the audit log
in a SQLite file on a persistent volume, and a second instance on the same file is refused.

## Install

```bash
helm install philter-ai-proxy deploy/helm/philter-ai-proxy \
  --set secrets.encryptionKey="$(openssl rand -hex 32)" \
  --set secrets.bootstrapApiKey="$(openssl rand -hex 32)"
```

Keep a copy of the encryption key: the database cannot be read without it, and the proxy refuses to start with a
different one. To keep both keys out of the release values, create a Secret with the keys `encryption-key` and
`bootstrap-api-key` and set `secrets.existingSecret` to its name.

## Values

See `values.yaml` for every value. The main ones:

| Value | What it does |
|---|---|
| `image.tag` | The release to deploy. Defaults to the chart's `appVersion`. |
| `secrets.encryptionKey` / `secrets.bootstrapApiKey` / `secrets.existingSecret` | The encryption key (required) and the bootstrap admin key. |
| `config` | The proxy's settings, as in `application.yaml`: providers, routes, defaults, limits. |
| `extraEnv` | Extra environment variables, such as cloud credentials for Bedrock or Vertex AI. |
| `persistence.*` | The volume for the database. On by default, and kept when the release is uninstalled. |
| `tls.mode` | `selfSigned` (default), `existingSecret` (`tls.existingSecret`, with `tls.crt` and `tls.key`), `certManager`, or `none` for plain HTTP behind an ingress or mesh that terminates TLS. |
| `mtls.enabled` / `mtls.caSecretName` | Require client certificates signed by the CA in the Secret's `ca.crt`. Needs `tls.mode` `existingSecret` or `certManager`. |
| `ingress.*` | An Ingress for the proxy port. |
| `serviceMonitor.enabled` | A Prometheus Operator ServiceMonitor for `/metrics` on port 9090. |
| `resources` | Requests 1.5 GiB of memory by default: the bundled PhEye model is loaded at startup. |

## Settings in `config`

`config` is rendered into a ConfigMap and loaded after the image's defaults. For example, to scan responses on a
route and add an OpenAI-compatible provider:

```yaml
config:
  proxy:
    providers:
      openai-compatible:
        local:
          target: http://vllm.internal:8000
    routes:
      - match:
          model: gpt-4o
        policy: default
        outbound:
          enabled: true
          action: redact
```

Secrets do not belong in `config`, which is a ConfigMap. Pass them with `extraEnv` from a Secret you manage.

## Test

```bash
helm test philter-ai-proxy
```

The test pod calls `/livez` through the Service.
