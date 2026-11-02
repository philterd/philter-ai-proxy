# Kubernetes

The repository includes a Helm chart (`deploy/helm/philter-ai-proxy/`) and plain manifests generated from it (`deploy/k8s/`).

The proxy runs as one replica. It keeps policies, API keys, contexts, and the audit log in a SQLite file on a persistent volume, and a second instance on the same file is refused, so the Deployment uses the `Recreate` strategy and the chart has no autoscaler. For more capacity, give the pod more CPU, or run separate releases (each with its own database) behind your gateway.

## Helm

```bash
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
export BOOTSTRAP_API_KEY="$(openssl rand -hex 32)"

helm install philter-ai-proxy deploy/helm/philter-ai-proxy \
  --set secrets.encryptionKey="$ENCRYPTION_KEY" \
  --set secrets.bootstrapApiKey="$BOOTSTRAP_API_KEY"
```

Keep a copy of the encryption key: the database cannot be read without it, and the proxy refuses to start with a different one. To keep the keys out of the release values, create the Secret yourself and name it in `secrets.existingSecret`:

```bash
kubectl create secret generic philter-ai-proxy-secrets \
  --from-literal=encryption-key="$ENCRYPTION_KEY" \
  --from-literal=bootstrap-api-key="$BOOTSTRAP_API_KEY"

helm install philter-ai-proxy deploy/helm/philter-ai-proxy --set secrets.existingSecret=philter-ai-proxy-secrets
```

The pod is ready once the PhEye model is loaded. Then create a key for your applications:

```bash
kubectl port-forward svc/philter-ai-proxy 8080:8080 &
curl -k https://localhost:8080/readyz

curl -k https://localhost:8080/admin/api/keys \
  -H "Authorization: Bearer $BOOTSTRAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-app", "roles": ["proxy"]}'
```

In the cluster, applications reach the proxy at `https://philter-ai-proxy.<namespace>.svc.cluster.local:8080`.

### Values

| Value | Default | What it does |
|---|---|---|
| `image.tag` | the chart's `appVersion` | The release to deploy. |
| `secrets.encryptionKey`, `secrets.bootstrapApiKey` | | The encryption key (required) and the bootstrap admin key. |
| `secrets.existingSecret` | | A Secret holding `encryption-key` and `bootstrap-api-key`, used instead of the two values above. |
| `config` | the default policy, no routes | The proxy's settings, as in `application.yaml`. See [Configuration](configuration.md). |
| `extraEnv` | `[]` | Extra environment variables, such as credentials for Bedrock or Vertex AI from a Secret. |
| `persistence.enabled`, `.size`, `.storageClass`, `.existingClaim` | on, 1Gi | The database volume. The claim is kept when the release is uninstalled. |
| `tls.mode` | `selfSigned` | `selfSigned`, `existingSecret`, `certManager`, or `none`. See [TLS](#tls). |
| `mtls.enabled`, `mtls.caSecretName` | off | Require client certificates signed by the CA in the Secret's `ca.crt`. The kubelet cannot present a client certificate, so with mTLS on the probes become TCP checks, and readiness no longer waits for the model to load. |
| `ingress.*` | off | An Ingress for port 8080. |
| `serviceMonitor.enabled` | off | A Prometheus Operator ServiceMonitor for `/metrics` on port 9090. |
| `networkPolicy.enabled`, `.proxyFrom`, `.metricsFrom` | off | A NetworkPolicy allowing port 8080 from `proxyFrom` (any peer when empty) and port 9090 only from `metricsFrom` (no peer when empty). Egress is not restricted. |
| `serviceAccount.automountToken` | `false` | Mount the service account token. The proxy does not call the Kubernetes API, and workload identity for Bedrock or Vertex AI does not need it. |
| `resources` | 500m CPU and 1.5 GiB requested, 2 GiB limit | The model is loaded into memory at startup. |

Settings in `config` are rendered into a ConfigMap, so keep secrets out of them. For example, to scan responses for one model and add an OpenAI-compatible provider:

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
        outbound:
          enabled: true
          action: redact
```

### TLS

| `tls.mode` | The proxy serves |
|---|---|
| `selfSigned` | HTTPS with a certificate generated at startup, which no client trusts. For evaluation. |
| `existingSecret` | HTTPS with `tls.crt` and `tls.key` from the Secret named in `tls.existingSecret`. |
| `certManager` | HTTPS with a certificate cert-manager issues (`tls.certManager.issuerRef`, `tls.certManager.dnsNames`). |
| `none` | Plain HTTP, for an ingress or service mesh that terminates TLS in front of the proxy. |

The probes follow the mode. The metrics port always serves plain HTTP.

`server.tomcat.connection-timeout` (10 seconds) is how long the proxy waits for a request to start and between reads of it; it is not a deadline for the whole request, so a client that sends a byte at a time can hold a connection. The proxy also does not limit how many TLS handshakes run at once. Put a load balancer or ingress in front of it to absorb slow clients and floods of handshakes or connections.

## Plain manifests

```bash
kubectl create secret generic philter-ai-proxy-secrets \
  --from-literal=encryption-key="$(openssl rand -hex 32)" \
  --from-literal=bootstrap-api-key="$(openssl rand -hex 32)"

kubectl apply -f deploy/k8s/
```

The manifests match the chart's defaults: one replica, a 1Gi volume claim, the self-signed certificate, and a read-only root filesystem. Edit the ConfigMap in your copy of `01-config.yaml` for your settings. `deploy/k8s/generate.sh` regenerates them from the chart.

## Grafana

`deploy/grafana/philter-ai-proxy.json` is a dashboard for the proxy's metrics. See [Monitoring](monitoring.md#grafana-dashboard).
