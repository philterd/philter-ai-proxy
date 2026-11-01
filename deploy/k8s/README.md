# Plain Kubernetes manifests

Manifests for running Philter AI Proxy without Helm. They are generated from the Helm chart's defaults, so they
match what the chart deploys with `tls.mode: selfSigned`. For an ingress, a ServiceMonitor, your own certificate,
mutual TLS, or cert-manager, use the chart in `deploy/helm/philter-ai-proxy/`.

| File | Contents |
|---|---|
| `01-config.yaml` | The proxy's settings (ConfigMap) and the volume claim for its database |
| `02-deployment.yaml` | One replica, recreated on update, with probes and a read-only root filesystem |
| `03-service.yaml` | The proxy port (8080) and the metrics port (9090) |

The proxy runs as a single replica: it keeps policies, API keys, contexts, and the audit log in a SQLite file on
the volume, and a second instance on the same file is refused.

## Deploy

```bash
# The encryption key protects values stored at rest; keep a copy, since the database cannot be read without it.
# The bootstrap key becomes an admin key on first start.
kubectl create secret generic philter-ai-proxy-secrets \
  --from-literal=encryption-key="$(openssl rand -hex 32)" \
  --from-literal=bootstrap-api-key="$(openssl rand -hex 32)"

kubectl apply -f deploy/k8s/

kubectl port-forward svc/philter-ai-proxy 8080:8080 &
curl -k https://localhost:8080/readyz
```

The proxy serves HTTPS with a self-signed certificate generated at startup, which no client trusts; `-k` skips
verification. See the [Kubernetes](https://philterd.github.io/philter-ai-proxy/kubernetes/) page for using your own
certificate, or plain HTTP behind an ingress that terminates TLS.

## Regenerate

After changing the chart:

```bash
deploy/k8s/generate.sh
```

CI runs `deploy/k8s/generate.sh --check` and fails when the manifests differ from what the chart renders.
