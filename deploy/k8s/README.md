# Plain Kubernetes manifests

A minimal, copy-pasteable set of manifests for users who don't want to install Helm. For anything beyond the basics - ingress, ServiceMonitor, HPA, mTLS, cert-manager integration - use the Helm chart at `deploy/helm/philter-ai-proxy/` instead.

These manifests deploy:

- `Secret` with the proxy's TLS cert/key (placeholder - replace before applying)
- `Secret` with the proxy config (referenced by the Deployment)
- `Deployment` (1 replica, with probes and resource requests)
- `Service` for the proxy port (8080)
- `Service` for the metrics port (9090)

## Quickstart

```bash
# 1. Generate a self-signed TLS cert (or use your real cert/key).
openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt -days 365 -nodes \
  -subj "/CN=philter-ai-proxy"

# 2. Create the TLS Secret. Update the namespace if not "default".
kubectl create secret tls philter-ai-proxy-tls --cert=tls.crt --key=tls.key

# 3. Edit configmap.yaml - point `philter.endpoint` at your Philter service.
# 4. Apply.
kubectl apply -f deploy/k8s/

# 5. Check.
kubectl get pods -l app=philter-ai-proxy
kubectl port-forward svc/philter-ai-proxy 8443:8080 &
curl -k https://localhost:8443/livez
curl -k https://localhost:8443/readyz
```

## Layout

| File | Purpose |
|---|---|
| `01-config.yaml` | Secret holding `config.yaml`. The proxy reads it via `--config /etc/philter-proxy/config/config.yaml`. |
| `02-deployment.yaml` | Single-replica Deployment with health probes, resource requests, and a read-only root filesystem. |
| `03-service.yaml` | ClusterIP Services on 8080 (proxy) and 9090 (metrics). |

The TLS cert is not in this directory - create it as a separate `kubernetes.io/tls` Secret as shown above.
