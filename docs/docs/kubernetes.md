# Kubernetes Quickstart

Two ways to run the proxy in Kubernetes:

- [**Helm chart**](#helm-chart) - recommended. Production-ready, every advanced feature opt-in.
- [**Plain manifests**](#plain-manifests) - for users who don't want Helm. Minimal Deployment + Service + Secret.

The metrics endpoint is wired up for Prometheus the same way in both cases. See the bottom of this page for the [starter Grafana dashboard](#grafana-dashboard).

## Helm chart

The chart lives at [`deploy/helm/philter-ai-proxy/`](https://github.com/philterd/philter-ai-proxy/tree/main/deploy/helm/philter-ai-proxy) in the repo. It is not yet published to a public registry; install from the source tree directly.

### Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- A reachable [Philter](https://philterd.ai/philter/) deployment
- A TLS certificate the proxy can serve on its listener (the proxy terminates TLS itself)

### 1. Provision the TLS Secret

```bash
# Use your real cert/key, or generate a self-signed pair for the quickstart:
openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt -days 365 -nodes \
  -subj "/CN=philter-ai-proxy.example.com"

kubectl create secret tls philter-ai-proxy-tls --cert=tls.crt --key=tls.key
```

If you have [cert-manager](https://cert-manager.io/) installed, skip this step and use the cert-manager values block in step 2 instead.

### 2. Install

```bash
git clone https://github.com/philterd/philter-ai-proxy
cd philter-ai-proxy

helm install proxy ./deploy/helm/philter-ai-proxy \
  --namespace philter-system --create-namespace \
  --set tls.existingSecret.name=philter-ai-proxy-tls \
  --set config.philter.endpoint=http://philter.philter-system.svc.cluster.local:8080
```

To issue the TLS cert via cert-manager instead:

```bash
helm install proxy ./deploy/helm/philter-ai-proxy \
  --namespace philter-system --create-namespace \
  --set tls.source=certManager \
  --set tls.certManager.issuerRef.name=letsencrypt-prod \
  --set tls.certManager.dnsNames[0]=philter-ai-proxy.example.com \
  --set config.philter.endpoint=http://philter.philter-system.svc.cluster.local:8080
```

### 3. Verify

```bash
kubectl --namespace philter-system get pods -l app.kubernetes.io/instance=proxy

# Port-forward + curl the health endpoint
kubectl --namespace philter-system port-forward svc/proxy-philter-ai-proxy 8443:8080 &
curl -k https://localhost:8443/health
# → {"status":"ok","philter":"ok"}
```

### Common configurations

**API key authentication.** Quickstart pattern (inline keys, fine for non-production):

```bash
helm upgrade proxy ./deploy/helm/philter-ai-proxy --reuse-values \
  --set auth.enabled=true \
  --set 'auth.keys[0].key=replace-me' \
  --set 'auth.keys[0].policy=hipaa-safe-harbor'
```

For production, pre-create a Secret with the full `config.yaml` under an `external-secrets` or `sealed-secrets` workflow, then set `--set existingConfigSecret=<name>`. See the chart [README](https://github.com/philterd/philter-ai-proxy/blob/main/deploy/helm/philter-ai-proxy/README.md#secrets-management) for the trade-offs.

**mTLS for client authentication.**

```bash
kubectl create secret generic philter-ai-proxy-client-ca --from-file=ca.crt=client-ca.pem

helm upgrade proxy ./deploy/helm/philter-ai-proxy --reuse-values \
  --set mtls.enabled=true \
  --set mtls.caSecretName=philter-ai-proxy-client-ca
```

**Ingress.**

```bash
helm upgrade proxy ./deploy/helm/philter-ai-proxy --reuse-values \
  --set ingress.enabled=true \
  --set ingress.className=nginx \
  --set 'ingress.hosts[0].host=proxy.example.com' \
  --set 'ingress.hosts[0].paths[0].path=/' \
  --set 'ingress.hosts[0].paths[0].pathType=Prefix' \
  --set 'ingress.annotations.nginx\.ingress\.kubernetes\.io/backend-protocol=HTTPS'
```

Since the proxy terminates TLS itself, prefer TLS passthrough at the ingress (e.g. `nginx-ingress` with `ssl-passthrough`) over re-encryption.

**Prometheus Operator.**

```bash
helm upgrade proxy ./deploy/helm/philter-ai-proxy --reuse-values \
  --set serviceMonitor.enabled=true
```

**Horizontal autoscaling.** Multi-replica scaling is safe today as long as you do **not** enable in-process rate limiting; per-client buckets are per-pod and will multiply the configured limit by the number of pods. A shared Redis backend is tracked as [#110](https://github.com/philterd/philterd-website/issues/110).

```bash
helm upgrade proxy ./deploy/helm/philter-ai-proxy --reuse-values \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=3 \
  --set autoscaling.maxReplicas=20 \
  --set autoscaling.targetCPUUtilizationPercentage=70 \
  --set podDisruptionBudget.enabled=true
```

### Reference

Every knob is documented in [`values.yaml`](https://github.com/philterd/philter-ai-proxy/blob/main/deploy/helm/philter-ai-proxy/values.yaml). For the proxy's own config schema (everything under `.Values.config`), see [Configuration](configuration.md).

## Plain manifests

If you don't want Helm, the [`deploy/k8s/`](https://github.com/philterd/philter-ai-proxy/tree/main/deploy/k8s) directory has a copy-pasteable set of manifests. They produce a single-replica Deployment with the same security defaults as the chart (non-root, read-only filesystem, capabilities dropped) but without ingress, ServiceMonitor, HPA, mTLS, or cert-manager integration. Use the chart for anything beyond the basics.

```bash
# 1. Generate a TLS cert (or use a real one)
openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt -days 365 -nodes \
  -subj "/CN=philter-ai-proxy"

kubectl create secret tls philter-ai-proxy-tls --cert=tls.crt --key=tls.key

# 2. Edit deploy/k8s/01-config.yaml - point philter.endpoint at your Philter.
# 3. Apply.
kubectl apply -f deploy/k8s/

# 4. Verify
kubectl get pods -l app=philter-ai-proxy
kubectl port-forward svc/philter-ai-proxy 8443:8080 &
curl -k https://localhost:8443/health
```

## Grafana dashboard

A starter dashboard covering request rate, latency, error rate, redactions, tokens, and concurrency lives at [`deploy/grafana/philter-ai-proxy.json`](https://github.com/philterd/philter-ai-proxy/blob/main/deploy/grafana/philter-ai-proxy.json). Import it in Grafana → **Dashboards** → **New** → **Import**.

It exposes a `datasource` variable so the same JSON works across environments. Pair it with the alerting rules in [Monitoring](monitoring.md#alerting-rules) for a baseline observability setup.
