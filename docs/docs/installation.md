# Installation

The proxy ships as a Docker image, `philterd/philter-ai-proxy`, that includes the PhEye model the default policy uses to find person names. It also runs as a jar on Java 25.

## Requirements

- About 1.5 GiB of memory. The PhEye model is loaded into memory when the proxy starts.
- A persistent directory for the proxy's SQLite database, which holds policies, API keys, contexts, and the audit log.
- Network access to the LLM providers you use.

## Docker

Generate the two keys the proxy needs, and keep a copy of the encryption key: the database cannot be read without it, and the proxy refuses to start with a different one.

```bash
export ENCRYPTION_KEY="$(openssl rand -hex 32)"
export BOOTSTRAP_API_KEY="$(openssl rand -hex 32)"

docker run -d --name philter-ai-proxy \
  -p 8080:8080 -p 127.0.0.1:9090:9090 \
  -v philter-ai-proxy-data:/var/lib/philter-ai-proxy \
  -e PHILTER_AI_PROXY_ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  -e PHILTER_AI_PROXY_BOOTSTRAP_API_KEY="$BOOTSTRAP_API_KEY" \
  philterd/philter-ai-proxy:1.0.0
```

- `PHILTER_AI_PROXY_ENCRYPTION_KEY` encrypts the policies and context replacements the database stores: 32 bytes as 64 hex characters or base64.
- `PHILTER_AI_PROXY_BOOTSTRAP_API_KEY` becomes an admin key on first start, while no API key exists. It must be at least 32 characters.
- Port 8080 serves provider traffic and the admin API. Port 9090 serves Prometheus metrics, unauthenticated; the examples publish it on the host's loopback address only. Keep it off the internet.

The proxy serves HTTPS with a self-signed certificate it generates at startup, so `curl` needs `-k`. See [Certificates](#certificates) to use your own, or to serve plain HTTP behind a load balancer.

Wait until the proxy has loaded the model:

```bash
curl -k https://localhost:8080/readyz
```

```json
{"status":"ok"}
```

### Create a key for your application

Applications authenticate to the proxy with a proxy key. Create one with the admin API, using the bootstrap key:

```bash
curl -k https://localhost:8080/admin/api/keys \
  -H "Authorization: Bearer $BOOTSTRAP_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-app", "roles": ["proxy"]}'
```

```json
{"roles":["proxy"],"providers":[],"models":[],"paths":[],"id":"5f0c8a4e-...","name":"my-app","createdAt":"...","key":"pap_..."}
```

The `key` is shown only once. See [API keys](api.md#api-keys) for limiting a key to providers, models, paths, or a policy.

### Send a request

Point the application at the proxy instead of the provider. It sends its provider credential as usual and its proxy key in `x-philter-proxy-key`:

```bash
curl -k https://localhost:8080/v1/chat/completions \
  -H "x-philter-proxy-key: $PROXY_KEY" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "George Washington wrote to me at george@example.com."}]}'
```

OpenAI receives `{{{REDACTED-name}}} wrote to me at {{{REDACTED-email-address}}}.` The default policy finds person names, SSNs, and email addresses; see [Policies](policies.md) to change it.

### Settings

Settings come from `application.yaml` and environment variables; see [Configuration](configuration.md). To use a settings file, mount it and point the proxy at it:

```bash
docker run -d --name philter-ai-proxy \
  -p 8080:8080 -p 127.0.0.1:9090:9090 \
  -v philter-ai-proxy-data:/var/lib/philter-ai-proxy \
  -v "$PWD/application.yaml:/etc/philter-ai-proxy/application.yaml:ro" \
  -e SPRING_CONFIG_ADDITIONAL_LOCATION=file:/etc/philter-ai-proxy/application.yaml \
  -e PHILTER_AI_PROXY_ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  philterd/philter-ai-proxy:1.0.0
```

## Docker Compose

The repository's `docker-compose.yaml` builds the image from source and reads its settings from `application.yaml` and its keys from `.env`:

```bash
cp .env.example .env     # then set both keys in .env
docker compose up -d --build
```

## Kubernetes

See [Kubernetes](kubernetes.md) for the Helm chart and plain manifests.

## Building from Source

The build needs Java 25. The Maven wrapper downloads Maven.

```bash
./mvnw package
java --enable-native-access=ALL-UNNAMED -jar target/philter-ai-proxy.jar \
  --proxy.storage.sqlite-path=./data/philter-ai-proxy.db \
  --proxy.models.directory=./models \
  --proxy.security.encryption-key="$ENCRYPTION_KEY" \
  --proxy.security.bootstrap-api-key="$BOOTSTRAP_API_KEY"
```

The jar does not include the model. The default policy names `ph-eye-pii-en-small`, which it expects in `<models directory>/ph-eye-pii-en-small`: download `gliner_config.json`, `tokenizer.json`, and `model.onnx` from the `onnx` folder of [philterd/ph-eye-pii-en-small](https://huggingface.co/philterd/ph-eye-pii-en-small) into that directory, or change the default policy. Without the model, requests that use the default policy are refused with `policy_invalid`.

Run without a certificate setting, the jar serves plain HTTP. `./mvnw verify` runs the tests and the coverage check.

### Checking the version

```bash
java -jar target/philter-ai-proxy.jar --version
```

```
philter-ai-proxy 1.0.0
```

### Validating the configuration

`--validate-config` checks the settings (providers, the encryption key, trusted proxies) and exits without serving requests. It does not open the database, so it can run beside a running proxy. It exits non-zero when the configuration is invalid.

```bash
docker run --rm -e PHILTER_AI_PROXY_ENCRYPTION_KEY="$ENCRYPTION_KEY" philterd/philter-ai-proxy:1.0.0 --validate-config
```

```
The configuration is valid.
```

## Certificates

The image serves HTTPS with a self-signed certificate generated at startup (`PROXY_TLS_DEVSELFSIGNEDCERT=true`). It encrypts the connection but does not prove the proxy's identity, so clients must skip verification. Use it for evaluation only.

To serve your own certificate, give it and its private key in PEM form:

```bash
docker run -d --name philter-ai-proxy \
  -p 8080:8080 -p 127.0.0.1:9090:9090 \
  -v philter-ai-proxy-data:/var/lib/philter-ai-proxy \
  -v "$PWD/tls:/etc/philter-ai-proxy/tls:ro" \
  -e SERVER_SSL_CERTIFICATE=/etc/philter-ai-proxy/tls/tls.crt \
  -e SERVER_SSL_CERTIFICATEPRIVATEKEY=/etc/philter-ai-proxy/tls/tls.key \
  -e SERVER_SSL_ENABLEDPROTOCOLS=TLSv1.3,TLSv1.2 \
  -e PHILTER_AI_PROXY_ENCRYPTION_KEY="$ENCRYPTION_KEY" \
  philterd/philter-ai-proxy:1.0.0
```

A configured certificate takes precedence over the self-signed one. To require client certificates (mutual TLS), also set `SERVER_SSL_TRUSTCERTIFICATE` to a PEM file of the CA that signs them and `SERVER_SSL_CLIENTAUTH=need`.

When a load balancer, ingress, or service mesh terminates TLS in front of the proxy, serve plain HTTP with `PROXY_TLS_DEVSELFSIGNEDCERT=false`.

The metrics port (9090) always serves plain HTTP.
