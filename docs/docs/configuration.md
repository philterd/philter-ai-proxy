# Configuration

The proxy is configured via environment variables.

| Variable | Description | Default |
|----------|-------------|---------|
| `PHILTER_ENDPOINT` | The URL of your Philter instance. | `https://localhost:8080` |
| `PHILTER_CONTEXT` | The context used for Philter requests. | `none` |
| `PHILTER_DOCUMENT_ID` | The document ID used for Philter requests. If not set, a random UUID will be used for each request. | (random UUID) |
| `PHILTER_POLICY_NAME` | The policy name used for Philter requests. | `default` |
| `PHILTER_TLS_VERIFY` | Enable TLS certificate verification for the Philter backend connection. | `true` |
| `PHILTER_CA_CERT` | Path to a custom CA certificate (PEM) for the Philter backend connection. Useful when Philter uses a self-signed or internal CA certificate. | (none) |
| `PROVIDER_TLS_VERIFY` | Enable TLS certificate verification for LLM provider connections (OpenAI, Anthropic, Gemini, Ollama). | `true` |
| `PHILTER_PROXY_PORT` | The port the proxy will listen on. | `8080` |
| `PHILTER_PROXY_CERT_FILE` | Path to the TLS certificate file. | `cert.pem` |
| `PHILTER_PROXY_KEY_FILE` | Path to the TLS private key file. | `key.pem` |

## TLS Configuration

By default, TLS certificate verification is enabled for all outbound connections (both to the Philter backend and to LLM providers). This is the recommended configuration for production deployments.

### Philter Backend with Self-Signed Certificate

If your Philter instance uses a self-signed certificate or a certificate from an internal CA, you can provide the CA certificate:

```bash
export PHILTER_CA_CERT=/etc/ssl/internal-ca.pem
```

### Disabling TLS Verification (Development Only)

To disable TLS verification for the Philter backend (e.g., during development):

```bash
export PHILTER_TLS_VERIFY=false
```

To disable TLS verification for LLM provider connections:

```bash
export PROVIDER_TLS_VERIFY=false
```

**Warning:** Disabling TLS verification makes connections vulnerable to man-in-the-middle attacks. Only disable verification in trusted development environments.

## Example

```bash
export PHILTER_ENDPOINT=https://your-philter-ip:8080
export PHILTER_PROXY_PORT=8080
./philter-ai-proxy
```
