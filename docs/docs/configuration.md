# Configuration

The proxy is configured via environment variables.

| Variable | Description | Default |
|----------|-------------|---------|
| `PHILTER_ENDPOINT` | The URL of your Philter instance. | `https://localhost:8080` |
| `PHILTER_CONTEXT` | The context used for Philter requests. | `none` |
| `PHILTER_DOCUMENT_ID` | The document ID used for Philter requests. If not set, a random UUID will be used for each request. | (random UUID) |
| `PHILTER_POLICY_NAME` | The policy name used for Philter requests. | `default` |
| `PHILTER_PROXY_PORT` | The port the proxy will listen on. | `8080` |
| `PHILTER_PROXY_CERT_FILE` | Path to the TLS certificate file. | `cert.pem` |
| `PHILTER_PROXY_KEY_FILE` | Path to the TLS private key file. | `key.pem` |

## Example

```bash
export PHILTER_ENDPOINT=https://your-philter-ip:8080
export PHILTER_PROXY_PORT=8080
./philter-openai-proxy
```
