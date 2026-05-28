// OpenAI streaming (SSE) through the proxy. Streaming has a different shape:
// the proxy buffers nothing on the response path, so end-to-end latency is
// dominated by the stub's chunk-delay. Threshold is relaxed to accommodate.

import http from 'k6/http';
import { check } from 'k6';
import { PROXY_URL, OPENAI_STREAM_BODY, INSECURE_OPTS } from './common.js';

export const options = {
  scenarios: {
    openai_streaming: {
      executor: 'constant-vus',
      vus: parseInt(__ENV.VUS || '5', 10),
      duration: __ENV.DURATION || '30s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    // Streaming responses are bounded by the stub's chunk schedule. The
    // default stub produces 4 chunks at 10ms apart = ~40ms baseline; the
    // proxy adds redaction and forwarding overhead.
    http_req_duration: ['p(95)<1000', 'p(99)<2000'],
  },
  ...INSECURE_OPTS,
};

export default function () {
  const res = http.post(
    `${PROXY_URL}/v1/chat/completions`,
    OPENAI_STREAM_BODY,
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response is SSE': (r) => r.body.indexOf('data:') >= 0,
    'received DONE marker': (r) => r.body.includes('[DONE]'),
  });
}
