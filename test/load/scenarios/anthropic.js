// Anthropic non-streaming through the proxy. Mirrors openai.js so a head-to-
// head comparison across providers is straightforward: same VUs, same
// duration, same fixture, only the URL path and body shape differ.

import http from 'k6/http';
import { check } from 'k6';
import { PROXY_URL, ANTHROPIC_BODY, DEFAULT_THRESHOLDS, INSECURE_OPTS } from './common.js';

export const options = {
  scenarios: {
    anthropic_inbound: {
      executor: 'constant-vus',
      vus: parseInt(__ENV.VUS || '10', 10),
      duration: __ENV.DURATION || '30s',
    },
  },
  thresholds: DEFAULT_THRESHOLDS,
  ...INSECURE_OPTS,
};

export default function () {
  const res = http.post(
    `${PROXY_URL}/v1/messages`,
    ANTHROPIC_BODY,
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response has type field': (r) => r.body.includes('"type"'),
  });
}
