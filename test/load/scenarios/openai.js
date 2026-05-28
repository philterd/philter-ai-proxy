// OpenAI non-streaming through the proxy. The default load profile: 10
// virtual users sustained for 30 seconds, gives ~hundreds of requests for a
// stable p95/p99 read.
//
// Run:
//   k6 run -e PROXY_URL=https://localhost:8080 scenarios/openai.js
//
// Or via Docker:
//   docker run --network host -e PROXY_URL=https://localhost:8080 \
//     -v "$PWD/scenarios:/scenarios" grafana/k6:latest \
//     run --insecure-skip-tls-verify /scenarios/openai.js

import http from 'k6/http';
import { check } from 'k6';
import { PROXY_URL, OPENAI_BODY, DEFAULT_THRESHOLDS, INSECURE_OPTS } from './common.js';

export const options = {
  scenarios: {
    openai_inbound: {
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
    `${PROXY_URL}/v1/chat/completions`,
    OPENAI_BODY,
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(res, {
    'status is 200': (r) => r.status === 200,
    'response has model field': (r) => r.body.includes('"model"'),
  });
}
