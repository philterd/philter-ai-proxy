// Outbound-scan scenario: the proxy scans the upstream response before
// returning it, so each request is redacted twice; the threshold reflects that.
//
// The route in config.load.yaml that gates outbound scanning matches on the
// `x-loadtest-mode: outbound` header, so we set it on every request.

import http from 'k6/http';
import { check } from 'k6';
import { PROXY_URL, OPENAI_BODY, INSECURE_OPTS, HEADERS } from './common.js';

export const options = {
  scenarios: {
    outbound_scan: {
      executor: 'constant-vus',
      vus: parseInt(__ENV.VUS || '10', 10),
      duration: __ENV.DURATION || '30s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    // Outbound scanning redacts the response as well as the request.
    http_req_duration: ['p(95)<800', 'p(99)<1500'],
  },
  ...INSECURE_OPTS,
};

export default function () {
  const res = http.post(
    `${PROXY_URL}/v1/chat/completions`,
    OPENAI_BODY,
    {
      headers: { ...HEADERS, 'x-loadtest-mode': 'outbound' },
    },
  );
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}
