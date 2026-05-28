// Direct-to-stub baseline. NO proxy, NO redaction. Same fixture body and
// load profile as scenarios/openai.js, so the delta between this and
// openai.js is precisely the cost of running the proxy + Philter for one
// inbound redaction pass.

import http from 'k6/http';
import { check } from 'k6';
import { STUB_URL, OPENAI_BODY, DEFAULT_THRESHOLDS, SUMMARY_TREND_STATS } from './common.js';

export const options = {
  scenarios: {
    no_redaction_baseline: {
      executor: 'constant-vus',
      vus: parseInt(__ENV.VUS || '10', 10),
      duration: __ENV.DURATION || '30s',
    },
  },
  thresholds: DEFAULT_THRESHOLDS,
  summaryTrendStats: SUMMARY_TREND_STATS,
};

export default function () {
  const res = http.post(
    `${STUB_URL}/v1/chat/completions`,
    OPENAI_BODY,
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}
