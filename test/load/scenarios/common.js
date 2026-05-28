// Shared helpers for all k6 scenarios. Pick targets from env so the same
// scripts can run against the local docker-compose stack (PROXY_URL=
// https://localhost:8080) or any other deployment.

export const PROXY_URL = __ENV.PROXY_URL || 'https://localhost:8080';
export const STUB_URL = __ENV.STUB_URL || 'http://localhost:8090';

// The fixture prompt deliberately carries SSN-shape PII so the redaction path
// actually has work to do on every iteration. The same fixture is used in
// every scenario so the comparison between scenarios is meaningful.
export const FIXTURE_PII = '123-45-6789';

export const OPENAI_BODY = JSON.stringify({
  model: 'stub-model',
  messages: [
    { role: 'user', content: `The SSN on file is ${FIXTURE_PII}. Summarize the case.` },
  ],
});

export const OPENAI_STREAM_BODY = JSON.stringify({
  model: 'stub-model',
  stream: true,
  messages: [
    { role: 'user', content: `The SSN on file is ${FIXTURE_PII}. Summarize the case.` },
  ],
});

export const ANTHROPIC_BODY = JSON.stringify({
  model: 'stub-model',
  max_tokens: 256,
  messages: [
    { role: 'user', content: `The SSN on file is ${FIXTURE_PII}. Summarize the case.` },
  ],
});

// Default thresholds applied by every scenario. Override per-scenario when a
// flow has a different latency budget (e.g. streaming).
export const DEFAULT_THRESHOLDS = {
  http_req_failed: ['rate<0.01'],          // <1% failures
  http_req_duration: ['p(95)<500', 'p(99)<1000'], // ms
};

// Tracked statistics for every Trend metric in the JSON summary export.
// p(99) is not in the default set; we want it for the load-test report.
export const SUMMARY_TREND_STATS = ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'];

// k6 by default validates server certs. The proxy uses a self-signed cert in
// the docker-compose stack, so scenarios opt out of verification with this.
export const INSECURE_OPTS = {
  insecureSkipTLSVerify: true,
  summaryTrendStats: SUMMARY_TREND_STATS,
};
