package main

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// maxModelLabelsPerProvider bounds the cardinality of the `model` Prometheus
// label per provider. The label value is set from the client-supplied
// `model` field of every request: an attacker holding a valid API key
// can otherwise emit one label set per arbitrary string, exhausting the
// metric scraper's memory. After the cap, additional unique model names
// are collapsed to the sentinel "other". 64 is generous compared to the
// real number of distinct production model identifiers (typically <20
// per provider) while bounding worst-case memory.
const (
	maxModelLabelsPerProvider = 64
	overflowModelLabel        = "other"
)

// modelLabelLimiter caps the cardinality of the `model` Prometheus label
// on per-provider token-usage counters. Each provider gets its own
// fixed-size set; once full, all subsequent unseen models are reported
// under "other". The limiter is safe for concurrent use.
type modelLabelLimiter struct {
	mu          sync.Mutex
	perProvider map[string]map[string]struct{}
	limit       int
}

func newModelLabelLimiter(limit int) *modelLabelLimiter {
	return &modelLabelLimiter{
		perProvider: make(map[string]map[string]struct{}),
		limit:       limit,
	}
}

// reduce returns the model name to use as the Prometheus label value:
// either `model` itself (if it is already in the per-provider set or
// admission still has headroom) or `overflowModelLabel`.
func (l *modelLabelLimiter) reduce(provider, model string) string {
	if model == "" {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	seen, ok := l.perProvider[provider]
	if !ok {
		seen = make(map[string]struct{})
		l.perProvider[provider] = seen
	}
	if _, exists := seen[model]; exists {
		return model
	}
	if len(seen) >= l.limit {
		return overflowModelLabel
	}
	seen[model] = struct{}{}
	return model
}

type ProxyMetrics struct {
	requestsTotal         *prometheus.CounterVec
	requestDuration       *prometheus.HistogramVec
	redactionDuration     *prometheus.HistogramVec
	entitiesRedacted      *prometheus.CounterVec
	promptTokensTotal     *prometheus.CounterVec
	completionTokensTotal *prometheus.CounterVec
	philterErrors         prometheus.Counter
	upstreamErrors        *prometheus.CounterVec
	activeRequests        prometheus.Gauge
	concurrencyShed       *prometheus.CounterVec
	concurrencyLimit      *prometheus.GaugeVec
	tlsHandshakesShed     prometheus.Counter
	// modelLabels caps the `model` label cardinality on the token-usage
	// counters. The model is supplied by the client; without this bound,
	// an attacker holding any valid key can drive the scraper out of
	// memory by emitting one request per random model name.
	modelLabels *modelLabelLimiter
}

func newMetrics(reg prometheus.Registerer) *ProxyMetrics {
	m := &ProxyMetrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "philter_proxy_requests_total",
			Help: "Total requests proxied, labeled by provider, HTTP status code, and policy.",
		}, []string{"provider", "status_code", "policy"}),

		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "philter_proxy_request_duration_seconds",
			Help:    "End-to-end request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"provider"}),

		redactionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "philter_proxy_redaction_duration_seconds",
			Help:    "Time spent on Philter redaction calls in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"provider", "policy"}),

		entitiesRedacted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "philter_proxy_entities_redacted_total",
			Help: "Total entities redacted, labeled by entity type and provider.",
		}, []string{"entity_type", "provider"}),

		promptTokensTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "philter_proxy_prompt_tokens_total",
			Help: "Total prompt (input) tokens reported by providers, labeled by provider and model.",
		}, []string{"provider", "model"}),

		completionTokensTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "philter_proxy_completion_tokens_total",
			Help: "Total completion (output) tokens reported by providers, labeled by provider and model.",
		}, []string{"provider", "model"}),

		philterErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "philter_proxy_philter_errors_total",
			Help: "Total failed calls to the Philter backend.",
		}),

		upstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "philter_proxy_upstream_errors_total",
			Help: "Total failed calls to LLM providers, labeled by provider and status code.",
		}, []string{"provider", "status_code"}),

		activeRequests: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "philter_proxy_active_requests",
			Help: "Currently in-flight requests.",
		}),

		concurrencyShed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "philter_proxy_concurrency_shed_total",
			Help: "Total requests rejected due to the max-concurrent-requests guard, labeled by scope (global).",
		}, []string{"scope"}),

		concurrencyLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "philter_proxy_concurrency_limit",
			Help: "Configured max-concurrent-requests ceiling, labeled by scope. 0 means unlimited. Pair with philter_proxy_active_requests to compute utilization.",
		}, []string{"scope"}),

		tlsHandshakesShed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "philter_proxy_tls_handshakes_shed_total",
			Help: "Total inbound TLS connections dropped because the max-concurrent-TLS-handshakes ceiling was reached.",
		}),

		modelLabels: newModelLabelLimiter(maxModelLabelsPerProvider),
	}

	reg.MustRegister(
		m.requestsTotal,
		m.requestDuration,
		m.redactionDuration,
		m.entitiesRedacted,
		m.promptTokensTotal,
		m.completionTokensTotal,
		m.philterErrors,
		m.upstreamErrors,
		m.activeRequests,
		m.concurrencyShed,
		m.concurrencyLimit,
		m.tlsHandshakesShed,
	)
	return m
}
