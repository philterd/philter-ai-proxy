package main

import "github.com/prometheus/client_golang/prometheus"

type ProxyMetrics struct {
	requestsTotal        *prometheus.CounterVec
	requestDuration      *prometheus.HistogramVec
	redactionDuration    *prometheus.HistogramVec
	entitiesRedacted     *prometheus.CounterVec
	promptTokensTotal    *prometheus.CounterVec
	completionTokensTotal *prometheus.CounterVec
	philterErrors        prometheus.Counter
	upstreamErrors       *prometheus.CounterVec
	activeRequests       prometheus.Gauge
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
	)
	return m
}
