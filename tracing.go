package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Tracing follows the convention "off by default, opt-in via config, configured
// via standard OTel env vars." When `tracing.enabled: false`, no SDK is built
// and the helpers below short-circuit to no-ops; the proxy's hot path pays
// zero overhead.
//
// When enabled, the OTLP exporter is configured from the standard env vars:
//
//   OTEL_EXPORTER_OTLP_ENDPOINT      - e.g. http://collector:4318 (HTTP) or :4317 (gRPC)
//   OTEL_EXPORTER_OTLP_PROTOCOL      - "http/protobuf" (default here) or "grpc"
//   OTEL_EXPORTER_OTLP_HEADERS       - comma-separated header=value pairs
//   OTEL_EXPORTER_OTLP_INSECURE      - "true" to skip TLS (gRPC)
//   OTEL_SERVICE_NAME                - default "philter-ai-proxy"
//   OTEL_RESOURCE_ATTRIBUTES         - key=value,key=value
//   OTEL_TRACES_SAMPLER              - default "always_off" so even with
//                                      tracing.enabled=true no spans flow
//                                      until an operator explicitly opts in
//   OTEL_TRACES_SAMPLER_ARG          - argument for ratio samplers, etc.
//
// Sampling defaults to "always_off" to honour the AC's "off by default"
// requirement: turning on the SDK does not by itself start emitting spans.

// shutdownTracerFunc is the cleanup callback returned from setupTracing. It is
// always non-nil; when tracing is disabled it is a no-op.
type shutdownTracerFunc func(context.Context) error

// setupTracing installs the global TracerProvider and Propagators when
// cfg.Enabled is true. Returns a shutdown function that flushes the exporter
// and a boolean indicating whether tracing is active.
func setupTracing(ctx context.Context, cfg TracingConfig) (shutdownTracerFunc, bool, error) {
	if !cfg.Enabled {
		return func(context.Context) error { return nil }, false, nil
	}

	exporter, err := newOTLPExporter(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("OTLP exporter: %w", err)
	}

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = cfg.ServiceName
	}
	if serviceName == "" {
		serviceName = "philter-ai-proxy"
	}

	res, err := resource.Merge(resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, false, fmt.Errorf("OTel resource: %w", err)
	}

	sampler := samplerFromEnv()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	slog.Info("OpenTelemetry tracing enabled", "service", serviceName, "sampler", samplerName())

	return func(ctx context.Context) error {
		// Bound the shutdown so it cannot stall process exit indefinitely.
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return tp.Shutdown(shutdownCtx)
	}, true, nil
}

// newOTLPExporter builds the OTLP exporter, switching between HTTP and gRPC
// based on OTEL_EXPORTER_OTLP_PROTOCOL (default "http/protobuf").
func newOTLPExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	protocol := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")))
	switch protocol {
	case "grpc":
		return otlptrace.New(ctx, otlptracegrpc.NewClient())
	case "", "http/protobuf", "http":
		return otlptrace.New(ctx, otlptracehttp.NewClient())
	default:
		return nil, fmt.Errorf("unsupported OTEL_EXPORTER_OTLP_PROTOCOL %q (want grpc or http/protobuf)", protocol)
	}
}

// samplerFromEnv mirrors a subset of OTel's standard sampler env-var contract.
// We implement the common cases ourselves rather than depend on the (still
// experimental) autoconfig SDK; this keeps the SDK init dependency-light.
//
// Default is always_off: tracing.enabled=true gets the SDK initialised and
// outbound trace context propagated when an incoming traceparent is present,
// but no new traces start until the operator sets OTEL_TRACES_SAMPLER.
func samplerFromEnv() sdktrace.Sampler {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER"))) {
	case "always_on":
		return sdktrace.AlwaysSample()
	case "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "parentbased_always_off":
		return sdktrace.ParentBased(sdktrace.NeverSample())
	case "traceidratio":
		return sdktrace.TraceIDRatioBased(samplerArg(1.0))
	case "parentbased_traceidratio":
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplerArg(1.0)))
	case "", "always_off":
		return sdktrace.NeverSample()
	default:
		slog.Warn("Unrecognized OTEL_TRACES_SAMPLER, falling back to always_off",
			"value", os.Getenv("OTEL_TRACES_SAMPLER"))
		return sdktrace.NeverSample()
	}
}

func samplerName() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER")))
	if v == "" {
		return "always_off"
	}
	return v
}

func samplerArg(def float64) float64 {
	v := os.Getenv("OTEL_TRACES_SAMPLER_ARG")
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		slog.Warn("Invalid OTEL_TRACES_SAMPLER_ARG, falling back to default", "value", v, "default", def)
		return def
	}
	return f
}

// instrumentTransport wraps the given http.Client's Transport with
// otelhttp.NewTransport so outbound calls automatically get a span and
// inject traceparent/tracestate headers. When tracing is disabled, the
// client is returned unchanged.
func instrumentTransport(client *http.Client, tracingEnabled bool, spanNameFmt string) *http.Client {
	if !tracingEnabled || client == nil {
		return client
	}
	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}
	client.Transport = otelhttp.NewTransport(client.Transport,
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return spanNameFmt
		}),
	)
	return client
}

// instrumentHandler wraps the proxy handler with otelhttp.NewHandler when
// tracing is enabled, creating a root span per inbound request. When disabled
// the handler is returned unchanged.
func instrumentHandler(h http.Handler, tracingEnabled bool) http.Handler {
	if !tracingEnabled {
		return h
	}
	return otelhttp.NewHandler(h, "proxy.request",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return "proxy.request " + r.Method + " " + r.URL.Path
		}),
	)
}

// traceIDFromContext returns the W3C trace ID for the current context's span,
// or "" when there's no recording span (tracing disabled, or current span
// not sampled).
func traceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}
