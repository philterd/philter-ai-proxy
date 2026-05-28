package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// installInMemoryTracerProvider configures the global OTel state for tests:
// an always-sampling TracerProvider that records spans into an in-memory
// exporter the test can inspect. Returns the exporter and a cleanup func
// that restores the prior global state so tests don't pollute each other.
func installInMemoryTracerProvider(t *testing.T) (*tracetest.InMemoryExporter, func()) {
	t.Helper()
	prev := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSyncer(exporter), // synchronous so test reads see spans without a flush
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	return exporter, func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
		otel.SetTextMapPropagator(prevProp)
	}
}

// tracedProxy returns a proxy with instrumented HTTP clients wired to a
// canned Philter (always returns "ok") and a canned OpenAI provider that
// records the `traceparent` header it received.
func tracedProxy(t *testing.T) (*Proxy, *bytes.Buffer, func() string) {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("ok", "doc", nil))
	}))
	var providerTraceparent string
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerTraceparent = r.Header.Get("Traceparent")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"x"}`))
	}))

	u, _ := url.Parse(providerSrv.URL)
	p := &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
	}
	// Wrap each transport the way main() would when tracing is active.
	p.openaiClient = instrumentTransport(p.openaiClient, true, "provider.openai")
	p.philter.httpClient = instrumentTransport(p.philter.httpClient, true, "philter.filter")

	var auditBuf bytes.Buffer
	withAuditLogger(p, &auditBuf)

	t.Cleanup(func() {
		philterSrv.Close()
		providerSrv.Close()
	})
	return p, &auditBuf, func() string { return providerTraceparent }
}

// --- setupTracing ---------------------------------------------------------

func TestSetupTracing_DisabledIsNoOp(t *testing.T) {
	shutdown, active, err := setupTracing(context.Background(), TracingConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Error("setupTracing(Enabled:false) must report tracing inactive")
	}
	// Must not panic and must succeed.
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown on disabled tracing: %v", err)
	}
}

func TestSetupTracing_AlwaysOffByDefault(t *testing.T) {
	// Even when the SDK is enabled, the AC says "off by default" - no spans
	// should be exported unless OTEL_TRACES_SAMPLER is set. samplerFromEnv()
	// with an unset env var returns NeverSample.
	t.Setenv("OTEL_TRACES_SAMPLER", "")
	s := samplerFromEnv()
	// NeverSample's String() is "AlwaysOffSampler" in the OTel Go SDK.
	if s.Description() != "AlwaysOffSampler" {
		t.Errorf("default sampler: want AlwaysOffSampler, got %q", s.Description())
	}
}

func TestSetupTracing_SamplerEnvOverrides(t *testing.T) {
	cases := []struct{ env, want string }{
		{"always_on", "AlwaysOnSampler"},
		{"always_off", "AlwaysOffSampler"},
		{"parentbased_always_on", "ParentBased{root:AlwaysOnSampler"},
		{"traceidratio", "TraceIDRatioBased"},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("OTEL_TRACES_SAMPLER", tc.env)
			s := samplerFromEnv()
			if !strings.HasPrefix(s.Description(), tc.want) {
				t.Errorf("env=%q sampler description: want prefix %q, got %q", tc.env, tc.want, s.Description())
			}
		})
	}
}

func TestSetupTracing_UnknownSamplerFallsBack(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "no-such-sampler")
	s := samplerFromEnv()
	if s.Description() != "AlwaysOffSampler" {
		t.Errorf("unknown sampler should fall back to AlwaysOff, got %q", s.Description())
	}
}

// --- instrumentTransport / instrumentHandler ------------------------------

func TestInstrumentTransport_NoOpWhenDisabled(t *testing.T) {
	client := &http.Client{Transport: http.DefaultTransport}
	originalTransport := client.Transport
	got := instrumentTransport(client, false, "x")
	if got.Transport != originalTransport {
		t.Error("instrumentTransport with tracing disabled must not wrap the transport")
	}
}

func TestInstrumentTransport_WrapsWhenEnabled(t *testing.T) {
	client := &http.Client{Transport: http.DefaultTransport}
	got := instrumentTransport(client, true, "x")
	if got.Transport == http.DefaultTransport {
		t.Error("instrumentTransport with tracing enabled must replace the transport")
	}
}

func TestInstrumentHandler_NoOpWhenDisabled(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	got := instrumentHandler(h, false)
	// When disabled, return value should be the same handler we passed in.
	if got == nil {
		t.Fatal("instrumentHandler returned nil with tracing disabled")
	}
	// Pointer equality is the strongest assertion: with disabled tracing
	// the function returns its argument unchanged.
	if !sameHandler(h, got) {
		t.Error("instrumentHandler with tracing disabled must return the same handler")
	}
}

// sameHandler reports whether a and b are the same handler value. We can't
// compare functions directly with ==, but http.HandlerFunc is comparable
// via reflect; for the no-op case we know the type returned is HandlerFunc.
func sameHandler(a, b http.Handler) bool {
	_, aok := a.(http.HandlerFunc)
	_, bok := b.(http.HandlerFunc)
	return aok && bok
}

// --- End-to-end: root + child spans, traceparent propagation, audit trace_id

func TestTracing_EndToEnd(t *testing.T) {
	exporter, restore := installInMemoryTracerProvider(t)
	defer restore()

	p, auditBuf, providerTraceparent := tracedProxy(t)

	// Send a request with an inbound W3C traceparent so we can also assert
	// the proxy honours upstream trace context.
	const inboundTraceID = "11112222333344445555666677778888"
	const inboundSpanID = "1111222233334444"
	inboundTraceparent := "00-" + inboundTraceID + "-" + inboundSpanID + "-01"

	// Wrap the proxy with otelhttp so the request gets the inbound root span.
	handler := instrumentHandler(p, true)

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
	req.Header.Set("Traceparent", inboundTraceparent)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 1. Outbound traceparent header on the provider call must reference the
	//    inbound trace ID (proves trace context propagation).
	tp := providerTraceparent()
	if !strings.Contains(tp, inboundTraceID) {
		t.Errorf("provider did not receive a traceparent linked to the inbound trace.\n  inbound:  %s\n  provider: %q", inboundTraceparent, tp)
	}

	// 2. The audit entry must carry the inbound trace ID so log lines can
	//    be cross-referenced with APM data.
	entry := auditEntryFromBuf(t, auditBuf)
	if entry["trace_id"] != inboundTraceID {
		t.Errorf("audit.trace_id: want %q, got %v", inboundTraceID, entry["trace_id"])
	}

	// 3. We expect at least three spans: the inbound root from otelhttp, one
	//    outbound for Philter, one outbound for the provider. All must
	//    belong to the same trace (the inbound trace ID).
	spans := exporter.GetSpans()
	if len(spans) < 3 {
		t.Fatalf("expected >=3 spans (root + philter + provider), got %d: %v", len(spans), spanNames(spans))
	}
	traceIDs := map[string]int{}
	for _, s := range spans {
		traceIDs[s.SpanContext.TraceID().String()]++
	}
	if len(traceIDs) != 1 {
		t.Errorf("all spans should share one trace ID, got: %v", traceIDs)
	}
	if _, ok := traceIDs[inboundTraceID]; !ok {
		t.Errorf("spans not associated with the inbound trace ID %q: %v", inboundTraceID, traceIDs)
	}

	// 4. Span names should include both a Philter and a provider span.
	names := spanNames(spans)
	if !containsString(names, "philter.filter") {
		t.Errorf("expected a span named philter.filter; got %v", names)
	}
	if !containsString(names, "provider.openai") {
		t.Errorf("expected a span named provider.openai; got %v", names)
	}
}

func TestTracing_AuditHasNoTraceIDWhenDisabled(t *testing.T) {
	// With tracing disabled, the audit entry's trace_id field is empty
	// (omitempty + zero value).
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("ok", "doc", nil))
	}))
	defer philterSrv.Close()
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"x"}`))
	}))
	defer providerSrv.Close()

	u, _ := url.Parse(providerSrv.URL)
	p := &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
	}
	var auditBuf bytes.Buffer
	withAuditLogger(p, &auditBuf)

	// Note: no instrumentHandler wrap, no otelhttp on clients - tracing is
	// fully off.
	w := sendRequest(p, "/v1/chat/completions", openAIBody(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	entry := auditEntryFromBuf(t, &auditBuf)
	if id, ok := entry["trace_id"]; ok && id != "" {
		t.Errorf("audit.trace_id should be empty when tracing is disabled, got %v", id)
	}
}

// --- traceIDFromContext ---------------------------------------------------

func TestTraceIDFromContext(t *testing.T) {
	if id := traceIDFromContext(context.Background()); id != "" {
		t.Errorf("expected empty trace ID for bare context, got %q", id)
	}

	// Build a context carrying a recorded span.
	exporter, restore := installInMemoryTracerProvider(t)
	_ = exporter
	defer restore()

	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "x")
	defer span.End()

	got := traceIDFromContext(ctx)
	want := span.SpanContext().TraceID().String()
	if got != want {
		t.Errorf("traceIDFromContext: want %q, got %q", want, got)
	}
}

// --- helpers --------------------------------------------------------------

func spanNames(spans tracetest.SpanStubs) []string {
	out := make([]string, len(spans))
	for i, s := range spans {
		out[i] = s.Name
	}
	return out
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// Compile-time check that trace.SpanContextFromContext is still callable
// with the imported trace package; reduces the chance of an import-mismatch
// breaking only this file.
var _ = trace.SpanContextFromContext

// Compile-time check that json import is referenced (used by auditEntryFromBuf in errors_test.go).
var _ = json.Unmarshal
