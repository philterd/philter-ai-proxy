package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// The proxy's published guarantee (docs/docs/faq.md) is that audit logs and
// telemetry carry metadata only, never message content. These tests hold it.
//
// Three distinct markers, so a failure says which content leaked:
//
//	promptMarker   what the client sent
//	responseMarker what the provider sent back
//	filteredMarker what Philter returned as FilteredText, which is derived from
//	               customer data and is the field most easily leaked by
//	               widening the struct copy in recordFilterResult
const (
	promptMarker   = "ZebraQuasarPromptMarker7391"
	responseMarker = "OcelotNebulaResponseMarker8827"
	filteredMarker = "MarmosetPulsarFilteredMarker5514"
)

// sink captures everything a request writes: the audit log, the application
// log, and the metric labels exported on /metrics.
type sink struct {
	audit bytes.Buffer
	app   bytes.Buffer
	reg   *prometheus.Registry
	prev  *slog.Logger
}

func newSink(t *testing.T) *sink {
	t.Helper()
	s := &sink{reg: prometheus.NewRegistry(), prev: slog.Default()}
	slog.SetDefault(slog.New(slog.NewJSONHandler(&s.app, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(s.prev) })
	return s
}

func (s *sink) auditLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&s.audit, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// assertClean fails if any marker reached a log or a metric label.
func (s *sink) assertClean(t *testing.T) {
	t.Helper()
	for _, m := range []string{promptMarker, responseMarker, filteredMarker} {
		if strings.Contains(s.audit.String(), m) {
			t.Errorf("content leaked into the audit log (%s):\n%s", markerName(m), s.audit.String())
		}
		if strings.Contains(s.app.String(), m) {
			t.Errorf("content leaked into the application log (%s):\n%s", markerName(m), s.app.String())
		}
	}

	mfs, err := s.reg.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range mfs {
		for _, metric := range mf.GetMetric() {
			for _, lp := range metric.GetLabel() {
				for _, m := range []string{promptMarker, responseMarker, filteredMarker} {
					if strings.Contains(lp.GetValue(), m) {
						t.Errorf("content leaked into metric %s, label %s=%q (%s)",
							mf.GetName(), lp.GetName(), lp.GetValue(), markerName(m))
					}
				}
			}
		}
	}
}

func markerName(m string) string {
	switch m {
	case promptMarker:
		return "prompt"
	case responseMarker:
		return "provider response"
	case filteredMarker:
		return "Philter FilteredText"
	}
	return "unknown"
}

// philterMarking is a Philter mock whose FilteredText is a marker, so any code
// that copies FilteredText into an audit entry trips the assertion.
func philterMarking() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write(explainJSON(filteredMarker, "doc-leak", []Span{{FilterType: "NER_ENTITY", Confidence: 0.9}}))
	}))
}

func providerEcho() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"` + responseMarker + `"}}],` +
			`"usage":{"prompt_tokens":11,"completion_tokens":22}}`))
	}))
}

func markedBody() string {
	b, _ := json.Marshal(map[string]any{
		"model":    "gpt-4",
		"messages": []any{map[string]string{"role": "user", "content": promptMarker}},
	})
	return string(b)
}

// leakProxy wires a proxy with the sink's metrics and audit logger attached.
func leakProxy(s *sink, philterURL, providerURL string, outbound OutboundConfig) *Proxy {
	cfg := testConfig(philterURL)
	cfg.Defaults.Outbound = outbound
	u, _ := url.Parse(providerURL)
	return &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterURL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		auditLogger:  s.auditLogger(),
		metrics:      newMetrics(s.reg),
	}
}

// TestContentNeverReachesLogs drives content through every path that produces
// an audit entry and asserts none of it is written anywhere observable.
func TestContentNeverReachesLogs(t *testing.T) {
	cases := []struct {
		name     string
		outbound OutboundConfig
	}{
		{"inbound redaction only", OutboundConfig{}},
		{"outbound redact", OutboundConfig{Enabled: true, Action: "redact"}},
		{"outbound block", OutboundConfig{Enabled: true, Action: "block"}},
		{"outbound flag", OutboundConfig{Enabled: true, Action: "flag"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newSink(t)
			philter := philterMarking()
			defer philter.Close()
			provider := providerEcho()
			defer provider.Close()

			p := leakProxy(s, philter.URL, provider.URL, tc.outbound)
			w := sendRequest(p, "/v1/chat/completions", markedBody(), nil)
			if w.Code == 0 {
				t.Fatal("no response written")
			}
			if s.audit.Len() == 0 {
				t.Fatal("no audit entry emitted; the assertion would be vacuous")
			}
			s.assertClean(t)
		})
	}
}

func TestContentNeverReachesLogs_Streaming(t *testing.T) {
	s := newSink(t)
	philter := philterMarking()
	defer philter.Close()

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\""+responseMarker+"\"}}]}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer provider.Close()

	p := leakProxy(s, philter.URL, provider.URL, OutboundConfig{Enabled: true, Action: "redact"})
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"` + promptMarker + `"}],"stream":true}`
	sendRequest(p, "/v1/chat/completions", body, nil)

	if s.audit.Len() == 0 {
		t.Fatal("no audit entry emitted; the assertion would be vacuous")
	}
	s.assertClean(t)
}

// Error paths are the likeliest place for a "log the body so we can debug it"
// line to appear, and the invalid-JSON case additionally depends on how the
// standard library formats decode errors, which is outside our control.
func TestContentNeverReachesLogs_ErrorPaths(t *testing.T) {
	t.Run("philter unreachable", func(t *testing.T) {
		s := newSink(t)
		provider := providerEcho()
		defer provider.Close()

		// Port 1 is closed, so the filter call fails at dial.
		p := leakProxy(s, "http://127.0.0.1:1", provider.URL, OutboundConfig{})
		sendRequest(p, "/v1/chat/completions", markedBody(), nil)
		s.assertClean(t)
	})

	t.Run("provider 5xx", func(t *testing.T) {
		s := newSink(t)
		philter := philterMarking()
		defer philter.Close()
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"upstream exploded: ` + responseMarker + `"}`))
		}))
		defer provider.Close()

		p := leakProxy(s, philter.URL, provider.URL, OutboundConfig{})
		sendRequest(p, "/v1/chat/completions", markedBody(), nil)
		s.assertClean(t)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		s := newSink(t)
		philter := philterMarking()
		defer philter.Close()
		provider := providerEcho()
		defer provider.Close()

		p := leakProxy(s, philter.URL, provider.URL, OutboundConfig{})
		truncated := `{"model":"gpt-4","messages":[{"role":"user","content":"` + promptMarker + `"`
		w := sendRequest(p, "/v1/chat/completions", truncated, nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for malformed JSON, got %d", w.Code)
		}
		s.assertClean(t)
	})

	t.Run("oversized body", func(t *testing.T) {
		s := newSink(t)
		philter := philterMarking()
		defer philter.Close()
		provider := providerEcho()
		defer provider.Close()

		p := leakProxy(s, philter.URL, provider.URL, OutboundConfig{})
		p.config.Listen.MaxRequestBodyBytes = 64
		oversized := `{"model":"gpt-4","messages":[{"role":"user","content":"` +
			strings.Repeat(promptMarker, 20) + `"}]}`
		w := sendRequest(p, "/v1/chat/completions", oversized, nil)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413 for an oversized body, got %d", w.Code)
		}
		s.assertClean(t)
	})

	t.Run("rejected before reaching a provider", func(t *testing.T) {
		s := newSink(t)
		philter := philterMarking()
		defer philter.Close()
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("provider must not be reached when auth fails")
		}))
		defer provider.Close()

		p := leakProxy(s, philter.URL, provider.URL, OutboundConfig{})
		p.keyStore = testKeyStore(map[string]string{"the-valid-key": ""})
		w := sendRequest(p, "/v1/chat/completions", markedBody(), nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 without a key, got %d", w.Code)
		}
		s.assertClean(t)
	})
}

// auditEntryFields is the agreed shape of an audit entry. The guarantee is
// about content, so this list is the place a new field has to be justified:
// adding one fails this test until it is named here, which forces the
// metadata-or-content question to be answered deliberately.
var auditEntryFields = []string{
	"RequestID",
	"Direction",
	"Provider",
	"Model",
	"PolicyName",
	"DocumentID",
	"FieldsRedacted",
	"EntityCount",
	"EntityTypes",
	"RedactLatency",
	"ClientIP",
	"KeyID",
	"HTTPStatus",
	"PromptTokens",
	"CompletionTokens",
	"ErrorType",
	"ErrorCode",
	"TraceID",
	"EntityTypeCounts",
}

func TestAuditEntry_FieldsAreMetadataOnly(t *testing.T) {
	allowed := make(map[string]bool, len(auditEntryFields))
	for _, f := range auditEntryFields {
		allowed[f] = true
	}

	typ := reflect.TypeOf(AuditEntry{})
	seen := make(map[string]bool, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		seen[name] = true
		if !allowed[name] {
			t.Errorf("AuditEntry.%s is new. If it carries message content it must not be logged; "+
				"if it is metadata, add it to auditEntryFields.", name)
		}
	}
	for _, f := range auditEntryFields {
		if !seen[f] {
			t.Errorf("AuditEntry.%s was removed or renamed; update auditEntryFields.", f)
		}
	}
}

// ClientIP is personal data under GDPR and is in the entry by design
// (docs/docs/faq.md). Pinning it present keeps that a decision rather than an
// oversight, and makes its removal a deliberate act.
func TestAuditEntry_ClientIPIsPresentByDesign(t *testing.T) {
	var buf bytes.Buffer
	emitAuditLog(slog.New(slog.NewJSONHandler(&buf, nil)), AuditEntry{ClientIP: "203.0.113.7"})

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("audit entry is not JSON: %v", err)
	}
	if entry["client_ip"] != "203.0.113.7" {
		t.Errorf("client_ip is documented as present in every entry, got %v", entry["client_ip"])
	}
}
