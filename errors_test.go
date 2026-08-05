package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// parseErrorBody parses the proxy's structured error response into a typed
// struct so individual tests don't repeat boilerplate.
type errorBody struct {
	Error struct {
		Message   string `json:"message"`
		Type      string `json:"type"`
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func parseErrorBody(t *testing.T, w *httptest.ResponseRecorder) errorBody {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("error response Content-Type must be application/json, got %q", ct)
	}
	var body errorBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error response is not valid JSON: %v\nbody: %s", err, w.Body.String())
	}
	if body.Error.Type == "" {
		t.Errorf("error.type must not be empty (body: %s)", w.Body.String())
	}
	if body.Error.Code == "" {
		t.Errorf("error.code must not be empty (body: %s)", w.Body.String())
	}
	if body.Error.RequestID == "" {
		t.Errorf("error.request_id must not be empty (body: %s)", w.Body.String())
	}
	if body.Error.Message == "" {
		t.Errorf("error.message must not be empty (body: %s)", w.Body.String())
	}
	return body
}

// auditEntryFromBuf reads the inbound audit log entry from a buffer that has
// captured one or more log lines. Returns the first entry with direction=inbound.
func auditEntryFromBuf(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	if buf.Len() == 0 {
		t.Fatal("no audit log lines emitted")
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("audit line is not JSON: %v\nline: %s", err, line)
		}
		if entry["direction"] == "inbound" {
			return entry
		}
	}
	t.Fatalf("no inbound audit entry found in:\n%s", buf.String())
	return nil
}

// withAuditLogger attaches a slog logger writing to buf as the proxy's
// audit logger.
func withAuditLogger(p *Proxy, buf *bytes.Buffer) {
	p.auditLogger = slog.New(slog.NewJSONHandler(buf, nil))
}

// proxyForErrors builds a minimal proxy with a working Philter mock. Callers
// override fields (e.g. keyIndex, openaiTarget) for the specific scenario.
func proxyForErrors(t *testing.T) (*Proxy, func()) {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	u, _ := url.Parse(providerSrv.URL)
	p := &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
	}
	return p, func() {
		philterSrv.Close()
		providerSrv.Close()
	}
}

// --- The error-contract table ----------------------------------------------
//
// Each entry pins the (status, type, code) the proxy is contractually committed
// to. Changing any value here is a breaking API change.

type contractCase struct {
	name       string
	wantStatus int
	wantType   string
	wantCode   string
	wantHeader map[string]string // additional response headers to assert
	drive      func(t *testing.T) *httptest.ResponseRecorder
}

func TestErrorContract(t *testing.T) {
	cases := []contractCase{
		{
			name:       "invalid_request/bad_json",
			wantStatus: http.StatusBadRequest,
			wantType:   "invalid_request",
			wantCode:   "bad_json",
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{not json`))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name:       "unauthorized/missing_api_key",
			wantStatus: http.StatusUnauthorized,
			wantType:   "unauthorized",
			wantCode:   "missing_api_key",
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				p.keyStore = testKeyStore(map[string]string{"valid-key": ""})
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name:       "unauthorized/invalid_api_key",
			wantStatus: http.StatusUnauthorized,
			wantType:   "unauthorized",
			wantCode:   "invalid_api_key",
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				p.keyStore = testKeyStore(map[string]string{"valid-key": ""})
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
				req.Header.Set("x-philter-proxy-key", "wrong-key")
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name:       "capacity/concurrency_exceeded",
			wantStatus: http.StatusServiceUnavailable,
			wantType:   "capacity",
			wantCode:   "concurrency_exceeded",
			wantHeader: map[string]string{"Retry-After": "1"},
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				// Fill the only slot synthetically by giving the limiter no headroom.
				p.concurrency = newConcurrencyLimiter(1)
				p.concurrency.global <- struct{}{} // hold the slot
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				<-p.concurrency.global // release
				return w
			},
		},
		{
			name:       "pii_blocked/outbound_stream_unscannable",
			wantStatus: http.StatusForbidden,
			wantType:   "pii_blocked",
			wantCode:   "outbound_stream_unscannable",
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				philter := philterRedact("[REDACTED]")
				defer philter.Close()
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					w.WriteHeader(http.StatusOK)
					io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"SSN 123-45-6789\"}}]}\n\n")
				}))
				defer provider.Close()
				p := newOutboundProxy(philter.URL, provider.URL, "openai", "block")
				req := httptest.NewRequest("POST", "/v1/chat/completions",
					strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name:       "not_found/bedrock_disabled",
			wantStatus: http.StatusNotFound,
			wantType:   "not_found",
			wantCode:   "bedrock_disabled",
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				// bedrockRegion is "" by default → bedrock path returns 404.
				req := httptest.NewRequest("POST", "/model/foo/converse", strings.NewReader(`{"messages":[]}`))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name:       "circuit_open/philter_unavailable",
			wantStatus: http.StatusServiceUnavailable,
			wantType:   "circuit_open",
			wantCode:   "philter_unavailable",
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				// Force the circuit open: 1-attempt retry, 1-failure threshold, block fallback.
				p.philter = newPhilterClient(http.DefaultClient, "http://127.0.0.1:1",
					RetryConfig{MaxAttempts: 1},
					CircuitBreakerConfig{Enabled: true, Threshold: 1, TimeoutSeconds: 60, Fallback: "block"},
				)
				// First request trips the breaker.
				sendRequest(p, "/v1/chat/completions", openAIBody(), nil)
				// Second request gets the structured 503.
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name:       "philter_error/request_failed",
			wantStatus: http.StatusBadGateway,
			wantType:   "philter_error",
			wantCode:   "request_failed",
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				// Point Philter at an unreachable address; no circuit breaker.
				p.philter = newPhilterClient(http.DefaultClient, "http://127.0.0.1:1",
					RetryConfig{MaxAttempts: 1},
					CircuitBreakerConfig{Enabled: false},
				)
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name:       "provider_error/unreachable",
			wantStatus: http.StatusBadGateway,
			wantType:   "provider_error",
			wantCode:   "unreachable",
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				// Point provider at an unreachable address.
				u, _ := url.Parse("http://127.0.0.1:1")
				p.openaiTarget = u
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name:       "pii_blocked/outbound_blocked",
			wantStatus: http.StatusForbidden,
			wantType:   "pii_blocked",
			wantCode:   "outbound_blocked",
			drive: func(t *testing.T) *httptest.ResponseRecorder {
				philter := philterRedact("[REDACTED]")
				t.Cleanup(philter.Close)
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"SSN here"}}]}`))
				}))
				t.Cleanup(provider.Close)
				p := newOutboundProxy(philter.URL, provider.URL, "openai", "block")
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := tc.drive(t)
			if w.Code != tc.wantStatus {
				t.Errorf("status: want %d, got %d (body: %s)", tc.wantStatus, w.Code, w.Body.String())
			}
			body := parseErrorBody(t, w)
			if body.Error.Type != tc.wantType {
				t.Errorf("error.type: want %q, got %q", tc.wantType, body.Error.Type)
			}
			if body.Error.Code != tc.wantCode {
				t.Errorf("error.code: want %q, got %q", tc.wantCode, body.Error.Code)
			}
			if got := w.Header().Get("X-Request-Id"); got == "" {
				t.Error("X-Request-Id header must be set on every response")
			} else if got != body.Error.RequestID {
				t.Errorf("X-Request-Id header (%q) must match error.request_id (%q)", got, body.Error.RequestID)
			}
			for header, wantVal := range tc.wantHeader {
				got := w.Header().Get(header)
				if got == "" {
					t.Errorf("header %s must be set", header)
				} else if wantVal != "" && got != wantVal {
					t.Errorf("header %s: want %q, got %q", header, wantVal, got)
				}
			}
		})
	}
}

// TestXRequestIdHonored verifies that an inbound X-Request-Id is propagated
// rather than overwritten, so callers can correlate across hops.
func TestXRequestIdHonored(t *testing.T) {
	p, cleanup := proxyForErrors(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
	req.Header.Set("X-Request-Id", "client-supplied-id-123")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := w.Header().Get("X-Request-Id"); got != "client-supplied-id-123" {
		t.Errorf("X-Request-Id must echo the inbound value, got %q", got)
	}
}

// TestXRequestIdOnSuccess verifies that a request_id is generated and exposed
// even when the client did not send one and the request succeeds.
func TestXRequestIdOnSuccess(t *testing.T) {
	p, cleanup := proxyForErrors(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	id := w.Header().Get("X-Request-Id")
	if id == "" {
		t.Fatal("X-Request-Id must be set on success")
	}
	if len(id) != 36 {
		t.Errorf("X-Request-Id should look like a UUID; got %q (len %d)", id, len(id))
	}
}

// TestAuditCarriesErrorCode verifies that audit entries reference the same
// (type, code, request_id) the client saw — the AC's correlation guarantee.
// Runs across multiple error paths so a regression in any one handler is
// caught, not just the one we happened to pick.
func TestAuditCarriesErrorCode(t *testing.T) {
	type setup struct {
		name  string
		drive func(t *testing.T, auditBuf *bytes.Buffer) *httptest.ResponseRecorder
	}
	setups := []setup{
		{
			name: "unauthorized",
			drive: func(t *testing.T, buf *bytes.Buffer) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				p.keyStore = testKeyStore(map[string]string{"valid-key": ""})
				withAuditLogger(p, buf)
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name: "invalid_request",
			drive: func(t *testing.T, buf *bytes.Buffer) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				withAuditLogger(p, buf)
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{not json`))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
		{
			name: "provider_error",
			drive: func(t *testing.T, buf *bytes.Buffer) *httptest.ResponseRecorder {
				p, cleanup := proxyForErrors(t)
				defer cleanup()
				u, _ := url.Parse("http://127.0.0.1:1")
				p.openaiTarget = u
				withAuditLogger(p, buf)
				req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
				w := httptest.NewRecorder()
				p.ServeHTTP(w, req)
				return w
			},
		},
	}

	for _, s := range setups {
		t.Run(s.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := s.drive(t, &buf)
			body := parseErrorBody(t, w)
			entry := auditEntryFromBuf(t, &buf)
			if entry["error_type"] != body.Error.Type {
				t.Errorf("audit.error_type (%v) must equal error.type (%q)", entry["error_type"], body.Error.Type)
			}
			if entry["error_code"] != body.Error.Code {
				t.Errorf("audit.error_code (%v) must equal error.code (%q)", entry["error_code"], body.Error.Code)
			}
			if entry["request_id"] != body.Error.RequestID {
				t.Errorf("audit.request_id (%v) must equal error.request_id (%q)", entry["request_id"], body.Error.RequestID)
			}
			if entry["http_status"] != float64(w.Code) {
				t.Errorf("audit.http_status (%v) must equal response status (%d)", entry["http_status"], w.Code)
			}
		})
	}
}

// TestAuditNotEmittedForHealth verifies /health stays out of the audit log
// (health checks happen frequently and would drown real traffic).
func TestAuditNotEmittedForHealth(t *testing.T) {
	p, cleanup := proxyForErrors(t)
	defer cleanup()

	var buf bytes.Buffer
	withAuditLogger(p, &buf)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if buf.Len() != 0 {
		t.Errorf("expected /health to produce no audit log entries; got:\n%s", buf.String())
	}
}
