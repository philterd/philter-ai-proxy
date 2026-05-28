package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// probeProxy returns a minimal Proxy whose only meaningful state is the
// PhilterClient — enough for the /livez and /readyz handlers to exercise
// every branch.
func probeProxy(philterURL string, cb CircuitBreakerConfig) *Proxy {
	cfg := testConfig(philterURL)
	cfg.Philter.CircuitBreaker = cb
	return &Proxy{
		config:  cfg,
		philter: newPhilterClient(http.DefaultClient, philterURL, RetryConfig{MaxAttempts: 1}, cb),
	}
}

// tripBreaker forces the configured PhilterClient's breaker into the open
// state by issuing failing Filter calls until the threshold is reached.
// The supplied breaker config must be Enabled with a Threshold; otherwise
// the test misconfigures itself.
func tripBreaker(t *testing.T, p *Proxy, threshold int) {
	t.Helper()
	for i := 0; i < threshold; i++ {
		_, _ = p.philter.Filter("x", "ctx", "doc", "policy")
	}
	if p.philter.cb == nil || p.philter.cb.State() != "open" {
		t.Fatalf("expected breaker to be open after %d failures; got state=%v",
			threshold,
			func() any {
				if p.philter.cb == nil {
					return "<nil>"
				}
				return p.philter.cb.State()
			}())
	}
}

// --- /livez ----------------------------------------------------------------

func TestLivez_AlwaysOK(t *testing.T) {
	// /livez must respond 200 regardless of Philter state. Point at an
	// unreachable Philter to prove the handler does NOT probe downstream.
	p := probeProxy("http://127.0.0.1:1", CircuitBreakerConfig{Enabled: false})
	req := httptest.NewRequest("GET", "/livez", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/livez status: want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("/livez content-type: want JSON, got %q", ct)
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("/livez body is not JSON: %v\n%s", err, w.Body.String())
	}
	if body.Status != "ok" {
		t.Errorf("/livez body.status: want ok, got %q", body.Status)
	}
}

func TestLivez_OKWhenBreakerOpen(t *testing.T) {
	// Even when the breaker is open and configured to block - which would
	// make /readyz fail - /livez stays 200. This is the AC's central
	// behavior: liveness and readiness diverge under upstream failure.
	cb := CircuitBreakerConfig{Enabled: true, Threshold: 1, TimeoutSeconds: 60, Fallback: "block"}
	p := probeProxy("http://127.0.0.1:1", cb)
	tripBreaker(t, p, 1)

	req := httptest.NewRequest("GET", "/livez", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/livez status: want 200 even with breaker open, got %d", w.Code)
	}
}

// --- /readyz ---------------------------------------------------------------

func TestReadyz_OKWhenBreakerDisabled(t *testing.T) {
	// No breaker configured -> always ready.
	p := probeProxy("http://127.0.0.1:1", CircuitBreakerConfig{Enabled: false})
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/readyz status with no breaker: want 200, got %d", w.Code)
	}
}

func TestReadyz_OKWhenBreakerClosed(t *testing.T) {
	// Breaker enabled but never tripped -> closed -> ready.
	cb := CircuitBreakerConfig{Enabled: true, Threshold: 5, TimeoutSeconds: 60, Fallback: "block"}
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("ok", "doc", nil))
	}))
	defer philterSrv.Close()
	p := probeProxy(philterSrv.URL, cb)

	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/readyz status with closed breaker: want 200, got %d", w.Code)
	}
}

func TestReadyz_503WhenBreakerOpenAndBlock(t *testing.T) {
	// This is the case the AC asks for: breaker open + fallback=block -> 503.
	cb := CircuitBreakerConfig{Enabled: true, Threshold: 1, TimeoutSeconds: 60, Fallback: "block"}
	p := probeProxy("http://127.0.0.1:1", cb)
	tripBreaker(t, p, 1)

	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz status with open+block: want 503, got %d", w.Code)
	}
	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("/readyz body is not JSON: %v\n%s", err, w.Body.String())
	}
	if body.Status != "not_ready" {
		t.Errorf("/readyz body.status: want not_ready, got %q", body.Status)
	}
	if body.Reason != "philter_circuit_open" {
		t.Errorf("/readyz body.reason: want philter_circuit_open, got %q", body.Reason)
	}
}

func TestReadyz_OKWhenBreakerOpenAndPassthrough(t *testing.T) {
	// fallback=passthrough means the proxy is still serving requests
	// (forwarding unredacted) when the breaker is open, so we are ready.
	cb := CircuitBreakerConfig{Enabled: true, Threshold: 1, TimeoutSeconds: 60, Fallback: "passthrough"}
	p := probeProxy("http://127.0.0.1:1", cb)
	tripBreaker(t, p, 1)

	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/readyz status with open+passthrough: want 200, got %d", w.Code)
	}
}

// --- Backwards compat for /health ------------------------------------------

func TestHealth_StillResponds(t *testing.T) {
	// /health is retained as documented-deprecated. Existing operator scripts
	// should continue to receive 200 when Philter is reachable.
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("ok", "doc", nil))
	}))
	defer philterSrv.Close()
	p := probeProxy(philterSrv.URL, CircuitBreakerConfig{Enabled: false})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("/health status: want 200, got %d", w.Code)
	}
}

// --- Probes are excluded from audit ----------------------------------------

func TestProbes_SkipAuditLog(t *testing.T) {
	// All three probe endpoints must skip the audit-emission defer, since
	// they fire many times per second and would drown real traffic.
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("ok", "doc", nil))
	}))
	defer philterSrv.Close()

	for _, path := range []string{"/livez", "/readyz", "/health"} {
		t.Run(path, func(t *testing.T) {
			p := probeProxy(philterSrv.URL, CircuitBreakerConfig{Enabled: false})
			var buf bytes.Buffer
			withAuditLogger(p, &buf)

			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)

			if buf.Len() != 0 {
				t.Errorf("%s emitted audit log entries:\n%s", path, buf.String())
			}
		})
	}
}
