package main

import (
	"bytes"
	"context"
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
		_, _ = p.philter.Filter(context.Background(), "x", "ctx", "doc", "policy")
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

// --- /health: the standard Philterd health contract ------------------------

// healthBody is the shared Philterd health response as a client sees it:
// `status` and `applicationVersion` at the top level, plus the proxy's
// `philter` reachability extension.
type healthBody struct {
	Status             string `json:"status"`
	ApplicationVersion string `json:"applicationVersion"`
	Philter            string `json:"philter"`
}

func getHealth(t *testing.T, p *Proxy) (*httptest.ResponseRecorder, healthBody) {
	t.Helper()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("/health content-type: want JSON, got %q", ct)
	}
	var body healthBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("/health body is not JSON: %v\n%s", err, w.Body.String())
	}
	return w, body
}

func TestHealth_UPWhenPhilterReachable(t *testing.T) {
	// The healthy path of the shared contract: 200 with status UP and the
	// build version at the top level.
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("ok", "doc", nil))
	}))
	defer philterSrv.Close()
	p := probeProxy(philterSrv.URL, CircuitBreakerConfig{Enabled: false})

	w, body := getHealth(t, p)
	if w.Code != http.StatusOK {
		t.Errorf("/health status: want 200, got %d", w.Code)
	}
	if body.Status != "UP" {
		t.Errorf("/health body.status: want UP, got %q", body.Status)
	}
	if body.ApplicationVersion != version {
		t.Errorf("/health body.applicationVersion: want %q, got %q", version, body.ApplicationVersion)
	}
	if body.Philter != "ok" {
		t.Errorf("/health body.philter: want ok, got %q", body.Philter)
	}
}

func TestHealth_DegradedWhenPhilterUnreachable(t *testing.T) {
	// The degraded path: non-200 and a status other than UP, still carrying
	// the version so a probe can report which build is unhealthy.
	p := probeProxy("http://127.0.0.1:1", CircuitBreakerConfig{Enabled: false})

	w, body := getHealth(t, p)
	if w.Code == http.StatusOK {
		t.Errorf("/health status when Philter is unreachable: want non-200, got %d", w.Code)
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("/health status when Philter is unreachable: want 503, got %d", w.Code)
	}
	if body.Status == "UP" {
		t.Error("/health body.status: want a status other than UP when degraded")
	}
	if body.Status != "DOWN" {
		t.Errorf("/health body.status: want DOWN, got %q", body.Status)
	}
	if body.ApplicationVersion != version {
		t.Errorf("/health body.applicationVersion: want %q, got %q", version, body.ApplicationVersion)
	}
}

func TestHealth_UPWithoutPhilterClient(t *testing.T) {
	// A Proxy with no config or Philter client cannot probe downstream. It
	// still answers the contract rather than falling through to the router.
	w, body := getHealth(t, &Proxy{})
	if w.Code != http.StatusOK {
		t.Errorf("/health status with no config: want 200, got %d", w.Code)
	}
	if body.Status != "UP" {
		t.Errorf("/health body.status: want UP, got %q", body.Status)
	}
	if body.ApplicationVersion != version {
		t.Errorf("/health body.applicationVersion: want %q, got %q", version, body.ApplicationVersion)
	}
	if body.Philter != "" {
		t.Errorf("/health body.philter: want omitted with no client, got %q", body.Philter)
	}
}

func TestHealth_Unauthenticated(t *testing.T) {
	// The endpoint must stay reachable without credentials even when API key
	// auth is configured, so a load balancer or container runtime can probe it.
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("ok", "doc", nil))
	}))
	defer philterSrv.Close()
	p := probeProxy(philterSrv.URL, CircuitBreakerConfig{Enabled: false})
	p.keyStore = testKeyStore(map[string]string{"secret-key": ""})

	w, body := getHealth(t, p)
	if w.Code != http.StatusOK {
		t.Errorf("/health status with auth enabled and no key: want 200, got %d", w.Code)
	}
	if body.Status != "UP" {
		t.Errorf("/health body.status: want UP, got %q", body.Status)
	}
}

// TestProbes_ShapeDecision records the decision required by issue #43: only
// /health adopts the shared Philterd contract. /livez and /readyz are
// Kubernetes probe endpoints whose bodies ("ok" / "not_ready" plus a
// machine-readable reason) are parsed by deployed manifests and operator
// scripts, and an orchestrator keys on the status code regardless - so they
// deliberately keep their own vocabulary and carry no applicationVersion.
func TestProbes_ShapeDecision(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("ok", "doc", nil))
	}))
	defer philterSrv.Close()

	for _, path := range []string{"/livez", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			p := probeProxy(philterSrv.URL, CircuitBreakerConfig{Enabled: false})
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, req)

			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("%s body is not JSON: %v\n%s", path, err, w.Body.String())
			}
			if body["status"] != "ok" {
				t.Errorf("%s body.status: want ok, got %v", path, body["status"])
			}
			if _, ok := body["applicationVersion"]; ok {
				t.Errorf("%s must not carry applicationVersion; got %s", path, w.Body.String())
			}
		})
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
