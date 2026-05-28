package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// hardeningProxy builds a proxy with the given listen config and working Philter
// + provider mocks.
func hardeningProxy(t *testing.T, listen ListenConfig) *Proxy {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	t.Cleanup(philterSrv.Close)
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	t.Cleanup(providerSrv.Close)

	cfg := testConfig(philterSrv.URL)
	cfg.Listen = listen
	u, _ := url.Parse(providerSrv.URL)
	return &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
	}
}

func bodyOfSize(n int) string {
	// A valid-ish chat body padded to exceed n bytes via the message content.
	pad := strings.Repeat("a", n)
	return `{"model":"gpt-4o","messages":[{"role":"user","content":"` + pad + `"}]}`
}

func TestHardening_OversizedBodyRejectedWith413(t *testing.T) {
	// Tiny 1 KiB cap; send ~2 KiB.
	p := hardeningProxy(t, ListenConfig{MaxRequestBodyBytes: 1024})
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(bodyOfSize(2048)))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "payload_too_large") || !strings.Contains(body, "request_body_too_large") {
		t.Errorf("expected structured 413 error, got: %s", body)
	}
}

func TestHardening_UnderLimitAllowed(t *testing.T) {
	p := hardeningProxy(t, ListenConfig{MaxRequestBodyBytes: 1 << 20}) // 1 MiB cap
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(bodyOfSize(1024)))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("body under the cap should pass, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHardening_DefaultLimitApplied(t *testing.T) {
	// No MaxRequestBodyBytes set → default (10 MiB) applies.
	p := hardeningProxy(t, ListenConfig{})
	if got := p.config.Listen.effectiveMaxRequestBodyBytes(); got != DefaultMaxRequestBodyBytes {
		t.Fatalf("default cap = %d, want %d", got, DefaultMaxRequestBodyBytes)
	}
	// A body well over the default is rejected.
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(bodyOfSize(DefaultMaxRequestBodyBytes+1024)))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("body over the default cap should be 413, got %d", w.Code)
	}
}

func TestEffectiveMaxRequestBodyBytes(t *testing.T) {
	if got := (ListenConfig{}).effectiveMaxRequestBodyBytes(); got != DefaultMaxRequestBodyBytes {
		t.Errorf("unset = %d, want default %d", got, DefaultMaxRequestBodyBytes)
	}
	if got := (ListenConfig{MaxRequestBodyBytes: 4096}).effectiveMaxRequestBodyBytes(); got != 4096 {
		t.Errorf("configured = %d, want 4096", got)
	}
}

func TestHardenedServer_DefaultsAndOverrides(t *testing.T) {
	// Defaults applied when unset.
	srv := hardenedServer(":8080", http.NewServeMux(), ListenConfig{})
	if srv.ReadHeaderTimeout != time.Duration(DefaultReadHeaderTimeoutMs)*time.Millisecond {
		t.Errorf("default ReadHeaderTimeout = %v", srv.ReadHeaderTimeout)
	}
	if srv.MaxHeaderBytes != DefaultMaxHeaderBytes {
		t.Errorf("default MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
	if srv.ReadTimeout != 0 {
		t.Errorf("ReadTimeout should be unset by default, got %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout must stay 0 so streaming responses are unbounded, got %v", srv.WriteTimeout)
	}

	// Overrides honored.
	srv = hardenedServer(":8080", http.NewServeMux(), ListenConfig{
		ReadHeaderTimeoutMs: 3000,
		MaxHeaderBytes:      4096,
		ReadTimeoutMs:       9000,
	})
	if srv.ReadHeaderTimeout != 3*time.Second {
		t.Errorf("override ReadHeaderTimeout = %v", srv.ReadHeaderTimeout)
	}
	if srv.MaxHeaderBytes != 4096 {
		t.Errorf("override MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
	if srv.ReadTimeout != 9*time.Second {
		t.Errorf("override ReadTimeout = %v", srv.ReadTimeout)
	}
}

// TestHardening_OversizedBody_EndToEnd drives the full HTTP stack (a real
// server + real client connection), not just ServeHTTP, so the actual
// MaxBytesReader/413 behavior is exercised end to end.
func TestHardening_OversizedBody_EndToEnd(t *testing.T) {
	p := hardeningProxy(t, ListenConfig{MaxRequestBodyBytes: 1024})
	srv := httptest.NewServer(p)
	defer srv.Close()

	// Oversized → 413 with the structured error.
	resp, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(bodyOfSize(4096)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: want 413, got %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "request_body_too_large") {
		t.Errorf("expected structured 413 body, got: %s", string(b))
	}

	// A small request still succeeds through the same server.
	resp2, err := http.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(bodyOfSize(64)))
	if err != nil {
		t.Fatalf("post small: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("small body should pass, got %d", resp2.StatusCode)
	}
}

func TestValidateConfig_HardeningNegativeRejected(t *testing.T) {
	for _, mut := range []func(*Config){
		func(c *Config) { c.Listen.MaxRequestBodyBytes = -1 },
		func(c *Config) { c.Listen.MaxHeaderBytes = -1 },
		func(c *Config) { c.Listen.ReadHeaderTimeoutMs = -1 },
		func(c *Config) { c.Listen.ReadTimeoutMs = -1 },
	} {
		cfg := defaultConfig()
		mut(cfg)
		if err := validateConfig(cfg); err == nil {
			t.Error("expected validation error for negative hardening value")
		}
	}
}
