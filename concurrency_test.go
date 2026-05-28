package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// --- Unit tests for ConcurrencyLimiter --------------------------------------

func TestConcurrencyLimiter_NilIsAllowed(t *testing.T) {
	var cl *ConcurrencyLimiter
	allowed, scope, release := cl.Acquire("anything")
	if !allowed {
		t.Error("nil limiter must always allow")
	}
	if scope != "" {
		t.Errorf("nil limiter must report empty scope, got %q", scope)
	}
	if release == nil {
		t.Error("release must be non-nil even on a nil limiter")
	}
	release() // must not panic
}

func TestConcurrencyLimiter_ZeroGlobalIsUnlimited(t *testing.T) {
	cl := newConcurrencyLimiter(0, nil)
	for i := 0; i < 100; i++ {
		allowed, _, release := cl.Acquire("")
		if !allowed {
			t.Fatalf("expected unlimited when global=0, got rejection at %d", i)
		}
		defer release()
	}
}

func TestConcurrencyLimiter_GlobalBound(t *testing.T) {
	cl := newConcurrencyLimiter(2, nil)

	releases := make([]func(), 0, 2)
	for i := 0; i < 2; i++ {
		allowed, _, release := cl.Acquire("")
		if !allowed {
			t.Fatalf("expected allow within global capacity (i=%d)", i)
		}
		releases = append(releases, release)
	}

	allowed, scope, _ := cl.Acquire("")
	if allowed {
		t.Fatal("expected rejection past global capacity")
	}
	if scope != "global" {
		t.Errorf("expected scope=global, got %q", scope)
	}

	releases[0]()
	allowed, _, release := cl.Acquire("")
	if !allowed {
		t.Fatal("expected slot to free after release")
	}
	release()
	releases[1]()
}

func TestConcurrencyLimiter_PerKeyBound(t *testing.T) {
	cl := newConcurrencyLimiter(0, map[string]int{"key-a": 1, "key-b": 2})

	// Key A has 1 slot; second concurrent should fail with per_key scope.
	allowedA, _, releaseA := cl.Acquire("key-a")
	if !allowedA {
		t.Fatal("expected first key-a request to be allowed")
	}
	rejectedA, scopeA, _ := cl.Acquire("key-a")
	if rejectedA {
		t.Fatal("expected second concurrent key-a request to be rejected")
	}
	if scopeA != "per_key" {
		t.Errorf("expected scope=per_key, got %q", scopeA)
	}

	// Key B independently has 2 slots; both should pass.
	for i := 0; i < 2; i++ {
		allowed, _, release := cl.Acquire("key-b")
		if !allowed {
			t.Fatalf("expected key-b slot %d to be allowed", i)
		}
		defer release()
	}

	// Unknown key has no per-key limit and no global limit -> always allowed.
	for i := 0; i < 10; i++ {
		allowed, _, release := cl.Acquire("unknown")
		if !allowed {
			t.Fatalf("expected unknown key with no global limit to be allowed (i=%d)", i)
		}
		release()
	}

	releaseA()
}

func TestConcurrencyLimiter_PerKeyRejection_ReleasesGlobal(t *testing.T) {
	// Regression: when the per-key slot is full but a global slot was just
	// taken, the global slot must be released so it doesn't leak.
	cl := newConcurrencyLimiter(10, map[string]int{"k": 1})

	allowed, _, release1 := cl.Acquire("k")
	if !allowed {
		t.Fatal("expected first acquire to pass")
	}

	// Hammer the global pool: 11 attempts with the same key. The first
	// succeeds; the next 10 must all be rejected at per_key and must each
	// return their global slot. If they didn't, we'd run out of global slots
	// after 10 attempts, even though only one slot is actually held.
	for i := 0; i < 100; i++ {
		ok, scope, _ := cl.Acquire("k")
		if ok {
			t.Fatalf("unexpected allow at i=%d", i)
		}
		if scope != "per_key" {
			t.Errorf("i=%d: expected per_key, got %q", i, scope)
		}
	}

	// Different key should still be admitted — global pool wasn't drained.
	allowed2, _, release2 := cl.Acquire("other")
	if !allowed2 {
		t.Fatal("global pool leaked: 'other' was rejected after per_key churn")
	}

	release1()
	release2()
}

// --- ServeHTTP integration tests --------------------------------------------

// newConcurrencyTestProxy builds a Proxy wired with a configurable concurrency
// limiter, a Philter that returns immediately, and a controllable provider
// that holds requests until the test releases them.
func newConcurrencyTestProxy(t *testing.T, globalLimit int, perKey map[string]int, hold chan struct{}) (*Proxy, func()) {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hold
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))

	u, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		concurrency:  newConcurrencyLimiter(globalLimit, perKey),
	}
	cleanup := func() {
		philterSrv.Close()
		providerSrv.Close()
	}
	return proxy, cleanup
}

func TestConcurrency_DisabledByDefault(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer providerSrv.Close()

	u, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		// concurrency intentionally nil
	}

	for i := 0; i < 50; i++ {
		w := sendRequest(proxy, "/v1/chat/completions", openAIBody(), nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 with concurrency disabled, got %d on req %d", w.Code, i+1)
		}
	}
}

func TestConcurrency_GlobalLimit_Sheds(t *testing.T) {
	hold := make(chan struct{})
	proxy, cleanup := newConcurrencyTestProxy(t, 1, nil, hold)
	defer cleanup()

	inflightStarted := make(chan struct{})
	go func() {
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
		w := httptest.NewRecorder()
		close(inflightStarted)
		proxy.ServeHTTP(w, req)
	}()

	<-inflightStarted
	// Give the in-flight goroutine time to actually acquire the slot and
	// reach the blocking provider call. Poll the limiter rather than sleep.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(proxy.concurrency.global) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(proxy.concurrency.global) != 1 {
		t.Fatal("in-flight request never acquired the global slot")
	}

	w := sendRequest(proxy, "/v1/chat/completions", openAIBody(), nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 over concurrency cap, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 503 shed response")
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content-type, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "capacity") {
		t.Errorf("expected error type=capacity in body, got %s", w.Body.String())
	}

	close(hold)
}

func TestConcurrency_SlotReleasesAfterRequest(t *testing.T) {
	hold := make(chan struct{})
	proxy, cleanup := newConcurrencyTestProxy(t, 1, nil, hold)
	defer cleanup()

	// First request: complete it immediately so the slot frees.
	close(hold)
	w := sendRequest(proxy, "/v1/chat/completions", openAIBody(), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d", w.Code)
	}

	// Slot must be empty again — a subsequent request still succeeds.
	w = sendRequest(proxy, "/v1/chat/completions", openAIBody(), nil)
	if w.Code != http.StatusOK {
		t.Errorf("expected slot to be released after completion, got %d", w.Code)
	}
}

func TestConcurrency_PerKeyLimit_Isolates(t *testing.T) {
	hold := make(chan struct{})
	proxy, cleanup := newConcurrencyTestProxy(t, 0, map[string]int{"key-a": 1, "key-b": 1}, hold)
	defer cleanup()

	// Enable auth so the proxy reads x-philter-proxy-key and ties acquires
	// to the key value.
	proxy.keyIndex = map[string]string{"key-a": "", "key-b": ""}

	// Hold one slot for key-a in a goroutine.
	inflight := make(chan struct{})
	go func() {
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
		req.Header.Set("x-philter-proxy-key", "key-a")
		w := httptest.NewRecorder()
		close(inflight)
		proxy.ServeHTTP(w, req)
	}()
	<-inflight

	// Wait until the in-flight key-a request has reached the provider.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(proxy.concurrency.perKey["key-a"]) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A second key-a request is rejected per-key.
	w := sendRequest(proxy, "/v1/chat/completions", openAIBody(),
		map[string]string{"x-philter-proxy-key": "key-a"})
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for second key-a, got %d", w.Code)
	}

	// key-b has its own bucket and must still be admitted. Release its hold
	// first so the provider returns.
	bDone := make(chan int)
	go func() {
		w := sendRequest(proxy, "/v1/chat/completions", openAIBody(),
			map[string]string{"x-philter-proxy-key": "key-b"})
		bDone <- w.Code
	}()
	// Both the key-a and key-b inflights are waiting on `hold`. Closing it
	// releases them both.
	close(hold)

	select {
	case code := <-bDone:
		if code != http.StatusOK {
			t.Errorf("expected key-b to pass independently, got %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("key-b request did not complete")
	}
}

// --- Metrics tests ----------------------------------------------------------

func TestConcurrency_LimitGauge_ReflectsConfig(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)

	// Simulate what main() does after constructing the limiter.
	m.concurrencyLimit.WithLabelValues("global").Set(150)

	g, err := m.concurrencyLimit.GetMetricWithLabelValues("global")
	if err != nil {
		t.Fatalf("failed to get gauge: %v", err)
	}
	if got := gaugeValue(g); got != 150 {
		t.Errorf("expected concurrency_limit{scope=global}=150, got %v", got)
	}
}

func TestConcurrency_ShedCounter_IncrementsByScope(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)

	hold := make(chan struct{})
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hold
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer providerSrv.Close()

	u, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		concurrency:  newConcurrencyLimiter(1, nil),
		metrics:      m,
	}

	inflightStarted := make(chan struct{})
	go func() {
		req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
		w := httptest.NewRecorder()
		close(inflightStarted)
		proxy.ServeHTTP(w, req)
	}()
	<-inflightStarted

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(proxy.concurrency.global) == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	w := sendRequest(proxy, "/v1/chat/completions", openAIBody(), nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}

	c, err := m.concurrencyShed.GetMetricWithLabelValues("global")
	if err != nil {
		t.Fatalf("failed to read shed counter: %v", err)
	}
	var dm dto.Metric
	c.Write(&dm)
	if got := dm.GetCounter().GetValue(); got != 1 {
		t.Errorf("expected concurrency_shed_total{scope=global}=1, got %v", got)
	}

	close(hold)
}

// --- Config validation tests ------------------------------------------------

func TestValidateConfig_NegativeMaxConcurrent(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1")
	cfg.Listen.MaxConcurrentRequests = -1
	if err := validateConfig(cfg); err == nil {
		t.Error("expected validation error for negative listen.maxConcurrentRequests")
	}

	cfg = testConfig("http://127.0.0.1:1")
	cfg.Auth.APIKeys = []APIKeyEntry{{Key: "k", MaxConcurrent: -5}}
	if err := validateConfig(cfg); err == nil {
		t.Error("expected validation error for negative auth.apiKeys[].maxConcurrent")
	}

	cfg = testConfig("http://127.0.0.1:1")
	cfg.Listen.MaxConcurrentRequests = 50
	cfg.Auth.APIKeys = []APIKeyEntry{{Key: "k", MaxConcurrent: 10}}
	if err := validateConfig(cfg); err != nil {
		t.Errorf("expected valid config to pass, got %v", err)
	}
}

// --- Helper construction tests ----------------------------------------------

func TestPerKeyConcurrencyMap(t *testing.T) {
	if got := perKeyConcurrencyMap(nil); got != nil {
		t.Errorf("nil input must produce nil map, got %v", got)
	}
	keys := []APIKeyEntry{
		{Key: "a", MaxConcurrent: 5},
		{Key: "b"}, // no concurrency limit
		{Key: "c", MaxConcurrent: 0},
		{Key: "d", MaxConcurrent: 2},
	}
	got := perKeyConcurrencyMap(keys)
	if len(got) != 2 || got["a"] != 5 || got["d"] != 2 {
		t.Errorf("unexpected map: %v", got)
	}
	if !hasPerKeyConcurrency(keys) {
		t.Error("hasPerKeyConcurrency should return true when at least one key sets a limit")
	}
	if hasPerKeyConcurrency([]APIKeyEntry{{Key: "x"}}) {
		t.Error("hasPerKeyConcurrency should return false when no key sets a limit")
	}
}

