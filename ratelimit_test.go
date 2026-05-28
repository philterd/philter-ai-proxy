package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"golang.org/x/time/rate"
)

// --- backend interface conformance: memory ---

func TestMemoryBackend_AllowsBurstThenBlocks(t *testing.T) {
	b := newMemoryBackend()
	defer b.Close()
	ctx := context.Background()

	// burst=3, very slow refill so tokens don't replenish during the test.
	for i := 0; i < 3; i++ {
		allowed, _, err := b.Allow(ctx, "k", 0.001, 3)
		if err != nil || !allowed {
			t.Fatalf("request %d: expected allow, got allowed=%v err=%v", i, allowed, err)
		}
	}
	allowed, retry, err := b.Allow(ctx, "k", 0.001, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("expected 4th request to be blocked after burst exhausted")
	}
	if retry <= 0 {
		t.Errorf("expected positive retryAfter, got %v", retry)
	}
}

func TestMemoryBackend_SeparateKeysIndependent(t *testing.T) {
	b := newMemoryBackend()
	defer b.Close()
	ctx := context.Background()

	allowed, _, _ := b.Allow(ctx, "a", 0.001, 1)
	if !allowed {
		t.Fatal("first request for key a should pass")
	}
	// key a is now exhausted, but key b has its own bucket.
	allowed, _, _ = b.Allow(ctx, "b", 0.001, 1)
	if !allowed {
		t.Fatal("first request for key b should pass (independent bucket)")
	}
	allowed, _, _ = b.Allow(ctx, "a", 0.001, 1)
	if allowed {
		t.Fatal("second request for key a should be blocked")
	}
}

// --- backend interface conformance: redis (miniredis) ---

func newTestRedisBackend(t *testing.T) (*redisBackend, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	b, err := newRedisBackend(RedisBackendConfig{Address: mr.Addr()})
	if err != nil {
		mr.Close()
		t.Fatalf("newRedisBackend: %v", err)
	}
	return b, mr
}

func TestRedisBackend_AllowsBurstThenBlocks(t *testing.T) {
	b, mr := newTestRedisBackend(t)
	defer mr.Close()
	defer b.Close()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		allowed, _, err := b.Allow(ctx, "client", 1, 3)
		if err != nil {
			t.Fatalf("request %d: unexpected error %v", i, err)
		}
		if !allowed {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	allowed, retry, err := b.Allow(ctx, "client", 1, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("request beyond burst should be blocked")
	}
	if retry <= 0 {
		t.Errorf("expected positive retryAfter, got %v", retry)
	}
}

func TestRedisBackend_RefillsOverTime(t *testing.T) {
	b, mr := newTestRedisBackend(t)
	defer mr.Close()
	defer b.Close()
	ctx := context.Background()

	// rate=10/s, burst=1. Consume the token, then advance the server clock by
	// 1s; one token should have refilled. (miniredis's TIME honors SetTime but
	// not FastForward, so advance with SetTime.)
	mr.SetTime(time.Unix(1_000, 0))
	if allowed, _, _ := b.Allow(ctx, "c", 10, 1); !allowed {
		t.Fatal("first request should pass")
	}
	if allowed, _, _ := b.Allow(ctx, "c", 10, 1); allowed {
		t.Fatal("second request should be blocked before refill")
	}
	mr.SetTime(time.Unix(1_001, 0))
	if allowed, _, _ := b.Allow(ctx, "c", 10, 1); !allowed {
		t.Fatal("request after 1s refill should pass")
	}
}

func TestRedisBackend_SharedStateAcrossClients(t *testing.T) {
	// Two backend instances pointing at the same Redis simulate two replicas;
	// they must share one bucket (the whole point of the feature).
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	b1, _ := newRedisBackend(RedisBackendConfig{Address: mr.Addr()})
	b2, _ := newRedisBackend(RedisBackendConfig{Address: mr.Addr()})
	defer b1.Close()
	defer b2.Close()
	ctx := context.Background()

	// burst=2 shared. b1 consumes one, b2 consumes one, then both exhausted.
	if allowed, _, _ := b1.Allow(ctx, "shared", 0.001, 2); !allowed {
		t.Fatal("replica1 first request should pass")
	}
	if allowed, _, _ := b2.Allow(ctx, "shared", 0.001, 2); !allowed {
		t.Fatal("replica2 first request should pass")
	}
	if allowed, _, _ := b1.Allow(ctx, "shared", 0.001, 2); allowed {
		t.Fatal("shared bucket should be exhausted across replicas")
	}
}

func TestRedisBackend_ErrorWhenDown(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	b, _ := newRedisBackend(RedisBackendConfig{Address: mr.Addr(), TimeoutMs: 50})
	defer b.Close()
	mr.Close() // simulate Redis going away

	_, _, err = b.Allow(context.Background(), "k", 1, 1)
	if err == nil {
		t.Fatal("expected error when Redis is unreachable")
	}
}

// --- ProxyRateLimiter failure modes ---

// errBackend always fails, to exercise the failure-mode paths deterministically.
type errBackend struct{}

func (errBackend) Name() string { return "redis" }
func (errBackend) Allow(context.Context, string, rate.Limit, int) (bool, time.Duration, error) {
	return false, 0, context.DeadlineExceeded
}
func (errBackend) Close() error { return nil }

func TestProxyRateLimiter_FailOpen_FallsBackToMemory(t *testing.T) {
	rl := &ProxyRateLimiter{
		backend:      errBackend{},
		fallback:     newMemoryBackend(),
		failureMode:  "open",
		defaultLimit: 0.001,
		defaultBurst: 2,
		perKeyLimit:  map[string]rate.Limit{},
		perKeyBurst:  map[string]int{},
	}
	defer rl.Close()
	ctx := context.Background()

	// Fail-open uses the local memory fallback, which still enforces burst=2.
	if allowed, _ := rl.Allow(ctx, "c"); !allowed {
		t.Fatal("request 1 should pass via fallback")
	}
	if allowed, _ := rl.Allow(ctx, "c"); !allowed {
		t.Fatal("request 2 should pass via fallback")
	}
	if allowed, _ := rl.Allow(ctx, "c"); allowed {
		t.Fatal("request 3 should be blocked by the local fallback limiter")
	}
}

func TestProxyRateLimiter_FailClosed_Denies(t *testing.T) {
	rl := &ProxyRateLimiter{
		backend:      errBackend{},
		failureMode:  "closed",
		defaultLimit: 1000,
		defaultBurst: 1000,
		perKeyLimit:  map[string]rate.Limit{},
		perKeyBurst:  map[string]int{},
	}
	allowed, retry := rl.Allow(context.Background(), "c")
	if allowed {
		t.Fatal("fail-closed should deny when the backend is unreachable")
	}
	if retry <= 0 {
		t.Errorf("expected a positive retry hint, got %v", retry)
	}
}

// --- constructor wiring ---

func TestNewProxyRateLimiter_RedisBackendSelected(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	cfg := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 1,
		Burst:             1,
		Backend: RateLimitBackendConfig{
			Type:  "redis",
			Redis: RedisBackendConfig{Address: mr.Addr()},
		},
	}
	rl, err := newProxyRateLimiter(cfg, nil, nil)
	if err != nil {
		t.Fatalf("newProxyRateLimiter: %v", err)
	}
	defer rl.Close()

	if rl.backend.Name() != "redis" {
		t.Errorf("expected redis backend, got %q", rl.backend.Name())
	}
	if rl.fallback == nil {
		t.Error("redis backend should have a local memory fallback")
	}
	if rl.failureMode != "open" {
		t.Errorf("expected default failureMode open, got %q", rl.failureMode)
	}
}

// TestRateLimit_RedisBackend_EndToEnd drives a full request through ServeHTTP
// with the Redis backend (miniredis), confirming the handler → limiter → Redis
// path enforces the limit and returns 429 after the burst is exhausted.
func TestRateLimit_RedisBackend_EndToEnd(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hello", "doc-id", nil))
	}))
	defer philterSrv.Close()
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	// Very slow refill, burst=2, backed by Redis.
	cfg.RateLimit = RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 0.001,
		Burst:             2,
		Backend: RateLimitBackendConfig{
			Type:  "redis",
			Redis: RedisBackendConfig{Address: mr.Addr()},
		},
	}
	rl, err := newProxyRateLimiter(cfg.RateLimit, nil, nil)
	if err != nil {
		t.Fatalf("newProxyRateLimiter: %v", err)
	}
	defer rl.Close()

	u, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		rateLimiter:  rl,
	}

	got429 := false
	for i := 0; i < 6; i++ {
		w := sendRequest(proxy, "/v1/chat/completions", openAIBody(), nil)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("expected a 429 once the Redis-backed burst was exhausted")
	}
}

func TestNewProxyRateLimiter_DefaultsToMemory(t *testing.T) {
	rl, err := newProxyRateLimiter(RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()
	if rl.backend.Name() != "memory" {
		t.Errorf("expected memory backend by default, got %q", rl.backend.Name())
	}
}
