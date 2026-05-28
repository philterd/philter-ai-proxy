package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

// providerWithUsage returns an httptest server that replies with a fixed
// non-streaming JSON body carrying a `usage` object, and counts how many times
// it is called.
func providerWithUsage(promptTokens, completionTokens int) (*httptest.Server, *int32) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":` +
			itoa(promptTokens) + `,"completion_tokens":` + itoa(completionTokens) + `}}`))
	}))
	return srv, &calls
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}

func philterPassThrough(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
}

func TestQuota_EndToEnd_429AfterExhausted(t *testing.T) {
	philterSrv := philterPassThrough(t)
	defer philterSrv.Close()
	providerSrv, _ := providerWithUsage(10, 0) // each call reports 10 prompt tokens
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Auth.APIKeys = []APIKeyEntry{{Key: "k"}}
	cfg.Quota = QuotaConfig{Enabled: true, Default: QuotaLimits{DailyTokens: 10}}

	store := newMemUsageStore()
	u, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		keyStore:     mustKeyStore(cfg.Auth.APIKeys),
		usage:        store,
		quota:        newQuotaEnforcer(cfg.Quota, cfg.Auth.APIKeys, store),
	}

	hdr := map[string]string{"x-philter-proxy-key": "k"}

	// First request: usage is 0, allowed; it records 10 tokens.
	w := sendRequest(proxy, "/v1/chat/completions", openAIBody(), hdr)
	if w.Code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", w.Code)
	}

	// Second request: accumulated usage (10) is at the daily quota → 429.
	w = sendRequest(proxy, "/v1/chat/completions", openAIBody(), hdr)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: want 429 (quota exceeded), got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on quota rejection")
	}
}

func TestCache_EndToEnd_HitSkipsProvider(t *testing.T) {
	philterSrv := philterPassThrough(t)
	defer philterSrv.Close()
	providerSrv, calls := providerWithUsage(5, 5)
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Cache = CacheConfig{Enabled: true, TTLSeconds: 300}

	cache, err := newResponseCache(cfg.Cache)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		cache:        cache,
	}

	// First request: MISS, provider called, response cached.
	w1 := sendRequest(proxy, "/v1/chat/completions", openAIBody(), nil)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", w1.Code)
	}
	if got := w1.Header().Get("X-Cache"); got != "MISS" {
		t.Errorf("first request X-Cache: want MISS, got %q", got)
	}

	// Second identical request: HIT, provider not called again.
	w2 := sendRequest(proxy, "/v1/chat/completions", openAIBody(), nil)
	if w2.Code != http.StatusOK {
		t.Fatalf("second request: want 200, got %d", w2.Code)
	}
	if got := w2.Header().Get("X-Cache"); got != "HIT" {
		t.Errorf("second request X-Cache: want HIT, got %q", got)
	}
	if w1.Body.String() != w2.Body.String() {
		t.Errorf("cached body differs:\n first=%q\n second=%q", w1.Body.String(), w2.Body.String())
	}
	if n := atomic.LoadInt32(calls); n != 1 {
		t.Errorf("provider should be called exactly once (cache hit on 2nd), got %d calls", n)
	}
}

func TestCache_StreamingRequestNotCached(t *testing.T) {
	philterSrv := philterPassThrough(t)
	defer philterSrv.Close()
	providerSrv, calls := providerWithUsage(5, 5)
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Cache = CacheConfig{Enabled: true, TTLSeconds: 300}
	cache, _ := newResponseCache(cfg.Cache)
	u, _ := url.Parse(providerSrv.URL)
	proxy := &Proxy{
		config: cfg, philter: testPhilterClient(philterSrv.URL),
		openaiTarget: u, openaiClient: http.DefaultClient, cache: cache,
	}

	streamingBody := `{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hello"}]}`
	sendRequest(proxy, "/v1/chat/completions", streamingBody, nil)
	sendRequest(proxy, "/v1/chat/completions", streamingBody, nil)

	if n := atomic.LoadInt32(calls); n != 2 {
		t.Errorf("streaming requests must not be cached; provider should be called twice, got %d", n)
	}
}
