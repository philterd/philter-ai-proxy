package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// philterPassThrough is a stub Philter that echoes a fixed explain response,
// letting the stress tests exercise the proxy path without a real Philter.
func philterPassThrough(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
}

// stressDims reads the stress-test dimensions from the environment so CI can run
// a smaller variant and developers can crank it locally. Defaults are modest so
// the test stays fast under `go test -race ./...`.
func stressDims() (n, m int) {
	return envInt("STRESS_N", 20), envInt("STRESS_M", 20)
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// countingSlogHandler counts the number of records emitted, used to verify the
// audit logger fires exactly once per request under concurrency.
type countingSlogHandler struct{ n *int64 }

func (h countingSlogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingSlogHandler) Handle(context.Context, slog.Record) error {
	atomic.AddInt64(h.n, 1)
	return nil
}
func (h countingSlogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingSlogHandler) WithGroup(string) slog.Handler      { return h }

// gatherCounterSum sums every series of the named counter metric in the registry.
func gatherCounterSum(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var sum float64
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, mtr := range f.GetMetric() {
			sum += mtr.GetCounter().GetValue()
		}
	}
	return sum
}

// TestStress_HighConcurrency fires N*M requests through the full ServeHTTP
// pipeline concurrently and asserts every request reaches a terminal status, the
// audit logger emits exactly N*M entries, and philter_proxy_requests_total sums
// to N*M -- with no panic and no -race warning.
func TestStress_HighConcurrency(t *testing.T) {
	n, m := stressDims()
	total := int64(n * m)

	philterSrv := philterPassThrough(t)
	defer philterSrv.Close()
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`))
	}))
	defer providerSrv.Close()

	reg := prometheus.NewRegistry()
	var auditCount int64
	u, _ := url.Parse(providerSrv.URL)
	p := &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		metrics:      newMetrics(reg),
		auditLogger:  slog.New(countingSlogHandler{n: &auditCount}),
	}
	srv := httptest.NewServer(p)

	var terminal int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{}
			for j := 0; j < m; j++ {
				resp, err := client.Post(srv.URL+"/v1/chat/completions", "application/json", strings.NewReader(openAIBody()))
				if err != nil {
					t.Errorf("request failed: %v", err)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK || (resp.StatusCode >= 400 && resp.StatusCode < 600) {
					atomic.AddInt64(&terminal, 1)
				}
			}
		}()
	}
	wg.Wait()
	srv.Close() // blocks until all handlers (and their deferred audit/metric emission) finish

	if terminal != total {
		t.Errorf("terminal statuses: got %d, want %d (some requests hung or errored)", terminal, total)
	}
	if got := atomic.LoadInt64(&auditCount); got != total {
		t.Errorf("audit entries: got %d, want %d", got, total)
	}
	if got := gatherCounterSum(t, reg, "philter_proxy_requests_total"); got != float64(total) {
		t.Errorf("philter_proxy_requests_total: got %v, want %d", got, total)
	}
}

// TestStress_HighConcurrency_WithCache runs the same shape with the response
// cache and per-key auth enabled. Each goroutine is a distinct tenant (its own
// API key id) issuing M sequential cacheable requests, and asserts: no
// cross-tenant cache poisoning (each tenant only ever sees its own response),
// and that cache hits/misses sum correctly (one miss per tenant, the rest hits).
func TestStress_HighConcurrency_WithCache(t *testing.T) {
	n, m := stressDims()

	philterSrv := philterPassThrough(t)
	defer philterSrv.Close()
	// The provider echoes the (forwarded) X-Tenant header into the response so a
	// poisoned cache entry would be detectable as another tenant's marker.
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.Header.Get("X-Tenant")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"choices":[{"message":{"role":"assistant","content":%q}}]}`, tenant)
	}))
	defer providerSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Cache = CacheConfig{Enabled: true, TTLSeconds: 300}
	keys := make([]APIKeyEntry, n)
	for i := range keys {
		keys[i] = APIKeyEntry{Key: fmt.Sprintf("key-%d", i), ID: fmt.Sprintf("tenant-%d", i)}
	}
	cfg.Auth.APIKeys = keys

	cache, err := newResponseCache(cfg.Cache)
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	u, _ := url.Parse(providerSrv.URL)
	p := &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		keyStore:     mustKeyStore(keys),
		cache:        cache,
		metrics:      newMetrics(reg),
	}
	srv := httptest.NewServer(p)

	var poisoned int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(tenant int) {
			defer wg.Done()
			marker := fmt.Sprintf("tenant-%d", tenant)
			client := &http.Client{}
			for j := 0; j < m; j++ {
				req, _ := http.NewRequest("POST", srv.URL+"/v1/chat/completions", strings.NewReader(openAIBody()))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("x-philter-proxy-key", fmt.Sprintf("key-%d", tenant))
				req.Header.Set("X-Tenant", marker)
				resp, err := client.Do(req)
				if err != nil {
					t.Errorf("tenant %d request failed: %v", tenant, err)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("tenant %d: status %d: %s", tenant, resp.StatusCode, string(body))
					continue
				}
				// The response must carry THIS tenant's marker and no other's.
				if !strings.Contains(string(body), marker) {
					atomic.AddInt64(&poisoned, 1)
				}
			}
		}(i)
	}
	wg.Wait()
	srv.Close()

	if poisoned != 0 {
		t.Errorf("cache poisoning detected: %d responses carried the wrong tenant marker", poisoned)
	}
	hits := gatherCounterSum(t, reg, "philter_proxy_cache_hits_total")
	misses := gatherCounterSum(t, reg, "philter_proxy_cache_misses_total")
	if hits+misses != float64(n*m) {
		t.Errorf("cache hits+misses = %v, want %d (every request is cacheable)", hits+misses, n*m)
	}
	// Each tenant's first request is a miss; the remaining M-1 are hits.
	if misses != float64(n) {
		t.Errorf("cache misses = %v, want %d (one per tenant)", misses, n)
	}
	if hits != float64(n*(m-1)) {
		t.Errorf("cache hits = %v, want %d", hits, n*(m-1))
	}
}
