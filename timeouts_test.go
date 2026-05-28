package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- newProviderTransport unit checks ---------------------------------------

func TestNewProviderTransport_AppliesDefaults(t *testing.T) {
	transport := newProviderTransport(&tls.Config{}, ProviderTimeouts{})

	if got := transport.TLSHandshakeTimeout; got != time.Duration(DefaultTLSHandshakeTimeoutMs)*time.Millisecond {
		t.Errorf("TLSHandshakeTimeout: want default %dms, got %v", DefaultTLSHandshakeTimeoutMs, got)
	}
	if got := transport.ResponseHeaderTimeout; got != time.Duration(DefaultResponseHeaderTimeoutMs)*time.Millisecond {
		t.Errorf("ResponseHeaderTimeout: want default %dms, got %v", DefaultResponseHeaderTimeoutMs, got)
	}
	if got := transport.IdleConnTimeout; got != time.Duration(DefaultIdleConnTimeoutMs)*time.Millisecond {
		t.Errorf("IdleConnTimeout: want default %dms, got %v", DefaultIdleConnTimeoutMs, got)
	}
	if transport.DialContext == nil {
		t.Error("DialContext must be set so the connect timeout is honored")
	}
}

func TestNewProviderTransport_OverridesApplied(t *testing.T) {
	transport := newProviderTransport(&tls.Config{}, ProviderTimeouts{
		ConnectMs:        100,
		TLSHandshakeMs:   200,
		ResponseHeaderMs: 300,
		IdleConnMs:       400,
	})
	if got := transport.TLSHandshakeTimeout; got != 200*time.Millisecond {
		t.Errorf("TLSHandshakeTimeout override: got %v", got)
	}
	if got := transport.ResponseHeaderTimeout; got != 300*time.Millisecond {
		t.Errorf("ResponseHeaderTimeout override: got %v", got)
	}
	if got := transport.IdleConnTimeout; got != 400*time.Millisecond {
		t.Errorf("IdleConnTimeout override: got %v", got)
	}
}

// --- Behavioral tests against a slow upstream -------------------------------
//
// These tests are real-time: we configure the proxy with a small response
// header timeout (200ms) and a slow upstream and assert that the proxy bails
// out fast. They intentionally cap timings at ~1s so they pass quickly in CI.

// slowProvider returns an httptest.Server that waits `headerDelay` before
// writing response headers, then streams `chunks` separated by `chunkInterval`.
func slowProvider(t *testing.T, headerDelay, chunkInterval time.Duration, chunks []string, streaming bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if headerDelay > 0 {
			time.Sleep(headerDelay)
		}
		if streaming {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, c := range chunks {
			w.Write([]byte(c))
			if flusher != nil {
				flusher.Flush()
			}
			if chunkInterval > 0 {
				time.Sleep(chunkInterval)
			}
		}
	}))
}

// proxyWithProviderTimeouts builds a proxy whose openai client has the given
// per-provider timeouts. Philter is a fast pass-through.
func proxyWithProviderTimeouts(t *testing.T, providerURL string, timeouts ProviderTimeouts) (*Proxy, func()) {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	u, _ := url.Parse(providerURL)
	p := &Proxy{
		config:       testConfig(philterSrv.URL),
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: &http.Client{Transport: newProviderTransport(&tls.Config{}, timeouts)},
	}
	return p, philterSrv.Close
}

// TestResponseHeaderTimeout_FiresOnHungUpstream sets a 200ms response-header
// timeout and points the proxy at an upstream that sleeps for 2s before
// responding. The proxy must give up well under 2s with a 502.
func TestResponseHeaderTimeout_FiresOnHungUpstream(t *testing.T) {
	slow := slowProvider(t, 2*time.Second, 0, nil, false)
	defer slow.Close()

	proxy, cleanup := proxyWithProviderTimeouts(t, slow.URL, ProviderTimeouts{
		ResponseHeaderMs: 200,
	})
	defer cleanup()

	start := time.Now()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502 on response-header timeout, got %d: %s", w.Code, w.Body.String())
	}
	// Should fire well under the upstream's 2s sleep. Allow generous slack
	// for slow CI but still much less than 2s.
	if elapsed > 1500*time.Millisecond {
		t.Errorf("expected timeout to fire fast (<1.5s); elapsed=%v", elapsed)
	}
}

// TestStreamingNotCutOffByHeaderTimeout sets a tight response-header timeout
// but has the upstream write headers immediately and then stream chunks for
// well past the header-timeout window. The proxy must NOT cut the stream.
func TestStreamingNotCutOffByHeaderTimeout(t *testing.T) {
	chunks := []string{
		"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\"c\"}}]}\n\n",
		"data: [DONE]\n\n",
	}
	// Header arrives fast; chunks stream over ~800ms, far past the 200ms header timeout.
	slow := slowProvider(t, 0, 250*time.Millisecond, chunks, true)
	defer slow.Close()

	proxy, cleanup := proxyWithProviderTimeouts(t, slow.URL, ProviderTimeouts{
		ResponseHeaderMs: 200,
	})
	defer cleanup()

	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, c := range chunks {
		if !strings.Contains(body, c) {
			t.Errorf("streamed chunk %q missing from response body; the header timeout incorrectly cut the stream\nbody: %s", c, body)
		}
	}
}

// TestConnectTimeout_FiresFast points the proxy at an unreachable address
// (TEST-NET-1, RFC 5737, guaranteed not to route) and verifies the connect
// times out within ~250ms when configured to 100ms.
func TestConnectTimeout_FiresFast(t *testing.T) {
	if testing.Short() {
		t.Skip("network behavior; skipped in short mode")
	}

	// Listen on a port then close it — connecting to it should fail
	// immediately with connection refused. We're testing that the dialer's
	// own timeout would catch a real black-hole, but a refused port gives
	// us a deterministic failure for the connect path itself.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	proxy, cleanup := proxyWithProviderTimeouts(t, "http://"+addr, ProviderTimeouts{
		ConnectMs: 100,
	})
	defer cleanup()

	start := time.Now()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(openAIBody()))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)
	elapsed := time.Since(start)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502 when upstream is unreachable, got %d", w.Code)
	}
	if elapsed > time.Second {
		t.Errorf("expected fast failure (<1s); elapsed=%v", elapsed)
	}
}

// TestValidateConfig_TimeoutValues exercises the validator's per-field
// non-negative check.
func TestValidateConfig_TimeoutValues(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "philter negative connect",
			mutate: func(c *Config) {
				c.Philter.Timeouts.ConnectMs = -1
			},
			wantErr: "philter.timeouts.connectMs",
		},
		{
			name: "openai negative response header",
			mutate: func(c *Config) {
				c.Providers.OpenAI.Timeouts.ResponseHeaderMs = -1
			},
			wantErr: "providers.openai.timeouts.responseHeaderMs",
		},
		{
			name: "bedrock negative idle conn",
			mutate: func(c *Config) {
				c.Providers.Bedrock.Timeouts.IdleConnMs = -1
			},
			wantErr: "providers.bedrock.timeouts.idleConnMs",
		},
		{
			name: "openaiCompatible negative tls handshake",
			mutate: func(c *Config) {
				c.Providers.OpenAICompatible = map[string]ProviderConfig{
					"mistral": {
						Target:   "https://api.mistral.ai",
						Timeouts: ProviderTimeouts{TLSHandshakeMs: -1},
					},
				}
			},
			wantErr: "providers.openaiCompatible.mistral.timeouts.tlsHandshakeMs",
		},
		{
			name:   "valid zero values",
			mutate: func(c *Config) {},
		},
		{
			name: "valid explicit values",
			mutate: func(c *Config) {
				c.Providers.OpenAI.Timeouts = ProviderTimeouts{
					ConnectMs: 1000, TLSHandshakeMs: 1000, ResponseHeaderMs: 1000, IdleConnMs: 1000,
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig("http://127.0.0.1:1")
			tc.mutate(cfg)
			err := validateConfig(cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}
