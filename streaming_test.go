package main

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newStreamingProxy builds a proxy with outbound scanning OFF so responses flow
// through the streaming path (forwardToProvider), wired to the given provider.
func newStreamingProxy(philterURL, providerURL, provider string) *Proxy {
	cfg := testConfig(philterURL)
	if provider == "vertex" {
		cfg.Providers.Vertex = VertexConfig{Project: "p", Location: "us-central1"}
	}
	u, _ := url.Parse(providerURL)
	p := &Proxy{config: cfg, philter: testPhilterClient(philterURL)}
	switch provider {
	case "openai":
		p.openaiTarget = u
		p.openaiClient = http.DefaultClient
	case "anthropic":
		p.anthropicTarget = u
		p.anthropicClient = http.DefaultClient
	case "gemini":
		p.geminiTarget = u
		p.geminiClient = http.DefaultClient
	case "ollama":
		p.ollamaTarget = u
		p.ollamaClient = http.DefaultClient
	case "vertex":
		p.vertexTarget = u
		p.vertexClient = http.DefaultClient
		p.vertexTokenSource = staticTokenSource{value: "tok"}
	}
	return p
}

// streamingChain wires philter + upstream + proxy as real httptest servers
// (so flushing works end to end) and returns the proxy and its URL. The caller
// supplies the upstream streaming handler.
func streamingChain(t *testing.T, provider string, upstream http.HandlerFunc) (*Proxy, string) {
	t.Helper()
	philter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc", nil))
	}))
	t.Cleanup(philter.Close)
	up := httptest.NewServer(upstream)
	t.Cleanup(up.Close)
	p := newStreamingProxy(philter.URL, up.URL, provider)
	proxySrv := httptest.NewServer(p)
	t.Cleanup(proxySrv.Close)
	return p, proxySrv.URL
}

// providerStreamCase describes how to route a streaming request to one provider.
type providerStreamCase struct {
	name        string
	provider    string
	path        string
	reqBody     string
	contentType string
}

var providerStreamCases = []providerStreamCase{
	{"openai", "openai", "/v1/chat/completions", `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`, "text/event-stream"},
	{"anthropic", "anthropic", "/v1/messages", `{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}`, "text/event-stream"},
	{"gemini", "gemini", "/v1beta/models/gemini-pro:streamGenerateContent", `{"contents":[{"parts":[{"text":"hi"}]}]}`, "text/event-stream"},
	{"ollama", "ollama", "/api/chat", `{"model":"llama3","messages":[{"role":"user","content":"hi"}]}`, "application/x-ndjson"},
	{"vertex", "vertex", "/v1/projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro:streamGenerateContent", `{"contents":[{"parts":[{"text":"hi"}]}]}`, "text/event-stream"},
}

// TestStreaming_PerProvider_NoBuffering drives a real streaming response through
// each provider and asserts the proxy delivers chunks incrementally rather than
// buffering: the upstream emits three chunks 80ms apart, and the client must
// observe comparable inter-chunk gaps on the proxied stream.
func TestStreaming_PerProvider_NoBuffering(t *testing.T) {
	for _, c := range providerStreamCases {
		t.Run(c.name, func(t *testing.T) {
			_, proxyURL := streamingChain(t, c.provider, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", c.contentType)
				w.WriteHeader(http.StatusOK)
				flusher, ok := w.(http.Flusher)
				if !ok {
					t.Error("upstream test server must support Flush")
					return
				}
				for i := 1; i <= 3; i++ {
					io.WriteString(w, "data: chunk-"+strconv.Itoa(i)+"\n\n")
					flusher.Flush()
					time.Sleep(80 * time.Millisecond)
				}
			})

			resp, err := http.Post(proxyURL+c.path, "application/json", strings.NewReader(c.reqBody))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			if ct := resp.Header.Get("Content-Type"); ct != c.contentType {
				t.Fatalf("Content-Type lost; got %q want %q", ct, c.contentType)
			}

			br := bufio.NewReader(resp.Body)
			var arrivals []time.Time
			for {
				line, err := br.ReadString('\n')
				if strings.Contains(line, "chunk-") {
					arrivals = append(arrivals, time.Now())
				}
				if err != nil {
					break
				}
			}
			if len(arrivals) != 3 {
				t.Fatalf("expected 3 chunks, got %d", len(arrivals))
			}
			for i := 1; i < len(arrivals); i++ {
				if gap := arrivals[i].Sub(arrivals[i-1]); gap < 30*time.Millisecond {
					t.Errorf("chunk %d-%d gap %v < 30ms -- response appears buffered", i-1, i, gap)
				}
			}
		})
	}
}

// TestStreaming_UpstreamCloseMidStream verifies that when the upstream finishes
// (closes) after two chunks, the client receives exactly those two chunks and a
// clean EOF -- no truncation error or duplicated/garbage trailing frame.
func TestStreaming_UpstreamCloseMidStream(t *testing.T) {
	_, proxyURL := streamingChain(t, "openai", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		io.WriteString(w, "data: chunk-1\n\n")
		flusher.Flush()
		io.WriteString(w, "data: chunk-2\n\n")
		flusher.Flush()
		// handler returns -> upstream closes the response cleanly.
	})

	resp, err := http.Post(proxyURL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the stream must end with a clean EOF, got: %v", err)
	}
	if got := string(body); got != "data: chunk-1\n\ndata: chunk-2\n\n" {
		t.Errorf("client must receive exactly the two chunks, got: %q", got)
	}
}

// TestStreaming_ClientCancelsContext verifies that when the client cancels its
// request mid-stream, the cancellation propagates to the upstream connection so
// it is released (the upstream's request context fires Done) within a bounded
// time.
func TestStreaming_ClientCancelsContext(t *testing.T) {
	upstreamCtxDone := make(chan struct{})
	started := make(chan struct{})
	_, proxyURL := streamingChain(t, "openai", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		io.WriteString(w, "data: chunk-1\n\n")
		flusher.Flush()
		close(started)
		select {
		case <-r.Context().Done():
			close(upstreamCtxDone)
		case <-time.After(3 * time.Second):
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", proxyURL+"/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	// Read the first chunk so we know the stream is in flight, then cancel.
	br := bufio.NewReader(resp.Body)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("reading first chunk: %v", err)
	}
	<-started
	cancel()

	select {
	case <-upstreamCtxDone:
		// Cancellation propagated; upstream connection released.
	case <-time.After(3 * time.Second):
		t.Fatal("client cancellation did not propagate to the upstream connection")
	}
}

// TestStreaming_PartialSSEOnEOF verifies that an incomplete final event (no
// trailing blank line) is forwarded verbatim and not re-emitted, duplicated, or
// otherwise corrupted.
func TestStreaming_PartialSSEOnEOF(t *testing.T) {
	_, proxyURL := streamingChain(t, "openai", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		io.WriteString(w, "data: hello") // no trailing \n\n; upstream then closes
		flusher.Flush()
	})

	resp, err := http.Post(proxyURL+"/v1/chat/completions", "application/json",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(body); got != "data: hello" {
		t.Errorf("partial final event must pass through verbatim, got: %q", got)
	}
}

// TestStreaming_OutboundScanPassesThrough confirms the streaming + outbound-scan
// contract: a streamed response is passed through unchanged AND a warning is
// logged that scanning was skipped. Asserts both.
func TestStreaming_OutboundScanPassesThrough(t *testing.T) {
	prev := slog.Default()
	var logBuf strings.Builder
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, nil)))
	defer slog.SetDefault(prev)

	philter := philterRedact("[REDACTED]") // would redact if the body were scanned
	defer philter.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"SSN 123-45-6789\"}}]}\n\n")
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "redact")
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "123-45-6789") {
		t.Errorf("streamed body must pass through unscanned, got: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "[REDACTED]") {
		t.Errorf("streamed body must not be redacted, got: %s", w.Body.String())
	}
	if !strings.Contains(logBuf.String(), "Outbound scanning skipped for streaming response") {
		t.Errorf("expected a skipped-scan warning to be logged, got: %s", logBuf.String())
	}
}
