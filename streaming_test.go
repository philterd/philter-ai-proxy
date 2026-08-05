package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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

// TestStreaming_TokenUsage asserts the streaming path extracts token usage from
// the final streaming event for OpenAI and Anthropic and records it in the audit
// log, the same way the non-streaming path does.
func TestStreaming_TokenUsage(t *testing.T) {
	cases := []struct {
		name     string
		provider string
		path     string
		reqBody  string
		events   string
	}{
		{
			name:     "openai",
			provider: "openai",
			path:     "/v1/chat/completions",
			reqBody:  `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true,"stream_options":{"include_usage":true}}`,
			events: "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n" +
				"data: {\"choices\":[{\"delta\":{}}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n" +
				"data: [DONE]\n\n",
		},
		{
			name:     "anthropic",
			provider: "anthropic",
			path:     "/v1/messages",
			reqBody:  `{"model":"claude-3","messages":[{"role":"user","content":"hi"}],"stream":true}`,
			events: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":1}}}\n\n" +
				"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			philter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(explainJSON("hi", "doc", nil))
			}))
			defer philter.Close()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, c.events)
			}))
			defer upstream.Close()

			p := newStreamingProxy(philter.URL, upstream.URL, c.provider)
			var logBuf strings.Builder
			p.auditLogger = slog.New(slog.NewJSONHandler(&logBuf, nil))

			// Drive ServeHTTP directly so the audit log is emitted synchronously
			// before we read it (a networked client can finish reading the stream
			// before the server emits its deferred audit entry).
			req := httptest.NewRequest("POST", c.path, strings.NewReader(c.reqBody))
			p.ServeHTTP(httptest.NewRecorder(), req)

			log := logBuf.String()
			if !strings.Contains(log, `"prompt_tokens":11`) {
				t.Errorf("expected prompt_tokens=11 from the streamed usage event, audit log: %s", log)
			}
			if !strings.Contains(log, `"completion_tokens":7`) {
				t.Errorf("expected completion_tokens=7 from the streamed usage event, audit log: %s", log)
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

func TestStreamingUsageSupported(t *testing.T) {
	supported := []string{"openai", "azure", "anthropic", "mistral", ""}
	for _, p := range supported {
		if !streamingUsageSupported(p) {
			t.Errorf("provider %q should support streaming usage", p)
		}
	}
	for _, p := range []string{"gemini", "vertex", "ollama", "bedrock"} {
		if streamingUsageSupported(p) {
			t.Errorf("provider %q should NOT support streaming usage", p)
		}
	}
}

func TestExtractStreamingUsage(t *testing.T) {
	cases := []struct {
		name         string
		provider     string
		event        string
		wantP, wantC int
	}{
		{"openai-final-usage", "openai", `{"choices":[{"delta":{}}],"usage":{"prompt_tokens":11,"completion_tokens":7}}`, 11, 7},
		{"openai-responses-shape", "openai", `{"usage":{"input_tokens":3,"output_tokens":4}}`, 3, 4},
		{"openai-no-usage", "openai", `{"choices":[{"delta":{"content":"hi"}}]}`, 0, 0},
		{"anthropic-message-start", "anthropic", `{"type":"message_start","message":{"usage":{"input_tokens":11,"output_tokens":1}}}`, 11, 1},
		{"anthropic-message-delta", "anthropic", `{"type":"message_delta","usage":{"output_tokens":7}}`, 0, 7},
		{"anthropic-no-usage", "anthropic", `{"type":"content_block_delta","delta":{"text":"hi"}}`, 0, 0},
		{"malformed", "openai", `{not json`, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, comp := extractStreamingUsage(c.provider, []byte(c.event))
			if p != c.wantP || comp != c.wantC {
				t.Errorf("extractStreamingUsage(%s) = (%d,%d), want (%d,%d)", c.provider, p, comp, c.wantP, c.wantC)
			}
		})
	}
}

func TestStreamUsageScanner_OpenAI_ChunkBoundaries(t *testing.T) {
	// The usage event is split across arbitrary 7-byte writes to exercise line
	// reassembly across chunk boundaries.
	full := "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: {\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7}}\n\n" +
		"data: [DONE]\n\n"
	s := newStreamUsageScanner("openai")
	for i := 0; i < len(full); i += 7 {
		end := i + 7
		if end > len(full) {
			end = len(full)
		}
		s.write([]byte(full[i:end]))
	}
	s.close()
	if s.prompt != 11 || s.completion != 7 {
		t.Errorf("scanner = (%d,%d), want (11,7)", s.prompt, s.completion)
	}
}

func TestStreamUsageScanner_NoTrailingNewline(t *testing.T) {
	// A final usage event without a trailing newline is only parsed on close().
	s := newStreamUsageScanner("openai")
	s.write([]byte(`data: {"usage":{"prompt_tokens":4,"completion_tokens":2}}`))
	if s.prompt != 0 || s.completion != 0 {
		t.Errorf("nothing should parse before close(), got (%d,%d)", s.prompt, s.completion)
	}
	s.close()
	if s.prompt != 4 || s.completion != 2 {
		t.Errorf("close() must flush the final line, got (%d,%d)", s.prompt, s.completion)
	}
}

func TestStreamUsageScanner_Anthropic_LastWins(t *testing.T) {
	s := newStreamUsageScanner("anthropic")
	s.write([]byte("data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11,\"output_tokens\":1}}}\n\n"))
	s.write([]byte("data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n"))
	s.close()
	if s.prompt != 11 || s.completion != 7 {
		t.Errorf("anthropic last-wins = (%d,%d), want (11,7)", s.prompt, s.completion)
	}
}

func TestStreamUsageScanner_DisabledProviderIsNoop(t *testing.T) {
	s := newStreamUsageScanner("gemini")
	s.write([]byte("data: {\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":3}}\n\n"))
	s.close()
	if s.prompt != 0 || s.completion != 0 {
		t.Errorf("disabled scanner must extract nothing, got (%d,%d)", s.prompt, s.completion)
	}
	if s.partial != nil {
		t.Errorf("disabled scanner must not buffer, got %d bytes", len(s.partial))
	}
}

func TestStreamUsageScanner_IgnoresNonDataLines(t *testing.T) {
	s := newStreamUsageScanner("openai")
	// [DONE], event:, and comment lines must not break parsing or extract usage.
	s.write([]byte(": keep-alive comment\nevent: ping\ndata: [DONE]\n\n"))
	s.close()
	if s.prompt != 0 || s.completion != 0 {
		t.Errorf("non-usage lines must not extract usage, got (%d,%d)", s.prompt, s.completion)
	}
}

func TestStreamCopy(t *testing.T) {
	src := strings.NewReader("hello world, streaming")
	rec := httptest.NewRecorder()
	var teed []byte
	streamCopy(rec, src, func(b []byte) { teed = append(teed, b...) })
	if rec.Body.String() != "hello world, streaming" {
		t.Errorf("body = %q", rec.Body.String())
	}
	if string(teed) != "hello world, streaming" {
		t.Errorf("teed = %q", string(teed))
	}
	if !rec.Flushed {
		t.Error("streamCopy should flush after writing")
	}
	// A nil tee must not panic.
	rec2 := httptest.NewRecorder()
	streamCopy(rec2, strings.NewReader("x"), nil)
	if rec2.Body.String() != "x" {
		t.Errorf("nil-tee body = %q", rec2.Body.String())
	}
}

// TestStreaming_Bedrock_ConverseStream_NoBuffering drives a Bedrock
// converse-stream request: the upstream emits AWS event-stream-typed frames
// 80ms apart, and the proxy must deliver them incrementally (no buffering)
// while still redacting the inbound request body.
func TestStreaming_Bedrock_ConverseStream_NoBuffering(t *testing.T) {
	philter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc", []Span{{FilterType: "NER_ENTITY", Confidence: 0.9}}))
	}))
	defer philter.Close()

	bodyCh := make(chan string, 1)
	bedrock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyCh <- string(b)
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for i := 1; i <= 3; i++ {
			io.WriteString(w, "frame-"+strconv.Itoa(i)+"\n")
			flusher.Flush()
			time.Sleep(80 * time.Millisecond)
		}
	}))
	defer bedrock.Close()

	proxy := newBedrockProxy(philter.URL, bedrock.URL)
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()

	reqBody := `{"messages":[{"role":"user","content":[{"text":"my SSN is 123-45-6789"}]}]}`
	resp, err := http.Post(proxySrv.URL+"/model/amazon.titan-text-v1/converse-stream",
		"application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "vnd.amazon.eventstream") {
		t.Fatalf("Content-Type lost; got %q", ct)
	}

	br := bufio.NewReader(resp.Body)
	var arrivals []time.Time
	for {
		line, err := br.ReadString('\n')
		if strings.Contains(line, "frame-") {
			arrivals = append(arrivals, time.Now())
		}
		if err != nil {
			break
		}
	}
	if len(arrivals) != 3 {
		t.Fatalf("expected 3 frames, got %d", len(arrivals))
	}
	for i := 1; i < len(arrivals); i++ {
		if gap := arrivals[i].Sub(arrivals[i-1]); gap < 30*time.Millisecond {
			t.Errorf("frame %d-%d gap %v < 30ms -- response appears buffered", i-1, i, gap)
		}
	}

	// converse-stream must still redact the inbound request before forwarding.
	gotBody := <-bodyCh
	if strings.Contains(gotBody, "123-45-6789") {
		t.Errorf("inbound SSN should have been redacted before forwarding, upstream got: %s", gotBody)
	}
	if !strings.Contains(gotBody, "REDACTED") {
		t.Errorf("expected redacted text forwarded upstream, got: %s", gotBody)
	}
}

// --- #29: fail closed on unscannable streams -------------------------------

// streamingContentTypes are the content types isStreamingResponse recognizes.
var streamingContentTypes = []struct {
	name string
	ct   string
}{
	{"sse", "text/event-stream"},
	{"ndjson", "application/x-ndjson"},
	{"aws_eventstream", "application/vnd.amazon.eventstream"},
}

// streamingProviderFor stubs a provider streaming a body containing PII.
func streamingProviderFor(ct string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"SSN 123-45-6789\"}}]}\n\n")
	}))
}

// TestStreaming_BlockRejectsUnscannableStream is the core of #29: under
// `action: block` an unscanned stream must not reach the client.
func TestStreaming_BlockRejectsUnscannableStream(t *testing.T) {
	for _, tc := range streamingContentTypes {
		t.Run(tc.name, func(t *testing.T) {
			philter := philterRedact("[REDACTED]")
			defer philter.Close()
			provider := streamingProviderFor(tc.ct)
			defer provider.Close()

			proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "block")
			req := httptest.NewRequest("POST", "/v1/chat/completions",
				strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`))
			w := httptest.NewRecorder()
			proxy.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("want 403, got %d (body: %s)", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "123-45-6789") {
				t.Errorf("unscanned provider body reached the client: %s", w.Body.String())
			}
			var body errorBody
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("error body is not JSON: %v (%s)", err, w.Body.String())
			}
			if body.Error.Type != "pii_blocked" || body.Error.Code != "outbound_stream_unscannable" {
				t.Errorf("want pii_blocked/outbound_stream_unscannable, got %s/%s",
					body.Error.Type, body.Error.Code)
			}
		})
	}
}

// TestStreaming_RedactAndFlagStillPassThrough pins the other half: neither
// action promises a clean response, so both keep passing streams through.
func TestStreaming_RedactAndFlagStillPassThrough(t *testing.T) {
	for _, action := range []string{"redact", "flag"} {
		for _, tc := range streamingContentTypes {
			t.Run(action+"_"+tc.name, func(t *testing.T) {
				prev := slog.Default()
				var logBuf strings.Builder
				slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, nil)))
				defer slog.SetDefault(prev)

				philter := philterRedact("[REDACTED]")
				defer philter.Close()
				provider := streamingProviderFor(tc.ct)
				defer provider.Close()

				proxy := newOutboundProxy(philter.URL, provider.URL, "openai", action)
				req := httptest.NewRequest("POST", "/v1/chat/completions",
					strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`))
				w := httptest.NewRecorder()
				proxy.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Fatalf("want 200, got %d", w.Code)
				}
				if !strings.Contains(w.Body.String(), "123-45-6789") {
					t.Errorf("body should pass through unscanned, got: %s", w.Body.String())
				}
				if !strings.Contains(logBuf.String(), "Outbound scanning skipped for streaming response") {
					t.Errorf("expected skipped-scan warning, got: %s", logBuf.String())
				}
			})
		}
	}
}

// TestStreaming_AllowUnscannedStreamsOptOut covers the escape hatch.
func TestStreaming_AllowUnscannedStreamsOptOut(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()
	provider := streamingProviderFor("text/event-stream")
	defer provider.Close()

	proxy := newOutboundProxyCfg(philter.URL, provider.URL, "openai",
		OutboundConfig{Enabled: true, Action: "block", AllowUnscannedStreams: true})
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("opt-out should restore pass-through; want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "123-45-6789") {
		t.Errorf("opt-out should pass the stream through, got: %s", w.Body.String())
	}
}

// TestStreaming_BlockRejectionIsAudited asserts the rejection is auditable.
func TestStreaming_BlockRejectionIsAudited(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()
	provider := streamingProviderFor("text/event-stream")
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "block")
	var buf bytes.Buffer
	withAuditLogger(proxy, &buf)

	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}

	var found bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var entry map[string]any
		if json.Unmarshal([]byte(line), &entry) != nil {
			continue
		}
		if entry["direction"] == "outbound" && entry["error_code"] == "outbound_stream_unscannable" {
			found = true
			if entry["http_status"] != float64(http.StatusForbidden) {
				t.Errorf("audit http_status = %v, want 403", entry["http_status"])
			}
		}
	}
	if !found {
		t.Errorf("no outbound audit entry recording the rejection:\n%s", buf.String())
	}
}

// TestStreaming_BlockAllowsCleanNonStreamingResponse guards the normal case
// against the fail-closed path.
func TestStreaming_BlockAllowsCleanNonStreamingResponse(t *testing.T) {
	philter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("all clear", "doc-out", nil)) // no spans -> no PII
	}))
	defer philter.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"all clear"}}]}`)
	}))
	defer provider.Close()

	proxy := newOutboundProxy(philter.URL, provider.URL, "openai", "block")
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("clean non-streaming response must pass; got %d (%s)", w.Code, w.Body.String())
	}
}

// TestStreaming_BedrockBlockRejectsConverseStream covers the Bedrock path,
// which has its own copy of the outbound-scan dispatch.
func TestStreaming_BedrockBlockRejectsConverseStream(t *testing.T) {
	philter := philterRedact("[REDACTED]")
	defer philter.Close()
	bedrock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "frame-with-SSN-123-45-6789\n")
	}))
	defer bedrock.Close()

	proxy := newBedrockProxy(philter.URL, bedrock.URL)
	proxy.config.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "block"}

	req := httptest.NewRequest("POST", "/model/amazon.titan-text-v1/converse-stream",
		strings.NewReader(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`))
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d (body: %s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "123-45-6789") {
		t.Errorf("unscanned Bedrock stream reached the client: %s", w.Body.String())
	}
}
