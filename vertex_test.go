package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// --- isVertexPath ----------------------------------------------------------

func TestIsVertexPath(t *testing.T) {
	cases := map[string]bool{
		"/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent":       true,
		"/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-1.5-pro:streamGenerateContent": true,
		"/v1/projects/p/locations/l/publishers/google/models/m:GENERATECONTENT":                                    true, // case-insensitive
		"/v1/models/gemini-1.5-pro:generateContent":                                                                false, // public Gemini, not Vertex
		"/v1beta/models/gemini-1.5-pro:generateContent":                                                            false, // public Gemini beta
		"/v1/projects/p/locations/l/publishers/google/models/m":                                                    false, // no action
		"/v1/messages":                                                                                             false,
		"/v1/chat/completions":                                                                                     false,
	}
	for path, want := range cases {
		if got := isVertexPath(path); got != want {
			t.Errorf("isVertexPath(%q) = %v, want %v", path, got, want)
		}
	}
}

// --- vertexModelFromPath --------------------------------------------------

func TestVertexModelFromPath(t *testing.T) {
	cases := map[string]string{
		"/v1/projects/p/locations/l/publishers/google/models/gemini-1.5-pro:generateContent":       "gemini-1.5-pro",
		"/v1/projects/p/locations/l/publishers/google/models/gemini-1.0-flash:streamGenerateContent": "gemini-1.0-flash",
		"/v1/projects/p/locations/l/publishers/google/models/m":                                    "m",
		"/v1/chat/completions":                                                                     "",
	}
	for path, want := range cases {
		if got := vertexModelFromPath(path); got != want {
			t.Errorf("vertexModelFromPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// --- vertexDefaultEndpoint + vertexTargetURL ------------------------------

func TestVertexDefaultEndpoint(t *testing.T) {
	if got := vertexDefaultEndpoint("us-central1"); got != "https://us-central1-aiplatform.googleapis.com" {
		t.Errorf("default endpoint = %q", got)
	}
	if got := vertexDefaultEndpoint("europe-west4"); got != "https://europe-west4-aiplatform.googleapis.com" {
		t.Errorf("eu default = %q", got)
	}
}

func TestVertexTargetURL_FromLocation(t *testing.T) {
	u, err := vertexTargetURL(VertexConfig{Project: "p", Location: "us-central1"})
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "https://us-central1-aiplatform.googleapis.com" {
		t.Errorf("target = %s", u.String())
	}
}

func TestVertexTargetURL_FromEndpoint(t *testing.T) {
	u, err := vertexTargetURL(VertexConfig{Project: "p", Endpoint: "https://override.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "https://override.example.com" {
		t.Errorf("target = %s", u.String())
	}
}

func TestVertexTargetURL_RequiresLocationOrEndpoint(t *testing.T) {
	if _, err := vertexTargetURL(VertexConfig{Project: "p"}); err == nil {
		t.Error("expected error when neither location nor endpoint is set")
	}
}

// --- staticTokenSource ----------------------------------------------------

func TestStaticTokenSource(t *testing.T) {
	ts := staticTokenSource{value: "abc"}
	tok, err := ts.token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "abc" {
		t.Errorf("got %q", tok)
	}
	if _, err := (staticTokenSource{}).token(t.Context()); err == nil {
		t.Error("empty token source should error")
	}
}

// --- Config validation ----------------------------------------------------

func TestValidateConfig_VertexRequiresLocation(t *testing.T) {
	cfg := defaultConfig()
	cfg.Providers.Vertex = VertexConfig{Project: "p"} // no location, no endpoint
	if err := validateConfig(cfg); err == nil {
		t.Error("expected validation error when location & endpoint both unset")
	}
}

func TestValidateConfig_VertexEndpointInvalid(t *testing.T) {
	cfg := defaultConfig()
	cfg.Providers.Vertex = VertexConfig{Project: "p", Endpoint: "://broken"}
	if err := validateConfig(cfg); err == nil {
		t.Error("expected validation error for malformed endpoint")
	}
}

func TestValidateConfig_VertexDisabledIsValid(t *testing.T) {
	cfg := defaultConfig()
	// Project empty -> disabled -> location is not required
	cfg.Providers.Vertex = VertexConfig{}
	if err := validateConfig(cfg); err != nil {
		t.Errorf("disabled Vertex should validate; got %v", err)
	}
}

// --- End-to-end: routing + token injection + redaction --------------------

// vertexCapture records what the proxy forwards to Vertex.
type vertexCapture struct {
	path  string
	authz string
	body  string
}

func newVertexProxy(t *testing.T, philterURL string, capture *vertexCapture, ts tokenSource) (*Proxy, *httptest.Server) {
	t.Helper()
	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capture.path = r.URL.Path
		capture.authz = r.Header.Get("Authorization")
		capture.body = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}`))
	}))
	t.Cleanup(vertexSrv.Close)

	cfg := testConfig(philterURL)
	cfg.Providers.Vertex = VertexConfig{Project: "p", Location: "us-central1"}
	u, _ := url.Parse(vertexSrv.URL)
	p := &Proxy{
		config:            cfg,
		philter:           testPhilterClient(philterURL),
		vertexTarget:      u,
		vertexClient:      http.DefaultClient,
		vertexTokenSource: ts,
	}
	return p, vertexSrv
}

func TestVertex_EndToEnd_Forwards_WithBearerToken_AndRedactsBody(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo a redacted explain response that replaces the PII.
		w.Write(explainJSON("Patient {{{REDACTED-PERSON}}} called", "doc-id", nil))
	}))
	defer philterSrv.Close()

	cap := &vertexCapture{}
	p, _ := newVertexProxy(t, philterSrv.URL, cap, staticTokenSource{value: "test-bearer"})

	w := sendRequest(p,
		"/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent",
		`{"contents":[{"parts":[{"text":"Patient John Smith called"}]}]}`,
		nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	// The bearer token from the configured source must be set on the upstream call.
	if cap.authz != "Bearer test-bearer" {
		t.Errorf("Authorization not forwarded; got %q", cap.authz)
	}
	// The body must have been redacted via the Gemini path before being forwarded.
	if !strings.Contains(cap.body, "{{{REDACTED-PERSON}}}") {
		t.Errorf("body should carry redacted text; got %q", cap.body)
	}
	if strings.Contains(cap.body, "John Smith") {
		t.Errorf("raw PII leaked to upstream; body=%q", cap.body)
	}
	// The Vertex resource path is preserved.
	if !strings.HasPrefix(cap.path, "/v1/projects/my-proj/") {
		t.Errorf("path not forwarded verbatim; got %q", cap.path)
	}
}

func TestVertex_TokenUsageRecorded(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	// Upstream returns a Vertex-shaped response with usageMetadata.
	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"hi"}]}}],"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":3}}`))
	}))
	defer vertexSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Providers.Vertex = VertexConfig{Project: "p", Location: "us-central1"}
	u, _ := url.Parse(vertexSrv.URL)

	var auditBuf bytes.Buffer
	p := &Proxy{
		config:            cfg,
		philter:           testPhilterClient(philterSrv.URL),
		vertexTarget:      u,
		vertexClient:      http.DefaultClient,
		vertexTokenSource: staticTokenSource{value: "tok"},
		auditLogger:       slog.New(slog.NewJSONHandler(&auditBuf, nil)),
	}

	w := sendRequest(p,
		"/v1/projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent",
		`{"contents":[{"parts":[{"text":"hello"}]}]}`,
		nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := auditBuf.String()
	if !strings.Contains(out, `"prompt_tokens":7`) {
		t.Errorf("expected prompt_tokens=7 in audit; got %s", out)
	}
	if !strings.Contains(out, `"completion_tokens":3`) {
		t.Errorf("expected completion_tokens=3 in audit; got %s", out)
	}
}

func TestVertex_AuditModelFromPath(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	// auditLogger captures audit emissions so we can assert model is populated
	// from the URL even though the body has no model field.
	var auditBuf bytes.Buffer
	cap := &vertexCapture{}
	p, _ := newVertexProxy(t, philterSrv.URL, cap, staticTokenSource{value: "tok"})
	p.auditLogger = slog.New(slog.NewJSONHandler(&auditBuf, nil))

	w := sendRequest(p,
		"/v1/projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent",
		`{"contents":[{"parts":[{"text":"hello"}]}]}`,
		nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := auditBuf.String()
	if !strings.Contains(out, `"provider":"vertex"`) {
		t.Errorf("audit must record provider=vertex; got %s", out)
	}
	if !strings.Contains(out, `"model":"gemini-1.5-pro"`) {
		t.Errorf("audit must record model from URL; got %s", out)
	}
}

func TestVertex_DisabledReturns404(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()
	// Build a proxy with NO Vertex target/client configured.
	cfg := testConfig(philterSrv.URL)
	p := &Proxy{
		config:  cfg,
		philter: testPhilterClient(philterSrv.URL),
	}
	w := sendRequest(p,
		"/v1/projects/p/locations/us-central1/publishers/google/models/m:generateContent",
		`{"contents":[{"parts":[{"text":"hi"}]}]}`,
		nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when Vertex disabled, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "vertex_disabled") {
		t.Errorf("expected vertex_disabled error code; got %s", w.Body.String())
	}
}

func TestVertex_TokenSourceErrorReturns502(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	cap := &vertexCapture{}
	p, _ := newVertexProxy(t, philterSrv.URL, cap, staticTokenSource{}) // empty -> errors

	w := sendRequest(p,
		"/v1/projects/p/locations/us-central1/publishers/google/models/m:generateContent",
		`{"contents":[{"parts":[{"text":"hi"}]}]}`,
		nil)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on token failure, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "vertex_auth_failed") {
		t.Errorf("expected vertex_auth_failed; got %s", w.Body.String())
	}
	if cap.body != "" {
		t.Error("upstream should not have been called on token failure")
	}
}

// --- resolveProviderName: Vertex precedence over public Gemini ------------

func TestResolveProviderName_VertexBeforeGemini(t *testing.T) {
	vertex := "/v1/projects/p/locations/us/publishers/google/models/m:generateContent"
	if got := resolveProviderName(vertex, ""); got != "vertex" {
		t.Errorf("Vertex path -> %q, want vertex", got)
	}
	public := "/v1/models/gemini-1.5-pro:generateContent"
	if got := resolveProviderName(public, ""); got != "gemini" {
		t.Errorf("public Gemini path -> %q, want gemini", got)
	}
}

// --- Streaming pass-through (real HTTP servers, observe inter-chunk timing) -

// TestVertex_Streaming_PassesChunksThrough drives a full HTTP/1.1 chain:
// real client -> proxy server -> philter stub -> vertex stub. The vertex
// stub writes three chunks with a 50ms gap between them, calling Flush
// after each. The test reads the proxy response line-by-line and records
// arrival timestamps. If the proxy buffered the response, all three chunks
// would arrive in a single burst; if it streams, the inter-chunk delays
// will be observable.
func TestVertex_Streaming_PassesChunksThrough(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream test server must support Flush")
			return
		}
		for i := 1; i <= 3; i++ {
			fmt.Fprintf(w, "data: chunk-%d\n\n", i)
			flusher.Flush()
			time.Sleep(80 * time.Millisecond)
		}
	}))
	defer vertexSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Providers.Vertex = VertexConfig{Project: "p", Location: "us-central1"}
	u, _ := url.Parse(vertexSrv.URL)
	p := &Proxy{
		config:            cfg,
		philter:           testPhilterClient(philterSrv.URL),
		vertexTarget:      u,
		vertexClient:      http.DefaultClient,
		vertexTokenSource: staticTokenSource{value: "tok"},
	}
	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()

	reqURL := proxySrv.URL + "/v1/projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro:streamGenerateContent"
	resp, err := http.Post(reqURL, "application/json",
		strings.NewReader(`{"contents":[{"parts":[{"text":"hi"}]}]}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("Content-Type lost; got %q", ct)
	}

	br := bufio.NewReader(resp.Body)
	var arrivals []time.Time
	for {
		line, err := br.ReadString('\n')
		if strings.HasPrefix(line, "data:") {
			arrivals = append(arrivals, time.Now())
		}
		if err != nil {
			break
		}
	}
	if len(arrivals) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(arrivals))
	}
	// Streaming: chunks ~80ms apart. Buffered: all within a few ms.
	// Require both gaps to be at least 30ms to call it streaming.
	for i := 1; i < len(arrivals); i++ {
		gap := arrivals[i].Sub(arrivals[i-1])
		if gap < 30*time.Millisecond {
			t.Errorf("chunk %d-%d gap %v < 30ms -- response appears buffered", i-1, i, gap)
		}
	}
}

// --- Token provider concurrent cache --------------------------------------

// countingOAuthTokenSource implements oauth2.TokenSource and records call
// counts so we can assert cache effectiveness under concurrent load.
type countingOAuthTokenSource struct {
	calls  atomic.Int64
	value  string
	expiry time.Time
}

func (c *countingOAuthTokenSource) Token() (*oauth2.Token, error) {
	c.calls.Add(1)
	// A small sleep makes a non-thread-safe implementation race-detectable
	// and gives concurrent callers a real chance to overlap.
	time.Sleep(5 * time.Millisecond)
	return &oauth2.Token{AccessToken: c.value, Expiry: c.expiry}, nil
}

// TestVertexTokenProvider_CachesAcrossConcurrentCalls drives the real
// vertexTokenProvider with an injected oauth2.TokenSource and N concurrent
// callers. Once one caller has populated the cache, the rest must read from
// it -- the underlying TokenSource must be called only once, and every
// caller must see the same token. Run under -race to also flag any data
// race in the cache logic.
func TestVertexTokenProvider_CachesAcrossConcurrentCalls(t *testing.T) {
	fake := &countingOAuthTokenSource{
		value:  "concurrent-token",
		expiry: time.Now().Add(time.Hour),
	}
	prov := &vertexTokenProvider{ts: fake}

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	tokens := make([]string, N)
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			tok, err := prov.token(context.Background())
			tokens[idx] = tok
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
		if tokens[i] != "concurrent-token" {
			t.Errorf("caller %d got %q, want concurrent-token", i, tokens[i])
		}
	}
	if got := fake.calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 underlying token fetch under contention, got %d", got)
	}
}

// TestVertexTokenProvider_RefreshesNearExpiry verifies the 5-minute skew:
// a token expiring in less than 5 minutes is refreshed on the next call.
func TestVertexTokenProvider_RefreshesNearExpiry(t *testing.T) {
	fake := &countingOAuthTokenSource{
		value:  "first",
		expiry: time.Now().Add(2 * time.Minute), // within the 5-minute skew
	}
	prov := &vertexTokenProvider{ts: fake}

	if _, err := prov.token(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Second call must NOT return the cached "first" -- expiry is too close,
	// so we re-fetch. Swap the fake's value so the test can observe it.
	fake.value = "second"
	fake.expiry = time.Now().Add(time.Hour)
	tok, err := prov.token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "second" {
		t.Errorf("token must be refreshed when close to expiry; got %q", tok)
	}
	if got := fake.calls.Load(); got != 2 {
		t.Errorf("expected 2 underlying fetches across the skew, got %d", got)
	}
}

// --- functionResponse recursive redaction --------------------------------

// TestVertex_FunctionResponseRedaction sends a Vertex request whose body
// carries a nested functionResponse with PII inside an arbitrary JSON
// object. The shared handleGeminiShaped redaction path walks
// functionResponse.response recursively via redactAny; this confirms that
// path runs for Vertex (not just public Gemini).
func TestVertex_FunctionResponseRedaction(t *testing.T) {
	// Philter stub: redact any text we send it.
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Philter receives the raw text as Content-Type: text/plain.
		raw, _ := io.ReadAll(r.Body)
		redacted := strings.ReplaceAll(string(raw), "John Smith", "{{{REDACTED-PERSON}}}")
		w.Write(explainJSON(redacted, "doc-id", nil))
	}))
	defer philterSrv.Close()

	cap := &vertexCapture{}
	p, _ := newVertexProxy(t, philterSrv.URL, cap, staticTokenSource{value: "tok"})

	reqBody := `{"contents":[{"parts":[{"functionResponse":{"name":"lookup","response":{"customer":{"name":"John Smith","note":"contact John Smith again"}}}}]}]}`
	w := sendRequest(p,
		"/v1/projects/p/locations/us-central1/publishers/google/models/m:generateContent",
		reqBody, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(cap.body, "John Smith") {
		t.Errorf("PII leaked through functionResponse; upstream body=%q", cap.body)
	}
	if !strings.Contains(cap.body, "{{{REDACTED-PERSON}}}") {
		t.Errorf("expected surrogate token in upstream body; got %q", cap.body)
	}
}

// --- Outbound scanning ----------------------------------------------------

// TestVertex_QueryStringPreserved confirms ?alt=sse (and any other query
// parameters the client supplies) reach the upstream verbatim. End-to-end
// streaming through the proxy requires Vertex's SSE mode, which the client
// requests via this query string.
func TestVertex_QueryStringPreserved(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var capturedQuery string
	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`))
	}))
	defer vertexSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Providers.Vertex = VertexConfig{Project: "p", Location: "us-central1"}
	u, _ := url.Parse(vertexSrv.URL)
	p := &Proxy{
		config:            cfg,
		philter:           testPhilterClient(philterSrv.URL),
		vertexTarget:      u,
		vertexClient:      http.DefaultClient,
		vertexTokenSource: staticTokenSource{value: "tok"},
	}

	w := sendRequest(p,
		"/v1/projects/p/locations/us-central1/publishers/google/models/m:streamGenerateContent?alt=sse&extra=keep",
		`{"contents":[{"parts":[{"text":"hi"}]}]}`,
		nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(capturedQuery, "alt=sse") {
		t.Errorf("upstream did not receive alt=sse; query was %q", capturedQuery)
	}
	if !strings.Contains(capturedQuery, "extra=keep") {
		t.Errorf("upstream lost extra query param; query was %q", capturedQuery)
	}
}

// TestVertex_OutboundScan_RedactsResponse turns on defaults.outbound with
// action=redact. Philter's redaction is invoked twice per request: once for
// inbound text and once per text part in the upstream response. The test
// asserts the response the client receives has PII replaced.
func TestVertex_OutboundScan_RedactsResponse(t *testing.T) {
	// A Philter stub that replaces any "John Smith" substring in the text
	// it receives. Used for both inbound and outbound calls. Note Philter
	// receives Content-Type: text/plain, not JSON.
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		redacted := strings.ReplaceAll(string(raw), "John Smith", "{{{REDACTED-PERSON}}}")
		// Provide a non-empty spans slice so EntityCount > 0 (otherwise the
		// outbound scanner with action=redact has nothing recorded; the
		// behavior we want -- replacing the text -- still happens).
		w.Write(explainJSON(redacted, "doc-id", nil))
	}))
	defer philterSrv.Close()

	// Vertex stub that returns a Gemini-shaped response with PII embedded.
	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"Hello John Smith"}]}}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}`))
	}))
	defer vertexSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Providers.Vertex = VertexConfig{Project: "p", Location: "us-central1"}
	cfg.Defaults.Outbound = OutboundConfig{Enabled: true, Action: "redact"}
	u, _ := url.Parse(vertexSrv.URL)
	p := &Proxy{
		config:            cfg,
		philter:           testPhilterClient(philterSrv.URL),
		vertexTarget:      u,
		vertexClient:      http.DefaultClient,
		vertexTokenSource: staticTokenSource{value: "tok"},
	}

	w := sendRequest(p,
		"/v1/projects/p/locations/us-central1/publishers/google/models/m:generateContent",
		`{"contents":[{"parts":[{"text":"hi"}]}]}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "John Smith") {
		t.Errorf("outbound scan failed to redact response; got %s", body)
	}
	if !strings.Contains(body, "{{{REDACTED-PERSON}}}") {
		t.Errorf("response should contain surrogate; got %s", body)
	}
}

