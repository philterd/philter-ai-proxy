package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// fakeCred is a stub azcore.TokenCredential for testing the token provider's
// caching without a real Azure identity.
type fakeCred struct {
	onGet func()
}

func (f fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.onGet != nil {
		f.onGet()
	}
	return azcore.AccessToken{Token: "tok", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestIsAzurePath(t *testing.T) {
	cases := map[string]bool{
		"/openai/deployments/gpt4o/chat/completions": true,
		"/openai/deployments/embed/embeddings":       true,
		"/v1/chat/completions":                       false,
		"/v1/messages":                               false,
		"/openai/files":                              false,
	}
	for path, want := range cases {
		if got := isAzurePath(path); got != want {
			t.Errorf("isAzurePath(%q) = %v, want %v", path, got, want)
		}
	}
}

// azureBackend captures what the proxy forwards to Azure: the path, query, an
// auth header, and the (redacted) request body.
type azureCapture struct {
	path     string
	rawQuery string
	apiKey   string
	authz    string
	body     string
}

func newAzureProxy(t *testing.T, philterURL string, capture *azureCapture, cred tokenSource) (*Proxy, *httptest.Server) {
	t.Helper()
	azureSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capture.path = r.URL.Path
		capture.rawQuery = r.URL.RawQuery
		capture.apiKey = r.Header.Get("api-key")
		capture.authz = r.Header.Get("Authorization")
		capture.body = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":11,"completion_tokens":4}}`))
	}))

	cfg := testConfig(philterURL)
	cfg.Providers.Azure = AzureConfig{Target: azureSrv.URL, APIVersion: "2024-02-01", EntraID: cred != nil}
	u, _ := url.Parse(azureSrv.URL)
	p := &Proxy{
		config:      cfg,
		philter:     testPhilterClient(philterURL),
		azureTarget: u,
		azureClient: http.DefaultClient,
		azureCred:   cred,
	}
	return p, azureSrv
}

func TestAzure_RoutesRedactsAndForwards(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Philter replaces the message text with a redacted marker.
		w.Write(explainJSON("my name is {{{REDACTED-name}}}", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var cap azureCapture
	p, azureSrv := newAzureProxy(t, philterSrv.URL, &cap, nil)
	defer azureSrv.Close()

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"my name is John Smith"}]}`
	req := httptest.NewRequest("POST", "/openai/deployments/gpt4o/chat/completions?api-version=2024-06-01", strings.NewReader(body))
	req.Header.Set("api-key", "client-azure-key")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	// Deployment path and the client's api-version are preserved to Azure.
	if cap.path != "/openai/deployments/gpt4o/chat/completions" {
		t.Errorf("forwarded path wrong: %q", cap.path)
	}
	if cap.rawQuery != "api-version=2024-06-01" {
		t.Errorf("api-version not preserved: %q", cap.rawQuery)
	}
	// api-key passes through untouched (no Entra ID configured).
	if cap.apiKey != "client-azure-key" {
		t.Errorf("api-key not passed through: %q", cap.apiKey)
	}
	if cap.authz != "" {
		t.Errorf("did not expect Authorization header without Entra ID, got %q", cap.authz)
	}
	// Redaction was applied: Azure must not see the original PII.
	if strings.Contains(cap.body, "John Smith") {
		t.Errorf("PII leaked to Azure: %q", cap.body)
	}
	if !strings.Contains(cap.body, "REDACTED") {
		t.Errorf("expected redacted body, got %q", cap.body)
	}
}

func TestAzure_InjectsDefaultAPIVersionWhenMissing(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var cap azureCapture
	p, azureSrv := newAzureProxy(t, philterSrv.URL, &cap, nil)
	defer azureSrv.Close()

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`
	// No api-version in the client request.
	req := httptest.NewRequest("POST", "/openai/deployments/gpt4o/chat/completions", strings.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if !strings.Contains(cap.rawQuery, "api-version=2024-02-01") {
		t.Errorf("expected default api-version injected, got query %q", cap.rawQuery)
	}
}

// TestAzure_PreservesNonMessageFields guards against the handler dropping
// request parameters: max_tokens, temperature, stream, tools, tool_choice,
// response_format, etc. must all reach the provider, while message content is
// still redacted.
func TestAzure_PreservesNonMessageFields(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("{{{REDACTED}}}", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var cap azureCapture
	p, azureSrv := newAzureProxy(t, philterSrv.URL, &cap, nil)
	defer azureSrv.Close()

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"John Smith"}],` +
		`"max_tokens":50,"temperature":0.7,"top_p":0.9,"stream":true,"stop":["x"],` +
		`"tools":[{"type":"function","function":{"name":"f"}}],"tool_choice":"auto",` +
		`"response_format":{"type":"json_object"},"seed":42}`
	req := httptest.NewRequest("POST", "/openai/deployments/gpt4o/chat/completions?api-version=2024-06-01", strings.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	for _, field := range []string{
		`"max_tokens":50`, `"temperature":0.7`, `"top_p":0.9`, `"stream":true`,
		`"stop":["x"]`, `"tools":`, `"tool_choice":"auto"`, `"response_format":`, `"seed":42`,
	} {
		if !strings.Contains(cap.body, field) {
			t.Errorf("forwarded body dropped %s\n full body: %s", field, cap.body)
		}
	}
	// Redaction still applied to message content.
	if strings.Contains(cap.body, "John Smith") {
		t.Errorf("PII leaked: %s", cap.body)
	}
}

// staticToken is a fake tokenSource for Entra ID tests.
type staticToken struct {
	val string
	err error
}

func (s staticToken) token(context.Context) (string, error) { return s.val, s.err }

func TestAzure_EntraIDInjectsBearer(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var cap azureCapture
	p, azureSrv := newAzureProxy(t, philterSrv.URL, &cap, staticToken{val: "aad-token-xyz"})
	defer azureSrv.Close()

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/openai/deployments/gpt4o/chat/completions?api-version=2024-06-01", strings.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if cap.authz != "Bearer aad-token-xyz" {
		t.Errorf("expected injected Entra ID bearer, got %q", cap.authz)
	}
}

func TestAzure_EntraIDTokenErrorReturns502(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var cap azureCapture
	p, azureSrv := newAzureProxy(t, philterSrv.URL, &cap, staticToken{err: errors.New("no credential")})
	defer azureSrv.Close()

	req := httptest.NewRequest("POST", "/openai/deployments/gpt4o/chat/completions?api-version=2024-06-01",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("token failure should yield 502, got %d", w.Code)
	}
}

func TestAzure_DisabledReturns404(t *testing.T) {
	cfg := testConfig("https://localhost:8080")
	p := &Proxy{config: cfg} // azureTarget nil → disabled
	req := httptest.NewRequest("POST", "/openai/deployments/gpt4o/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[]}`))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("azure disabled should yield 404, got %d", w.Code)
	}
}

func TestAzureAuthMode(t *testing.T) {
	if azureAuthMode(true) != "entra-id" {
		t.Errorf("entra-id expected, got %q", azureAuthMode(true))
	}
	if azureAuthMode(false) != "api-key" {
		t.Errorf("api-key expected, got %q", azureAuthMode(false))
	}
}

func TestAzure_StreamingResponsePassedThrough(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	azureSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer azureSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Providers.Azure = AzureConfig{Target: azureSrv.URL}
	u, _ := url.Parse(azureSrv.URL)
	p := &Proxy{config: cfg, philter: testPhilterClient(philterSrv.URL), azureTarget: u, azureClient: http.DefaultClient}

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/deployments/gpt4o/chat/completions?api-version=2024-06-01", strings.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "[DONE]") {
		t.Errorf("streamed body not passed through: %q", w.Body.String())
	}
}

// TestAzure_EmbeddingsInputRedacted verifies the Azure embeddings path redacts
// its `input` (cross-provider embeddings redaction, #153).
func TestAzure_EmbeddingsInputRedacted(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterSrv.Close()

	var cap azureCapture
	p, azureSrv := newAzureProxy(t, philterSrv.URL, &cap, nil)
	defer azureSrv.Close()

	body := `{"model":"text-embedding-3-small","input":"my SSN is 123-45-6789"}`
	req := httptest.NewRequest("POST", "/openai/deployments/embed/embeddings?api-version=2024-06-01", strings.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("embeddings request should route to Azure (200), got %d", w.Code)
	}
	if strings.Contains(cap.body, "123-45-6789") {
		t.Errorf("Azure embeddings input must be redacted, got: %s", cap.body)
	}
}

func TestAzure_TokenProviderCaches(t *testing.T) {
	calls := 0
	tp := &azureTokenProvider{cred: fakeCred{onGet: func() { calls++ }}, scope: azureCognitiveScope}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		tok, err := tp.token(ctx)
		if err != nil || tok != "tok" {
			t.Fatalf("unexpected token result: %q %v", tok, err)
		}
	}
	if calls != 1 {
		t.Errorf("expected the credential to be called once (cached), got %d", calls)
	}
}
