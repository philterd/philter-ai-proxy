package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---------- enforceScopes unit tests ----------

func TestEnforceScopes_NilScopesAllowsAnything(t *testing.T) {
	if d := enforceScopes(nil, "openai", "gpt-4", "/v1/chat/completions"); d != nil {
		t.Errorf("nil scopes must allow; got %+v", d)
	}
}

func TestEnforceScopes_EmptyDimensionAllowsAnything(t *testing.T) {
	s := &APIKeyScopes{} // all dimensions empty
	if d := enforceScopes(s, "anthropic", "claude-3", "/v1/messages"); d != nil {
		t.Errorf("empty scopes must allow; got %+v", d)
	}
}

func TestEnforceScopes_ProviderAllowList(t *testing.T) {
	s := &APIKeyScopes{Providers: []string{"openai"}}
	if d := enforceScopes(s, "openai", "gpt-4", "/v1/chat/completions"); d != nil {
		t.Errorf("expected allow, got %+v", d)
	}
	d := enforceScopes(s, "anthropic", "claude-3", "/v1/messages")
	if d == nil {
		t.Fatal("expected denial for disallowed provider")
	}
	if d.Code != "scope_denied_provider" || d.Field != "provider" || d.Value != "anthropic" {
		t.Errorf("denial = %+v", d)
	}
}

func TestEnforceScopes_ModelAllowList(t *testing.T) {
	s := &APIKeyScopes{Models: []string{"gpt-4", "gpt-3.5-turbo"}}
	if d := enforceScopes(s, "openai", "gpt-4", "/v1/chat/completions"); d != nil {
		t.Errorf("exact match should allow; got %+v", d)
	}
	d := enforceScopes(s, "openai", "gpt-4-turbo", "/v1/chat/completions")
	if d == nil || d.Code != "scope_denied_model" {
		t.Errorf("expected scope_denied_model, got %+v", d)
	}
}

func TestEnforceScopes_ModelGlobMatch(t *testing.T) {
	s := &APIKeyScopes{Models: []string{"gpt-4*"}}
	for _, m := range []string{"gpt-4", "gpt-4-turbo", "gpt-4o"} {
		if d := enforceScopes(s, "openai", m, "/v1/chat/completions"); d != nil {
			t.Errorf("%q should match gpt-4*; got %+v", m, d)
		}
	}
	if d := enforceScopes(s, "openai", "gpt-3.5-turbo", "/v1/chat/completions"); d == nil {
		t.Error("gpt-3.5-turbo should NOT match gpt-4*")
	}
}

func TestEnforceScopes_PathPrefixMatch(t *testing.T) {
	s := &APIKeyScopes{Paths: []string{"/v1/chat/"}}
	if d := enforceScopes(s, "openai", "gpt-4", "/v1/chat/completions"); d != nil {
		t.Errorf("prefix should allow; got %+v", d)
	}
	d := enforceScopes(s, "openai", "gpt-4", "/v1/embeddings")
	if d == nil || d.Code != "scope_denied_path" {
		t.Errorf("expected scope_denied_path, got %+v", d)
	}
}

func TestEnforceScopes_DimensionsAreANDed(t *testing.T) {
	s := &APIKeyScopes{
		Providers: []string{"openai"},
		Models:    []string{"gpt-4*"},
		Paths:     []string{"/v1/chat/"},
	}
	// Provider OK, model OK, path OK -> allow.
	if d := enforceScopes(s, "openai", "gpt-4o", "/v1/chat/completions"); d != nil {
		t.Errorf("all dimensions match -> allow; got %+v", d)
	}
	// Provider OK, model OK, but path wrong -> deny.
	if d := enforceScopes(s, "openai", "gpt-4o", "/v1/embeddings"); d == nil || d.Code != "scope_denied_path" {
		t.Errorf("expected path denial, got %+v", d)
	}
}

func TestEnforceScopes_ModelRequiredWhenAllowListSet(t *testing.T) {
	// A model allow-list combined with a request that has no model field
	// (extractModel returns "") must deny -- otherwise an empty model would
	// silently slip past the gate.
	s := &APIKeyScopes{Models: []string{"gpt-4"}}
	d := enforceScopes(s, "openai", "", "/v1/chat/completions")
	if d == nil || d.Code != "scope_denied_model" {
		t.Errorf("expected scope_denied_model for empty model, got %+v", d)
	}
}

// ---------- resolveProviderName ----------

func TestResolveProviderName(t *testing.T) {
	cases := []struct {
		path   string
		compat string
		want   string
	}{
		{"/v1/chat/completions", "", "openai"},
		{"/v1/messages", "", "anthropic"},
		{"/v1/models/x:generateContent", "", "gemini"},
		{"/v1/models/x:streamGenerateContent", "", "gemini"},
		{"/api/chat", "", "ollama"},
		{"/api/generate", "", "ollama"},
		{"/openai/deployments/foo/chat/completions", "", "azure"},
		{"/model/anthropic.claude-3/converse", "", "bedrock"},
		{"/v1/chat/completions", "mistral", "mistral"}, // compat wins
	}
	for _, tc := range cases {
		if got := resolveProviderName(tc.path, tc.compat); got != tc.want {
			t.Errorf("path=%q compat=%q -> %q, want %q", tc.path, tc.compat, got, tc.want)
		}
	}
}

// ---------- End-to-end: scope enforcement on the request path ----------

func scopesProxy(t *testing.T, entry APIKeyEntry) (*Proxy, *bytes.Buffer) {
	t.Helper()
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	t.Cleanup(philterSrv.Close)
	providerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(providerSrv.Close)
	u, _ := url.Parse(providerSrv.URL)

	ks, err := newKeyStore([]APIKeyEntry{entry})
	if err != nil {
		t.Fatalf("newKeyStore: %v", err)
	}
	var auditBuf bytes.Buffer
	cfg := testConfig(philterSrv.URL)
	cfg.Auth.APIKeys = []APIKeyEntry{entry}
	p := &Proxy{
		config:       cfg,
		philter:      testPhilterClient(philterSrv.URL),
		openaiTarget: u,
		openaiClient: http.DefaultClient,
		keyStore:     ks,
		auditLogger:  slog.New(slog.NewJSONHandler(&auditBuf, nil)),
	}
	return p, &auditBuf
}

func TestScopes_BackwardsCompat_NoScopesFullAccess(t *testing.T) {
	p, _ := scopesProxy(t, APIKeyEntry{Key: "alpha"}) // no scopes
	w := sendRequest(p, "/v1/chat/completions", openAIBody(),
		map[string]string{"x-philter-proxy-key": "alpha"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (no scopes = full access), got %d: %s", w.Code, w.Body.String())
	}
}

func TestScopes_ProviderDenied_403(t *testing.T) {
	p, auditBuf := scopesProxy(t, APIKeyEntry{
		Key: "alpha",
		Scopes: &APIKeyScopes{
			Providers: []string{"anthropic"}, // openai is not allowed
		},
	})
	w := sendRequest(p, "/v1/chat/completions", openAIBody(),
		map[string]string{"x-philter-proxy-key": "alpha"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "forbidden") || !strings.Contains(body, "scope_denied_provider") {
		t.Errorf("expected structured 403 with scope_denied_provider; got %q", body)
	}
	// Audit entry must carry the key ID and the error code.
	auditOut := auditBuf.String()
	if !strings.Contains(auditOut, `"key_id":"key-0"`) {
		t.Errorf("audit entry must include key_id; got: %s", auditOut)
	}
	if !strings.Contains(auditOut, `"error_code":"scope_denied_provider"`) {
		t.Errorf("audit entry must include error_code; got: %s", auditOut)
	}
}

func TestScopes_ProviderAllowed_200(t *testing.T) {
	p, _ := scopesProxy(t, APIKeyEntry{
		Key: "alpha",
		Scopes: &APIKeyScopes{
			Providers: []string{"openai"},
		},
	})
	w := sendRequest(p, "/v1/chat/completions", openAIBody(),
		map[string]string{"x-philter-proxy-key": "alpha"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScopes_ModelDenied_403(t *testing.T) {
	p, _ := scopesProxy(t, APIKeyEntry{
		Key: "alpha",
		Scopes: &APIKeyScopes{
			Models: []string{"gpt-3.5-turbo"}, // openAIBody uses gpt-4
		},
	})
	w := sendRequest(p, "/v1/chat/completions", openAIBody(),
		map[string]string{"x-philter-proxy-key": "alpha"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "scope_denied_model") {
		t.Errorf("expected scope_denied_model; got %q", w.Body.String())
	}
}

func TestScopes_PathDenied_403(t *testing.T) {
	p, _ := scopesProxy(t, APIKeyEntry{
		Key: "alpha",
		Scopes: &APIKeyScopes{
			Paths: []string{"/v1/chat/"}, // only chat allowed
		},
	})
	w := sendRequest(p, "/v1/embeddings",
		`{"model":"text-embedding-3-small","input":"hello"}`,
		map[string]string{"x-philter-proxy-key": "alpha"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "scope_denied_path") {
		t.Errorf("expected scope_denied_path; got %q", w.Body.String())
	}
}

func TestScopes_MultiDimensionAllAllowed_200(t *testing.T) {
	p, _ := scopesProxy(t, APIKeyEntry{
		Key: "alpha",
		Scopes: &APIKeyScopes{
			Providers: []string{"openai"},
			Models:    []string{"gpt-4*"},
			Paths:     []string{"/v1/chat/"},
		},
	})
	w := sendRequest(p, "/v1/chat/completions", openAIBody(),
		map[string]string{"x-philter-proxy-key": "alpha"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with all dimensions matching, got %d: %s", w.Code, w.Body.String())
	}
}

// --- modelForScopeCheck ----------------------------------------------------

func TestModelForScopeCheck_VertexFromPath(t *testing.T) {
	got := modelForScopeCheck("vertex",
		"/v1/projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent",
		[]byte(`{"contents":[{"parts":[{"text":"hi"}]}]}`))
	if got != "gemini-1.5-pro" {
		t.Errorf("vertex model from URL: got %q, want gemini-1.5-pro", got)
	}
}

func TestModelForScopeCheck_BedrockFromPath(t *testing.T) {
	got := modelForScopeCheck("bedrock",
		"/model/anthropic.claude-3-sonnet/converse",
		[]byte(`{"messages":[]}`))
	if got != "anthropic.claude-3-sonnet" {
		t.Errorf("bedrock model from URL: got %q, want anthropic.claude-3-sonnet", got)
	}
}

func TestModelForScopeCheck_OpenAIFromBody(t *testing.T) {
	got := modelForScopeCheck("openai",
		"/v1/chat/completions",
		[]byte(`{"model":"gpt-4","messages":[]}`))
	if got != "gpt-4" {
		t.Errorf("openai model from body: got %q, want gpt-4", got)
	}
}

// --- End-to-end: model scope enforcement for URL-model providers ----------

func TestScopes_VertexModelAllowedViaURL(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()
	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`))
	}))
	defer vertexSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Providers.Vertex = VertexConfig{Project: "p", Location: "us-central1"}
	entry := APIKeyEntry{
		Key: "alpha",
		Scopes: &APIKeyScopes{
			Models: []string{"gemini-1.5-pro"}, // only gemini-1.5-pro allowed
		},
	}
	cfg.Auth.APIKeys = []APIKeyEntry{entry}
	ks, _ := newKeyStore([]APIKeyEntry{entry})
	u, _ := url.Parse(vertexSrv.URL)
	p := &Proxy{
		config:            cfg,
		philter:           testPhilterClient(philterSrv.URL),
		vertexTarget:      u,
		vertexClient:      http.DefaultClient,
		vertexTokenSource: staticTokenSource{value: "tok"},
		keyStore:          ks,
	}

	// Allowed model -> 200 (proves URL-extracted model satisfies the scope).
	w := sendRequest(p,
		"/v1/projects/p/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent",
		`{"contents":[{"parts":[{"text":"hi"}]}]}`,
		map[string]string{"x-philter-proxy-key": "alpha"})
	if w.Code != http.StatusOK {
		t.Fatalf("URL model matches scope -> expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScopes_VertexModelDeniedViaURL(t *testing.T) {
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()
	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be called when scope denies the request")
	}))
	defer vertexSrv.Close()

	cfg := testConfig(philterSrv.URL)
	cfg.Providers.Vertex = VertexConfig{Project: "p", Location: "us-central1"}
	entry := APIKeyEntry{
		Key: "alpha",
		Scopes: &APIKeyScopes{
			Models: []string{"gemini-1.5-pro"}, // only 1.5-pro
		},
	}
	cfg.Auth.APIKeys = []APIKeyEntry{entry}
	ks, _ := newKeyStore([]APIKeyEntry{entry})
	u, _ := url.Parse(vertexSrv.URL)
	p := &Proxy{
		config:            cfg,
		philter:           testPhilterClient(philterSrv.URL),
		vertexTarget:      u,
		vertexClient:      http.DefaultClient,
		vertexTokenSource: staticTokenSource{value: "tok"},
		keyStore:          ks,
	}

	// gemini-1.0-flash is NOT in the allow-list -> 403 scope_denied_model.
	w := sendRequest(p,
		"/v1/projects/p/locations/us-central1/publishers/google/models/gemini-1.0-flash:generateContent",
		`{"contents":[{"parts":[{"text":"hi"}]}]}`,
		map[string]string{"x-philter-proxy-key": "alpha"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "scope_denied_model") {
		t.Errorf("expected scope_denied_model; got %s", w.Body.String())
	}
}

func TestScopes_BedrockModelDeniedViaURL(t *testing.T) {
	// The Bedrock "allow" case requires standing up SigV4 credentials and a
	// fake AWS endpoint, which is more than this targeted test needs. The
	// "deny" case 403s before any of that, so we drive it end-to-end via
	// ServeHTTP; the "allow" case is covered by the direct
	// modelForScopeCheck + enforceScopes assertion below.
	philterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(explainJSON("hi", "doc-id", nil))
	}))
	defer philterSrv.Close()

	cfg := testConfig(philterSrv.URL)
	entry := APIKeyEntry{
		Key: "alpha",
		Scopes: &APIKeyScopes{
			Models: []string{"anthropic.claude-3*"}, // glob: all claude-3 variants
		},
	}
	cfg.Auth.APIKeys = []APIKeyEntry{entry}
	ks, _ := newKeyStore([]APIKeyEntry{entry})
	p := &Proxy{
		config:        cfg,
		philter:       testPhilterClient(philterSrv.URL),
		keyStore:      ks,
		bedrockRegion: "us-east-1", // any non-empty value to pass the disabled check
	}

	// Disallowed model -> 403 (the scope check denies before the handler).
	w := sendRequest(p,
		"/model/amazon.titan-text-express/converse",
		`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`,
		map[string]string{"x-philter-proxy-key": "alpha"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unallowed bedrock model, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "scope_denied_model") {
		t.Errorf("expected scope_denied_model; got %s", w.Body.String())
	}

	// Direct assertion: an allowed model from the URL satisfies the scope.
	scope := &APIKeyScopes{Models: []string{"anthropic.claude-3*"}}
	if d := enforceScopes(scope, "bedrock",
		modelForScopeCheck("bedrock", "/model/anthropic.claude-3-sonnet/converse", nil),
		"/model/anthropic.claude-3-sonnet/converse"); d != nil {
		t.Errorf("URL-extracted bedrock model should match the glob; got denial %+v", d)
	}
}

func TestScopes_InvalidEmptyEntryRejectedAtValidation(t *testing.T) {
	for _, scopes := range []*APIKeyScopes{
		{Providers: []string{""}},
		{Models: []string{""}},
		{Paths: []string{""}},
	} {
		cfg := defaultConfig()
		cfg.Auth.APIKeys = []APIKeyEntry{{Key: "alpha", Scopes: scopes}}
		if err := validateConfig(cfg); err == nil {
			t.Errorf("expected validation error for empty scope entry: %+v", scopes)
		}
	}
}
