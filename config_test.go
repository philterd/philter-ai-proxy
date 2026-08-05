package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Listen.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", cfg.Listen.Port)
	}
	if cfg.Philter.Endpoint != "https://localhost:8080" {
		t.Errorf("Expected default philter endpoint, got %s", cfg.Philter.Endpoint)
	}
	if cfg.Defaults.Policy != "default" {
		t.Errorf("Expected default policy, got %s", cfg.Defaults.Policy)
	}
	if cfg.Defaults.Context != "none" {
		t.Errorf("Expected default context 'none', got %s", cfg.Defaults.Context)
	}
	if cfg.Providers.OpenAI.Target != "https://api.openai.com" {
		t.Errorf("Expected default OpenAI target, got %s", cfg.Providers.OpenAI.Target)
	}
}

func TestLoadConfig_RequiresFile(t *testing.T) {
	_, err := loadConfig("")
	if err == nil {
		t.Error("Expected error when no config file provided")
	}
}

func TestLoadConfig_YAMLFile(t *testing.T) {
	tmp, _ := os.CreateTemp("", "config-*.yaml")
	tmp.WriteString(`
listen:
  port: 9090
  cert: custom-cert.pem
  key: custom-key.pem
philter:
  endpoint: https://philter.internal:8080
providers:
  openai:
    target: https://custom-openai.example.com
  ollama:
    target: http://ollama.internal:11434
routes:
  - match:
      header: x-philter-policy
      value: hipaa
    policy: hipaa-safe-harbor
    context: healthcare
  - match:
      path: /v1/chat/completions
      model: gpt-4
    policy: general-purpose
defaults:
  policy: my-default
  context: my-context
`)
	tmp.Close()
	defer os.Remove(tmp.Name())

	cfg, err := loadConfig(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Listen.Port != 9090 {
		t.Errorf("Expected port 9090, got %d", cfg.Listen.Port)
	}
	if cfg.Listen.Cert != "custom-cert.pem" {
		t.Errorf("Expected custom-cert.pem, got %s", cfg.Listen.Cert)
	}
	if cfg.Philter.Endpoint != "https://philter.internal:8080" {
		t.Errorf("Expected custom philter endpoint, got %s", cfg.Philter.Endpoint)
	}
	if cfg.Providers.OpenAI.Target != "https://custom-openai.example.com" {
		t.Errorf("Expected custom OpenAI target, got %s", cfg.Providers.OpenAI.Target)
	}
	if cfg.Providers.Ollama.Target != "http://ollama.internal:11434" {
		t.Errorf("Expected custom Ollama target, got %s", cfg.Providers.Ollama.Target)
	}
	if cfg.Providers.Anthropic.Target != "https://api.anthropic.com" {
		t.Errorf("Expected default Anthropic target (not overridden), got %s", cfg.Providers.Anthropic.Target)
	}
	if cfg.Defaults.Policy != "my-default" {
		t.Errorf("Expected my-default policy, got %s", cfg.Defaults.Policy)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("Expected 2 routes, got %d", len(cfg.Routes))
	}
	if cfg.Routes[0].Policy != "hipaa-safe-harbor" {
		t.Errorf("Expected hipaa-safe-harbor, got %s", cfg.Routes[0].Policy)
	}
	if cfg.Routes[1].Match.Model != "gpt-4" {
		t.Errorf("Expected model gpt-4, got %s", cfg.Routes[1].Match.Model)
	}
}

func TestLoadConfig_InvalidFile(t *testing.T) {
	_, err := loadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent config file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmp, _ := os.CreateTemp("", "config-*.yaml")
	tmp.WriteString("invalid: yaml: content: [broken")
	tmp.Close()
	defer os.Remove(tmp.Name())

	_, err := loadConfig(tmp.Name())
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestValidateConfig_InvalidPort(t *testing.T) {
	cfg := defaultConfig()
	cfg.Listen.Port = 0
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected validation error for port 0")
	}
}

func TestValidateConfig_Version(t *testing.T) {
	// Omitted version (0) is accepted -- existing configs keep working.
	cfg := defaultConfig()
	cfg.Version = 0
	if err := validateConfig(cfg); err != nil {
		t.Errorf("omitted version should be accepted, got: %v", err)
	}
	// The current supported version is accepted.
	cfg = defaultConfig()
	cfg.Version = SupportedConfigVersion
	if err := validateConfig(cfg); err != nil {
		t.Errorf("supported version %d should be accepted, got: %v", SupportedConfigVersion, err)
	}
	// An unsupported version fails with an error that names both versions.
	cfg = defaultConfig()
	cfg.Version = SupportedConfigVersion + 1
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected validation error for an unsupported config version")
	}
	if !strings.Contains(err.Error(), "unsupported config version") {
		t.Errorf("error should name the problem, got: %v", err)
	}
}

func TestValidateConfig_EmptyTarget(t *testing.T) {
	cfg := defaultConfig()
	cfg.Providers.OpenAI.Target = ""
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected validation error for empty target")
	}
}

func TestValidateConfig_RouteNoMatch(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{{Policy: "test"}}
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected validation error for route with no match criteria")
	}
}

func TestValidateConfig_RouteHeaderNoValue(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{{Match: RouteMatch{Header: "x-policy"}, Policy: "test"}}
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected validation error for header match with no value")
	}
}

func TestValidateConfig_RouteNoPolicy(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{{Match: RouteMatch{Path: "/v1/chat"}}}
	if err := validateConfig(cfg); err == nil {
		t.Error("Expected validation error for route with no policy")
	}
}

func TestMatchRoute_HeaderMatch(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{
		{Match: RouteMatch{Header: "x-philter-policy", Value: "hipaa"}, Policy: "hipaa-policy", Context: "healthcare"},
	}

	result := matchRoute(cfg, "/v1/chat/completions", "gpt-4", func(key string) string {
		if key == "x-philter-policy" {
			return "hipaa"
		}
		return ""
	})

	if result.Policy != "hipaa-policy" {
		t.Errorf("Expected hipaa-policy, got %s", result.Policy)
	}
	if result.Context != "healthcare" {
		t.Errorf("Expected healthcare context, got %s", result.Context)
	}
}

func TestMatchRoute_PathMatch(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{
		{Match: RouteMatch{Path: "/v1/messages"}, Policy: "anthropic-policy"},
	}

	result := matchRoute(cfg, "/v1/messages", "claude-3", func(string) string { return "" })

	if result.Policy != "anthropic-policy" {
		t.Errorf("Expected anthropic-policy, got %s", result.Policy)
	}
	if result.Context != "none" {
		t.Errorf("Expected default context 'none', got %s", result.Context)
	}
}

func TestMatchRoute_ModelMatch(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{
		{Match: RouteMatch{Model: "gpt-4"}, Policy: "gpt4-policy", Context: "analytics"},
	}

	result := matchRoute(cfg, "/v1/chat/completions", "gpt-4", func(string) string { return "" })

	if result.Policy != "gpt4-policy" {
		t.Errorf("Expected gpt4-policy, got %s", result.Policy)
	}
}

func TestMatchRoute_CombinedMatch(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{
		{Match: RouteMatch{Path: "/v1/chat/completions", Model: "gpt-4"}, Policy: "specific-policy"},
	}

	result := matchRoute(cfg, "/v1/chat/completions", "gpt-4", func(string) string { return "" })
	if result.Policy != "specific-policy" {
		t.Errorf("Expected specific-policy, got %s", result.Policy)
	}

	result = matchRoute(cfg, "/v1/chat/completions", "gpt-3.5", func(string) string { return "" })
	if result.Policy != "default" {
		t.Errorf("Expected default (model mismatch), got %s", result.Policy)
	}
}

func TestMatchRoute_NoMatch_FallsToDefaults(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{
		{Match: RouteMatch{Header: "x-policy", Value: "special"}, Policy: "special-policy"},
	}

	result := matchRoute(cfg, "/v1/chat/completions", "gpt-4", func(string) string { return "" })

	if result.Policy != "default" {
		t.Errorf("Expected default policy, got %s", result.Policy)
	}
}

func TestMatchRoute_FirstMatchWins(t *testing.T) {
	cfg := defaultConfig()
	cfg.Routes = []RouteConfig{
		{Match: RouteMatch{Path: "/v1/chat/completions"}, Policy: "first-policy"},
		{Match: RouteMatch{Path: "/v1/chat/completions"}, Policy: "second-policy"},
	}

	result := matchRoute(cfg, "/v1/chat/completions", "", func(string) string { return "" })

	if result.Policy != "first-policy" {
		t.Errorf("Expected first-policy (first match wins), got %s", result.Policy)
	}
}

func TestRouteMatching_EndToEnd(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("p") != "hipaa-safe-harbor" {
			t.Errorf("Expected policy 'hipaa-safe-harbor', got '%s'", q.Get("p"))
		}
		if q.Get("c") != "healthcare" {
			t.Errorf("Expected context 'healthcare', got '%s'", q.Get("c"))
		}
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	cfg := testConfig(philterServer.URL)
	cfg.Routes = []RouteConfig{
		{Match: RouteMatch{Header: "x-philter-policy", Value: "hipaa"}, Policy: "hipaa-safe-harbor", Context: "healthcare"},
	}

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       cfg,
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(cfg.Philter.Endpoint),
	}

	reqBody := `{"model": "gpt-4", "messages": [{"role": "user", "content": "patient data"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("x-philter-policy", "hipaa")
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestRouteMatching_ModelMatch_EndToEnd(t *testing.T) {
	philterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("p") != "gpt4-policy" {
			t.Errorf("Expected policy 'gpt4-policy', got '%s'", q.Get("p"))
		}
		w.Write(explainJSON("REDACTED", "doc-id", nil))
	}))
	defer philterServer.Close()

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer openaiServer.Close()

	cfg := testConfig(philterServer.URL)
	cfg.Routes = []RouteConfig{
		{Match: RouteMatch{Model: "gpt-4"}, Policy: "gpt4-policy"},
	}

	openaiURL, _ := url.Parse(openaiServer.URL)
	proxy := &Proxy{
		config:       cfg,
		openaiTarget: openaiURL,
		openaiClient: http.DefaultClient,
		philter:      testPhilterClient(cfg.Philter.Endpoint),
	}

	reqBody := `{"model": "gpt-4", "messages": [{"role": "user", "content": "data"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}
