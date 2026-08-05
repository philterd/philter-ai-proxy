package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ListenConfig struct {
	Port                  int    `yaml:"port"`
	Cert                  string `yaml:"cert"`
	Key                   string `yaml:"key"`
	ShutdownTimeout       int    `yaml:"shutdownTimeout"`
	ClientCA              string `yaml:"clientCA"`
	MaxConcurrentRequests int    `yaml:"maxConcurrentRequests"` // 0 = unlimited (default)

	// Inbound request hardening. These bound the size and duration of inbound
	// client requests (distinct from the per-provider timeouts, which bound
	// outbound calls). Secure defaults are applied when a value is 0.
	//
	// MaxRequestBodyBytes caps the inbound request body; a larger body is
	// rejected with HTTP 413. Default: 10 MiB.
	MaxRequestBodyBytes int `yaml:"maxRequestBodyBytes"`
	// MaxHeaderBytes caps the total size of request headers. Default: 1 MiB.
	MaxHeaderBytes int `yaml:"maxHeaderBytes"`
	// ReadHeaderTimeoutMs bounds how long a client may take to send the request
	// headers — the primary slowloris mitigation. Default: 10000 (10s).
	ReadHeaderTimeoutMs int `yaml:"readHeaderTimeoutMs"`
	// ReadTimeoutMs bounds reading the entire request including the body. It
	// only affects request reads (never response streaming). Disabled by
	// default (0) so very large or slow legitimate uploads are not truncated;
	// set it to bound slow-body attacks under the size cap.
	ReadTimeoutMs int `yaml:"readTimeoutMs"`
	// TLSHandshakeTimeoutMs bounds how long a client may take to complete the
	// TLS handshake. ReadHeaderTimeoutMs only begins ticking after the
	// handshake completes, so a client that opens a TLS connection and then
	// dribbles the handshake (or never finishes it) is not bounded by any
	// other timeout. Default: 10000 (10s). 0 means "use the default";
	// negative is rejected at validation.
	TLSHandshakeTimeoutMs int `yaml:"tlsHandshakeTimeoutMs"`
	// MaxConcurrentTLSHandshakes caps the number of in-flight TLS handshakes
	// the listener will process at once. Each accepted TCP connection performs
	// its handshake on its own goroutine bounded by TLSHandshakeTimeoutMs; this
	// ceiling bounds how many such goroutines (and their buffers) can exist
	// simultaneously, so a TCP+ClientHello flood cannot transiently spawn tens
	// of thousands of goroutines each pinned for the full handshake timeout.
	// When the ceiling is reached, new connections are dropped immediately
	// (counted by philter_proxy_tls_handshakes_shed_total). Established
	// connections are unaffected. Default: 16384 (well above any real
	// workload). 0 means "use the default"; negative is rejected at validation.
	MaxConcurrentTLSHandshakes int `yaml:"maxConcurrentTLSHandshakes"`
	// TrustedProxies is a list of CIDR ranges (e.g. ["10.0.0.0/8",
	// "192.168.1.0/24"]) whose connections may legitimately set
	// `X-Forwarded-For`. The proxy reads the header only when the immediate
	// peer (`r.RemoteAddr`) is inside one of these CIDRs; otherwise it uses
	// `r.RemoteAddr` directly. **Default is empty**, which means
	// X-Forwarded-For is NEVER trusted -- the safe behavior when the proxy
	// is exposed directly to the internet. Operators running behind a
	// trusted load balancer (ALB, Nginx, Cloudflare, etc.) must add the
	// load balancer's source CIDR here to keep their audit-log IPs accurate.
	TrustedProxies []string `yaml:"trustedProxies"`
}

type APIKeyEntry struct {
	Key string `yaml:"key"`
	// ID is the stable opaque identifier used in audit logs and the per-key
	// concurrency bucket. **Setting this explicitly is strongly
	// recommended.** When unset, the proxy falls back to the
	// positional `key-N` identifier; reordering or inserting entries in
	// `auth.apiKeys` will then re-shuffle which key owns which identifier,
	// silently misattributing audit history and concurrency budgets.
	// See [Per-key Stable Identifiers](docs/docs/configuration.md#per-key-stable-identifiers).
	ID     string        `yaml:"id"`
	Policy string        `yaml:"policy"`
	Scopes *APIKeyScopes `yaml:"scopes"` // per-key allow-lists (providers/models/paths); nil/empty = full access
}

// APIKeyScopes restricts which providers, models, and request paths an API key
// may access. Empty / unset slices mean "no restriction on this dimension"
// (full access on that axis); a non-empty slice is a deny-by-default
// allow-list. A nil *APIKeyScopes (or zero-valued struct) preserves
// backwards-compatible full access. Each dimension is checked independently:
// a request must match all configured allow-lists (logical AND across
// dimensions, OR within each list).
//
//	Providers: exact match against the provider name the proxy resolves the
//	           request to ("openai", "anthropic", "gemini", "ollama", "azure",
//	           "bedrock", or a configured `openaiCompatible[].name`).
//	Models:    exact match, or trailing `*` glob (e.g. `gpt-4*`).
//	Paths:     prefix match against the request path after any
//	           openai-compatible provider prefix has been stripped.
type APIKeyScopes struct {
	Providers []string `yaml:"providers"`
	Models    []string `yaml:"models"`
	Paths     []string `yaml:"paths"`
}

type AuthConfig struct {
	Header  string        `yaml:"header"`
	APIKeys []APIKeyEntry `yaml:"apiKeys"`
}

type LoggingConfig struct {
	Enabled bool   `yaml:"enabled"`
	File    string `yaml:"file"`
}

type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type TracingConfig struct {
	// Enabled toggles OpenTelemetry SDK initialization. Disabled by default;
	// with the SDK off the proxy pays zero per-request tracing overhead.
	Enabled bool `yaml:"enabled"`
	// ServiceName overrides the OTel `service.name` resource attribute when
	// OTEL_SERVICE_NAME is not set in the environment.
	ServiceName string `yaml:"serviceName"`
}

type RetryConfig struct {
	MaxAttempts      int `yaml:"maxAttempts"`      // total attempts (1 = no retry); default 3
	InitialBackoffMs int `yaml:"initialBackoffMs"` // initial backoff in ms; default 100
	MaxBackoffMs     int `yaml:"maxBackoffMs"`     // maximum backoff in ms; default 2000
}

type CircuitBreakerConfig struct {
	Enabled        bool   `yaml:"enabled"`        // default false
	Threshold      int    `yaml:"threshold"`      // consecutive failures before opening; default 5
	TimeoutSeconds int    `yaml:"timeoutSeconds"` // seconds in open state before probe; default 30
	Fallback       string `yaml:"fallback"`       // "block" (503, default) or "passthrough"
}

type PhilterConfig struct {
	Endpoint       string               `yaml:"endpoint"`
	TLSVerify      *bool                `yaml:"tlsVerify"`
	CACert         string               `yaml:"caCert"`
	Retry          RetryConfig          `yaml:"retry"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuitBreaker"`
	Timeouts       ProviderTimeouts     `yaml:"timeouts"`
}

// ProviderTimeouts bounds the network phases of outbound HTTP calls. They are
// transport-level (not whole-request) timeouts, which matters for streaming:
// once headers are received, the body can stream indefinitely. The proxy
// deliberately does NOT set http.Client.Timeout (which would also kill the
// body stream).
//
// All values are milliseconds. A value of 0 means "use the default".
type ProviderTimeouts struct {
	// ConnectMs bounds the TCP dial phase. Default: 5000.
	ConnectMs int `yaml:"connectMs"`
	// TLSHandshakeMs bounds the TLS handshake. Default: 5000.
	TLSHandshakeMs int `yaml:"tlsHandshakeMs"`
	// ResponseHeaderMs bounds the wait for the upstream to send response
	// headers. This is the timeout that fires for a hung LLM that never
	// starts responding. It does NOT bound body reads, so streaming
	// responses are unaffected. Default: 30000.
	ResponseHeaderMs int `yaml:"responseHeaderMs"`
	// IdleConnMs bounds how long an idle keep-alive connection in the pool
	// stays open before being closed. Default: 90000.
	IdleConnMs int `yaml:"idleConnMs"`
}

// Default timeout values applied at use-site when a config entry's value is 0
// (i.e., not set in YAML). Kept as named constants so they can be referenced
// from tests and docs.
const (
	DefaultConnectTimeoutMs        = 5000
	DefaultTLSHandshakeTimeoutMs   = 5000
	DefaultResponseHeaderTimeoutMs = 30000
	DefaultIdleConnTimeoutMs       = 90000
)

// Inbound request-hardening defaults, applied at use-site when the config value
// is 0.
const (
	DefaultMaxRequestBodyBytes         = 10 << 20 // 10 MiB
	DefaultMaxHeaderBytes              = 1 << 20  // 1 MiB (matches net/http's default)
	DefaultReadHeaderTimeoutMs         = 10000    // 10s slowloris mitigation
	DefaultListenTLSHandshakeTimeoutMs = 10000    // 10s slow-handshake slowloris mitigation
	DefaultMaxConcurrentTLSHandshakes  = 16384    // ceiling on in-flight handshake goroutines
)

// effectiveMaxRequestBodyBytes returns the configured inbound body cap or the
// default when unset.
func (c ListenConfig) effectiveMaxRequestBodyBytes() int64 {
	if c.MaxRequestBodyBytes > 0 {
		return int64(c.MaxRequestBodyBytes)
	}
	return DefaultMaxRequestBodyBytes
}

// effectiveTLSHandshakeTimeout returns the configured TLS handshake timeout or
// the default (10s) when unset.
func (c ListenConfig) effectiveTLSHandshakeTimeout() time.Duration {
	if c.TLSHandshakeTimeoutMs > 0 {
		return time.Duration(c.TLSHandshakeTimeoutMs) * time.Millisecond
	}
	return time.Duration(DefaultListenTLSHandshakeTimeoutMs) * time.Millisecond
}

// effectiveMaxConcurrentTLSHandshakes returns the configured ceiling on
// in-flight TLS handshakes or the default (16384) when unset.
func (c ListenConfig) effectiveMaxConcurrentTLSHandshakes() int {
	if c.MaxConcurrentTLSHandshakes > 0 {
		return c.MaxConcurrentTLSHandshakes
	}
	return DefaultMaxConcurrentTLSHandshakes
}

type ProviderConfig struct {
	Target    string           `yaml:"target"`
	TLSVerify *bool            `yaml:"tlsVerify"`
	Timeouts  ProviderTimeouts `yaml:"timeouts"`
}

type BedrockConfig struct {
	Region    string           `yaml:"region"`
	RoleArn   string           `yaml:"roleArn"`
	TLSVerify *bool            `yaml:"tlsVerify"`
	Timeouts  ProviderTimeouts `yaml:"timeouts"`
}

// AzureConfig configures the first-class Azure OpenAI provider. It is enabled
// by setting `target`. Azure's API surface differs from OpenAI: requests use
// deployment-based paths (`/openai/deployments/{deployment}/...`) with a
// required `api-version` query parameter, and authenticate with either an
// `api-key` header (passed through from the client) or an Azure AD / Entra ID
// bearer token (acquired by the proxy when `entraID` is set).
type AzureConfig struct {
	// Target is the Azure OpenAI resource endpoint, e.g.
	// https://my-resource.openai.azure.com. Required to enable Azure.
	Target string `yaml:"target"`
	// APIVersion, when set, is injected as the `api-version` query parameter
	// for requests that omit it. Azure requires this parameter; setting a
	// default here lets clients that don't send it still work.
	APIVersion string `yaml:"apiVersion"`
	// EntraID enables Azure AD (Entra ID) authentication: the proxy acquires a
	// bearer token via the default Azure credential chain (managed identity,
	// workload identity, environment, etc.) and sets it as the Authorization
	// header. When false (default), the client's `api-key` header is passed
	// through unchanged.
	EntraID   bool             `yaml:"entraID"`
	TLSVerify *bool            `yaml:"tlsVerify"`
	Timeouts  ProviderTimeouts `yaml:"timeouts"`
}

type ProvidersConfig struct {
	OpenAI           ProviderConfig            `yaml:"openai"`
	Anthropic        ProviderConfig            `yaml:"anthropic"`
	Gemini           ProviderConfig            `yaml:"gemini"`
	Ollama           ProviderConfig            `yaml:"ollama"`
	Bedrock          BedrockConfig             `yaml:"bedrock"`
	Azure            AzureConfig               `yaml:"azure"`
	Vertex           VertexConfig              `yaml:"vertex"`
	OpenAICompatible map[string]ProviderConfig `yaml:"openaiCompatible"`
}

// VertexConfig configures the first-class Vertex AI provider (Gemini on
// Google Cloud). Enabled by setting `project` (and typically `location`).
// Vertex's API surface differs from the public Gemini API:
//
//   - Regional endpoint: https://{location}-aiplatform.googleapis.com.
//   - Resource-style paths:
//     /v1/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent
//     and the `:streamGenerateContent` variant.
//   - Authentication via a Google OAuth2 bearer token (Application Default
//     Credentials). No `?key=` query parameter.
//
// Request and response bodies are the same Gemini schema as the public
// provider, so inbound redaction and outbound-scan behavior reuse the
// existing Gemini path verbatim.
type VertexConfig struct {
	// Project is the GCP project ID. Required to enable Vertex.
	Project string `yaml:"project"`
	// Location is the regional endpoint to use (e.g. "us-central1"). Used
	// to build the default target URL when `endpoint` is empty.
	Location string `yaml:"location"`
	// Endpoint overrides the target URL. Leave empty to use the regional
	// default https://{location}-aiplatform.googleapis.com.
	Endpoint  string           `yaml:"endpoint"`
	TLSVerify *bool            `yaml:"tlsVerify"`
	Timeouts  ProviderTimeouts `yaml:"timeouts"`
}

type RouteMatch struct {
	Header string `yaml:"header"`
	Value  string `yaml:"value"`
	Path   string `yaml:"path"`
	Model  string `yaml:"model"`
}

type OutboundConfig struct {
	Enabled bool   `yaml:"enabled"`
	Action  string `yaml:"action"` // "redact" (default), "block", or "flag"
}

type RouteConfig struct {
	Match    RouteMatch     `yaml:"match"`
	Policy   string         `yaml:"policy"`
	Context  string         `yaml:"context"`
	Outbound OutboundConfig `yaml:"outbound"`
}

type DefaultsConfig struct {
	Policy   string         `yaml:"policy"`
	Context  string         `yaml:"context"`
	Outbound OutboundConfig `yaml:"outbound"`
}

type Config struct {
	// Version is the config schema version. It is optional and defaults to the
	// current schema (SupportedConfigVersion) when omitted, so existing configs
	// keep working. A value the running build does not support fails startup
	// with a clear error. See the configuration compatibility policy.
	Version   int             `yaml:"version"`
	Listen    ListenConfig    `yaml:"listen"`
	Logging   LoggingConfig   `yaml:"logging"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Tracing   TracingConfig   `yaml:"tracing"`
	Philter   PhilterConfig   `yaml:"philter"`
	Providers ProvidersConfig `yaml:"providers"`
	Routes    []RouteConfig   `yaml:"routes"`
	Defaults  DefaultsConfig  `yaml:"defaults"`
	Auth      AuthConfig      `yaml:"auth"`
}

func defaultConfig() *Config {
	t := true
	return &Config{
		Listen: ListenConfig{
			Port:            8080,
			Cert:            "cert.pem",
			Key:             "key.pem",
			ShutdownTimeout: 30,
		},
		Logging: LoggingConfig{
			Enabled: true,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    9090,
		},
		Philter: PhilterConfig{
			Endpoint:  "https://localhost:8080",
			TLSVerify: &t,
			Retry: RetryConfig{
				MaxAttempts:      3,
				InitialBackoffMs: 100,
				MaxBackoffMs:     2000,
			},
		},
		Providers: ProvidersConfig{
			OpenAI:    ProviderConfig{Target: "https://api.openai.com"},
			Anthropic: ProviderConfig{Target: "https://api.anthropic.com"},
			Gemini:    ProviderConfig{Target: "https://generativelanguage.googleapis.com"},
			Ollama:    ProviderConfig{Target: "http://localhost:11434"},
		},
		Defaults: DefaultsConfig{
			Policy:  "default",
			Context: "none",
		},
	}
}

func loadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config file is required: use --config <path> or set PHILTER_PROXY_CONFIG")
	}

	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	warnRemovedKeys(data)

	// Expand ${ENV_VAR} / file: secret references before validation so the
	// rest of the pipeline (validation, key hashing) sees the actual values.
	if err := resolveSecrets(cfg); err != nil {
		return nil, err
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// warnRemovedKeys logs a warning for config keys that used to do something and
// no longer do. Parsing is deliberately non-strict, so a stale key is ignored
// rather than rejected; without this an operator upgrading from a build that
// enforced rate limits would silently lose the limit they configured.
func warnRemovedKeys(data []byte) {
	var raw struct {
		RateLimit map[string]any `yaml:"rateLimit"`
		Cache     map[string]any `yaml:"cache"`
		Auth      struct {
			APIKeys []struct {
				ID            string         `yaml:"id"`
				RateLimit     map[string]any `yaml:"rateLimit"`
				MaxConcurrent *int           `yaml:"maxConcurrent"`
			} `yaml:"apiKeys"`
		} `yaml:"auth"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return // the strict decode above already succeeded; nothing to report
	}

	const rateLimitAdvice = "rate limiting was removed from the proxy; enforce it in your AI gateway or ingress instead"
	const cacheAdvice = "the response cache was removed from the proxy; use your AI gateway's cache instead"
	const perKeyConcurrencyAdvice = "per-key concurrency caps were removed; use your AI gateway's per-key parallelism control, or listen.maxConcurrentRequests for a proxy-wide ceiling"
	if raw.RateLimit != nil {
		slog.Warn("Ignoring removed config key `rateLimit`", "advice", rateLimitAdvice)
	}
	if raw.Cache != nil {
		slog.Warn("Ignoring removed config key `cache`", "advice", cacheAdvice)
	}
	for i, k := range raw.Auth.APIKeys {
		id := k.ID
		if id == "" {
			id = keyIDForIndex(i)
		}
		if k.RateLimit != nil {
			slog.Warn("Ignoring removed config key `auth.apiKeys[].rateLimit`", "key", id, "advice", rateLimitAdvice)
		}
		if k.MaxConcurrent != nil {
			slog.Warn("Ignoring removed config key `auth.apiKeys[].maxConcurrent`", "key", id, "advice", perKeyConcurrencyAdvice)
		}
	}
}

// SupportedConfigVersion is the config schema version this build understands.
// A config may omit `version` (treated as the current version) or set it
// explicitly; any other value is rejected at startup. Bump this only on a
// breaking config-shape change, alongside migration guidance in the docs.
const SupportedConfigVersion = 1

func validateConfig(cfg *Config) error {
	if cfg.Version != 0 && cfg.Version != SupportedConfigVersion {
		return fmt.Errorf("config: unsupported config version %d (this build supports version %d) -- see the configuration compatibility policy for migration guidance", cfg.Version, SupportedConfigVersion)
	}

	targets := map[string]string{
		"philter.endpoint":    cfg.Philter.Endpoint,
		"providers.openai":    cfg.Providers.OpenAI.Target,
		"providers.anthropic": cfg.Providers.Anthropic.Target,
		"providers.gemini":    cfg.Providers.Gemini.Target,
		"providers.ollama":    cfg.Providers.Ollama.Target,
	}
	for name, target := range targets {
		if target == "" {
			return fmt.Errorf("config: %s target is required", name)
		}
		if _, err := url.Parse(target); err != nil {
			return fmt.Errorf("config: %s has invalid URL %q: %w", name, target, err)
		}
	}

	if cfg.Listen.Port < 1 || cfg.Listen.Port > 65535 {
		return fmt.Errorf("config: listen.port %d is out of range (1-65535)", cfg.Listen.Port)
	}

	for i, cidr := range cfg.Listen.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("config: listen.trustedProxies[%d] %q is not a valid CIDR: %w", i, cidr, err)
		}
	}

	if cfg.Listen.MaxConcurrentRequests < 0 {
		return fmt.Errorf("config: listen.maxConcurrentRequests must be >= 0")
	}
	for _, f := range []struct {
		name  string
		value int
	}{
		{"maxRequestBodyBytes", cfg.Listen.MaxRequestBodyBytes},
		{"maxHeaderBytes", cfg.Listen.MaxHeaderBytes},
		{"readHeaderTimeoutMs", cfg.Listen.ReadHeaderTimeoutMs},
		{"readTimeoutMs", cfg.Listen.ReadTimeoutMs},
		{"tlsHandshakeTimeoutMs", cfg.Listen.TLSHandshakeTimeoutMs},
		{"maxConcurrentTLSHandshakes", cfg.Listen.MaxConcurrentTLSHandshakes},
	} {
		if f.value < 0 {
			return fmt.Errorf("config: listen.%s must be >= 0", f.name)
		}
	}

	if cfg.Metrics.Enabled && (cfg.Metrics.Port < 1 || cfg.Metrics.Port > 65535) {
		return fmt.Errorf("config: metrics.port %d is out of range (1-65535)", cfg.Metrics.Port)
	}

	timeoutFields := func(provider string, t ProviderTimeouts) error {
		fields := []struct {
			name  string
			value int
		}{
			{"connectMs", t.ConnectMs},
			{"tlsHandshakeMs", t.TLSHandshakeMs},
			{"responseHeaderMs", t.ResponseHeaderMs},
			{"idleConnMs", t.IdleConnMs},
		}
		for _, f := range fields {
			if f.value < 0 {
				return fmt.Errorf("config: %s.timeouts.%s must be >= 0", provider, f.name)
			}
		}
		return nil
	}
	if err := timeoutFields("philter", cfg.Philter.Timeouts); err != nil {
		return err
	}
	for _, p := range []struct {
		name string
		t    ProviderTimeouts
	}{
		{"providers.openai", cfg.Providers.OpenAI.Timeouts},
		{"providers.anthropic", cfg.Providers.Anthropic.Timeouts},
		{"providers.gemini", cfg.Providers.Gemini.Timeouts},
		{"providers.ollama", cfg.Providers.Ollama.Timeouts},
		{"providers.bedrock", cfg.Providers.Bedrock.Timeouts},
		{"providers.azure", cfg.Providers.Azure.Timeouts},
		{"providers.vertex", cfg.Providers.Vertex.Timeouts},
	} {
		if err := timeoutFields(p.name, p.t); err != nil {
			return err
		}
	}

	// Azure is optional (enabled by setting a target); validate the URL when set.
	if cfg.Providers.Azure.Target != "" {
		if _, err := url.Parse(cfg.Providers.Azure.Target); err != nil {
			return fmt.Errorf("config: providers.azure has invalid URL %q: %w", cfg.Providers.Azure.Target, err)
		}
	}

	// Vertex is optional (enabled by setting `project`). When enabled, a
	// location is required so we can build the regional endpoint URL, unless
	// an explicit endpoint override is supplied.
	if cfg.Providers.Vertex.Project != "" {
		if cfg.Providers.Vertex.Location == "" && cfg.Providers.Vertex.Endpoint == "" {
			return fmt.Errorf("config: providers.vertex.location is required when providers.vertex.project is set (or set providers.vertex.endpoint explicitly)")
		}
		if cfg.Providers.Vertex.Endpoint != "" {
			if _, err := url.Parse(cfg.Providers.Vertex.Endpoint); err != nil {
				return fmt.Errorf("config: providers.vertex.endpoint has invalid URL %q: %w", cfg.Providers.Vertex.Endpoint, err)
			}
		}
	}
	for name, pc := range cfg.Providers.OpenAICompatible {
		if err := timeoutFields("providers.openaiCompatible."+name, pc.Timeouts); err != nil {
			return err
		}
	}

	if cfg.Philter.Retry.MaxAttempts < 0 {
		return fmt.Errorf("config: philter.retry.maxAttempts must be >= 0")
	}
	if cfg.Philter.Retry.InitialBackoffMs < 0 {
		return fmt.Errorf("config: philter.retry.initialBackoffMs must be >= 0")
	}
	if cfg.Philter.Retry.MaxBackoffMs < 0 {
		return fmt.Errorf("config: philter.retry.maxBackoffMs must be >= 0")
	}

	validFallbacks := map[string]bool{"block": true, "passthrough": true, "": true}
	if !validFallbacks[cfg.Philter.CircuitBreaker.Fallback] {
		return fmt.Errorf("config: philter.circuitBreaker.fallback %q is invalid (must be block or passthrough)", cfg.Philter.CircuitBreaker.Fallback)
	}

	validOutboundActions := map[string]bool{"redact": true, "block": true, "flag": true, "": true}

	for i, route := range cfg.Routes {
		if route.Match.Header == "" && route.Match.Path == "" && route.Match.Model == "" {
			return fmt.Errorf("config: route[%d] must have at least one match criterion (header, path, or model)", i)
		}
		if route.Match.Header != "" && route.Match.Value == "" {
			return fmt.Errorf("config: route[%d] specifies header %q but no value", i, route.Match.Header)
		}
		if route.Policy == "" {
			return fmt.Errorf("config: route[%d] must specify a policy", i)
		}
		if !validOutboundActions[route.Outbound.Action] {
			return fmt.Errorf("config: route[%d].outbound.action %q is invalid (must be redact, block, or flag)", i, route.Outbound.Action)
		}
	}

	if !validOutboundActions[cfg.Defaults.Outbound.Action] {
		return fmt.Errorf("config: defaults.outbound.action %q is invalid (must be redact, block, or flag)", cfg.Defaults.Outbound.Action)
	}

	seen := map[string]bool{}
	seenIDs := map[string]int{}
	for i, entry := range cfg.Auth.APIKeys {
		if entry.Key == "" {
			return fmt.Errorf("config: auth.apiKeys[%d].key must not be empty", i)
		}
		if seen[entry.Key] {
			return fmt.Errorf("config: auth.apiKeys contains duplicate key at index %d", i)
		}
		seen[entry.Key] = true
		if entry.ID != "" {
			// Explicit IDs must be unique across the list and must not
			// collide with the legacy `key-N` positional identifier scheme
			// (otherwise an explicit `id: key-3` could shadow position 3's
			// historical state).
			if prev, ok := seenIDs[entry.ID]; ok {
				return fmt.Errorf("config: auth.apiKeys[%d].id %q duplicates auth.apiKeys[%d]", i, entry.ID, prev)
			}
			if strings.HasPrefix(entry.ID, "key-") {
				return fmt.Errorf("config: auth.apiKeys[%d].id %q must not start with the reserved prefix %q", i, entry.ID, "key-")
			}
			seenIDs[entry.ID] = i
		}
		if entry.Scopes != nil {
			for j, p := range entry.Scopes.Paths {
				if p == "" {
					return fmt.Errorf("config: auth.apiKeys[%d].scopes.paths[%d] must not be empty", i, j)
				}
			}
			for j, m := range entry.Scopes.Models {
				if m == "" {
					return fmt.Errorf("config: auth.apiKeys[%d].scopes.models[%d] must not be empty", i, j)
				}
			}
			for j, prov := range entry.Scopes.Providers {
				if prov == "" {
					return fmt.Errorf("config: auth.apiKeys[%d].scopes.providers[%d] must not be empty", i, j)
				}
			}
		}
	}

	// A compat name becomes a URL path prefix (/{name}/...) and the provider
	// label in audit logs and per-key scopes, so it may not collide with a
	// built-in route prefix or provider identifier, nor contain a path
	// separator (which would make the prefix ambiguous / unroutable).
	reservedNames := map[string]bool{
		"v1": true, "api": true, "model": true, "health": true,
		"openai": true, "anthropic": true, "gemini": true,
		"ollama": true, "bedrock": true, "azure": true, "vertex": true,
	}
	for name, pc := range cfg.Providers.OpenAICompatible {
		if name == "" {
			return fmt.Errorf("config: providers.openaiCompatible has an entry with an empty name")
		}
		if strings.ContainsAny(name, "/\\") {
			return fmt.Errorf("config: providers.openaiCompatible name %q must not contain a path separator", name)
		}
		if reservedNames[name] {
			return fmt.Errorf("config: providers.openaiCompatible name %q is reserved (it collides with a built-in provider or route prefix)", name)
		}
		if pc.Target == "" {
			return fmt.Errorf("config: providers.openaiCompatible[%s].target is required", name)
		}
		if _, err := url.Parse(pc.Target); err != nil {
			return fmt.Errorf("config: providers.openaiCompatible[%s] has invalid URL %q: %w", name, pc.Target, err)
		}
	}

	return nil
}

type resolvedRoute struct {
	Policy   string
	Context  string
	Outbound OutboundConfig
}

func matchRoute(cfg *Config, path string, model string, headerGetter func(string) string) resolvedRoute {
	for _, route := range cfg.Routes {
		if route.Match.Header != "" {
			if headerGetter(route.Match.Header) != route.Match.Value {
				continue
			}
		}
		if route.Match.Path != "" {
			if path != route.Match.Path {
				continue
			}
		}
		if route.Match.Model != "" {
			if model != route.Match.Model {
				continue
			}
		}
		ctx := route.Context
		if ctx == "" {
			ctx = cfg.Defaults.Context
		}
		return resolvedRoute{Policy: route.Policy, Context: ctx, Outbound: route.Outbound}
	}
	return resolvedRoute{Policy: cfg.Defaults.Policy, Context: cfg.Defaults.Context, Outbound: cfg.Defaults.Outbound}
}
