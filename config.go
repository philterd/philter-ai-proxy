package main

import (
	"fmt"
	"net/url"
	"os"
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
}

type RateLimitBucket struct {
	RequestsPerSecond float64 `yaml:"requestsPerSecond"`
	Burst             int     `yaml:"burst"`
}

type RateLimitConfig struct {
	Enabled           bool                   `yaml:"enabled"`
	RequestsPerSecond float64                `yaml:"requestsPerSecond"`
	Burst             int                    `yaml:"burst"`
	Global            RateLimitBucket        `yaml:"global"`
	Backend           RateLimitBackendConfig `yaml:"backend"`
}

// RateLimitBackendConfig selects where token-bucket state lives. The default
// (empty / "memory") keeps per-replica state in process memory. Selecting
// "redis" shares state across replicas so N replicas behind a load balancer
// enforce one consistent global limit instead of N times the configured limit.
type RateLimitBackendConfig struct {
	// Type is "memory" (default) or "redis".
	Type string `yaml:"type"`
	// FailureMode governs behavior when the configured backend is unreachable:
	// "open" (default) degrades to the local in-memory limiter so traffic keeps
	// flowing (bounded per-replica); "closed" rejects requests while the backend
	// is down. Only meaningful for the redis backend.
	FailureMode string             `yaml:"failureMode"`
	Redis       RedisBackendConfig `yaml:"redis"`
}

type RedisBackendConfig struct {
	// Address is the Redis endpoint, host:port. Required when type is "redis".
	Address string `yaml:"address"`
	// Username/Password authenticate to Redis (Redis 6+ ACL or legacy
	// requirepass). Password accepts ${ENV_VAR} / file: secret references.
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// DB is the Redis logical database number (default 0).
	DB int `yaml:"db"`
	// KeyPrefix namespaces the proxy's keys (default "philter:rl:").
	KeyPrefix string `yaml:"keyPrefix"`
	// TimeoutMs bounds each Redis round-trip. On timeout the FailureMode
	// applies. Default 100.
	TimeoutMs int            `yaml:"timeoutMs"`
	TLS       RedisTLSConfig `yaml:"tls"`
}

type RedisTLSConfig struct {
	Enabled            bool   `yaml:"enabled"`
	CACert             string `yaml:"caCert"`
	Cert               string `yaml:"cert"`
	Key                string `yaml:"key"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
}

type APIKeyEntry struct {
	Key           string           `yaml:"key"`
	Policy        string           `yaml:"policy"`
	RateLimit     *RateLimitBucket `yaml:"rateLimit"`
	MaxConcurrent int              `yaml:"maxConcurrent"` // 0 = unlimited (default)
	Quota         *QuotaLimits     `yaml:"quota"`         // per-key token quota override
	Scopes        *APIKeyScopes    `yaml:"scopes"`        // per-key allow-lists (providers/models/paths); nil/empty = full access
	AdminRole     string           `yaml:"adminRole"`     // "" (none) or "usage-read" (may call GET /admin/usage)
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

// Recognized values for APIKeyEntry.AdminRole. Kept as constants so callers
// stay consistent and typo-safe.
const (
	AdminRoleNone      = ""
	AdminRoleUsageRead = "usage-read"
)

// QuotaLimits caps token consumption per rolling calendar window. 0 means
// unlimited for that window. Quotas are distinct from rate limits: rate limits
// bound request frequency, quotas bound cumulative token usage (for billing /
// cost control).
type QuotaLimits struct {
	DailyTokens   int64 `yaml:"dailyTokens"`   // prompt+completion tokens per UTC calendar day
	MonthlyTokens int64 `yaml:"monthlyTokens"` // prompt+completion tokens per UTC calendar month
}

// StateBackendConfig selects where per-key usage counters or cached responses
// live. The default (empty / "memory") keeps state in process memory; "redis"
// shares it across replicas.
type StateBackendConfig struct {
	Type  string             `yaml:"type"`  // "memory" (default) or "redis"
	Redis RedisBackendConfig `yaml:"redis"` // used when Type is "redis"
}

// QuotaConfig enables per-key daily/monthly token quotas. Off by default.
type QuotaConfig struct {
	Enabled bool               `yaml:"enabled"`
	Default QuotaLimits        `yaml:"default"` // applied to keys without their own quota
	Backend StateBackendConfig `yaml:"backend"`
}

// CacheConfig enables an optional response cache keyed on
// (key, model, sha256(request body)). Off by default.
type CacheConfig struct {
	Enabled      bool               `yaml:"enabled"`
	TTLSeconds   int                `yaml:"ttlSeconds"`   // entry lifetime; default 300
	MaxEntries   int                `yaml:"maxEntries"`   // in-memory cap; default 1024
	MaxBodyBytes int                `yaml:"maxBodyBytes"` // skip caching larger responses; default 1048576
	Backend      StateBackendConfig `yaml:"backend"`
}

// AdminConfig enables the GET /admin/usage export endpoint. Off by default.
type AdminConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`  // required when enabled; accepts ${ENV_VAR} / file: references
	Header  string `yaml:"header"` // header carrying the admin token; default x-philter-admin-token
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
	OpenAICompatible map[string]ProviderConfig `yaml:"openaiCompatible"`
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
	Listen    ListenConfig    `yaml:"listen"`
	Logging   LoggingConfig   `yaml:"logging"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Tracing   TracingConfig   `yaml:"tracing"`
	Philter   PhilterConfig   `yaml:"philter"`
	Providers ProvidersConfig `yaml:"providers"`
	Routes    []RouteConfig   `yaml:"routes"`
	Defaults  DefaultsConfig  `yaml:"defaults"`
	Auth      AuthConfig      `yaml:"auth"`
	RateLimit RateLimitConfig `yaml:"rateLimit"`
	Quota     QuotaConfig     `yaml:"quota"`
	Cache     CacheConfig     `yaml:"cache"`
	Admin     AdminConfig     `yaml:"admin"`
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

func validateConfig(cfg *Config) error {
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

	if cfg.RateLimit.Enabled {
		if cfg.RateLimit.RequestsPerSecond <= 0 {
			return fmt.Errorf("config: rateLimit.requestsPerSecond must be > 0 when rate limiting is enabled")
		}
		if cfg.RateLimit.Burst < 1 {
			return fmt.Errorf("config: rateLimit.burst must be >= 1 when rate limiting is enabled")
		}
		if cfg.RateLimit.Global.RequestsPerSecond < 0 {
			return fmt.Errorf("config: rateLimit.global.requestsPerSecond must be >= 0")
		}
		if cfg.RateLimit.Global.Burst < 0 {
			return fmt.Errorf("config: rateLimit.global.burst must be >= 0")
		}

		validBackends := map[string]bool{"": true, "memory": true, "redis": true}
		if !validBackends[cfg.RateLimit.Backend.Type] {
			return fmt.Errorf("config: rateLimit.backend.type %q is invalid (must be memory or redis)", cfg.RateLimit.Backend.Type)
		}
		validFailureModes := map[string]bool{"": true, "open": true, "closed": true}
		if !validFailureModes[cfg.RateLimit.Backend.FailureMode] {
			return fmt.Errorf("config: rateLimit.backend.failureMode %q is invalid (must be open or closed)", cfg.RateLimit.Backend.FailureMode)
		}
		if cfg.RateLimit.Backend.Type == "redis" {
			r := cfg.RateLimit.Backend.Redis
			if r.Address == "" {
				return fmt.Errorf("config: rateLimit.backend.redis.address is required when backend type is redis")
			}
			if r.DB < 0 {
				return fmt.Errorf("config: rateLimit.backend.redis.db must be >= 0")
			}
			if r.TimeoutMs < 0 {
				return fmt.Errorf("config: rateLimit.backend.redis.timeoutMs must be >= 0")
			}
		}
	}

	seen := map[string]bool{}
	for i, entry := range cfg.Auth.APIKeys {
		if entry.Key == "" {
			return fmt.Errorf("config: auth.apiKeys[%d].key must not be empty", i)
		}
		if seen[entry.Key] {
			return fmt.Errorf("config: auth.apiKeys contains duplicate key at index %d", i)
		}
		seen[entry.Key] = true
		if entry.RateLimit != nil {
			if entry.RateLimit.RequestsPerSecond <= 0 {
				return fmt.Errorf("config: auth.apiKeys[%d].rateLimit.requestsPerSecond must be > 0", i)
			}
			if entry.RateLimit.Burst < 1 {
				return fmt.Errorf("config: auth.apiKeys[%d].rateLimit.burst must be >= 1", i)
			}
		}
		if entry.MaxConcurrent < 0 {
			return fmt.Errorf("config: auth.apiKeys[%d].maxConcurrent must be >= 0", i)
		}
		if entry.Quota != nil {
			if entry.Quota.DailyTokens < 0 {
				return fmt.Errorf("config: auth.apiKeys[%d].quota.dailyTokens must be >= 0", i)
			}
			if entry.Quota.MonthlyTokens < 0 {
				return fmt.Errorf("config: auth.apiKeys[%d].quota.monthlyTokens must be >= 0", i)
			}
		}
		switch entry.AdminRole {
		case AdminRoleNone, AdminRoleUsageRead:
		default:
			return fmt.Errorf("config: auth.apiKeys[%d].adminRole %q is invalid (must be empty or %q)", i, entry.AdminRole, AdminRoleUsageRead)
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

	// validateStateBackend checks a memory/redis backend selector shared by the
	// quota and cache subsystems.
	validateStateBackend := func(name string, b StateBackendConfig) error {
		validTypes := map[string]bool{"": true, "memory": true, "redis": true}
		if !validTypes[b.Type] {
			return fmt.Errorf("config: %s.type %q is invalid (must be memory or redis)", name, b.Type)
		}
		if b.Type == "redis" {
			if b.Redis.Address == "" {
				return fmt.Errorf("config: %s.redis.address is required when type is redis", name)
			}
			if b.Redis.DB < 0 {
				return fmt.Errorf("config: %s.redis.db must be >= 0", name)
			}
			if b.Redis.TimeoutMs < 0 {
				return fmt.Errorf("config: %s.redis.timeoutMs must be >= 0", name)
			}
		}
		return nil
	}

	if cfg.Quota.Enabled {
		if cfg.Quota.Default.DailyTokens < 0 {
			return fmt.Errorf("config: quota.default.dailyTokens must be >= 0")
		}
		if cfg.Quota.Default.MonthlyTokens < 0 {
			return fmt.Errorf("config: quota.default.monthlyTokens must be >= 0")
		}
	}
	// quota.backend also stores usage for the /admin/usage export, so validate
	// it whenever either subsystem is enabled.
	if cfg.Quota.Enabled || cfg.Admin.Enabled {
		if err := validateStateBackend("quota.backend", cfg.Quota.Backend); err != nil {
			return err
		}
	}

	if cfg.Cache.Enabled {
		if cfg.Cache.TTLSeconds < 0 {
			return fmt.Errorf("config: cache.ttlSeconds must be >= 0")
		}
		if cfg.Cache.MaxEntries < 0 {
			return fmt.Errorf("config: cache.maxEntries must be >= 0")
		}
		if cfg.Cache.MaxBodyBytes < 0 {
			return fmt.Errorf("config: cache.maxBodyBytes must be >= 0")
		}
		if err := validateStateBackend("cache.backend", cfg.Cache.Backend); err != nil {
			return err
		}
	}

	if cfg.Admin.Enabled && cfg.Admin.Token == "" {
		return fmt.Errorf("config: admin.token is required when admin endpoint is enabled")
	}

	// Reserved path prefixes used by built-in providers.
	reservedNames := map[string]bool{"v1": true, "api": true, "model": true, "health": true}
	for name, pc := range cfg.Providers.OpenAICompatible {
		if name == "" {
			return fmt.Errorf("config: providers.openaiCompatible has an entry with an empty name")
		}
		if reservedNames[name] {
			return fmt.Errorf("config: providers.openaiCompatible name %q conflicts with a built-in route prefix", name)
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
