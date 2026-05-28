package main

import (
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

type ListenConfig struct {
	Port                  int    `yaml:"port"`
	Cert                  string `yaml:"cert"`
	Key                   string `yaml:"key"`
	ShutdownTimeout       int    `yaml:"shutdownTimeout"`
	ClientCA              string `yaml:"clientCA"`
	MaxConcurrentRequests int    `yaml:"maxConcurrentRequests"` // 0 = unlimited (default)
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

type ProvidersConfig struct {
	OpenAI           ProviderConfig            `yaml:"openai"`
	Anthropic        ProviderConfig            `yaml:"anthropic"`
	Gemini           ProviderConfig            `yaml:"gemini"`
	Ollama           ProviderConfig            `yaml:"ollama"`
	Bedrock          BedrockConfig             `yaml:"bedrock"`
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
	} {
		if err := timeoutFields(p.name, p.t); err != nil {
			return err
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
