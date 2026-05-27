package main

import (
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

type ListenConfig struct {
	Port            int    `yaml:"port"`
	Cert            string `yaml:"cert"`
	Key             string `yaml:"key"`
	ShutdownTimeout int    `yaml:"shutdownTimeout"`
	ClientCA        string `yaml:"clientCA"`
}

type APIKeyEntry struct {
	Key    string `yaml:"key"`
	Policy string `yaml:"policy"`
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
}

type ProviderConfig struct {
	Target    string `yaml:"target"`
	TLSVerify *bool  `yaml:"tlsVerify"`
}

type BedrockConfig struct {
	Region    string `yaml:"region"`
	RoleArn   string `yaml:"roleArn"`
	TLSVerify *bool  `yaml:"tlsVerify"`
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

	if cfg.Metrics.Enabled && (cfg.Metrics.Port < 1 || cfg.Metrics.Port > 65535) {
		return fmt.Errorf("config: metrics.port %d is out of range (1-65535)", cfg.Metrics.Port)
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
	for i, entry := range cfg.Auth.APIKeys {
		if entry.Key == "" {
			return fmt.Errorf("config: auth.apiKeys[%d].key must not be empty", i)
		}
		if seen[entry.Key] {
			return fmt.Errorf("config: auth.apiKeys contains duplicate key at index %d", i)
		}
		seen[entry.Key] = true
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
