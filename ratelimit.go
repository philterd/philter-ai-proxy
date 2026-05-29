package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimitBackend is the pluggable store for token-bucket state. The default
// memoryBackend keeps state per-replica in process memory; redisBackend shares
// it across replicas so a multi-replica deployment enforces one consistent
// limit instead of (replicas × limit).
//
// Allow consumes one token for `key` under a token bucket of `limit`
// tokens/second with capacity `burst`. It returns whether the request is
// allowed and, when denied, how long until a token is available. A non-nil
// error means the backend itself was unreachable (the decision is unknown);
// callers apply their configured failure mode.
type rateLimitBackend interface {
	Allow(ctx context.Context, key string, limit rate.Limit, burst int) (allowed bool, retryAfter time.Duration, err error)
	Name() string
	Close() error
}

const globalBucketKey = "__global__"

type clientEntry struct {
	limiter  *rate.Limiter
	limit    rate.Limit
	burst    int
	lastSeen time.Time
}

// memoryBackend is the in-process token-bucket store. It is the default backend
// and also serves as the fail-open fallback when a remote backend is
// unreachable. It is safe for concurrent use and never returns an error.
type memoryBackend struct {
	mu      sync.Mutex
	clients map[string]*clientEntry
	stop    chan struct{}
}

func newMemoryBackend() *memoryBackend {
	b := &memoryBackend{
		clients: make(map[string]*clientEntry),
		stop:    make(chan struct{}),
	}
	go b.cleanupLoop()
	return b
}

func (b *memoryBackend) Name() string { return "memory" }

func (b *memoryBackend) Allow(_ context.Context, key string, limit rate.Limit, burst int) (bool, time.Duration, error) {
	lim := b.getLimiter(key, limit, burst)
	r := lim.Reserve()
	if delay := r.Delay(); delay > 0 {
		r.Cancel()
		return false, delay, nil
	}
	return true, 0, nil
}

func (b *memoryBackend) getLimiter(key string, limit rate.Limit, burst int) *rate.Limiter {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry, ok := b.clients[key]
	if !ok {
		entry = &clientEntry{limiter: rate.NewLimiter(limit, burst), limit: limit, burst: burst}
		b.clients[key] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

// cleanupLoop removes per-client limiters idle for 10 minutes, preventing
// unbounded map growth from rotating IPs or keys.
func (b *memoryBackend) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			b.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for id, entry := range b.clients {
				if entry.lastSeen.Before(cutoff) {
					delete(b.clients, id)
				}
			}
			b.mu.Unlock()
		}
	}
}

func (b *memoryBackend) Close() error {
	close(b.stop)
	return nil
}

// ProxyRateLimiter enforces per-client and optional global request rate limits.
// It resolves the applicable limit/burst for each client and delegates the
// token-bucket decision to a pluggable backend. It is safe for concurrent use.
type ProxyRateLimiter struct {
	backend     rateLimitBackend
	fallback    *memoryBackend // local fallback used when backend errors (nil for memory backend)
	failureMode string         // "open" or "closed"
	timeout     time.Duration  // per-call backend timeout (0 = no timeout)
	metrics     *ProxyMetrics

	defaultLimit rate.Limit
	defaultBurst int
	perKeyLimit  map[string]rate.Limit // stable key ID → override limit
	perKeyBurst  map[string]int
	globalLimit  rate.Limit
	globalBurst  int
}

// newProxyRateLimiter builds the limiter from config. It returns an error only
// when the configured backend cannot be constructed (e.g. invalid Redis TLS
// material). The memory backend never errors.
func newProxyRateLimiter(cfg RateLimitConfig, apiKeys []APIKeyEntry, metrics *ProxyMetrics) (*ProxyRateLimiter, error) {
	rl := &ProxyRateLimiter{
		failureMode:  cfg.Backend.FailureMode,
		metrics:      metrics,
		defaultLimit: rate.Limit(cfg.RequestsPerSecond),
		defaultBurst: cfg.Burst,
		perKeyLimit:  make(map[string]rate.Limit),
		perKeyBurst:  make(map[string]int),
	}
	if rl.failureMode == "" {
		rl.failureMode = "open"
	}

	if cfg.Global.RequestsPerSecond > 0 && cfg.Global.Burst > 0 {
		rl.globalLimit = rate.Limit(cfg.Global.RequestsPerSecond)
		rl.globalBurst = cfg.Global.Burst
	}

	// Per-key buckets are keyed by the stable opaque ID (`key-N`) assigned to
	// the entry at the same index in the keyStore. Keying by the raw API key
	// would defeat hashing-at-rest, and bcrypt-prefixed values couldn't be
	// looked up anyway.
	for i, entry := range apiKeys {
		if entry.RateLimit != nil {
			id := keyIDFor(entry, i)
			rl.perKeyLimit[id] = rate.Limit(entry.RateLimit.RequestsPerSecond)
			rl.perKeyBurst[id] = entry.RateLimit.Burst
		}
	}

	switch cfg.Backend.Type {
	case "redis":
		rb, err := newRedisBackend(cfg.Backend.Redis)
		if err != nil {
			return nil, err
		}
		rl.backend = rb
		rl.fallback = newMemoryBackend()
		rl.timeout = time.Duration(cfg.Backend.Redis.TimeoutMs) * time.Millisecond
		if rl.timeout == 0 {
			rl.timeout = 100 * time.Millisecond
		}
		slog.Info("Rate-limit backend: redis",
			"address", cfg.Backend.Redis.Address,
			"failureMode", rl.failureMode,
			"tls", cfg.Backend.Redis.TLS.Enabled)
	default: // "" or "memory"
		rl.backend = newMemoryBackend()
	}

	return rl, nil
}

// Allow checks whether clientID may proceed. Returns (true, 0) when allowed, or
// (false, retryAfter) when the rate limit is exceeded.
func (rl *ProxyRateLimiter) Allow(ctx context.Context, clientID string) (bool, time.Duration) {
	// Global backstop first — fastest rejection path and shared across clients.
	if rl.globalBurst > 0 {
		if allowed, retryAfter := rl.decide(ctx, globalBucketKey, rl.globalLimit, rl.globalBurst); !allowed {
			return false, retryAfter
		}
	}

	limit := rl.defaultLimit
	burst := rl.defaultBurst
	if l, found := rl.perKeyLimit[clientID]; found {
		limit = l
		burst = rl.perKeyBurst[clientID]
	}
	return rl.decide(ctx, clientID, limit, burst)
}

// decide runs one backend call with timing/error metrics and applies the
// configured failure mode when the backend is unreachable.
func (rl *ProxyRateLimiter) decide(ctx context.Context, key string, limit rate.Limit, burst int) (bool, time.Duration) {
	callCtx := ctx
	if rl.timeout > 0 {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, rl.timeout)
		defer cancel()
	}

	start := time.Now()
	allowed, retryAfter, err := rl.backend.Allow(callCtx, key, limit, burst)
	elapsed := time.Since(start)

	if err != nil {
		rl.observe(elapsed, false)
		return rl.handleBackendError(ctx, key, limit, burst, err)
	}
	rl.observe(elapsed, true)
	return allowed, retryAfter
}

func (rl *ProxyRateLimiter) handleBackendError(ctx context.Context, key string, limit rate.Limit, burst int, err error) (bool, time.Duration) {
	if rl.metrics != nil {
		rl.metrics.rateLimitBackendErrors.WithLabelValues(rl.backend.Name()).Inc()
	}
	if rl.failureMode == "closed" {
		slog.Warn("Rate-limit backend unreachable; failing closed", "backend", rl.backend.Name(), "error", err)
		// Deny with a short, non-zero retry hint.
		return false, time.Second
	}
	// Fail open: degrade to the local in-memory limiter so traffic keeps
	// flowing, still bounded per-replica.
	slog.Warn("Rate-limit backend unreachable; falling back to local memory", "backend", rl.backend.Name(), "error", err)
	if rl.metrics != nil {
		rl.metrics.rateLimitFallback.Inc()
	}
	if rl.fallback == nil {
		return true, 0
	}
	allowed, retryAfter, _ := rl.fallback.Allow(ctx, key, limit, burst)
	return allowed, retryAfter
}

func (rl *ProxyRateLimiter) observe(elapsed time.Duration, ok bool) {
	if rl.metrics == nil {
		return
	}
	result := "ok"
	if !ok {
		result = "error"
	}
	rl.metrics.rateLimitBackendDuration.WithLabelValues(rl.backend.Name(), result).Observe(elapsed.Seconds())
}

// Close releases backend resources (Redis connections, cleanup goroutines).
func (rl *ProxyRateLimiter) Close() error {
	if rl.fallback != nil {
		rl.fallback.Close()
	}
	if rl.backend != nil {
		return rl.backend.Close()
	}
	return nil
}
