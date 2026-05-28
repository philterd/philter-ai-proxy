package main

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type clientEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// ProxyRateLimiter enforces per-client and optional global request rate limits
// using token bucket algorithm. It is safe for concurrent use.
type ProxyRateLimiter struct {
	mu           sync.Mutex
	clients      map[string]*clientEntry
	defaultLimit rate.Limit
	defaultBurst int
	perKeyLimit  map[string]rate.Limit // API key value → override limit
	perKeyBurst  map[string]int
	global       *rate.Limiter // nil when no global limit is configured
}

func newProxyRateLimiter(cfg RateLimitConfig, apiKeys []APIKeyEntry) *ProxyRateLimiter {
	rl := &ProxyRateLimiter{
		clients:      make(map[string]*clientEntry),
		defaultLimit: rate.Limit(cfg.RequestsPerSecond),
		defaultBurst: cfg.Burst,
		perKeyLimit:  make(map[string]rate.Limit),
		perKeyBurst:  make(map[string]int),
	}

	if cfg.Global.RequestsPerSecond > 0 && cfg.Global.Burst > 0 {
		rl.global = rate.NewLimiter(rate.Limit(cfg.Global.RequestsPerSecond), cfg.Global.Burst)
	}

	// Per-key buckets are keyed by the stable opaque ID (`key-N`) assigned
	// to the entry at the same index in the keyStore. Keying by the raw API
	// key would defeat hashing-at-rest, and bcrypt-prefixed values couldn't
	// be looked up anyway.
	for i, entry := range apiKeys {
		if entry.RateLimit != nil {
			id := keyIDForIndex(i)
			rl.perKeyLimit[id] = rate.Limit(entry.RateLimit.RequestsPerSecond)
			rl.perKeyBurst[id] = entry.RateLimit.Burst
		}
	}

	go rl.cleanupLoop()
	return rl
}

// Allow checks whether clientID may proceed. Returns (true, 0) when allowed,
// or (false, retryAfter) when the rate limit is exceeded.
func (rl *ProxyRateLimiter) Allow(clientID string) (bool, time.Duration) {
	// Global backstop checked first — fastest rejection path.
	if rl.global != nil {
		r := rl.global.Reserve()
		if delay := r.Delay(); delay > 0 {
			r.Cancel()
			return false, delay
		}
	}

	limiter := rl.getLimiter(clientID)
	r := limiter.Reserve()
	if delay := r.Delay(); delay > 0 {
		r.Cancel()
		return false, delay
	}
	return true, 0
}

func (rl *ProxyRateLimiter) getLimiter(clientID string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.clients[clientID]
	if !ok {
		limit := rl.defaultLimit
		burst := rl.defaultBurst
		if l, found := rl.perKeyLimit[clientID]; found {
			limit = l
			burst = rl.perKeyBurst[clientID]
		}
		entry = &clientEntry{limiter: rate.NewLimiter(limit, burst)}
		rl.clients[clientID] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

// cleanupLoop removes per-client limiters that have been idle for 10 minutes,
// preventing unbounded map growth from rotating IPs or keys.
func (rl *ProxyRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for id, entry := range rl.clients {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.clients, id)
			}
		}
		rl.mu.Unlock()
	}
}
