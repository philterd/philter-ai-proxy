package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// CachedResponse is a stored upstream response replayed verbatim on a cache
// hit. Only successful, non-streaming responses are cached.
type CachedResponse struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

// ResponseCache stores client-facing responses keyed on
// (key, model, sha256(request body)). Implementations are safe for concurrent
// use. A nil ResponseCache means caching is disabled.
type ResponseCache interface {
	Get(ctx context.Context, key string) (*CachedResponse, bool)
	Set(ctx context.Context, key string, resp *CachedResponse)
	Close() error
}

// cacheKeyFor derives the cache key from the tenant key ID, the model, and a
// SHA-256 of the request body (the prompt). Distinct keys/models/prompts never
// collide, and a tenant can never read another tenant's cached responses.
func cacheKeyFor(keyID, model string, body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%s|%s|%x", keyID, model, sum)
}

// newResponseCache builds the configured cache (memory by default).
func newResponseCache(cfg CacheConfig) (ResponseCache, error) {
	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl == 0 {
		ttl = 300 * time.Second
	}
	if cfg.Backend.Type == "redis" {
		client, err := newRedisClient(cfg.Backend.Redis)
		if err != nil {
			return nil, err
		}
		prefix := cfg.Backend.Redis.KeyPrefix
		if prefix == "" {
			prefix = "philter:cache:"
		}
		return &redisCache{client: client, prefix: prefix, ttl: ttl}, nil
	}
	max := cfg.MaxEntries
	if max == 0 {
		max = 1024
	}
	return &memCache{
		m:     make(map[string]memCacheEntry),
		ttl:   ttl,
		max:   max,
		nowFn: time.Now,
	}, nil
}

// --- in-memory ---

type memCacheEntry struct {
	resp    *CachedResponse
	expires time.Time
}

type memCache struct {
	mu    sync.Mutex
	m     map[string]memCacheEntry
	order []string // insertion order, for FIFO eviction at capacity
	ttl   time.Duration
	max   int
	nowFn func() time.Time // overridable in tests
}

func (c *memCache) Get(_ context.Context, key string) (*CachedResponse, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return nil, false
	}
	if c.nowFn().After(e.expires) {
		delete(c.m, key)
		return nil, false
	}
	return e.resp, true
}

func (c *memCache) Set(_ context.Context, key string, resp *CachedResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.m[key]; !exists {
		if len(c.m) >= c.max {
			c.evictOneLocked()
		}
		c.order = append(c.order, key)
	}
	c.m[key] = memCacheEntry{resp: resp, expires: c.nowFn().Add(c.ttl)}
}

// evictOneLocked removes the oldest still-present entry. Caller holds c.mu.
func (c *memCache) evictOneLocked() {
	for len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		if _, ok := c.m[oldest]; ok {
			delete(c.m, oldest)
			return
		}
	}
}

func (c *memCache) Close() error { return nil }

// --- redis ---

type redisCache struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

func (c *redisCache) Get(ctx context.Context, key string) (*CachedResponse, bool) {
	data, err := c.client.Get(ctx, c.prefix+key).Bytes()
	if err != nil {
		return nil, false // redis.Nil (miss) or a transport error → treat as miss
	}
	var resp CachedResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, false
	}
	return &resp, true
}

func (c *redisCache) Set(ctx context.Context, key string, resp *CachedResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	// Best-effort: a cache write failure must never fail the request.
	_ = c.client.Set(ctx, c.prefix+key, data, c.ttl).Err()
}

func (c *redisCache) Close() error { return c.client.Close() }
