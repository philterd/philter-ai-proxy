package main

import (
	"context"
	"testing"
	"time"
)

func TestCacheKeyFor_Distinct(t *testing.T) {
	body := []byte(`{"prompt":"hello"}`)
	base := cacheKeyFor("key-0", "gpt-4", body)

	if cacheKeyFor("key-1", "gpt-4", body) == base {
		t.Error("different tenant keys must produce different cache keys")
	}
	if cacheKeyFor("key-0", "gpt-3.5", body) == base {
		t.Error("different models must produce different cache keys")
	}
	if cacheKeyFor("key-0", "gpt-4", []byte(`{"prompt":"world"}`)) == base {
		t.Error("different bodies must produce different cache keys")
	}
	if cacheKeyFor("key-0", "gpt-4", body) != base {
		t.Error("identical inputs must produce the same key")
	}
}

func newTestMemCache(max int, ttl time.Duration, now func() time.Time) *memCache {
	return &memCache{m: make(map[string]memCacheEntry), ttl: ttl, max: max, nowFn: now}
}

func TestMemCache_SetGet(t *testing.T) {
	c := newTestMemCache(10, time.Minute, time.Now)
	ctx := context.Background()
	resp := &CachedResponse{Status: 200, ContentType: "application/json", Body: []byte(`{"ok":true}`)}

	if _, ok := c.Get(ctx, "k"); ok {
		t.Error("expected miss before set")
	}
	c.Set(ctx, "k", resp)
	got, ok := c.Get(ctx, "k")
	if !ok {
		t.Fatal("expected hit after set")
	}
	if got.Status != 200 || string(got.Body) != `{"ok":true}` {
		t.Errorf("unexpected cached value: %+v", got)
	}
}

func TestMemCache_Expiry(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := now
	c := newTestMemCache(10, 30*time.Second, func() time.Time { return clock })
	ctx := context.Background()

	c.Set(ctx, "k", &CachedResponse{Status: 200, Body: []byte("x")})
	clock = now.Add(29 * time.Second)
	if _, ok := c.Get(ctx, "k"); !ok {
		t.Error("entry should still be live before TTL")
	}
	clock = now.Add(31 * time.Second)
	if _, ok := c.Get(ctx, "k"); ok {
		t.Error("entry should be expired after TTL")
	}
}

func TestMemCache_EvictionAtCapacity(t *testing.T) {
	c := newTestMemCache(2, time.Minute, time.Now)
	ctx := context.Background()
	c.Set(ctx, "a", &CachedResponse{Status: 200, Body: []byte("a")})
	c.Set(ctx, "b", &CachedResponse{Status: 200, Body: []byte("b")})
	c.Set(ctx, "c", &CachedResponse{Status: 200, Body: []byte("c")}) // evicts "a" (FIFO)

	if _, ok := c.Get(ctx, "a"); ok {
		t.Error("oldest entry 'a' should have been evicted")
	}
	if _, ok := c.Get(ctx, "c"); !ok {
		t.Error("newest entry 'c' should be present")
	}
	if len(c.m) != 2 {
		t.Errorf("cache should stay at capacity 2, got %d", len(c.m))
	}
}
