package main

// Tests for the Redis-backed cache and usage store. These run in the
// default `go test ./...` build by standing up an in-process miniredis
// instance: no `realredis` build tag, no external Redis required.
//
// The `_realredis_test.go` files remain for verifying genuine Redis
// semantics that miniredis only approximates (TIME resolution, EVALSHA
// caching, etc.), but the basic CRUD / TTL / scan behavior that backs
// the cache and usage store can be exercised here.

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// newTestMiniRedis starts a fresh in-process redis and returns it plus a
// cleanup hook bound to t.
func newTestMiniRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(func() { mr.Close() })
	return mr
}

// --- redisCache --------------------------------------------------------

func newTestRedisCache(t *testing.T, ttl time.Duration) (*redisCache, *miniredis.Miniredis) {
	t.Helper()
	mr := newTestMiniRedis(t)
	c, err := newResponseCache(CacheConfig{
		TTLSeconds: int(ttl / time.Second),
		Backend: StateBackendConfig{
			Type:  "redis",
			Redis: RedisBackendConfig{Address: mr.Addr(), KeyPrefix: "test:cache:"},
		},
	})
	if err != nil {
		t.Fatalf("newResponseCache: %v", err)
	}
	rc, ok := c.(*redisCache)
	if !ok {
		t.Fatalf("expected *redisCache, got %T", c)
	}
	t.Cleanup(func() { rc.Close() })
	return rc, mr
}

func TestRedisCache_SetGet_Roundtrip(t *testing.T) {
	rc, _ := newTestRedisCache(t, time.Hour)
	ctx := context.Background()

	want := &CachedResponse{
		Status:      200,
		ContentType: "application/json",
		Body:        []byte(`{"hello":"world"}`),
	}
	rc.Set(ctx, "k1", want)

	got, ok := rc.Get(ctx, "k1")
	if !ok {
		t.Fatal("Set then Get returned miss")
	}
	if got.Status != want.Status || got.ContentType != want.ContentType || string(got.Body) != string(want.Body) {
		t.Errorf("roundtrip mismatch: got %+v", got)
	}
}

func TestRedisCache_Miss(t *testing.T) {
	rc, _ := newTestRedisCache(t, time.Hour)
	if _, ok := rc.Get(context.Background(), "never-set"); ok {
		t.Error("Get of unknown key must miss")
	}
}

func TestRedisCache_KeyPrefixApplied(t *testing.T) {
	rc, mr := newTestRedisCache(t, time.Hour)
	rc.Set(context.Background(), "abc", &CachedResponse{Status: 200, Body: []byte("x")})

	keys := mr.Keys()
	if len(keys) == 0 {
		t.Fatal("no keys stored in redis")
	}
	for _, k := range keys {
		if !startsWith(k, "test:cache:") {
			t.Errorf("redis key %q is missing the configured prefix", k)
		}
	}
}

func TestRedisCache_TTLExpires(t *testing.T) {
	// 1s TTL; miniredis lets us fast-forward time.
	rc, mr := newTestRedisCache(t, time.Second)
	ctx := context.Background()
	rc.Set(ctx, "ephemeral", &CachedResponse{Status: 200, Body: []byte("x")})

	if _, ok := rc.Get(ctx, "ephemeral"); !ok {
		t.Fatal("entry should be present immediately after Set")
	}
	// Advance miniredis past the TTL.
	mr.FastForward(2 * time.Second)
	if _, ok := rc.Get(ctx, "ephemeral"); ok {
		t.Error("entry should have expired after TTL")
	}
}

func TestRedisCache_GarbageDataReturnsMiss(t *testing.T) {
	// A value that doesn't decode as JSON must produce a clean miss rather
	// than crashing. Simulates a corrupted cache entry or version-skew
	// across replicas writing incompatible encodings.
	rc, mr := newTestRedisCache(t, time.Hour)
	mr.Set("test:cache:bad", "this is not json")

	if _, ok := rc.Get(context.Background(), "bad"); ok {
		t.Error("invalid JSON should produce a miss, not crash")
	}
}

func TestRedisCache_SetFailureSilent(t *testing.T) {
	// The cache contract is best-effort: a Redis outage during Set must
	// not error or panic. Close the server before Set to simulate it
	// going away mid-request.
	rc, mr := newTestRedisCache(t, time.Hour)
	mr.Close()

	rc.Set(context.Background(), "k", &CachedResponse{Status: 200, Body: []byte("x")})
	// No panic, no t.Error -- just confirming the call returns.
}

func TestRedisCache_Close(t *testing.T) {
	rc, _ := newTestRedisCache(t, time.Hour)
	if err := rc.Close(); err != nil {
		t.Errorf("Close returned %v", err)
	}
}

// --- newResponseCache Redis-path coverage ----------------------------

func TestNewResponseCache_RedisPath(t *testing.T) {
	mr := newTestMiniRedis(t)
	c, err := newResponseCache(CacheConfig{
		TTLSeconds: 60,
		Backend: StateBackendConfig{
			Type:  "redis",
			Redis: RedisBackendConfig{Address: mr.Addr()},
		},
	})
	if err != nil {
		t.Fatalf("newResponseCache redis: %v", err)
	}
	if _, ok := c.(*redisCache); !ok {
		t.Errorf("expected redisCache, got %T", c)
	}
	c.Close()
}

// --- small helpers used by tests ---------------------------------------

func startsWith(s, prefix string) bool { return len(s) >= len(prefix) && s[:len(prefix)] == prefix }
