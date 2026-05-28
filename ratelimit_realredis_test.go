//go:build realredis

// These tests run the Redis rate-limit backend against a *real* Redis server,
// verifying the atomic token-bucket Lua script under genuine Redis semantics
// (TIME resolution, HSET float formatting, EVALSHA caching) — things miniredis
// only approximates. They are excluded from the default build via the
// `realredis` build tag, so `go test ./...` stays self-contained; CI runs them
// with `-tags realredis` against a Redis service container.
//
// Point them at a server with REDIS_ADDR (default localhost:6379). Keys are
// namespaced per test with a nanosecond suffix so repeated runs against a
// persistent server don't collide.

package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func realRedisAddr() string {
	if a := os.Getenv("REDIS_ADDR"); a != "" {
		return a
	}
	return "localhost:6379"
}

// newRealRedisBackend dials the real server and fails fast (not skips) if it is
// unreachable — when these tests are selected, a server is expected to exist.
func newRealRedisBackend(t *testing.T, prefix string) *redisBackend {
	t.Helper()
	b, err := newRedisBackend(RedisBackendConfig{
		Address:   realRedisAddr(),
		KeyPrefix: prefix,
		TimeoutMs: 1000,
	})
	if err != nil {
		t.Fatalf("newRedisBackend: %v", err)
	}
	if err := b.client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("cannot reach real redis at %s: %v", realRedisAddr(), err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

// uniqueKey returns a key unlikely to collide with prior runs on a persistent
// server.
func uniqueKey(name string) string {
	return fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
}

func TestRealRedis_BurstThenBlocks(t *testing.T) {
	b := newRealRedisBackend(t, "philter-it:")
	ctx := context.Background()
	key := uniqueKey("burst")

	for i := 0; i < 3; i++ {
		allowed, _, err := b.Allow(ctx, key, 0.001, 3)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("request %d within burst should be allowed", i)
		}
	}
	allowed, retry, err := b.Allow(ctx, key, 0.001, 3)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("request beyond burst should be blocked")
	}
	if retry <= 0 {
		t.Errorf("expected positive retryAfter, got %v", retry)
	}
}

func TestRealRedis_RefillsOverTime(t *testing.T) {
	b := newRealRedisBackend(t, "philter-it:")
	ctx := context.Background()
	key := uniqueKey("refill")

	// rate=20/s, burst=1: consume the token, then wait long enough for the
	// real server clock to refill at least one token.
	if allowed, _, _ := b.Allow(ctx, key, 20, 1); !allowed {
		t.Fatal("first request should pass")
	}
	if allowed, _, _ := b.Allow(ctx, key, 20, 1); allowed {
		t.Fatal("second request should be blocked before refill")
	}
	time.Sleep(150 * time.Millisecond) // 20/s ⇒ ~3 tokens accrue
	if allowed, _, _ := b.Allow(ctx, key, 20, 1); !allowed {
		t.Fatal("request after refill window should pass")
	}
}

func TestRealRedis_SharedStateAcrossClients(t *testing.T) {
	// Two independent backends pointing at the same server model two replicas;
	// they must share one bucket.
	b1 := newRealRedisBackend(t, "philter-it:")
	b2 := newRealRedisBackend(t, "philter-it:")
	ctx := context.Background()
	key := uniqueKey("shared")

	if allowed, _, _ := b1.Allow(ctx, key, 0.001, 2); !allowed {
		t.Fatal("replica1 first request should pass")
	}
	if allowed, _, _ := b2.Allow(ctx, key, 0.001, 2); !allowed {
		t.Fatal("replica2 first request should pass")
	}
	if allowed, _, _ := b1.Allow(ctx, key, 0.001, 2); allowed {
		t.Fatal("shared bucket should be exhausted across replicas")
	}
}

// TestRealRedis_KeyPrefixApplied verifies the configured prefix is actually
// used for the stored key — a path miniredis tests didn't assert.
func TestRealRedis_KeyPrefixApplied(t *testing.T) {
	prefix := "philter-it-prefixcheck:"
	b := newRealRedisBackend(t, prefix)
	ctx := context.Background()
	key := uniqueKey("prefixed")

	if _, _, err := b.Allow(ctx, key, 1, 5); err != nil {
		t.Fatal(err)
	}
	exists, err := b.client.Exists(ctx, prefix+key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if exists != 1 {
		t.Errorf("expected key %q to exist in redis under the configured prefix", prefix+key)
	}
}

// TestRealRedis_EndToEndProxy drives the full ProxyRateLimiter over real Redis.
func TestRealRedis_EndToEndProxy(t *testing.T) {
	cfg := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 0.001,
		Burst:             2,
		Backend: RateLimitBackendConfig{
			Type:  "redis",
			Redis: RedisBackendConfig{Address: realRedisAddr(), KeyPrefix: "philter-it-e2e:", TimeoutMs: 1000},
		},
	}
	rl, err := newProxyRateLimiter(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rl.Close() })

	ctx := context.Background()
	client := uniqueKey("e2e")
	blocked := false
	for i := 0; i < 5; i++ {
		if allowed, _ := rl.Allow(ctx, client); !allowed {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Error("expected a block once the real-Redis-backed burst was exhausted")
	}
}
