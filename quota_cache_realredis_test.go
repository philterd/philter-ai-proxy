//go:build realredis

// Real-Redis coverage for the usage store and response cache (the quota and
// cache subsystems' shared-state backends). Excluded from the default build;
// run with `-tags realredis` against a Redis service container. See
// ratelimit_realredis_test.go for REDIS_ADDR / helper details.

package main

import (
	"context"
	"testing"
	"time"
)

func TestRealRedis_UsageStore(t *testing.T) {
	store, err := newUsageStore(StateBackendConfig{
		Type:  "redis",
		Redis: RedisBackendConfig{Address: realRedisAddr(), KeyPrefix: "philter-it-usage:"},
	})
	if err != nil {
		t.Fatalf("newUsageStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()
	key := uniqueKey("usage")
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	if err := store.Add(ctx, key, 10, 5, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(ctx, key, 3, 2, now); err != nil {
		t.Fatal(err)
	}

	rec, err := store.Get(ctx, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DayTokens != 20 || rec.MonthTokens != 20 {
		t.Errorf("windows: want 20/20, got %d/%d", rec.DayTokens, rec.MonthTokens)
	}
	if rec.TotalPrompt != 13 || rec.TotalCompletion != 7 {
		t.Errorf("totals: want 13/7, got %d/%d", rec.TotalPrompt, rec.TotalCompletion)
	}

	// New day → day counter resets, month + totals persist.
	next := now.Add(24 * time.Hour)
	if err := store.Add(ctx, key, 1, 0, next); err != nil {
		t.Fatal(err)
	}
	rec, _ = store.Get(ctx, key, next)
	if rec.DayTokens != 1 {
		t.Errorf("day should reset on new day: want 1, got %d", rec.DayTokens)
	}
	if rec.MonthTokens != 21 {
		t.Errorf("month should accumulate: want 21, got %d", rec.MonthTokens)
	}

	snap, err := store.Snapshot(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap[key]; !ok {
		t.Errorf("snapshot should include key %q", key)
	}
}

func TestRealRedis_Cache(t *testing.T) {
	cache, err := newResponseCache(CacheConfig{
		Enabled:    true,
		TTLSeconds: 60,
		Backend:    StateBackendConfig{Type: "redis", Redis: RedisBackendConfig{Address: realRedisAddr(), KeyPrefix: "philter-it-cache:"}},
	})
	if err != nil {
		t.Fatalf("newResponseCache: %v", err)
	}
	t.Cleanup(func() { cache.Close() })

	ctx := context.Background()
	key := uniqueKey("cache")

	if _, ok := cache.Get(ctx, key); ok {
		t.Error("expected miss before set")
	}
	cache.Set(ctx, key, &CachedResponse{Status: 200, ContentType: "application/json", Body: []byte(`{"ok":true}`)})
	got, ok := cache.Get(ctx, key)
	if !ok {
		t.Fatal("expected hit after set")
	}
	if got.Status != 200 || got.ContentType != "application/json" || string(got.Body) != `{"ok":true}` {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}
