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

// --- redisUsageStore ---------------------------------------------------

func newTestRedisUsageStore(t *testing.T) (*redisUsageStore, *miniredis.Miniredis) {
	t.Helper()
	mr := newTestMiniRedis(t)
	s, err := newUsageStore(StateBackendConfig{
		Type:  "redis",
		Redis: RedisBackendConfig{Address: mr.Addr(), KeyPrefix: "test:usage:"},
	})
	if err != nil {
		t.Fatalf("newUsageStore: %v", err)
	}
	rs, ok := s.(*redisUsageStore)
	if !ok {
		t.Fatalf("expected *redisUsageStore, got %T", s)
	}
	t.Cleanup(func() { rs.Close() })
	return rs, mr
}

func TestRedisUsageStore_AddThenGet(t *testing.T) {
	s, _ := newTestRedisUsageStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := s.Add(ctx, "key-a", 100, 50, now); err != nil {
		t.Fatalf("Add: %v", err)
	}
	rec, err := s.Get(ctx, "key-a", now)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.DayTokens != 150 || rec.MonthTokens != 150 {
		t.Errorf("window totals: got day=%d month=%d, want 150/150", rec.DayTokens, rec.MonthTokens)
	}
	if rec.TotalPrompt != 100 || rec.TotalCompletion != 50 {
		t.Errorf("lifetime totals: got prompt=%d completion=%d, want 100/50", rec.TotalPrompt, rec.TotalCompletion)
	}
	if rec.Day != "2026-05-15" || rec.Month != "2026-05" {
		t.Errorf("window labels: got day=%q month=%q", rec.Day, rec.Month)
	}
}

func TestRedisUsageStore_AccumulatesAcrossCalls(t *testing.T) {
	s, _ := newTestRedisUsageStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		if err := s.Add(ctx, "key-a", 10, 5, now); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
	}
	rec, err := s.Get(ctx, "key-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DayTokens != 75 {
		t.Errorf("DayTokens = %d, want 75 (5 x (10+5))", rec.DayTokens)
	}
	if rec.TotalPrompt != 50 || rec.TotalCompletion != 25 {
		t.Errorf("lifetime: prompt=%d completion=%d, want 50/25", rec.TotalPrompt, rec.TotalCompletion)
	}
}

func TestRedisUsageStore_DayWindowRollover(t *testing.T) {
	// Day window is keyed on UTC date. Tokens accrued on day N must not
	// show up in the window count for day N+1, but lifetime totals must
	// keep accumulating.
	s, _ := newTestRedisUsageStore(t)
	ctx := context.Background()
	dayOne := time.Date(2026, 5, 15, 23, 0, 0, 0, time.UTC)
	dayTwo := time.Date(2026, 5, 16, 1, 0, 0, 0, time.UTC)

	if err := s.Add(ctx, "key-a", 100, 0, dayOne); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "key-a", 7, 0, dayTwo); err != nil {
		t.Fatal(err)
	}

	rec, err := s.Get(ctx, "key-a", dayTwo)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DayTokens != 7 {
		t.Errorf("day-2 DayTokens = %d, want 7 (only day-2 activity counts toward the day window)", rec.DayTokens)
	}
	if rec.MonthTokens != 107 {
		t.Errorf("month tokens = %d, want 107 (same calendar month)", rec.MonthTokens)
	}
	if rec.TotalPrompt != 107 {
		t.Errorf("lifetime prompt = %d, want 107", rec.TotalPrompt)
	}
}

func TestRedisUsageStore_MonthWindowRollover(t *testing.T) {
	s, _ := newTestRedisUsageStore(t)
	ctx := context.Background()
	monthOne := time.Date(2026, 5, 31, 23, 0, 0, 0, time.UTC)
	monthTwo := time.Date(2026, 6, 1, 1, 0, 0, 0, time.UTC)

	if err := s.Add(ctx, "key-a", 200, 0, monthOne); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "key-a", 3, 0, monthTwo); err != nil {
		t.Fatal(err)
	}
	rec, err := s.Get(ctx, "key-a", monthTwo)
	if err != nil {
		t.Fatal(err)
	}
	if rec.MonthTokens != 3 {
		t.Errorf("month-2 MonthTokens = %d, want 3 (only this month's activity)", rec.MonthTokens)
	}
	if rec.TotalPrompt != 203 {
		t.Errorf("lifetime prompt = %d, want 203", rec.TotalPrompt)
	}
}

func TestRedisUsageStore_GetUnknownKey(t *testing.T) {
	s, _ := newTestRedisUsageStore(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	rec, err := s.Get(context.Background(), "never-added", now)
	if err != nil {
		t.Fatalf("Get on unknown key should not error; got %v", err)
	}
	if rec.DayTokens != 0 || rec.MonthTokens != 0 || rec.TotalPrompt != 0 || rec.TotalCompletion != 0 {
		t.Errorf("unknown-key record should be all zeros, got %+v", rec)
	}
}

func TestRedisUsageStore_SnapshotReflectsAllKnownKeys(t *testing.T) {
	s, _ := newTestRedisUsageStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	if err := s.Add(ctx, "key-a", 100, 50, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "key-b", 7, 3, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "key-c", 1, 0, now); err != nil {
		t.Fatal(err)
	}

	snap, err := s.Snapshot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 3 {
		t.Fatalf("snapshot size = %d, want 3 (got keys: %v)", len(snap), keySet(snap))
	}
	if snap["key-a"].TotalPrompt != 100 {
		t.Errorf("key-a TotalPrompt = %d", snap["key-a"].TotalPrompt)
	}
	if snap["key-c"].TotalPrompt != 1 {
		t.Errorf("key-c TotalPrompt = %d", snap["key-c"].TotalPrompt)
	}
}

func TestRedisUsageStore_SnapshotIsolatesPrefix(t *testing.T) {
	// Two stores with different prefixes against the same underlying
	// miniredis must NOT see each other's entries via Snapshot.
	mr := newTestMiniRedis(t)
	sA, _ := newUsageStore(StateBackendConfig{
		Type:  "redis",
		Redis: RedisBackendConfig{Address: mr.Addr(), KeyPrefix: "tenantA:"},
	})
	defer sA.Close()
	sB, _ := newUsageStore(StateBackendConfig{
		Type:  "redis",
		Redis: RedisBackendConfig{Address: mr.Addr(), KeyPrefix: "tenantB:"},
	})
	defer sB.Close()
	ctx := context.Background()
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	sA.Add(ctx, "key-shared", 10, 0, now)
	sB.Add(ctx, "key-shared", 99, 0, now)

	snapA, _ := sA.Snapshot(ctx, now)
	snapB, _ := sB.Snapshot(ctx, now)
	if snapA["key-shared"].TotalPrompt != 10 {
		t.Errorf("tenant A leaked: TotalPrompt = %d, want 10", snapA["key-shared"].TotalPrompt)
	}
	if snapB["key-shared"].TotalPrompt != 99 {
		t.Errorf("tenant B leaked: TotalPrompt = %d, want 99", snapB["key-shared"].TotalPrompt)
	}
}

func TestRedisUsageStore_KeyPrefixApplied(t *testing.T) {
	s, mr := newTestRedisUsageStore(t)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	s.Add(context.Background(), "key-a", 1, 1, now)

	keys := mr.Keys()
	if len(keys) == 0 {
		t.Fatal("no keys stored")
	}
	for _, k := range keys {
		if !startsWith(k, "test:usage:") {
			t.Errorf("redis key %q missing configured prefix", k)
		}
	}
}

func TestRedisUsageStore_DayKeyTTL(t *testing.T) {
	// Day counters have a 49h TTL so abandoned days self-evict. Use
	// miniredis fast-forward to confirm the day key expires.
	s, mr := newTestRedisUsageStore(t)
	ctx := context.Background()
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	if err := s.Add(ctx, "key-a", 10, 0, now); err != nil {
		t.Fatal(err)
	}
	// 50 hours later: day-window key should be gone, lifetime totals still present.
	mr.FastForward(50 * time.Hour)

	rec, err := s.Get(ctx, "key-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DayTokens != 0 {
		t.Errorf("day window key should have expired; DayTokens = %d", rec.DayTokens)
	}
	if rec.TotalPrompt != 10 {
		t.Errorf("lifetime totals must persist past day TTL; TotalPrompt = %d", rec.TotalPrompt)
	}
}

func TestRedisUsageStore_Close(t *testing.T) {
	s, _ := newTestRedisUsageStore(t)
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestParseRedisInt(t *testing.T) {
	cases := []struct {
		in   interface{}
		want int64
	}{
		{"42", 42},
		{"0", 0},
		{nil, 0},
		{"not a number", 0},
		{"", 0},
		{123, 0}, // wrong type -> 0 rather than panic
	}
	for _, c := range cases {
		if got := parseRedisInt(c.in); got != c.want {
			t.Errorf("parseRedisInt(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

// --- newResponseCache / newUsageStore Redis-path coverage --------------

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

func TestNewUsageStore_RedisPath(t *testing.T) {
	mr := newTestMiniRedis(t)
	s, err := newUsageStore(StateBackendConfig{
		Type:  "redis",
		Redis: RedisBackendConfig{Address: mr.Addr()},
	})
	if err != nil {
		t.Fatalf("newUsageStore redis: %v", err)
	}
	if _, ok := s.(*redisUsageStore); !ok {
		t.Errorf("expected redisUsageStore, got %T", s)
	}
	s.Close()
}

// --- small helpers used by tests ---------------------------------------

func startsWith(s, prefix string) bool { return len(s) >= len(prefix) && s[:len(prefix)] == prefix }

func keySet(m map[string]UsageRecord) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
