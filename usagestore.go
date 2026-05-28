package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// UsageRecord is a point-in-time view of one key's token consumption: the
// running totals for the current UTC day and month windows, plus lifetime
// totals. It backs both quota enforcement and the /admin/usage export.
type UsageRecord struct {
	Day             string `json:"day"` // UTC calendar day, e.g. "2026-05-28"
	DayTokens       int64  `json:"day_tokens"`
	Month           string `json:"month"` // UTC calendar month, e.g. "2026-05"
	MonthTokens     int64  `json:"month_tokens"`
	TotalPrompt     int64  `json:"total_prompt_tokens"`
	TotalCompletion int64  `json:"total_completion_tokens"`
}

// UsageStore accumulates per-key token usage. Implementations are safe for
// concurrent use. The `now` argument is passed in (rather than read from a
// hidden clock) so window rollover is deterministic and testable.
type UsageStore interface {
	// Add records prompt+completion tokens for keyID at time now.
	Add(ctx context.Context, keyID string, prompt, completion int64, now time.Time) error
	// Get returns keyID's usage as of now (stale day/month windows read as 0).
	Get(ctx context.Context, keyID string, now time.Time) (UsageRecord, error)
	// Snapshot returns usage for every known key as of now.
	Snapshot(ctx context.Context, now time.Time) (map[string]UsageRecord, error)
	Close() error
}

func dayWindow(t time.Time) string   { return t.UTC().Format("2006-01-02") }
func monthWindow(t time.Time) string { return t.UTC().Format("2006-01") }

// newUsageStore builds the configured usage store (memory by default).
func newUsageStore(cfg StateBackendConfig) (UsageStore, error) {
	if cfg.Type == "redis" {
		client, err := newRedisClient(cfg.Redis)
		if err != nil {
			return nil, err
		}
		prefix := cfg.Redis.KeyPrefix
		if prefix == "" {
			prefix = "philter:usage:"
		}
		return &redisUsageStore{client: client, prefix: prefix}, nil
	}
	return newMemUsageStore(), nil
}

// --- in-memory ---

type usageEntry struct {
	day             string
	dayTokens       int64
	month           string
	monthTokens     int64
	totalPrompt     int64
	totalCompletion int64
}

type memUsageStore struct {
	mu sync.Mutex
	m  map[string]*usageEntry
}

func newMemUsageStore() *memUsageStore {
	return &memUsageStore{m: make(map[string]*usageEntry)}
}

func (s *memUsageStore) Add(_ context.Context, keyID string, prompt, completion int64, now time.Time) error {
	day, month := dayWindow(now), monthWindow(now)
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.m[keyID]
	if e == nil {
		e = &usageEntry{}
		s.m[keyID] = e
	}
	if e.day != day {
		e.day = day
		e.dayTokens = 0
	}
	if e.month != month {
		e.month = month
		e.monthTokens = 0
	}
	total := prompt + completion
	e.dayTokens += total
	e.monthTokens += total
	e.totalPrompt += prompt
	e.totalCompletion += completion
	return nil
}

func (s *memUsageStore) Get(_ context.Context, keyID string, now time.Time) (UsageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordLocked(keyID, now), nil
}

// recordLocked builds a UsageRecord with stale windows reported as 0. Caller
// must hold s.mu.
func (s *memUsageStore) recordLocked(keyID string, now time.Time) UsageRecord {
	day, month := dayWindow(now), monthWindow(now)
	rec := UsageRecord{Day: day, Month: month}
	e := s.m[keyID]
	if e == nil {
		return rec
	}
	if e.day == day {
		rec.DayTokens = e.dayTokens
	}
	if e.month == month {
		rec.MonthTokens = e.monthTokens
	}
	rec.TotalPrompt = e.totalPrompt
	rec.TotalCompletion = e.totalCompletion
	return rec
}

func (s *memUsageStore) Snapshot(_ context.Context, now time.Time) (map[string]UsageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]UsageRecord, len(s.m))
	for k := range s.m {
		out[k] = s.recordLocked(k, now)
	}
	return out, nil
}

func (s *memUsageStore) Close() error { return nil }

// --- redis ---

// redisUsageStore shares usage counters across replicas. Day/month counters
// carry a TTL so abandoned windows self-evict; lifetime totals are persistent
// and serve as the canonical key set for Snapshot.
type redisUsageStore struct {
	client *redis.Client
	prefix string
}

func (s *redisUsageStore) dayKey(keyID, day string) string {
	return fmt.Sprintf("%s%s:day:%s", s.prefix, keyID, day)
}
func (s *redisUsageStore) monthKey(keyID, month string) string {
	return fmt.Sprintf("%s%s:month:%s", s.prefix, keyID, month)
}
func (s *redisUsageStore) promptTotalKey(keyID string) string {
	return fmt.Sprintf("%s%s:total:prompt", s.prefix, keyID)
}
func (s *redisUsageStore) completionTotalKey(keyID string) string {
	return fmt.Sprintf("%s%s:total:completion", s.prefix, keyID)
}

func (s *redisUsageStore) Add(ctx context.Context, keyID string, prompt, completion int64, now time.Time) error {
	day, month := dayWindow(now), monthWindow(now)
	total := prompt + completion
	pipe := s.client.Pipeline()
	dk, mk := s.dayKey(keyID, day), s.monthKey(keyID, month)
	pipe.IncrBy(ctx, dk, total)
	pipe.Expire(ctx, dk, 49*time.Hour)
	pipe.IncrBy(ctx, mk, total)
	pipe.Expire(ctx, mk, 35*24*time.Hour)
	pipe.IncrBy(ctx, s.promptTotalKey(keyID), prompt)
	pipe.IncrBy(ctx, s.completionTotalKey(keyID), completion)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("redis usage Add: %w", err)
	}
	return nil
}

func (s *redisUsageStore) Get(ctx context.Context, keyID string, now time.Time) (UsageRecord, error) {
	day, month := dayWindow(now), monthWindow(now)
	vals, err := s.client.MGet(ctx,
		s.dayKey(keyID, day),
		s.monthKey(keyID, month),
		s.promptTotalKey(keyID),
		s.completionTotalKey(keyID),
	).Result()
	if err != nil {
		return UsageRecord{}, fmt.Errorf("redis usage Get: %w", err)
	}
	return UsageRecord{
		Day:             day,
		DayTokens:       parseRedisInt(vals[0]),
		Month:           month,
		MonthTokens:     parseRedisInt(vals[1]),
		TotalPrompt:     parseRedisInt(vals[2]),
		TotalCompletion: parseRedisInt(vals[3]),
	}, nil
}

func (s *redisUsageStore) Snapshot(ctx context.Context, now time.Time) (map[string]UsageRecord, error) {
	out := make(map[string]UsageRecord)
	pattern := s.prefix + "*:total:prompt"
	var cursor uint64
	for {
		keys, next, err := s.client.Scan(ctx, cursor, pattern, 256).Result()
		if err != nil {
			return nil, fmt.Errorf("redis usage Snapshot scan: %w", err)
		}
		for _, k := range keys {
			keyID := strings.TrimSuffix(strings.TrimPrefix(k, s.prefix), ":total:prompt")
			rec, err := s.Get(ctx, keyID, now)
			if err != nil {
				return nil, err
			}
			out[keyID] = rec
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return out, nil
}

func (s *redisUsageStore) Close() error { return s.client.Close() }

// parseRedisInt converts a MGet result element (string or nil) to int64.
func parseRedisInt(v interface{}) int64 {
	str, ok := v.(string)
	if !ok {
		return 0
	}
	var n int64
	_, _ = fmt.Sscan(str, &n)
	return n
}
