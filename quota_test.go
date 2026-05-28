package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestQuota_UnderLimitAllows(t *testing.T) {
	store := newMemUsageStore()
	q := newQuotaEnforcer(QuotaConfig{Default: QuotaLimits{DailyTokens: 100}}, nil, store)
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	q.Record(context.Background(), "key-0", 40, 10, now) // 50 used
	allowed, _, _, err := q.Check(context.Background(), "key-0", now)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("expected allow under the daily quota")
	}
}

func TestQuota_DailyExceeded429Window(t *testing.T) {
	store := newMemUsageStore()
	q := newQuotaEnforcer(QuotaConfig{Default: QuotaLimits{DailyTokens: 100}}, nil, store)
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	q.Record(context.Background(), "key-0", 100, 0, now) // exactly at limit
	allowed, retryAfter, window, _ := q.Check(context.Background(), "key-0", now)
	if allowed {
		t.Fatal("expected block at/over the daily quota")
	}
	if window != "daily" {
		t.Errorf("window: want daily, got %q", window)
	}
	// Retry-After should point at the next UTC midnight (12h away here).
	if retryAfter <= 0 || retryAfter > 24*time.Hour {
		t.Errorf("retryAfter out of range: %v", retryAfter)
	}
	if got := untilNextDay(now); retryAfter != got {
		t.Errorf("retryAfter: want %v, got %v", got, retryAfter)
	}
}

func TestQuota_MonthlyTakesPrecedence(t *testing.T) {
	store := newMemUsageStore()
	q := newQuotaEnforcer(QuotaConfig{Default: QuotaLimits{DailyTokens: 100, MonthlyTokens: 1000}}, nil, store)
	now := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	// Push both over: 1000 tokens today exceeds both daily(100) and monthly(1000).
	q.Record(context.Background(), "key-0", 1000, 0, now)
	allowed, retryAfter, window, _ := q.Check(context.Background(), "key-0", now)
	if allowed {
		t.Fatal("expected block")
	}
	if window != "monthly" {
		t.Errorf("monthly should take precedence, got %q", window)
	}
	if got := untilNextMonth(now); retryAfter != got {
		t.Errorf("retryAfter: want %v (next month), got %v", got, retryAfter)
	}
}

func TestQuota_PerKeyOverrideBeatsDefault(t *testing.T) {
	store := newMemUsageStore()
	apiKeys := []APIKeyEntry{
		{Key: "k0"},
		{Key: "k1", Quota: &QuotaLimits{DailyTokens: 10}},
	}
	q := newQuotaEnforcer(QuotaConfig{Default: QuotaLimits{DailyTokens: 1000}}, apiKeys, store)
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	// key-1 has a tight 10-token daily override.
	q.Record(context.Background(), "key-1", 10, 0, now)
	if allowed, _, _, _ := q.Check(context.Background(), "key-1", now); allowed {
		t.Error("key-1 should be blocked by its per-key override")
	}
	// key-0 uses the generous default.
	q.Record(context.Background(), "key-0", 10, 0, now)
	if allowed, _, _, _ := q.Check(context.Background(), "key-0", now); !allowed {
		t.Error("key-0 should still be under the default quota")
	}
}

func TestQuota_NoLimitsAlwaysAllows(t *testing.T) {
	store := newMemUsageStore()
	q := newQuotaEnforcer(QuotaConfig{Default: QuotaLimits{}}, nil, store) // 0/0 = unlimited
	now := time.Now()
	q.Record(context.Background(), "key-0", 1_000_000, 0, now)
	if allowed, _, _, _ := q.Check(context.Background(), "key-0", now); !allowed {
		t.Error("unlimited quota should always allow")
	}
}

// errUsageStore fails Get to exercise the fail-open path.
type errUsageStore struct{}

func (errUsageStore) Add(context.Context, string, int64, int64, time.Time) error { return nil }
func (errUsageStore) Get(context.Context, string, time.Time) (UsageRecord, error) {
	return UsageRecord{}, errors.New("store down")
}
func (errUsageStore) Snapshot(context.Context, time.Time) (map[string]UsageRecord, error) {
	return nil, errors.New("store down")
}
func (errUsageStore) Close() error { return nil }

func TestQuota_FailsOpenOnStoreError(t *testing.T) {
	q := newQuotaEnforcer(QuotaConfig{Default: QuotaLimits{DailyTokens: 1}}, nil, errUsageStore{})
	allowed, _, _, err := q.Check(context.Background(), "key-0", time.Now())
	if err == nil {
		t.Error("expected the store error to be surfaced to the caller")
	}
	if !allowed {
		t.Error("quota check should fail open (allow) when the store errors")
	}
}
