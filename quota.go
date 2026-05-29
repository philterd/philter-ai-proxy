package main

import (
	"context"
	"time"
)

// QuotaEnforcer enforces per-key daily/monthly token quotas on top of a
// UsageStore. Quotas are checked pre-flight (against accumulated usage) and
// usage is recorded after each response, once token counts are known.
type QuotaEnforcer struct {
	store  UsageStore
	def    QuotaLimits
	perKey map[string]QuotaLimits // stable key ID -> per-key override
}

// newQuotaEnforcer builds an enforcer over a shared UsageStore (so the
// /admin/usage endpoint reads the same counters quota enforcement uses).
func newQuotaEnforcer(cfg QuotaConfig, apiKeys []APIKeyEntry, store UsageStore) *QuotaEnforcer {
	q := &QuotaEnforcer{store: store, def: cfg.Default, perKey: make(map[string]QuotaLimits)}
	for i, e := range apiKeys {
		if e.Quota != nil {
			q.perKey[keyIDFor(e, i)] = *e.Quota
		}
	}
	return q
}

func (q *QuotaEnforcer) limitsFor(keyID string) QuotaLimits {
	if l, ok := q.perKey[keyID]; ok {
		return l
	}
	return q.def
}

// Check reports whether keyID may proceed. When a window is at or over quota it
// returns allowed=false, the duration until that window resets (for
// Retry-After), and which window ("daily"/"monthly") was breached.
//
// On a store error it fails open (allows the request) and returns the error so
// the caller can log/meter it — availability is preferred over hard-blocking on
// an infrastructure blip, matching the rate limiter's default.
func (q *QuotaEnforcer) Check(ctx context.Context, keyID string, now time.Time) (allowed bool, retryAfter time.Duration, window string, err error) {
	lim := q.limitsFor(keyID)
	if lim.DailyTokens == 0 && lim.MonthlyTokens == 0 {
		return true, 0, "", nil
	}
	rec, gerr := q.store.Get(ctx, keyID, now)
	if gerr != nil {
		return true, 0, "", gerr
	}
	// Check the longer window first so an exhausted month doesn't hand back a
	// short (daily) Retry-After.
	if lim.MonthlyTokens > 0 && rec.MonthTokens >= lim.MonthlyTokens {
		return false, untilNextMonth(now), "monthly", nil
	}
	if lim.DailyTokens > 0 && rec.DayTokens >= lim.DailyTokens {
		return false, untilNextDay(now), "daily", nil
	}
	return true, 0, "", nil
}

// Record accumulates a request's token usage for keyID. The underlying store is
// owned (and closed) by the Proxy, since it is shared with the admin endpoint.
func (q *QuotaEnforcer) Record(ctx context.Context, keyID string, prompt, completion int64, now time.Time) error {
	return q.store.Add(ctx, keyID, prompt, completion, now)
}

func untilNextDay(now time.Time) time.Duration {
	u := now.UTC()
	next := time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
	return next.Sub(u)
}

func untilNextMonth(now time.Time) time.Duration {
	u := now.UTC()
	next := time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	return next.Sub(u)
}
