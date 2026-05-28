package main

import (
	"context"
	"testing"
	"time"
)

func TestMemUsageStore_AddAndGet(t *testing.T) {
	s := newMemUsageStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

	if err := s.Add(ctx, "key-0", 10, 5, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "key-0", 3, 2, now); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.Get(ctx, "key-0", now)
	if rec.DayTokens != 20 {
		t.Errorf("DayTokens: want 20, got %d", rec.DayTokens)
	}
	if rec.MonthTokens != 20 {
		t.Errorf("MonthTokens: want 20, got %d", rec.MonthTokens)
	}
	if rec.TotalPrompt != 13 || rec.TotalCompletion != 7 {
		t.Errorf("totals: want prompt=13 completion=7, got %d/%d", rec.TotalPrompt, rec.TotalCompletion)
	}
}

func TestMemUsageStore_DayRollover(t *testing.T) {
	s := newMemUsageStore()
	ctx := context.Background()
	d1 := time.Date(2026, 5, 28, 23, 0, 0, 0, time.UTC)
	d2 := time.Date(2026, 5, 29, 1, 0, 0, 0, time.UTC) // next day, same month

	s.Add(ctx, "k", 100, 0, d1)
	s.Add(ctx, "k", 7, 0, d2)

	rec, _ := s.Get(ctx, "k", d2)
	if rec.DayTokens != 7 {
		t.Errorf("day should have reset: want 7, got %d", rec.DayTokens)
	}
	if rec.MonthTokens != 107 {
		t.Errorf("month should accumulate across days: want 107, got %d", rec.MonthTokens)
	}
	if rec.TotalPrompt != 107 {
		t.Errorf("lifetime total: want 107, got %d", rec.TotalPrompt)
	}
}

func TestMemUsageStore_MonthRollover(t *testing.T) {
	s := newMemUsageStore()
	ctx := context.Background()
	m1 := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	m2 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	s.Add(ctx, "k", 50, 0, m1)
	rec, _ := s.Get(ctx, "k", m2)
	if rec.MonthTokens != 0 {
		t.Errorf("month should reset on new month: want 0, got %d", rec.MonthTokens)
	}
	if rec.TotalPrompt != 50 {
		t.Errorf("lifetime total persists: want 50, got %d", rec.TotalPrompt)
	}
}

func TestMemUsageStore_GetStaleWindowReadsZero(t *testing.T) {
	s := newMemUsageStore()
	ctx := context.Background()
	s.Add(ctx, "k", 10, 0, time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC))

	// Reading on a later day without an Add must report 0 for the day window
	// (and not mutate state).
	rec, _ := s.Get(ctx, "k", time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC))
	if rec.DayTokens != 0 {
		t.Errorf("stale day window should read 0, got %d", rec.DayTokens)
	}
}

func TestMemUsageStore_Snapshot(t *testing.T) {
	s := newMemUsageStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	s.Add(ctx, "key-0", 10, 1, now)
	s.Add(ctx, "key-1", 20, 2, now)

	snap, err := s.Snapshot(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 2 {
		t.Fatalf("want 2 keys, got %d", len(snap))
	}
	if snap["key-1"].DayTokens != 22 {
		t.Errorf("key-1 day tokens: want 22, got %d", snap["key-1"].DayTokens)
	}
}
