package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func adminTestProxy(t *testing.T, token string) *Proxy {
	t.Helper()
	store := newMemUsageStore()
	now := time.Now().UTC()
	store.Add(context.Background(), "key-0", 100, 50, now)
	store.Add(context.Background(), "key-1", 7, 3, now)

	cfg := testConfig("https://localhost:8080")
	// Production hashes the admin token on the Proxy and zeros the
	// plaintext config field. Mirror that so the comparison path is the
	// same one production uses.
	cfg.Admin = AdminConfig{Enabled: true}
	return &Proxy{config: cfg, usage: store, adminTokenHash: hashAdminToken(token)}
}

func TestAdminUsage_RequiresToken(t *testing.T) {
	p := adminTestProxy(t, "s3cret")

	// Missing token.
	req := httptest.NewRequest("GET", "/admin/usage", nil)
	w := httptest.NewRecorder()
	p.handleAdminUsage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing token: want 401, got %d", w.Code)
	}

	// Wrong token.
	req = httptest.NewRequest("GET", "/admin/usage", nil)
	req.Header.Set(defaultAdminHeader, "wrong")
	w = httptest.NewRecorder()
	p.handleAdminUsage(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: want 401, got %d", w.Code)
	}
}

func TestAdminUsage_JSON(t *testing.T) {
	p := adminTestProxy(t, "s3cret")
	req := httptest.NewRequest("GET", "/admin/usage", nil)
	req.Header.Set(defaultAdminHeader, "s3cret")
	w := httptest.NewRecorder()
	p.handleAdminUsage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type: want application/json, got %q", ct)
	}
	var out struct {
		Usage []usageExportRow `json:"usage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Usage) != 2 {
		t.Fatalf("want 2 rows, got %d", len(out.Usage))
	}
	// Sorted by key_id, so key-0 first.
	if out.Usage[0].KeyID != "key-0" || out.Usage[0].DayTokens != 150 {
		t.Errorf("key-0 row wrong: %+v", out.Usage[0])
	}
	if out.Usage[0].TotalPrompt != 100 || out.Usage[0].TotalCompletion != 50 {
		t.Errorf("key-0 totals wrong: %+v", out.Usage[0])
	}
}

func TestAdminUsage_CSV(t *testing.T) {
	p := adminTestProxy(t, "s3cret")
	req := httptest.NewRequest("GET", "/admin/usage?format=csv", nil)
	req.Header.Set(defaultAdminHeader, "s3cret")
	w := httptest.NewRecorder()
	p.handleAdminUsage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("content-type: want text/csv, got %q", ct)
	}
	body := w.Body.String()
	if !strings.HasPrefix(body, "key_id,day,day_tokens,month,month_tokens,total_prompt_tokens,total_completion_tokens") {
		t.Errorf("missing/incorrect CSV header: %q", body)
	}
	if !strings.Contains(body, "key-0,") || !strings.Contains(body, "key-1,") {
		t.Errorf("CSV missing key rows: %q", body)
	}
}

func TestAdminUsage_MethodNotAllowed(t *testing.T) {
	p := adminTestProxy(t, "s3cret")
	req := httptest.NewRequest("POST", "/admin/usage", nil)
	req.Header.Set(defaultAdminHeader, "s3cret")
	w := httptest.NewRecorder()
	p.handleAdminUsage(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", w.Code)
	}
}

func TestAdminUsage_LogsAccessWithoutLeakingToken(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	p := adminTestProxy(t, "s3cret-token")

	// Denied attempt.
	denied := httptest.NewRequest("GET", "/admin/usage", nil)
	denied.Header.Set(defaultAdminHeader, "wrong-token")
	p.handleAdminUsage(httptest.NewRecorder(), denied)

	// Successful access.
	ok := httptest.NewRequest("GET", "/admin/usage", nil)
	ok.Header.Set(defaultAdminHeader, "s3cret-token")
	p.handleAdminUsage(httptest.NewRecorder(), ok)

	out := buf.String()
	if !strings.Contains(out, "Admin usage access denied") {
		t.Error("expected a denied-access log line")
	}
	if !strings.Contains(out, "Admin usage exported") {
		t.Error("expected a successful-access log line")
	}
	if strings.Contains(out, "s3cret-token") || strings.Contains(out, "wrong-token") {
		t.Errorf("admin tokens must never appear in logs; got:\n%s", out)
	}
}

func TestAdminUsage_DisabledReturns404(t *testing.T) {
	// Through ServeHTTP with admin disabled.
	cfg := testConfig("https://localhost:8080")
	cfg.Admin.Enabled = false
	p := &Proxy{config: cfg}
	req := httptest.NewRequest("GET", "/admin/usage", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("admin disabled: want 404, got %d", w.Code)
	}
}
