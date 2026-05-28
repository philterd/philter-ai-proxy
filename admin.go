package main

import (
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"
)

const defaultAdminHeader = "x-philter-admin-token"

// usageExportRow is one key's usage in the export, including its stable key ID.
type usageExportRow struct {
	KeyID string `json:"key_id"`
	UsageRecord
}

// handleAdminUsage serves GET /admin/usage: a per-key token-usage export for
// billing and quota inspection. It is gated by a constant-time comparison
// against the configured admin token and returns JSON by default, or CSV when
// ?format=csv is supplied. Only reachable when admin.enabled is set.
func (p *Proxy) handleAdminUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, nil, http.StatusMethodNotAllowed, "method_not_allowed", "method_not_allowed", "method not allowed")
		return
	}

	headerName := p.config.Admin.Header
	if headerName == "" {
		headerName = defaultAdminHeader
	}
	provided := r.Header.Get(headerName)
	// Constant-time compare; also reject when no token was supplied. The token
	// is never logged; a denied attempt is logged so brute-force attempts are
	// visible (the endpoint is not behind the request rate limiter).
	if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(p.config.Admin.Token)) != 1 {
		slog.Warn("Admin usage access denied", "client", clientIP(r), "method", r.Method)
		writeError(w, nil, http.StatusUnauthorized, "unauthorized", "invalid_admin_token", "invalid or missing admin token")
		return
	}

	snap, err := p.usage.Snapshot(r.Context(), time.Now().UTC())
	if err != nil {
		slog.Error("Admin usage snapshot failed", "client", clientIP(r), "error", err)
		writeError(w, nil, http.StatusInternalServerError, "internal_error", "usage_snapshot_failed", "failed to read usage")
		return
	}

	// Stable ordering for deterministic output.
	keyIDs := make([]string, 0, len(snap))
	for k := range snap {
		keyIDs = append(keyIDs, k)
	}
	sort.Strings(keyIDs)

	format := "json"
	if r.URL.Query().Get("format") == "csv" {
		format = "csv"
	}
	// Successful access to per-key billing data is recorded (no token).
	slog.Info("Admin usage exported", "client", clientIP(r), "format", format, "keys", len(keyIDs))

	if format == "csv" {
		p.writeUsageCSV(w, keyIDs, snap)
		return
	}

	rows := make([]usageExportRow, 0, len(keyIDs))
	for _, k := range keyIDs {
		rows = append(rows, usageExportRow{KeyID: k, UsageRecord: snap[k]})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"usage": rows})
}

func (p *Proxy) writeUsageCSV(w http.ResponseWriter, keyIDs []string, snap map[string]UsageRecord) {
	w.Header().Set("Content-Type", "text/csv")
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"key_id", "day", "day_tokens", "month", "month_tokens", "total_prompt_tokens", "total_completion_tokens"})
	for _, k := range keyIDs {
		rec := snap[k]
		_ = cw.Write([]string{
			k,
			rec.Day,
			strconv.FormatInt(rec.DayTokens, 10),
			rec.Month,
			strconv.FormatInt(rec.MonthTokens, 10),
			strconv.FormatInt(rec.TotalPrompt, 10),
			strconv.FormatInt(rec.TotalCompletion, 10),
		})
	}
}
