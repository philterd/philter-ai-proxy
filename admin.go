package main

import (
	"crypto/sha256"
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

	// Per-IP rate limit. The main request-path rate limiter does not cover
	// admin routes (they return early before its checkpoint), so we apply
	// a dedicated, deliberately tight bucket. 5 requests per second with
	// a burst of 10 is enough for legitimate operator polling and
	// dashboard refreshes; it bounds brute-force attempts on the admin
	// token. The bucket is keyed on the client IP -- not the supplied
	// token -- so a single attacker cannot rotate guesses faster than
	// the bucket refill rate.
	if p.adminLimiter != nil {
		peer := p.clientIP(r)
		if allowed, retryAfter, _ := p.adminLimiter.Allow(r.Context(), "admin|"+peer, 5, 10); !allowed {
			retrySecs := int(retryAfter.Seconds())
			if retrySecs < 1 {
				retrySecs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retrySecs))
			slog.Warn("Admin usage rate limit exceeded", "client", peer)
			writeError(w, nil, http.StatusTooManyRequests, "rate_limit_error", "admin_rate_limited", "admin endpoint rate limit exceeded")
			return
		}
	}

	headerName := p.config.Admin.Header
	if headerName == "" {
		headerName = defaultAdminHeader
	}

	// Two acceptable credentials:
	//   1. The full admin token (carries all admin privileges).
	//   2. An API key whose `adminRole: usage-read` is set, presented in the
	//      regular `auth.header` (default `x-philter-proxy-key`). This is the
	//      scoped admin role -- read-only access to usage/billing, no full-
	//      admin capabilities.
	authorized := false
	authMode := ""
	authKeyID := ""

	// The admin token is held only as a SHA256 hash on the Proxy. We hash
	// the supplied value and compare the two 32-byte arrays in constant
	// time; an unconfigured token (zero-valued hash) is treated as a hard
	// reject so an attacker who finds an undocumented "" path cannot
	// authenticate.
	if provided := r.Header.Get(headerName); provided != "" && !isZeroHash(p.adminTokenHash) {
		providedHash := sha256.Sum256([]byte(provided))
		if subtle.ConstantTimeCompare(providedHash[:], p.adminTokenHash[:]) == 1 {
			authorized = true
			authMode = "admin_token"
		}
	}

	if !authorized && p.keyStore != nil {
		apiHeader := p.config.Auth.Header
		if apiHeader == "" {
			apiHeader = "x-philter-proxy-key"
		}
		if k := r.Header.Get(apiHeader); k != "" {
			if resolved, ok := p.keyStore.lookup(k); ok && resolved.AdminRole == AdminRoleUsageRead {
				authorized = true
				authMode = "api_key_usage_read"
				authKeyID = resolved.ID
			}
		}
	}

	if !authorized {
		slog.Warn("Admin usage access denied", "client", p.clientIP(r), "method", r.Method)
		writeError(w, nil, http.StatusUnauthorized, "unauthorized", "invalid_admin_token", "invalid or missing admin credentials")
		return
	}

	snap, err := p.usage.Snapshot(r.Context(), time.Now().UTC())
	if err != nil {
		slog.Error("Admin usage snapshot failed", "client", p.clientIP(r), "error", err)
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
	// The auth mode and the opaque key ID (when applicable) are logged so
	// operators can distinguish admin-token vs scoped-API-key accesses.
	slog.Info("Admin usage exported", "client", p.clientIP(r), "format", format, "keys", len(keyIDs), "auth_mode", authMode, "key_id", authKeyID)

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
