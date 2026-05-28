package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"crypto/sha256"
	"encoding/hex"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type OpenAIToolCall struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"`
	Function OpenAIFunction `json:"function"`
}

type OpenAIMessage struct {
	Role       string           `json:"role"`
	Content    json.RawMessage  `json:"content,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	ToolCalls  []OpenAIToolCall `json:"tool_calls,omitempty"`
	Name       string           `json:"name,omitempty"`
}

type OpenAIRequest struct {
	Model    string          `json:"model"`
	Messages []OpenAIMessage `json:"messages"`
}

type AnthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type AnthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // Can be string or []AnthropicContent
}

type AnthropicRequest struct {
	Model    string             `json:"model"`
	Messages []AnthropicMessage `json:"messages"`
	System   string             `json:"system,omitempty"`
}

type GeminiFunctionResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

type GeminiPart struct {
	Text             string                  `json:"text,omitempty"`
	FunctionResponse *GeminiFunctionResponse `json:"functionResponse,omitempty"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []GeminiPart `json:"parts"`
}

type GeminiRequest struct {
	Contents []GeminiContent `json:"contents"`
}

type OllamaGenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	System string `json:"system,omitempty"`
}

type OllamaChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type BedrockContentBlock struct {
	Text string `json:"text,omitempty"`
}

type BedrockMessage struct {
	Role    string                `json:"role"`
	Content []BedrockContentBlock `json:"content"`
}

type BedrockSystemBlock struct {
	Text string `json:"text"`
}

type BedrockConverseRequest struct {
	Messages        []BedrockMessage     `json:"messages"`
	System          []BedrockSystemBlock `json:"system,omitempty"`
	InferenceConfig map[string]any       `json:"inferenceConfig,omitempty"`
}

type BedrockConverseOutput struct {
	Message BedrockMessage `json:"message"`
}

type BedrockConverseResponse struct {
	Output     BedrockConverseOutput `json:"output"`
	StopReason string                `json:"stopReason,omitempty"`
}

type Proxy struct {
	config                  *Config
	openaiTarget            *url.URL
	anthropicTarget         *url.URL
	geminiTarget            *url.URL
	ollamaTarget            *url.URL
	openaiClient            *http.Client
	anthropicClient         *http.Client
	geminiClient            *http.Client
	ollamaClient            *http.Client
	bedrockClient           *http.Client
	bedrockRegion           string
	bedrockCreds            aws.CredentialsProvider
	azureTarget             *url.URL // nil when Azure is not configured
	azureClient             *http.Client
	azureCred               tokenSource // non-nil only when Entra ID auth is enabled
	openaiCompatibleTargets map[string]*url.URL
	openaiCompatibleClients map[string]*http.Client
	philter                 *PhilterClient
	auditLogger             *slog.Logger
	metrics                 *ProxyMetrics
	keyStore                *keyStore // hashed API keys; nil when auth is disabled
	rateLimiter             *ProxyRateLimiter
	concurrency             *ConcurrencyLimiter
	usage                   UsageStore     // per-key token accounting; nil when quota & admin both off
	quota                   *QuotaEnforcer // per-key token quotas; nil when disabled
	cache                   ResponseCache  // response cache; nil when disabled
}

type AuditEntry struct {
	RequestID        string        `json:"request_id"`
	Direction        string        `json:"direction"`
	Provider         string        `json:"provider"`
	Model            string        `json:"model"`
	PolicyName       string        `json:"policy_name"`
	DocumentID       string        `json:"document_id"`
	FieldsRedacted   int           `json:"fields_redacted"`
	EntityCount      int           `json:"entity_count"`
	EntityTypes      []string      `json:"entity_types"`
	RedactLatency    time.Duration `json:"redact_latency_ms"`
	ClientIP         string        `json:"client_ip"`
	HTTPStatus       int           `json:"http_status"`
	PromptTokens     int           `json:"prompt_tokens,omitempty"`
	CompletionTokens int           `json:"completion_tokens,omitempty"`
	// ErrorType / ErrorCode mirror the values the client received in the
	// JSON error body. Empty on 2xx responses.
	ErrorType string `json:"error_type,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	// TraceID is the W3C trace ID for this request when OpenTelemetry tracing
	// is enabled and the request was sampled. Empty otherwise.
	TraceID          string         `json:"trace_id,omitempty"`
	EntityTypeCounts map[string]int `json:"-"`
}

type responseCapture struct {
	http.ResponseWriter
	statusCode int
	// captureBody tees response bytes into buf (up to limit) so the response
	// can be stored in the cache after the handler returns. Enabled only for
	// cacheable (non-streaming) cache-miss requests. If the body exceeds limit,
	// tooLarge is set and the buffer is discarded so we never cache partials.
	captureBody bool
	limit       int
	buf         bytes.Buffer
	tooLarge    bool
}

func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	if rc.captureBody && !rc.tooLarge {
		if rc.buf.Len()+len(b) > rc.limit {
			rc.tooLarge = true
			rc.buf.Reset()
		} else {
			rc.buf.Write(b)
		}
	}
	return rc.ResponseWriter.Write(b)
}

// cachedBody returns the buffered response body, or nil if capture was off or
// the response exceeded the size limit.
func (rc *responseCapture) cachedBody() []byte {
	if !rc.captureBody || rc.tooLarge {
		return nil
	}
	return rc.buf.Bytes()
}

func (rc *responseCapture) Flush() {
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// writeJSONError writes the proxy's stable structured error response. The
// shape is:
//
//	{"error":{"message":"...","type":"...","code":"...","request_id":"..."}}
//
// (type, code) pairs form the stable contract documented in the
// "Error Responses" section of the docs. They are part of the proxy's public
// API and must not change across minor versions. New codes may be added; old
// codes may not be removed or repurposed.
// writeError is the canonical error-response helper used throughout the proxy.
// It writes a structured JSON body via writeJSONError and records the same
// (type, code) on the audit entry so the audit log mirrors what the client
// received. Every error path the proxy generates should funnel through here.
func writeError(w http.ResponseWriter, audit *AuditEntry, status int, errType, code, message string) {
	if audit != nil {
		audit.ErrorType = errType
		audit.ErrorCode = code
	}
	var requestID string
	if audit != nil {
		requestID = audit.RequestID
	}
	writeJSONError(w, status, errType, code, message, requestID)
}

func writeJSONError(w http.ResponseWriter, status int, errType, code, message, requestID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	payload, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"message":    message,
			"type":       errType,
			"code":       code,
			"request_id": requestID,
		},
	})
	w.Write(payload)
}

func sanitizeQuery(rawQuery string) string {
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	for _, sensitive := range []string{"key", "token", "api_key"} {
		if params.Has(sensitive) {
			params.Set(sensitive, "REDACTED")
		}
	}
	return params.Encode()
}

func (p *Proxy) philterError(w http.ResponseWriter, audit *AuditEntry, err error) {
	if p.metrics != nil {
		p.metrics.philterErrors.Inc()
	}
	var cbErr *CircuitOpenError
	if errors.As(err, &cbErr) {
		slog.Warn("Philter circuit breaker open, blocking request", "request_id", audit.RequestID)
		writeError(w, audit, http.StatusServiceUnavailable, "circuit_open", "philter_unavailable", "redaction service unavailable")
		return
	}
	slog.Error("Philter request failed", "error", err, "request_id", audit.RequestID)
	writeError(w, audit, http.StatusBadGateway, "philter_error", "request_failed", "philter request failed")
}

// handleLivez serves the Kubernetes-style liveness endpoint. It is intentionally
// dependency-free: any reply (even 200) proves the process is alive and the
// listener is accepting connections. Treating Philter unreachability as a
// liveness failure used to cause k8s to restart healthy pods during transient
// upstream blips; that responsibility now belongs to /readyz.
func (p *Proxy) handleLivez(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleReadyz serves the Kubernetes-style readiness endpoint. It returns 503
// only when the proxy is in a state where every request will fail - currently
// that means the Philter circuit breaker is open AND its fallback is "block".
// In any other state (no breaker, breaker closed, half-open, or breaker open
// with fallback=passthrough) the proxy is considered ready: individual
// requests may still fail, but k8s shouldn't shed traffic from us.
//
// Unlike /health, /readyz does NOT make an active outbound probe; the breaker
// state is the source of truth. This keeps readiness checks cheap and avoids
// adding extra load to a struggling Philter.
func (p *Proxy) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if p.philter != nil && !p.philter.Ready() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"not_ready","reason":"philter_circuit_open"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleHealth is retained for backwards compatibility. New deployments
// should point Kubernetes probes at /livez (liveness) and /readyz
// (readiness) instead.
func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if p.config == nil || p.philter == nil {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", p.config.Philter.Endpoint, nil)
	resp, err := p.philter.httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","philter":"ok"}`))
		return
	}

	slog.Warn("Philter health check failed", "error", err)
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(`{"status":"degraded","philter":"unreachable"}`))
}

// extractTokenUsage parses prompt and completion token counts from a non-streaming
// provider response body. Returns (0, 0) when the body cannot be parsed or does
// not contain usage data (e.g. streaming responses, errors).
func extractTokenUsage(provider string, body []byte) (promptTokens, completionTokens int) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return
	}
	fi := func(m map[string]interface{}, key string) int {
		if m == nil {
			return 0
		}
		v, _ := m[key].(float64)
		return int(v)
	}
	switch provider {
	case "anthropic":
		usage, _ := raw["usage"].(map[string]interface{})
		return fi(usage, "input_tokens"), fi(usage, "output_tokens")
	case "gemini":
		meta, _ := raw["usageMetadata"].(map[string]interface{})
		return fi(meta, "promptTokenCount"), fi(meta, "candidatesTokenCount")
	case "ollama":
		return fi(raw, "prompt_eval_count"), fi(raw, "eval_count")
	case "bedrock":
		usage, _ := raw["usage"].(map[string]interface{})
		return fi(usage, "inputTokens"), fi(usage, "outputTokens")
	default: // openai, openai-compatible
		usage, _ := raw["usage"].(map[string]interface{})
		return fi(usage, "prompt_tokens"), fi(usage, "completion_tokens")
	}
}

func (p *Proxy) forwardToProvider(w http.ResponseWriter, origReq *http.Request, target *url.URL, client *http.Client, body []byte, provider string, audit *AuditEntry) {
	targetURL := *target
	targetURL.Path = origReq.URL.Path
	targetURL.RawQuery = origReq.URL.RawQuery

	req, err := http.NewRequestWithContext(origReq.Context(), origReq.Method, targetURL.String(), bytes.NewReader(body))
	if err != nil {
		slog.Error("Failed to create provider request", "error", err, "path", origReq.URL.Path, "request_id", audit.RequestID)
		writeError(w, audit, http.StatusInternalServerError, "internal_error", "request_creation_failed", "failed to create provider request")
		return
	}

	for key, values := range origReq.Header {
		if hopByHopHeaders[key] {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	req.ContentLength = int64(len(body))
	req.Host = target.Host

	resp, err := client.Do(req)
	if err != nil {
		safeURL := target.Host + origReq.URL.Path
		if origReq.URL.RawQuery != "" {
			safeURL += "?" + sanitizeQuery(origReq.URL.RawQuery)
		}
		slog.Error("Provider request failed", "error", err, "url", safeURL, "request_id", audit.RequestID)
		if p.metrics != nil {
			p.metrics.upstreamErrors.WithLabelValues(provider, "502").Inc()
		}
		writeError(w, audit, http.StatusBadGateway, "provider_error", "unreachable", "provider request failed")
		return
	}
	defer resp.Body.Close()

	if p.metrics != nil && resp.StatusCode >= 400 {
		p.metrics.upstreamErrors.WithLabelValues(provider, strconv.Itoa(resp.StatusCode)).Inc()
	}

	for key, values := range resp.Header {
		if hopByHopHeaders[key] {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	if !isStreamingResponse(resp.Header) {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("Failed to read provider response", "error", err, "request_id", audit.RequestID)
			writeError(w, audit, http.StatusBadGateway, "provider_error", "response_read_failed", "failed to read provider response")
			return
		}
		if audit != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			audit.PromptTokens, audit.CompletionTokens = extractTokenUsage(provider, respBody)
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	w.WriteHeader(resp.StatusCode)
	flusher, canFlush := w.(http.Flusher)
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr != nil {
			break
		}
	}
}

func emitAuditLog(logger *slog.Logger, entry AuditEntry) {
	if logger == nil {
		return
	}
	logger.Info("request",
		"request_id", entry.RequestID,
		"direction", entry.Direction,
		"provider", entry.Provider,
		"model", entry.Model,
		"policy_name", entry.PolicyName,
		"document_id", entry.DocumentID,
		"fields_redacted", entry.FieldsRedacted,
		"entity_count", entry.EntityCount,
		"entity_types", entry.EntityTypes,
		"redact_latency_ms", entry.RedactLatency.Milliseconds(),
		"client_ip", entry.ClientIP,
		"http_status", entry.HTTPStatus,
		"prompt_tokens", entry.PromptTokens,
		"completion_tokens", entry.CompletionTokens,
		"error_type", entry.ErrorType,
		"error_code", entry.ErrorCode,
		"trace_id", entry.TraceID,
	)
}

// newProviderTransport builds an http.Transport with the four timeouts the
// proxy treats as a stable contract:
//
//   - Dial (connect) timeout — bounds the TCP handshake to a hung host.
//   - TLS handshake timeout — bounds the TLS handshake after dial succeeds.
//   - Response header timeout — bounds the wait for the upstream to start
//     responding. This is the timeout that catches a hung LLM. It does NOT
//     bound body reads, so streaming responses can run as long as the
//     upstream is sending data.
//   - Idle connection timeout — bounds how long keep-alive connections stay
//     in the pool when not in use.
//
// Zero values in t are replaced with the package-level defaults.
//
// The returned transport is paired with an http.Client whose own Timeout is
// left at 0. http.Client.Timeout is a whole-request deadline that would also
// kill streaming bodies, so it must not be set.
func newProviderTransport(tlsCfg *tls.Config, t ProviderTimeouts) *http.Transport {
	if t.ConnectMs <= 0 {
		t.ConnectMs = DefaultConnectTimeoutMs
	}
	if t.TLSHandshakeMs <= 0 {
		t.TLSHandshakeMs = DefaultTLSHandshakeTimeoutMs
	}
	if t.ResponseHeaderMs <= 0 {
		t.ResponseHeaderMs = DefaultResponseHeaderTimeoutMs
	}
	if t.IdleConnMs <= 0 {
		t.IdleConnMs = DefaultIdleConnTimeoutMs
	}
	dialer := &net.Dialer{Timeout: time.Duration(t.ConnectMs) * time.Millisecond}
	return &http.Transport{
		TLSClientConfig:       tlsCfg,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   time.Duration(t.TLSHandshakeMs) * time.Millisecond,
		ResponseHeaderTimeout: time.Duration(t.ResponseHeaderMs) * time.Millisecond,
		IdleConnTimeout:       time.Duration(t.IdleConnMs) * time.Millisecond,
	}
}

func buildTLSConfig(skipVerify bool, caCertPath string) (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: skipVerify}

	if caCertPath != "" && !skipVerify {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate %s: %w", caCertPath, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate %s", caCertPath)
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

func (a *AuditEntry) recordFilterResult(fr FilterResponse) {
	a.DocumentID = fr.DocumentId
	a.FieldsRedacted++
	a.EntityCount += fr.EntityCount
	a.RedactLatency += fr.Latency
	for _, t := range fr.EntityTypes {
		found := false
		for _, existing := range a.EntityTypes {
			if existing == t {
				found = true
				break
			}
		}
		if !found {
			a.EntityTypes = append(a.EntityTypes, t)
		}
	}
	if len(fr.EntityTypeCounts) > 0 {
		if a.EntityTypeCounts == nil {
			a.EntityTypeCounts = make(map[string]int)
		}
		for t, count := range fr.EntityTypeCounts {
			a.EntityTypeCounts[t] += count
		}
	}
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}

func redactAny(reqCtx context.Context, filter filterFunc, v any, philterCtx, docID, policy string, audit *AuditEntry) (any, error) {
	switch val := v.(type) {
	case string:
		if val != "" {
			fr, err := filter(reqCtx, val, philterCtx, docID, policy)
			if err != nil {
				return nil, err
			}
			audit.recordFilterResult(fr)
			return fr.FilteredText, nil
		}
		return val, nil
	case map[string]any:
		for k, elem := range val {
			redacted, err := redactAny(reqCtx, filter, elem, philterCtx, docID, policy, audit)
			if err != nil {
				return nil, err
			}
			val[k] = redacted
		}
		return val, nil
	case []any:
		for i, elem := range val {
			redacted, err := redactAny(reqCtx, filter, elem, philterCtx, docID, policy, audit)
			if err != nil {
				return nil, err
			}
			val[i] = redacted
		}
		return val, nil
	default:
		return v, nil
	}
}

func redactJSONArguments(reqCtx context.Context, filter filterFunc, arguments, philterCtx, docID, policy string, audit *AuditEntry) (string, error) {
	var parsed any
	if err := json.Unmarshal([]byte(arguments), &parsed); err != nil {
		fr, err := filter(reqCtx, arguments, philterCtx, docID, policy)
		if err != nil {
			return "", err
		}
		audit.recordFilterResult(fr)
		return fr.FilteredText, nil
	}
	result, err := redactAny(reqCtx, filter, parsed, philterCtx, docID, policy, audit)
	if err != nil {
		return "", err
	}
	j, err := json.Marshal(result)
	if err != nil {
		return arguments, nil
	}
	return string(j), nil
}

func extractModel(body []byte) string {
	var m struct {
		Model string `json:"model"`
	}
	json.Unmarshal(body, &m)
	return m.Model
}

func isStreamingResponse(headers http.Header) bool {
	ct := headers.Get("Content-Type")
	return strings.Contains(ct, "text/event-stream") || strings.Contains(ct, "application/x-ndjson")
}

func writeBufferedResponse(w http.ResponseWriter, statusCode int, headers http.Header, body []byte) {
	for key, values := range headers {
		if hopByHopHeaders[key] {
			continue
		}
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(statusCode)
	w.Write(body)
}

func (p *Proxy) captureFromProvider(origReq *http.Request, target *url.URL, client *http.Client, body []byte, provider string) (int, http.Header, []byte, error) {
	targetURL := *target
	targetURL.Path = origReq.URL.Path
	targetURL.RawQuery = origReq.URL.RawQuery

	req, err := http.NewRequestWithContext(origReq.Context(), origReq.Method, targetURL.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to create provider request: %w", err)
	}

	for key, values := range origReq.Header {
		if hopByHopHeaders[key] {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	req.ContentLength = int64(len(body))
	req.Host = target.Host

	resp, err := client.Do(req)
	if err != nil {
		safeURL := target.Host + origReq.URL.Path
		if origReq.URL.RawQuery != "" {
			safeURL += "?" + sanitizeQuery(origReq.URL.RawQuery)
		}
		slog.Error("Provider request failed", "error", err, "url", safeURL)
		if p.metrics != nil {
			p.metrics.upstreamErrors.WithLabelValues(provider, "502").Inc()
		}
		return 0, nil, nil, fmt.Errorf("provider request failed: %w", err)
	}
	defer resp.Body.Close()

	if p.metrics != nil && resp.StatusCode >= 400 {
		p.metrics.upstreamErrors.WithLabelValues(provider, strconv.Itoa(resp.StatusCode)).Inc()
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to read provider response: %w", err)
	}

	return resp.StatusCode, resp.Header, respBody, nil
}

// outboundScanText runs a single text value through Philter and applies the configured action.
// Returns (resultText, blocked, error). blocked=true means the response should be blocked entirely.
func (p *Proxy) outboundScanText(reqCtx context.Context, text, philterCtx, docID, policy, action string, audit *AuditEntry) (string, bool, error) {
	if text == "" {
		return text, false, nil
	}
	fr, err := p.philter.Filter(reqCtx, text, philterCtx, docID, policy)
	if err != nil {
		return "", false, err
	}
	audit.recordFilterResult(fr)

	switch action {
	case "block":
		if fr.EntityCount > 0 {
			return "", true, nil
		}
		return text, false, nil
	case "flag":
		if fr.EntityCount > 0 {
			slog.Warn("PII detected in outbound response", "entity_count", fr.EntityCount, "entity_types", fr.EntityTypes, "document_id", docID)
		}
		return text, false, nil
	default: // "redact" or ""
		return fr.FilteredText, false, nil
	}
}

type responseScanner func(context.Context, []byte, string, string, string, string, *AuditEntry) ([]byte, bool, error)

func (p *Proxy) forwardWithOutboundScan(
	w http.ResponseWriter, r *http.Request,
	target *url.URL, client *http.Client, body []byte, provider string,
	philterCtx, docID, policy, action string,
	audit *AuditEntry,
	scanner responseScanner,
) {
	statusCode, respHeaders, respBody, err := p.captureFromProvider(r, target, client, body, provider)
	if err != nil {
		writeError(w, audit, http.StatusBadGateway, "provider_error", "unreachable", "provider request failed")
		return
	}

	if audit != nil && statusCode >= 200 && statusCode < 300 {
		audit.PromptTokens, audit.CompletionTokens = extractTokenUsage(provider, respBody)
	}

	outboundAudit := &AuditEntry{
		RequestID:  audit.RequestID,
		Direction:  "outbound",
		Provider:   audit.Provider,
		Model:      audit.Model,
		PolicyName: audit.PolicyName,
		DocumentID: audit.DocumentID,
		ClientIP:   audit.ClientIP,
		HTTPStatus: statusCode,
	}

	if statusCode >= 200 && statusCode < 300 && !isStreamingResponse(respHeaders) {
		modified, blocked, scanErr := scanner(r.Context(), respBody, philterCtx, docID, policy, action, outboundAudit)
		if scanErr != nil {
			outboundAudit.HTTPStatus = http.StatusBadGateway
			outboundAudit.ErrorType, outboundAudit.ErrorCode = "philter_error", "request_failed"
			emitAuditLog(p.auditLogger, *outboundAudit)
			p.philterError(w, audit, scanErr)
			return
		}
		if blocked {
			outboundAudit.HTTPStatus = http.StatusForbidden
			outboundAudit.ErrorType, outboundAudit.ErrorCode = "pii_blocked", "outbound_blocked"
			emitAuditLog(p.auditLogger, *outboundAudit)
			writeError(w, audit, http.StatusForbidden, "pii_blocked", "outbound_blocked", "response blocked: PII detected")
			return
		}
		respBody = modified
	} else if isStreamingResponse(respHeaders) {
		slog.Warn("Outbound scanning skipped for streaming response", "provider", provider, "document_id", docID)
	}

	emitAuditLog(p.auditLogger, *outboundAudit)
	writeBufferedResponse(w, statusCode, respHeaders, respBody)
}

func (p *Proxy) scanOpenAIResponse(reqCtx context.Context, respBody []byte, philterCtx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return respBody, false, nil
	}
	choices, _ := resp["choices"].([]interface{})
	for _, choice := range choices {
		choiceMap, ok := choice.(map[string]interface{})
		if !ok {
			continue
		}
		message, ok := choiceMap["message"].(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := message["content"].(string)
		if !ok || content == "" {
			continue
		}
		result, blocked, err := p.outboundScanText(reqCtx, content, philterCtx, docID, policy, action, audit)
		if err != nil {
			return nil, false, err
		}
		if blocked {
			return nil, true, nil
		}
		message["content"] = result
	}
	modified, err := json.Marshal(resp)
	if err != nil {
		return respBody, false, nil
	}
	return modified, false, nil
}

func (p *Proxy) scanAnthropicResponse(reqCtx context.Context, respBody []byte, philterCtx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return respBody, false, nil
	}
	content, _ := resp["content"].([]interface{})
	for _, block := range content {
		blockMap, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		if blockMap["type"] != "text" {
			continue
		}
		text, ok := blockMap["text"].(string)
		if !ok || text == "" {
			continue
		}
		result, blocked, err := p.outboundScanText(reqCtx, text, philterCtx, docID, policy, action, audit)
		if err != nil {
			return nil, false, err
		}
		if blocked {
			return nil, true, nil
		}
		blockMap["text"] = result
	}
	modified, err := json.Marshal(resp)
	if err != nil {
		return respBody, false, nil
	}
	return modified, false, nil
}

func (p *Proxy) scanGeminiResponse(reqCtx context.Context, respBody []byte, philterCtx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return respBody, false, nil
	}
	candidates, _ := resp["candidates"].([]interface{})
	for _, candidate := range candidates {
		candidateMap, ok := candidate.(map[string]interface{})
		if !ok {
			continue
		}
		contentMap, ok := candidateMap["content"].(map[string]interface{})
		if !ok {
			continue
		}
		parts, _ := contentMap["parts"].([]interface{})
		for _, part := range parts {
			partMap, ok := part.(map[string]interface{})
			if !ok {
				continue
			}
			text, ok := partMap["text"].(string)
			if !ok || text == "" {
				continue
			}
			result, blocked, err := p.outboundScanText(reqCtx, text, philterCtx, docID, policy, action, audit)
			if err != nil {
				return nil, false, err
			}
			if blocked {
				return nil, true, nil
			}
			partMap["text"] = result
		}
	}
	modified, err := json.Marshal(resp)
	if err != nil {
		return respBody, false, nil
	}
	return modified, false, nil
}

func (p *Proxy) scanOllamaGenerateResponse(reqCtx context.Context, respBody []byte, philterCtx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return respBody, false, nil
	}
	response, ok := resp["response"].(string)
	if !ok || response == "" {
		return respBody, false, nil
	}
	result, blocked, err := p.outboundScanText(reqCtx, response, philterCtx, docID, policy, action, audit)
	if err != nil {
		return nil, false, err
	}
	if blocked {
		return nil, true, nil
	}
	resp["response"] = result
	modified, err := json.Marshal(resp)
	if err != nil {
		return respBody, false, nil
	}
	return modified, false, nil
}

func (p *Proxy) scanOllamaChatResponse(reqCtx context.Context, respBody []byte, philterCtx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return respBody, false, nil
	}
	message, ok := resp["message"].(map[string]interface{})
	if !ok {
		return respBody, false, nil
	}
	content, ok := message["content"].(string)
	if !ok || content == "" {
		return respBody, false, nil
	}
	result, blocked, err := p.outboundScanText(reqCtx, content, philterCtx, docID, policy, action, audit)
	if err != nil {
		return nil, false, err
	}
	if blocked {
		return nil, true, nil
	}
	message["content"] = result
	modified, err := json.Marshal(resp)
	if err != nil {
		return respBody, false, nil
	}
	return modified, false, nil
}

func bedrockTargetURL(region string) string {
	return fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", region)
}

func isBedrockPath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	return len(parts) == 3 && parts[0] == "model" && parts[2] == "converse"
}

func bedrockModelFromPath(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newBedrockHTTPClient(skipVerify bool, t ProviderTimeouts) *http.Client {
	return &http.Client{
		Transport: newProviderTransport(&tls.Config{InsecureSkipVerify: skipVerify}, t),
	}
}

func (p *Proxy) signBedrockRequest(ctx context.Context, req *http.Request, body []byte) error {
	creds, err := p.bedrockCreds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}
	signer := v4.NewSigner()
	return signer.SignHTTP(ctx, creds, req, sha256Hex(body), "bedrock-runtime", p.bedrockRegion, time.Now())
}

func (p *Proxy) handleBedrock(w http.ResponseWriter, r *http.Request, bodyBytes []byte, philterCtx string, docID string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	var req BedrockConverseRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", err.Error())
		return
	}

	audit.Model = bedrockModelFromPath(r.URL.Path)

	for i := range req.System {
		if req.System[i].Text == "" {
			continue
		}
		fr, err := p.philter.Filter(r.Context(), req.System[i].Text, philterCtx, docID, policyName)
		if err != nil {
			p.philterError(w, audit, err)
			return
		}
		req.System[i].Text = fr.FilteredText
		audit.recordFilterResult(fr)
	}

	for i := range req.Messages {
		for j := range req.Messages[i].Content {
			if req.Messages[i].Content[j].Text == "" {
				continue
			}
			fr, err := p.philter.Filter(r.Context(), req.Messages[i].Content[j].Text, philterCtx, docID, policyName)
			if err != nil {
				p.philterError(w, audit, err)
				return
			}
			req.Messages[i].Content[j].Text = fr.FilteredText
			audit.recordFilterResult(fr)
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		writeError(w, audit, http.StatusInternalServerError, "internal_error", "marshal_failed", err.Error())
		return
	}

	if outbound.Enabled {
		p.forwardBedrockWithOutboundScan(w, r, body, philterCtx, docID, policyName, outbound.Action, audit)
		return
	}
	p.forwardToBedrockProvider(w, r, body, audit)
}

func (p *Proxy) forwardToBedrockProvider(w http.ResponseWriter, origReq *http.Request, body []byte, audit *AuditEntry) {
	targetURL := bedrockTargetURL(p.bedrockRegion) + origReq.URL.Path

	req, err := http.NewRequestWithContext(origReq.Context(), "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		slog.Error("Failed to create Bedrock request", "error", err, "request_id", audit.RequestID)
		writeError(w, audit, http.StatusInternalServerError, "internal_error", "request_creation_failed", "failed to create provider request")
		return
	}
	req.Header.Set("Content-Type", "application/json")

	if err := p.signBedrockRequest(origReq.Context(), req, body); err != nil {
		slog.Error("Failed to sign Bedrock request", "error", err, "request_id", audit.RequestID)
		writeError(w, audit, http.StatusInternalServerError, "internal_error", "bedrock_sign_failed", "failed to sign provider request")
		return
	}

	resp, err := p.bedrockClient.Do(req)
	if err != nil {
		slog.Error("Bedrock request failed", "error", err, "request_id", audit.RequestID)
		if p.metrics != nil {
			p.metrics.upstreamErrors.WithLabelValues("bedrock", "502").Inc()
		}
		writeError(w, audit, http.StatusBadGateway, "provider_error", "unreachable", "provider request failed")
		return
	}
	defer resp.Body.Close()

	if p.metrics != nil && resp.StatusCode >= 400 {
		p.metrics.upstreamErrors.WithLabelValues("bedrock", strconv.Itoa(resp.StatusCode)).Inc()
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read Bedrock response", "error", err, "request_id", audit.RequestID)
		writeError(w, audit, http.StatusBadGateway, "provider_error", "response_read_failed", "failed to read provider response")
		return
	}
	if audit != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		audit.PromptTokens, audit.CompletionTokens = extractTokenUsage("bedrock", respBody)
	}

	for key, values := range resp.Header {
		if hopByHopHeaders[key] {
			continue
		}
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (p *Proxy) captureFromBedrockProvider(origReq *http.Request, body []byte) (int, http.Header, []byte, error) {
	targetURL := bedrockTargetURL(p.bedrockRegion) + origReq.URL.Path

	req, err := http.NewRequestWithContext(origReq.Context(), "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to create Bedrock request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if err := p.signBedrockRequest(origReq.Context(), req, body); err != nil {
		return 0, nil, nil, fmt.Errorf("failed to sign Bedrock request: %w", err)
	}

	resp, err := p.bedrockClient.Do(req)
	if err != nil {
		slog.Error("Bedrock request failed", "error", err)
		if p.metrics != nil {
			p.metrics.upstreamErrors.WithLabelValues("bedrock", "502").Inc()
		}
		return 0, nil, nil, fmt.Errorf("provider request failed: %w", err)
	}
	defer resp.Body.Close()

	if p.metrics != nil && resp.StatusCode >= 400 {
		p.metrics.upstreamErrors.WithLabelValues("bedrock", strconv.Itoa(resp.StatusCode)).Inc()
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to read Bedrock response: %w", err)
	}
	return resp.StatusCode, resp.Header, respBody, nil
}

func (p *Proxy) forwardBedrockWithOutboundScan(
	w http.ResponseWriter, r *http.Request, body []byte,
	philterCtx, docID, policy, action string,
	audit *AuditEntry,
) {
	statusCode, respHeaders, respBody, err := p.captureFromBedrockProvider(r, body)
	if err != nil {
		writeError(w, audit, http.StatusBadGateway, "provider_error", "unreachable", "provider request failed")
		return
	}

	if statusCode >= 200 && statusCode < 300 {
		audit.PromptTokens, audit.CompletionTokens = extractTokenUsage("bedrock", respBody)
	}

	outboundAudit := &AuditEntry{
		RequestID:  audit.RequestID,
		Direction:  "outbound",
		Provider:   "bedrock",
		Model:      audit.Model,
		PolicyName: audit.PolicyName,
		DocumentID: audit.DocumentID,
		ClientIP:   audit.ClientIP,
		HTTPStatus: statusCode,
	}

	if statusCode >= 200 && statusCode < 300 && !isStreamingResponse(respHeaders) {
		modified, blocked, scanErr := p.scanBedrockResponse(r.Context(), respBody, philterCtx, docID, policy, action, outboundAudit)
		if scanErr != nil {
			outboundAudit.HTTPStatus = http.StatusBadGateway
			outboundAudit.ErrorType, outboundAudit.ErrorCode = "philter_error", "request_failed"
			emitAuditLog(p.auditLogger, *outboundAudit)
			p.philterError(w, audit, scanErr)
			return
		}
		if blocked {
			outboundAudit.HTTPStatus = http.StatusForbidden
			outboundAudit.ErrorType, outboundAudit.ErrorCode = "pii_blocked", "outbound_blocked"
			emitAuditLog(p.auditLogger, *outboundAudit)
			writeError(w, audit, http.StatusForbidden, "pii_blocked", "outbound_blocked", "response blocked: PII detected")
			return
		}
		respBody = modified
	} else if isStreamingResponse(respHeaders) {
		slog.Warn("Outbound scanning skipped for streaming response", "provider", "bedrock", "document_id", docID)
	}

	emitAuditLog(p.auditLogger, *outboundAudit)
	writeBufferedResponse(w, statusCode, respHeaders, respBody)
}

func (p *Proxy) scanBedrockResponse(reqCtx context.Context, respBody []byte, philterCtx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
	var resp BedrockConverseResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return respBody, false, nil
	}

	for i := range resp.Output.Message.Content {
		text := resp.Output.Message.Content[i].Text
		if text == "" {
			continue
		}
		result, blocked, err := p.outboundScanText(reqCtx, text, philterCtx, docID, policy, action, audit)
		if err != nil {
			return nil, false, err
		}
		if blocked {
			return nil, true, nil
		}
		resp.Output.Message.Content[i].Text = result
	}

	modified, err := json.Marshal(resp)
	if err != nil {
		return respBody, false, nil
	}
	return modified, false, nil
}

// resolveOpenAICompatible checks whether path begins with a configured
// OpenAI-compatible provider prefix (e.g. /mistral/v1/...). When matched it
// returns the provider name, its target and HTTP client, and the path with the
// prefix stripped (e.g. /v1/...).
func (p *Proxy) resolveOpenAICompatible(path string) (name string, target *url.URL, client *http.Client, stripped string, ok bool) {
	if len(p.openaiCompatibleTargets) == 0 || !strings.HasPrefix(path, "/") {
		return
	}
	rest := path[1:] // drop leading /
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return
	}
	prefix := rest[:slash]
	target, ok = p.openaiCompatibleTargets[prefix]
	if !ok {
		return
	}
	return prefix, target, p.openaiCompatibleClients[prefix], path[1+slash:], true
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	switch r.URL.Path {
	case "/livez":
		p.handleLivez(w, r)
		return
	case "/readyz":
		p.handleReadyz(w, r)
		return
	case "/health":
		p.handleHealth(w, r)
		return
	case "/admin/usage":
		if !p.config.Admin.Enabled {
			writeError(w, nil, http.StatusNotFound, "not_found", "admin_disabled", "admin endpoint not enabled")
			return
		}
		p.handleAdminUsage(w, r)
		return
	}

	// Establish the request_id up front so every downstream error path can
	// reference it. An inbound X-Request-Id is honored for tracing across
	// hops; otherwise we generate one.
	requestID := r.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = uuid.New().String()
	}
	w.Header().Set("X-Request-Id", requestID)

	// Build the audit entry early so even auth / rate-limit / concurrency
	// rejections produce a log line. Fields that aren't known yet stay empty;
	// later code fills them in as the request progresses.
	//
	// TraceID is read from the request context, which carries the root span
	// installed by otelhttp when tracing is active (empty otherwise). This
	// links audit log lines to APM traces by W3C trace ID.
	audit := &AuditEntry{
		RequestID: requestID,
		Direction: "inbound",
		ClientIP:  clientIP(r),
		TraceID:   traceIDFromContext(r.Context()),
	}
	rc := newResponseCapture(w)
	start := time.Now()

	defer func() {
		audit.HTTPStatus = rc.statusCode
		emitAuditLog(p.auditLogger, *audit)
		if p.metrics != nil {
			dur := time.Since(start).Seconds()
			statusStr := strconv.Itoa(rc.statusCode)
			p.metrics.requestsTotal.WithLabelValues(audit.Provider, statusStr, audit.PolicyName).Inc()
			p.metrics.requestDuration.WithLabelValues(audit.Provider).Observe(dur)
			if audit.RedactLatency > 0 {
				p.metrics.redactionDuration.WithLabelValues(audit.Provider, audit.PolicyName).Observe(audit.RedactLatency.Seconds())
			}
			for entityType, count := range audit.EntityTypeCounts {
				p.metrics.entitiesRedacted.WithLabelValues(entityType, audit.Provider).Add(float64(count))
			}
			if audit.PromptTokens > 0 {
				p.metrics.promptTokensTotal.WithLabelValues(audit.Provider, audit.Model).Add(float64(audit.PromptTokens))
			}
			if audit.CompletionTokens > 0 {
				p.metrics.completionTokensTotal.WithLabelValues(audit.Provider, audit.Model).Add(float64(audit.CompletionTokens))
			}
		}
	}()

	// API key authentication. Enforced only when keys are configured; disabled by default.
	// clientKeyID is the stable per-entry identifier used downstream for
	// per-key rate limits and per-key concurrency caps; never the raw key.
	var clientKeyID string
	var keyBoundPolicy string
	if p.keyStore != nil {
		headerName := p.config.Auth.Header
		if headerName == "" {
			headerName = "x-philter-proxy-key"
		}
		clientKey := r.Header.Get(headerName)
		if clientKey == "" {
			writeError(rc, audit, http.StatusUnauthorized, "unauthorized", "missing_api_key", "missing API key")
			return
		}
		id, boundPolicy, ok := p.keyStore.lookup(clientKey)
		if !ok {
			writeError(rc, audit, http.StatusUnauthorized, "unauthorized", "invalid_api_key", "invalid API key")
			return
		}
		clientKeyID = id
		keyBoundPolicy = boundPolicy
		// Strip the proxy auth header so it is never forwarded to the LLM provider.
		r.Header.Del(headerName)
	}

	// Rate limiting. Uses the stable per-entry key ID as client identifier when
	// auth is enabled, falling back to client IP. Disabled by default
	// (rateLimiter == nil). The raw API key never reaches the rate limiter so
	// it cannot leak into log fields like `client`.
	if p.rateLimiter != nil {
		id := clientKeyID
		if id == "" {
			id = clientIP(r)
		}
		if allowed, retryAfter := p.rateLimiter.Allow(r.Context(), id); !allowed {
			slog.Warn("Rate limit exceeded", "client", id, "request_id", requestID)
			retrySecs := int(retryAfter.Seconds())
			if retrySecs < 1 {
				retrySecs = 1
			}
			rc.Header().Set("Retry-After", strconv.Itoa(retrySecs))
			writeError(rc, audit, http.StatusTooManyRequests, "rate_limit_error", "rate_limited", "rate limit exceeded")
			return
		}
	}

	// Token quota. Pre-flight check against accumulated usage; on breach return
	// 429 + Retry-After pointing at the window reset. Per-key only (quotas are
	// meaningless without an authenticated key). Fails open on a store error.
	if p.quota != nil && clientKeyID != "" {
		allowed, retryAfter, window, qerr := p.quota.Check(r.Context(), clientKeyID, time.Now())
		if qerr != nil {
			slog.Warn("Quota check failed; allowing (fail-open)", "error", qerr, "client", clientKeyID, "request_id", requestID)
		} else if !allowed {
			retrySecs := int(retryAfter.Seconds())
			if retrySecs < 1 {
				retrySecs = 1
			}
			slog.Warn("Quota exceeded", "client", clientKeyID, "window", window, "request_id", requestID)
			if p.metrics != nil {
				p.metrics.quotaRejections.WithLabelValues(window).Inc()
			}
			rc.Header().Set("Retry-After", strconv.Itoa(retrySecs))
			writeError(rc, audit, http.StatusTooManyRequests, "quota_exceeded", window+"_quota_exceeded", "token quota exceeded")
			return
		}
	}

	// Concurrency guard. Bounds the number of in-flight requests with a graceful
	// 503 + Retry-After when the configured ceiling is reached. Acquire happens
	// after auth and rate limiting so shedded requests are charged against the
	// right client identity and never starve the global pool with junk traffic.
	if p.concurrency != nil {
		allowed, scope, release := p.concurrency.Acquire(clientKeyID)
		if !allowed {
			slog.Warn("Concurrency limit exceeded", "scope", scope, "client", clientKeyID, "request_id", requestID)
			if p.metrics != nil {
				p.metrics.concurrencyShed.WithLabelValues(scope).Inc()
			}
			rc.Header().Set("Retry-After", "1")
			writeError(rc, audit, http.StatusServiceUnavailable, "capacity", "concurrency_exceeded", "concurrency limit exceeded")
			return
		}
		defer release()
	}

	if p.metrics != nil {
		p.metrics.activeRequests.Inc()
		defer p.metrics.activeRequests.Dec()
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		writeError(rc, audit, http.StatusBadRequest, "invalid_request", "body_read", err.Error())
		return
	}

	// Strip OpenAI-compatible provider prefix before routing and route matching.
	// E.g. /mistral/v1/chat/completions → provider "mistral", path /v1/chat/completions.
	var openaiCompatName string
	var openaiCompatTarget *url.URL
	var openaiCompatClient *http.Client
	if name, tgt, cli, strippedPath, matched := p.resolveOpenAICompatible(r.URL.Path); matched {
		openaiCompatName = name
		openaiCompatTarget = tgt
		openaiCompatClient = cli
		newURL := *r.URL
		newURL.Path = strippedPath
		newR := *r
		newR.URL = &newURL
		r = &newR
	}

	model := extractModel(bodyBytes)
	route := matchRoute(p.config, r.URL.Path, model, r.Header.Get)

	// A per-key policy binding overrides whatever the route matched.
	if keyBoundPolicy != "" {
		route.Policy = keyBoundPolicy
	}

	philter_context := route.Context
	philter_document_id := uuid.New().String()
	philter_policy_name := route.Policy

	audit.PolicyName = philter_policy_name
	audit.DocumentID = philter_document_id

	// Response cache lookup. Only non-streaming POSTs are cacheable. A hit is
	// served directly, skipping Philter and the provider entirely. The key is
	// (tenant key, model, sha256(body)) so tenants never share cached entries.
	var cacheKey string
	cacheable := p.cache != nil && r.Method == http.MethodPost && !isStreamingRequest(r.URL.Path, bodyBytes)
	if cacheable {
		tenant := clientKeyID
		if tenant == "" {
			tenant = "anon"
		}
		cacheKey = cacheKeyFor(tenant, model, bodyBytes)
		if cached, ok := p.cache.Get(r.Context(), cacheKey); ok {
			if p.metrics != nil {
				p.metrics.cacheHits.Inc()
			}
			audit.Model = model
			rc.Header().Set("X-Cache", "HIT")
			if cached.ContentType != "" {
				rc.Header().Set("Content-Type", cached.ContentType)
			}
			rc.WriteHeader(cached.Status)
			rc.Write(cached.Body)
			return
		}
		if p.metrics != nil {
			p.metrics.cacheMisses.Inc()
		}
		rc.Header().Set("X-Cache", "MISS")
		// Buffer the response so it can be stored after the handler returns.
		rc.captureBody = true
		rc.limit = p.cacheBodyLimit()
	}

	if openaiCompatName != "" {
		audit.Provider = openaiCompatName
		p.handleOpenAICompatible(rc, r, bodyBytes, philter_context, philter_document_id, philter_policy_name, audit, route.Outbound, openaiCompatTarget, openaiCompatClient, openaiCompatName)
	} else if strings.HasPrefix(r.URL.Path, "/v1/messages") {
		audit.Provider = "anthropic"
		p.handleAnthropic(rc, r, bodyBytes, philter_context, philter_document_id, philter_policy_name, audit, route.Outbound)
	} else if strings.Contains(strings.ToLower(r.URL.Path), "generatecontent") {
		audit.Provider = "gemini"
		p.handleGeminiNative(rc, r, bodyBytes, philter_context, philter_document_id, philter_policy_name, audit, route.Outbound)
	} else if r.URL.Path == "/api/generate" {
		audit.Provider = "ollama"
		p.handleOllamaGenerate(rc, r, bodyBytes, philter_context, philter_document_id, philter_policy_name, audit, route.Outbound)
	} else if r.URL.Path == "/api/chat" {
		audit.Provider = "ollama"
		p.handleOllamaChat(rc, r, bodyBytes, philter_context, philter_document_id, philter_policy_name, audit, route.Outbound)
	} else if isAzurePath(r.URL.Path) {
		audit.Provider = "azure"
		if p.azureTarget == nil {
			writeError(rc, audit, http.StatusNotFound, "not_found", "azure_disabled", "azure provider not configured")
		} else {
			p.handleAzure(rc, r, bodyBytes, philter_context, philter_document_id, philter_policy_name, audit, route.Outbound)
		}
	} else if isBedrockPath(r.URL.Path) {
		audit.Provider = "bedrock"
		if p.bedrockRegion == "" {
			writeError(rc, audit, http.StatusNotFound, "not_found", "bedrock_disabled", "bedrock provider not configured")
		} else {
			p.handleBedrock(rc, r, bodyBytes, philter_context, philter_document_id, philter_policy_name, audit, route.Outbound)
		}
	} else {
		audit.Provider = "openai"
		p.handleOpenAI(rc, r, bodyBytes, philter_context, philter_document_id, philter_policy_name, audit, route.Outbound)
	}

	// Post-response bookkeeping. Token counts are known now (handlers set them
	// on the audit entry). Accumulate per-key usage for quotas/export, and
	// populate the cache on a successful, non-streaming miss.
	if p.usage != nil && clientKeyID != "" && (audit.PromptTokens > 0 || audit.CompletionTokens > 0) {
		if err := p.usage.Add(r.Context(), clientKeyID, int64(audit.PromptTokens), int64(audit.CompletionTokens), time.Now()); err != nil {
			slog.Warn("Usage record failed", "error", err, "client", clientKeyID, "request_id", requestID)
		}
	}
	if cacheable && rc.statusCode >= 200 && rc.statusCode < 300 {
		if body := rc.cachedBody(); len(body) > 0 {
			p.cache.Set(r.Context(), cacheKey, &CachedResponse{
				Status:      rc.statusCode,
				ContentType: rc.Header().Get("Content-Type"),
				Body:        append([]byte(nil), body...),
			})
		}
	}
}

// backendTypeName normalizes an empty backend type to its "memory" default for
// log lines.
func backendTypeName(t string) string {
	if t == "" {
		return "memory"
	}
	return t
}

// cacheBodyLimit is the maximum response size the cache will store; larger
// responses are passed through uncached.
func (p *Proxy) cacheBodyLimit() int {
	if p.config.Cache.MaxBodyBytes > 0 {
		return p.config.Cache.MaxBodyBytes
	}
	return 1 << 20 // 1 MiB
}

// isStreamingRequest reports whether the request asks for a streaming response,
// which must never be cached. Covers the `"stream": true` JSON flag
// (OpenAI/Anthropic/Ollama) and the streaming URL forms (Gemini
// streamGenerateContent, Bedrock converse-stream).
func isStreamingRequest(path string, body []byte) bool {
	lp := strings.ToLower(path)
	if strings.Contains(lp, "streamgeneratecontent") || strings.Contains(lp, "converse-stream") {
		return true
	}
	var probe struct {
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return probe.Stream != nil && *probe.Stream
}

func (p *Proxy) handleOllamaGenerate(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	var o OllamaGenerateRequest
	if err := json.Unmarshal(bodyBytes, &o); err != nil {
		writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", err.Error())
		return
	}

	audit.Model = o.Model

	if o.Prompt != "" {
		fr, err := p.philter.Filter(r.Context(), o.Prompt, context, documentId, policyName)
		if err != nil {
			p.philterError(w, audit, err)
			return
		}
		o.Prompt = fr.FilteredText
		audit.recordFilterResult(fr)
	}

	if o.System != "" {
		fr, err := p.philter.Filter(r.Context(), o.System, context, documentId, policyName)
		if err != nil {
			p.philterError(w, audit, err)
			return
		}
		o.System = fr.FilteredText
		audit.recordFilterResult(fr)
	}

	j, err := json.Marshal(o)
	if err != nil {
		writeError(w, audit, http.StatusInternalServerError, "internal_error", "marshal_failed", err.Error())
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama",
			context, documentId, policyName, outbound.Action, audit, p.scanOllamaGenerateResponse)
		return
	}
	p.forwardToProvider(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama", audit)
}

func (p *Proxy) handleOllamaChat(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	var o OllamaChatRequest
	if err := json.Unmarshal(bodyBytes, &o); err != nil {
		writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", err.Error())
		return
	}

	audit.Model = o.Model

	for i := range o.Messages {
		fr, err := p.philter.Filter(r.Context(), o.Messages[i].Content, context, documentId, policyName)
		if err != nil {
			p.philterError(w, audit, err)
			return
		}
		o.Messages[i].Content = fr.FilteredText
		audit.recordFilterResult(fr)
	}

	j, err := json.Marshal(o)
	if err != nil {
		writeError(w, audit, http.StatusInternalServerError, "internal_error", "marshal_failed", err.Error())
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama",
			context, documentId, policyName, outbound.Action, audit, p.scanOllamaChatResponse)
		return
	}
	p.forwardToProvider(w, r, p.ollamaTarget, p.ollamaClient, j, "ollama", audit)
}

func (p *Proxy) handleGeminiNative(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	var g GeminiRequest
	if err := json.Unmarshal(bodyBytes, &g); err != nil {
		writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", err.Error())
		return
	}

	var filterErr error
loop:
	for i := range g.Contents {
		for j := range g.Contents[i].Parts {
			part := &g.Contents[i].Parts[j]
			if part.Text != "" {
				fr, err := p.philter.Filter(r.Context(), part.Text, context, documentId, policyName)
				if err != nil {
					filterErr = err
					break loop
				}
				part.Text = fr.FilteredText
				audit.recordFilterResult(fr)
			}
			if part.FunctionResponse != nil && part.FunctionResponse.Response != nil {
				if _, err := redactAny(r.Context(), p.philter.Filter, part.FunctionResponse.Response, context, documentId, policyName, audit); err != nil {
					filterErr = err
					break loop
				}
			}
		}
	}
	if filterErr != nil {
		p.philterError(w, audit, filterErr)
		return
	}

	j, err := json.Marshal(g)
	if err != nil {
		writeError(w, audit, http.StatusInternalServerError, "internal_error", "marshal_failed", err.Error())
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, p.geminiTarget, p.geminiClient, j, "gemini",
			context, documentId, policyName, outbound.Action, audit, p.scanGeminiResponse)
		return
	}
	p.forwardToProvider(w, r, p.geminiTarget, p.geminiClient, j, "gemini", audit)
}

func (p *Proxy) handleOpenAI(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	p.handleOpenAICompatible(w, r, bodyBytes, context, documentId, policyName, audit, outbound, p.openaiTarget, p.openaiClient, "openai")
}

func (p *Proxy) handleOpenAICompatible(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig, target *url.URL, client *http.Client, provider string) {
	// Parse into a generic object so every top-level field the client sent
	// (max_tokens, temperature, top_p, stream, stop, tools, tool_choice,
	// response_format, seed, ...) is preserved verbatim when we re-serialize.
	// Only `messages` is rewritten with redacted content; everything else
	// passes through unchanged. Unmarshaling into a fixed struct here would
	// silently drop those parameters and break sampling, streaming, and
	// function-calling for OpenAI, Azure OpenAI, and every openai-compatible
	// provider.
	var root map[string]json.RawMessage
	if err := json.Unmarshal(bodyBytes, &root); err != nil {
		writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", err.Error())
		return
	}

	if rawModel, ok := root["model"]; ok {
		var m string
		_ = json.Unmarshal(rawModel, &m)
		audit.Model = m
	}

	if rawMsgs, ok := root["messages"]; ok && len(rawMsgs) > 0 {
		var messages []OpenAIMessage
		if err := json.Unmarshal(rawMsgs, &messages); err != nil {
			writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", err.Error())
			return
		}

		for i := range messages {
			msg := &messages[i]

			if len(msg.Content) > 0 {
				var s string
				if json.Unmarshal(msg.Content, &s) == nil && s != "" {
					fr, err := p.philter.Filter(r.Context(), s, context, documentId, policyName)
					if err != nil {
						p.philterError(w, audit, err)
						return
					}
					msg.Content, _ = json.Marshal(fr.FilteredText)
					audit.recordFilterResult(fr)
				}
			}

			for j := range msg.ToolCalls {
				tc := &msg.ToolCalls[j]
				if tc.Function.Arguments != "" {
					redacted, err := redactJSONArguments(r.Context(), p.philter.Filter, tc.Function.Arguments, context, documentId, policyName, audit)
					if err != nil {
						p.philterError(w, audit, err)
						return
					}
					tc.Function.Arguments = redacted
				}
			}
		}

		newMsgs, err := json.Marshal(messages)
		if err != nil {
			writeError(w, audit, http.StatusInternalServerError, "internal_error", "marshal_failed", err.Error())
			return
		}
		root["messages"] = newMsgs
	}

	j, err := json.Marshal(root)
	if err != nil {
		writeError(w, audit, http.StatusInternalServerError, "internal_error", "marshal_failed", err.Error())
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, target, client, j, provider,
			context, documentId, policyName, outbound.Action, audit, p.scanOpenAIResponse)
		return
	}
	p.forwardToProvider(w, r, target, client, j, provider, audit)
}

func (p *Proxy) handleAnthropic(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	var a AnthropicRequest
	if err := json.Unmarshal(bodyBytes, &a); err != nil {
		writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", err.Error())
		return
	}

	audit.Model = a.Model

	var filterErr error

	if a.System != "" {
		fr, err := p.philter.Filter(r.Context(), a.System, context, documentId, policyName)
		if err != nil {
			p.philterError(w, audit, err)
			return
		}
		a.System = fr.FilteredText
		audit.recordFilterResult(fr)
	}

msgloop:
	for i := range a.Messages {
		switch v := a.Messages[i].Content.(type) {
		case string:
			fr, err := p.philter.Filter(r.Context(), v, context, documentId, policyName)
			if err != nil {
				filterErr = err
				break msgloop
			}
			a.Messages[i].Content = fr.FilteredText
			audit.recordFilterResult(fr)
		case []any:
			for j := range v {
				if block, ok := v[j].(map[string]any); ok {
					switch block["type"] {
					case "text":
						if text, ok := block["text"].(string); ok && text != "" {
							fr, err := p.philter.Filter(r.Context(), text, context, documentId, policyName)
							if err != nil {
								filterErr = err
								break msgloop
							}
							block["text"] = fr.FilteredText
							audit.recordFilterResult(fr)
						}
					case "tool_result":
						switch c := block["content"].(type) {
						case string:
							if c != "" {
								fr, err := p.philter.Filter(r.Context(), c, context, documentId, policyName)
								if err != nil {
									filterErr = err
									break msgloop
								}
								block["content"] = fr.FilteredText
								audit.recordFilterResult(fr)
							}
						case []any:
							for _, elem := range c {
								if subBlock, ok := elem.(map[string]any); ok {
									if subBlock["type"] == "text" {
										if text, ok := subBlock["text"].(string); ok && text != "" {
											fr, err := p.philter.Filter(r.Context(), text, context, documentId, policyName)
											if err != nil {
												filterErr = err
												break msgloop
											}
											subBlock["text"] = fr.FilteredText
											audit.recordFilterResult(fr)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if filterErr != nil {
		p.philterError(w, audit, filterErr)
		return
	}

	j, err := json.Marshal(a)
	if err != nil {
		writeError(w, audit, http.StatusInternalServerError, "internal_error", "marshal_failed", err.Error())
		return
	}

	if outbound.Enabled {
		p.forwardWithOutboundScan(w, r, p.anthropicTarget, p.anthropicClient, j, "anthropic",
			context, documentId, policyName, outbound.Action, audit, p.scanAnthropicResponse)
		return
	}
	p.forwardToProvider(w, r, p.anthropicTarget, p.anthropicClient, j, "anthropic", audit)
}

func setupAuditLogger(enabled bool, filePath string) *slog.Logger {
	if !enabled {
		return nil
	}

	var w io.Writer = os.Stdout
	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			slog.Error("Failed to open log file", "path", filePath, "error", err)
			os.Exit(1)
		}
		w = io.MultiWriter(os.Stdout, f)
	}

	return slog.New(slog.NewJSONHandler(w, nil))
}

func main() {

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	configPath := os.Getenv("PHILTER_PROXY_CONFIG")
	if len(os.Args) > 2 && os.Args[1] == "--config" {
		configPath = os.Args[2]
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		slog.Error("Configuration error", "error", err)
		os.Exit(1)
	}

	auditLogger := setupAuditLogger(cfg.Logging.Enabled, cfg.Logging.File)

	// OpenTelemetry. setupTracing is a no-op when cfg.Tracing.Enabled is false,
	// so the rest of the wiring below stays oblivious to whether tracing is on.
	shutdownTracer, tracingActive, err := setupTracing(context.Background(), cfg.Tracing)
	if err != nil {
		slog.Error("Tracing setup error", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := shutdownTracer(context.Background()); err != nil {
			slog.Warn("Tracer shutdown error", "error", err)
		}
	}()

	philterTLSVerify := true
	if cfg.Philter.TLSVerify != nil {
		philterTLSVerify = *cfg.Philter.TLSVerify
	}

	philterTLSConfig, err := buildTLSConfig(!philterTLSVerify, cfg.Philter.CACert)
	if err != nil {
		slog.Error("Philter TLS configuration error", "error", err)
		os.Exit(1)
	}

	philterHTTPClient := &http.Client{
		Transport: newProviderTransport(philterTLSConfig, cfg.Philter.Timeouts),
	}
	philterHTTPClient = instrumentTransport(philterHTTPClient, tracingActive, "philter.filter")
	philterClient := newPhilterClient(philterHTTPClient, cfg.Philter.Endpoint, cfg.Philter.Retry, cfg.Philter.CircuitBreaker)

	type providerSetup struct {
		name   string
		config ProviderConfig
	}
	providers := []providerSetup{
		{"openai", cfg.Providers.OpenAI},
		{"anthropic", cfg.Providers.Anthropic},
		{"gemini", cfg.Providers.Gemini},
		{"ollama", cfg.Providers.Ollama},
	}

	targets := make([]*url.URL, 4)
	clients := make([]*http.Client, 4)
	for i, prov := range providers {
		t, err := url.Parse(prov.config.Target)
		if err != nil {
			slog.Error("Invalid provider target URL", "provider", prov.name, "error", err)
			os.Exit(1)
		}
		targets[i] = t

		verify := true
		if prov.config.TLSVerify != nil {
			verify = *prov.config.TLSVerify
		}
		tlsCfg, err := buildTLSConfig(!verify, "")
		if err != nil {
			slog.Error("Provider TLS configuration error", "provider", prov.name, "error", err)
			os.Exit(1)
		}
		clients[i] = &http.Client{
			Transport: newProviderTransport(tlsCfg, prov.config.Timeouts),
		}
		clients[i] = instrumentTransport(clients[i], tracingActive, "provider."+prov.name)
	}

	// Bedrock is optional; only initialize if a region is configured.
	var bedrockRegion string
	var bedrockClient *http.Client
	var bedrockCreds aws.CredentialsProvider
	if cfg.Providers.Bedrock.Region != "" {
		bedrockRegion = cfg.Providers.Bedrock.Region
		awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
			awsconfig.WithRegion(bedrockRegion),
		)
		if err != nil {
			slog.Error("Failed to load AWS configuration for Bedrock", "error", err)
			os.Exit(1)
		}
		if cfg.Providers.Bedrock.RoleArn != "" {
			stsClient := sts.NewFromConfig(awsCfg)
			bedrockCreds = aws.NewCredentialsCache(
				stscreds.NewAssumeRoleProvider(stsClient, cfg.Providers.Bedrock.RoleArn),
			)
			slog.Info("Bedrock using assumed IAM role", "role_arn", cfg.Providers.Bedrock.RoleArn)
		} else {
			bedrockCreds = awsCfg.Credentials
		}

		skipVerify := false
		if cfg.Providers.Bedrock.TLSVerify != nil && !*cfg.Providers.Bedrock.TLSVerify {
			skipVerify = true
		}
		bedrockClient = newBedrockHTTPClient(skipVerify, cfg.Providers.Bedrock.Timeouts)
		bedrockClient = instrumentTransport(bedrockClient, tracingActive, "provider.bedrock")
		slog.Info("Bedrock provider configured", "region", bedrockRegion)
	}

	openaiCompatTargets := make(map[string]*url.URL)
	openaiCompatClients := make(map[string]*http.Client)
	for name, pc := range cfg.Providers.OpenAICompatible {
		t, err := url.Parse(pc.Target)
		if err != nil {
			slog.Error("Invalid openaiCompatible target URL", "provider", name, "error", err)
			os.Exit(1)
		}
		openaiCompatTargets[name] = t
		verify := true
		if pc.TLSVerify != nil {
			verify = *pc.TLSVerify
		}
		tlsCfg, err := buildTLSConfig(!verify, "")
		if err != nil {
			slog.Error("OpenAI-compatible provider TLS configuration error", "provider", name, "error", err)
			os.Exit(1)
		}
		openaiCompatClients[name] = instrumentTransport(
			&http.Client{Transport: newProviderTransport(tlsCfg, pc.Timeouts)},
			tracingActive, "provider."+name,
		)
		slog.Info("OpenAI-compatible provider configured", "name", name, "target", pc.Target)
	}

	// Azure OpenAI is optional; only initialize if a target is configured.
	var azureTarget *url.URL
	var azureClient *http.Client
	var azureCred tokenSource
	if cfg.Providers.Azure.Target != "" {
		azureTarget, err = url.Parse(cfg.Providers.Azure.Target)
		if err != nil {
			slog.Error("Invalid Azure target URL", "error", err)
			os.Exit(1)
		}
		verify := true
		if cfg.Providers.Azure.TLSVerify != nil {
			verify = *cfg.Providers.Azure.TLSVerify
		}
		tlsCfg, err := buildTLSConfig(!verify, "")
		if err != nil {
			slog.Error("Azure TLS configuration error", "error", err)
			os.Exit(1)
		}
		azureClient = instrumentTransport(
			&http.Client{Transport: newProviderTransport(tlsCfg, cfg.Providers.Azure.Timeouts)},
			tracingActive, "provider.azure",
		)
		if cfg.Providers.Azure.EntraID {
			cred, err := newAzureTokenProvider()
			if err != nil {
				slog.Error("Failed to initialize Azure AD credential", "error", err)
				os.Exit(1)
			}
			azureCred = cred
		}
		slog.Info("Azure OpenAI provider configured",
			"target", cfg.Providers.Azure.Target,
			"auth", azureAuthMode(cfg.Providers.Azure.EntraID),
			"apiVersionDefault", cfg.Providers.Azure.APIVersion)
	}

	var proxyMetrics *ProxyMetrics
	var metricsReg *prometheus.Registry
	if cfg.Metrics.Enabled {
		metricsReg = prometheus.NewRegistry()
		proxyMetrics = newMetrics(metricsReg)
	}

	// Build the keyStore. Plaintext keys in YAML get hashed at this point;
	// the keyStore is the only in-memory holder of key material from here on.
	// Returns nil (auth disabled) when no keys are configured.
	keyStoreInstance, err := newKeyStore(cfg.Auth.APIKeys)
	if err != nil {
		slog.Error("Invalid API key configuration", "error", err)
		os.Exit(1)
	}
	if keyStoreInstance != nil {
		slog.Info("API key authentication enabled", "keys", len(keyStoreInstance.entries))
	}

	var proxyRateLimiter *ProxyRateLimiter
	if cfg.RateLimit.Enabled {
		proxyRateLimiter, err = newProxyRateLimiter(cfg.RateLimit, cfg.Auth.APIKeys, proxyMetrics)
		if err != nil {
			slog.Error("Failed to initialize rate-limit backend", "error", err)
			os.Exit(1)
		}
		slog.Info("Rate limiting enabled",
			"requestsPerSecond", cfg.RateLimit.RequestsPerSecond,
			"burst", cfg.RateLimit.Burst)
	}

	var proxyConcurrency *ConcurrencyLimiter
	if cfg.Listen.MaxConcurrentRequests > 0 || hasPerKeyConcurrency(cfg.Auth.APIKeys) {
		proxyConcurrency = newConcurrencyLimiter(
			cfg.Listen.MaxConcurrentRequests,
			perKeyConcurrencyMap(cfg.Auth.APIKeys),
		)
		slog.Info("Concurrency guard enabled",
			"global", cfg.Listen.MaxConcurrentRequests,
			"perKeyEntries", len(perKeyConcurrencyMap(cfg.Auth.APIKeys)),
		)
	}
	if proxyMetrics != nil {
		proxyMetrics.concurrencyLimit.WithLabelValues("global").Set(float64(cfg.Listen.MaxConcurrentRequests))
	}

	// Usage store backs both quotas and the /admin/usage export, so build it
	// when either is enabled. Quota enforcement layers on top of it.
	var usageStore UsageStore
	var quotaEnforcer *QuotaEnforcer
	if cfg.Quota.Enabled || cfg.Admin.Enabled {
		usageStore, err = newUsageStore(cfg.Quota.Backend)
		if err != nil {
			slog.Error("Failed to initialize usage store", "error", err)
			os.Exit(1)
		}
	}
	if cfg.Quota.Enabled {
		quotaEnforcer = newQuotaEnforcer(cfg.Quota, cfg.Auth.APIKeys, usageStore)
		slog.Info("Token quotas enabled",
			"defaultDailyTokens", cfg.Quota.Default.DailyTokens,
			"defaultMonthlyTokens", cfg.Quota.Default.MonthlyTokens,
			"backend", backendTypeName(cfg.Quota.Backend.Type))
	}
	if cfg.Admin.Enabled {
		slog.Info("Admin usage endpoint enabled at /admin/usage")
	}

	var responseCache ResponseCache
	if cfg.Cache.Enabled {
		responseCache, err = newResponseCache(cfg.Cache)
		if err != nil {
			slog.Error("Failed to initialize response cache", "error", err)
			os.Exit(1)
		}
		slog.Info("Response cache enabled",
			"ttlSeconds", cfg.Cache.TTLSeconds,
			"backend", backendTypeName(cfg.Cache.Backend.Type))
	}

	p := &Proxy{
		config:                  cfg,
		openaiTarget:            targets[0],
		anthropicTarget:         targets[1],
		geminiTarget:            targets[2],
		ollamaTarget:            targets[3],
		openaiClient:            clients[0],
		anthropicClient:         clients[1],
		geminiClient:            clients[2],
		ollamaClient:            clients[3],
		bedrockClient:           bedrockClient,
		bedrockRegion:           bedrockRegion,
		bedrockCreds:            bedrockCreds,
		azureTarget:             azureTarget,
		azureClient:             azureClient,
		azureCred:               azureCred,
		openaiCompatibleTargets: openaiCompatTargets,
		openaiCompatibleClients: openaiCompatClients,
		philter:                 philterClient,
		auditLogger:             auditLogger,
		metrics:                 proxyMetrics,
		keyStore:                keyStoreInstance,
		rateLimiter:             proxyRateLimiter,
		concurrency:             proxyConcurrency,
		usage:                   usageStore,
		quota:                   quotaEnforcer,
		cache:                   responseCache,
	}

	port := fmt.Sprintf("%d", cfg.Listen.Port)
	cert_file := cfg.Listen.Cert
	key_file := cfg.Listen.Key
	shutdownTimeoutSec := cfg.Listen.ShutdownTimeout

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: instrumentHandler(p, tracingActive),
	}

	// mTLS: require and verify client certificates when clientCA is configured.
	if cfg.Listen.ClientCA != "" {
		caCert, err := os.ReadFile(cfg.Listen.ClientCA)
		if err != nil {
			slog.Error("Failed to read client CA certificate", "path", cfg.Listen.ClientCA, "error", err)
			os.Exit(1)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			slog.Error("Failed to parse client CA certificate", "path", cfg.Listen.ClientCA)
			os.Exit(1)
		}
		srv.TLSConfig = &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		}
		slog.Info("mTLS enabled", "clientCA", cfg.Listen.ClientCA)
	}

	var metricsSrv *http.Server
	if cfg.Metrics.Enabled {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(metricsReg, promhttp.HandlerOpts{}))
		metricsSrv = &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.Metrics.Port),
			Handler: mux,
		}
		go func() {
			slog.Info("Started metrics server", "port", cfg.Metrics.Port)
			if err := metricsSrv.ListenAndServe(); err != http.ErrServerClosed {
				slog.Warn("Metrics server stopped", "error", err)
			}
		}()
	}

	go func() {
		slog.Info("Started philter-ai-proxy", "port", port)
		if err := srv.ListenAndServeTLS(cert_file, key_file); err != http.ErrServerClosed {
			slog.Error("Listen error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	slog.Info("Shutting down", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(shutdownTimeoutSec)*time.Second)
	defer cancel()

	if metricsSrv != nil {
		metricsSrv.Shutdown(ctx)
	}

	if proxyRateLimiter != nil {
		proxyRateLimiter.Close()
	}

	if responseCache != nil {
		responseCache.Close()
	}

	if usageStore != nil {
		usageStore.Close()
	}

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Forced shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Shutdown complete")
}
