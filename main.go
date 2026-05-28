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
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
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
	Role    string               `json:"role"`
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
	config          *Config
	openaiTarget    *url.URL
	anthropicTarget *url.URL
	geminiTarget    *url.URL
	ollamaTarget    *url.URL
	openaiClient    *http.Client
	anthropicClient *http.Client
	geminiClient    *http.Client
	ollamaClient    *http.Client
	bedrockClient            *http.Client
	bedrockRegion            string
	bedrockCreds             aws.CredentialsProvider
	openaiCompatibleTargets  map[string]*url.URL
	openaiCompatibleClients  map[string]*http.Client
	philter         *PhilterClient
	auditLogger     *slog.Logger
	metrics         *ProxyMetrics
	keyIndex        map[string]string // API key value → bound policy (empty string = no override)
	rateLimiter     *ProxyRateLimiter
	concurrency     *ConcurrencyLimiter
}

type AuditEntry struct {
	RequestID        string         `json:"request_id"`
	Direction        string         `json:"direction"`
	Provider         string         `json:"provider"`
	Model            string         `json:"model"`
	PolicyName       string         `json:"policy_name"`
	DocumentID       string         `json:"document_id"`
	FieldsRedacted   int            `json:"fields_redacted"`
	EntityCount      int            `json:"entity_count"`
	EntityTypes      []string       `json:"entity_types"`
	RedactLatency    time.Duration  `json:"redact_latency_ms"`
	ClientIP         string         `json:"client_ip"`
	HTTPStatus       int            `json:"http_status"`
	PromptTokens     int            `json:"prompt_tokens,omitempty"`
	CompletionTokens int            `json:"completion_tokens,omitempty"`
	// ErrorType / ErrorCode mirror the values the client received in the
	// JSON error body. Empty on 2xx responses.
	ErrorType        string         `json:"error_type,omitempty"`
	ErrorCode        string         `json:"error_code,omitempty"`
	EntityTypeCounts map[string]int `json:"-"`
}

type responseCapture struct {
	http.ResponseWriter
	statusCode int
}

func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{ResponseWriter: w, statusCode: http.StatusOK}
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
	rc.ResponseWriter.WriteHeader(code)
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

	req, err := http.NewRequest(origReq.Method, targetURL.String(), bytes.NewReader(body))
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
	)
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

func redactAny(filter filterFunc, v any, ctx, docID, policy string, audit *AuditEntry) (any, error) {
	switch val := v.(type) {
	case string:
		if val != "" {
			fr, err := filter(val, ctx, docID, policy)
			if err != nil {
				return nil, err
			}
			audit.recordFilterResult(fr)
			return fr.FilteredText, nil
		}
		return val, nil
	case map[string]any:
		for k, elem := range val {
			redacted, err := redactAny(filter, elem, ctx, docID, policy, audit)
			if err != nil {
				return nil, err
			}
			val[k] = redacted
		}
		return val, nil
	case []any:
		for i, elem := range val {
			redacted, err := redactAny(filter, elem, ctx, docID, policy, audit)
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

func redactJSONArguments(filter filterFunc, arguments, ctx, docID, policy string, audit *AuditEntry) (string, error) {
	var parsed any
	if err := json.Unmarshal([]byte(arguments), &parsed); err != nil {
		fr, err := filter(arguments, ctx, docID, policy)
		if err != nil {
			return "", err
		}
		audit.recordFilterResult(fr)
		return fr.FilteredText, nil
	}
	result, err := redactAny(filter, parsed, ctx, docID, policy, audit)
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

	req, err := http.NewRequest(origReq.Method, targetURL.String(), bytes.NewReader(body))
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
func (p *Proxy) outboundScanText(text, ctx, docID, policy, action string, audit *AuditEntry) (string, bool, error) {
	if text == "" {
		return text, false, nil
	}
	fr, err := p.philter.Filter(text, ctx, docID, policy)
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

type responseScanner func([]byte, string, string, string, string, *AuditEntry) ([]byte, bool, error)

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
		modified, blocked, scanErr := scanner(respBody, philterCtx, docID, policy, action, outboundAudit)
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

func (p *Proxy) scanOpenAIResponse(respBody []byte, ctx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
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
		result, blocked, err := p.outboundScanText(content, ctx, docID, policy, action, audit)
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

func (p *Proxy) scanAnthropicResponse(respBody []byte, ctx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
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
		result, blocked, err := p.outboundScanText(text, ctx, docID, policy, action, audit)
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

func (p *Proxy) scanGeminiResponse(respBody []byte, ctx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
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
			result, blocked, err := p.outboundScanText(text, ctx, docID, policy, action, audit)
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

func (p *Proxy) scanOllamaGenerateResponse(respBody []byte, ctx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
	var resp map[string]interface{}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return respBody, false, nil
	}
	response, ok := resp["response"].(string)
	if !ok || response == "" {
		return respBody, false, nil
	}
	result, blocked, err := p.outboundScanText(response, ctx, docID, policy, action, audit)
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

func (p *Proxy) scanOllamaChatResponse(respBody []byte, ctx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
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
	result, blocked, err := p.outboundScanText(content, ctx, docID, policy, action, audit)
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

func newBedrockHTTPClient(skipVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
		},
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
		fr, err := p.philter.Filter(req.System[i].Text, philterCtx, docID, policyName)
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
			fr, err := p.philter.Filter(req.Messages[i].Content[j].Text, philterCtx, docID, policyName)
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
		modified, blocked, scanErr := p.scanBedrockResponse(respBody, philterCtx, docID, policy, action, outboundAudit)
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

func (p *Proxy) scanBedrockResponse(respBody []byte, ctx, docID, policy, action string, audit *AuditEntry) ([]byte, bool, error) {
	var resp BedrockConverseResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return respBody, false, nil
	}

	for i := range resp.Output.Message.Content {
		text := resp.Output.Message.Content[i].Text
		if text == "" {
			continue
		}
		result, blocked, err := p.outboundScanText(text, ctx, docID, policy, action, audit)
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

	if r.URL.Path == "/health" {
		p.handleHealth(w, r)
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
	audit := &AuditEntry{
		RequestID: requestID,
		Direction: "inbound",
		ClientIP:  clientIP(r),
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
	var clientKey string
	var keyBoundPolicy string
	if len(p.keyIndex) > 0 {
		headerName := p.config.Auth.Header
		if headerName == "" {
			headerName = "x-philter-proxy-key"
		}
		clientKey = r.Header.Get(headerName)
		if clientKey == "" {
			writeError(rc, audit, http.StatusUnauthorized, "unauthorized", "missing_api_key", "missing API key")
			return
		}
		boundPolicy, ok := p.keyIndex[clientKey]
		if !ok {
			writeError(rc, audit, http.StatusUnauthorized, "unauthorized", "invalid_api_key", "invalid API key")
			return
		}
		keyBoundPolicy = boundPolicy
		// Strip the proxy auth header so it is never forwarded to the LLM provider.
		r.Header.Del(headerName)
	}

	// Rate limiting. Uses the API key as client identifier when auth is enabled,
	// falling back to client IP. Disabled by default (rateLimiter == nil).
	if p.rateLimiter != nil {
		id := clientKey
		if id == "" {
			id = clientIP(r)
		}
		if allowed, retryAfter := p.rateLimiter.Allow(id); !allowed {
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

	// Concurrency guard. Bounds the number of in-flight requests with a graceful
	// 503 + Retry-After when the configured ceiling is reached. Acquire happens
	// after auth and rate limiting so shedded requests are charged against the
	// right client identity and never starve the global pool with junk traffic.
	if p.concurrency != nil {
		allowed, scope, release := p.concurrency.Acquire(clientKey)
		if !allowed {
			slog.Warn("Concurrency limit exceeded", "scope", scope, "client", clientKey, "request_id", requestID)
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
}

func (p *Proxy) handleOllamaGenerate(w http.ResponseWriter, r *http.Request, bodyBytes []byte, context string, documentId string, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	var o OllamaGenerateRequest
	if err := json.Unmarshal(bodyBytes, &o); err != nil {
		writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", err.Error())
		return
	}

	audit.Model = o.Model

	if o.Prompt != "" {
		fr, err := p.philter.Filter(o.Prompt, context, documentId, policyName)
		if err != nil {
			p.philterError(w, audit, err)
			return
		}
		o.Prompt = fr.FilteredText
		audit.recordFilterResult(fr)
	}

	if o.System != "" {
		fr, err := p.philter.Filter(o.System, context, documentId, policyName)
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
		fr, err := p.philter.Filter(o.Messages[i].Content, context, documentId, policyName)
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
				fr, err := p.philter.Filter(part.Text, context, documentId, policyName)
				if err != nil {
					filterErr = err
					break loop
				}
				part.Text = fr.FilteredText
				audit.recordFilterResult(fr)
			}
			if part.FunctionResponse != nil && part.FunctionResponse.Response != nil {
				if _, err := redactAny(p.philter.Filter, part.FunctionResponse.Response, context, documentId, policyName, audit); err != nil {
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
	var o OpenAIRequest
	if err := json.Unmarshal(bodyBytes, &o); err != nil {
		writeError(w, audit, http.StatusBadRequest, "invalid_request", "bad_json", err.Error())
		return
	}

	audit.Model = o.Model

	for i := range o.Messages {
		msg := &o.Messages[i]

		if len(msg.Content) > 0 {
			var s string
			if json.Unmarshal(msg.Content, &s) == nil && s != "" {
				fr, err := p.philter.Filter(s, context, documentId, policyName)
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
				redacted, err := redactJSONArguments(p.philter.Filter, tc.Function.Arguments, context, documentId, policyName, audit)
				if err != nil {
					p.philterError(w, audit, err)
					return
				}
				tc.Function.Arguments = redacted
			}
		}
	}

	j, err := json.Marshal(o)
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
		fr, err := p.philter.Filter(a.System, context, documentId, policyName)
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
			fr, err := p.philter.Filter(v, context, documentId, policyName)
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
							fr, err := p.philter.Filter(text, context, documentId, policyName)
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
								fr, err := p.philter.Filter(c, context, documentId, policyName)
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
											fr, err := p.philter.Filter(text, context, documentId, policyName)
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
		Transport: &http.Transport{
			TLSClientConfig: philterTLSConfig,
		},
	}
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
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		}
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
		bedrockClient = newBedrockHTTPClient(skipVerify)
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
		openaiCompatClients[name] = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
		slog.Info("OpenAI-compatible provider configured", "name", name, "target", pc.Target)
	}

	var proxyMetrics *ProxyMetrics
	var metricsReg *prometheus.Registry
	if cfg.Metrics.Enabled {
		metricsReg = prometheus.NewRegistry()
		proxyMetrics = newMetrics(metricsReg)
	}

	// Build the API key index (key value → bound policy, or "" for no override).
	// Empty index means authentication is disabled.
	keyIndex := make(map[string]string, len(cfg.Auth.APIKeys))
	for _, entry := range cfg.Auth.APIKeys {
		keyIndex[entry.Key] = entry.Policy
	}
	if len(keyIndex) > 0 {
		slog.Info("API key authentication enabled", "keys", len(keyIndex))
	}

	var proxyRateLimiter *ProxyRateLimiter
	if cfg.RateLimit.Enabled {
		proxyRateLimiter = newProxyRateLimiter(cfg.RateLimit, cfg.Auth.APIKeys)
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

	p := &Proxy{
		config:          cfg,
		openaiTarget:    targets[0],
		anthropicTarget: targets[1],
		geminiTarget:    targets[2],
		ollamaTarget:    targets[3],
		openaiClient:    clients[0],
		anthropicClient: clients[1],
		geminiClient:    clients[2],
		ollamaClient:    clients[3],
		bedrockClient:           bedrockClient,
		bedrockRegion:           bedrockRegion,
		bedrockCreds:            bedrockCreds,
		openaiCompatibleTargets: openaiCompatTargets,
		openaiCompatibleClients: openaiCompatClients,
		philter:                 philterClient,
		auditLogger:             auditLogger,
		metrics:                 proxyMetrics,
		keyIndex:                keyIndex,
		rateLimiter:             proxyRateLimiter,
		concurrency:             proxyConcurrency,
	}

	port := fmt.Sprintf("%d", cfg.Listen.Port)
	cert_file := cfg.Listen.Cert
	key_file := cfg.Listen.Key
	shutdownTimeoutSec := cfg.Listen.ShutdownTimeout

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: p,
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

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Forced shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Shutdown complete")
}
